// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Orchestrator: discovers and runs leak components, then post-processes
// tagged output to produce a section-aware summary.
//
// Component discovery order:
//   1. KASLD_COMPONENT_DIR environment variable (explicit override)
//   2. components/ relative to the binary (build tree / tarball)
//   3. ../libexec/kasld/ relative to the binary (FHS install)
//
// Tagged line format: <type> <section> <addr> <region>[:<name>]
//   type:    V (virtual), P (physical), D (default/KASLR-disabled)
//   section: text, module, directmap, data, dram, pageoffset, or - (default)
//   region:  what kind of thing is at the address (KASLD_REGION_* constant)
//   name:    specific instance, when known (e.g. symbol, module, PCI BDF)
// ---
// <bcoles@gmail.com>

#define _POSIX_C_SOURCE 200809L

#include "include/kasld_inference.h"
#include "include/kasld_internal.h"

#include <dirent.h>
#include <errno.h>
#include <fnmatch.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <elf.h>
#ifdef HAVE_PTHREAD
#include <pthread.h>
#endif

#ifndef VERSION
#define VERSION "unknown"
#endif

int verbose;
int quiet;
int json_output;
int oneline_output;
int markdown_output;
int color_output;
int explain_mode;
int fast_mode;
int hardening_mode;
int experimental_mode;

#define MAX_SKIP_PATTERNS 64
static char skip_patterns[MAX_SKIP_PATTERNS][256];
static int num_skip_patterns;

/* Stored sysctl values for hardening report (-1 = unavailable) */
int sysctl_kptr_restrict = -1;
int sysctl_dmesg_restrict = -1;
int sysctl_perf_event_paranoid = -1;

/* Kernel lockdown status */
enum lockdown_mode sysctl_lockdown = LOCKDOWN_UNAVAILABLE;

/* True when no structured output format is selected (plain text mode) */
#define plain_output() (!json_output && !oneline_output && !markdown_output)

/* =========================================================================
 * Runtime memory layout (initialized from compile-time defaults, may be
 * adjusted at runtime when a pageoffset result overrides PAGE_OFFSET)
 * =========================================================================
 */
struct kasld_layout layout = {
    .page_offset = PAGE_OFFSET,
    .kernel_vas_start = KERNEL_VAS_START,
    .kernel_vas_end = KERNEL_VAS_END,
    .kernel_base_min = KERNEL_BASE_MIN,
    .kernel_base_max = KERNEL_BASE_MAX,
    .modules_start = MODULES_START,
    .modules_end = MODULES_END,
    .kernel_align = KERNEL_ALIGN,
    .text_offset = TEXT_OFFSET,
    .kernel_text_default = KERNEL_TEXT_DEFAULT,
    .kaslr_base_min = KASLR_BASE_MIN,
    .kaslr_base_max = KASLR_BASE_MAX,
    .kaslr_align = KASLR_ALIGN,
};

/* Adjust layout when runtime PAGE_OFFSET differs from compile-time default.
 * On 32-bit, the floor shifts with PAGE_OFFSET; the ceiling stays fixed.
 * Modules shift with PAGE_OFFSET on arm32/ppc32 (where modules_end == old PO),
 * but are fixed on x86_32/mips32.
 * On decoupled architectures (x86_64, modern riscv64), kernel text is not at
 * PAGE_OFFSET, so only directmap/VAS bounds change. */
static void adjust_for_page_offset(unsigned long new_po) {
  unsigned long old_po = layout.page_offset;
  if (new_po == old_po)
    return;

  long delta = (long)(new_po - old_po);

  if (verbose && !quiet && !json_output)
    printf("[layout] PAGE_OFFSET adjusted: %#lx -> %#lx (delta %+ld)\n", old_po,
           new_po, delta);

  layout.page_offset = new_po;
  layout.kernel_vas_start = new_po;

  /* Ensure VAS start doesn't exceed any section that extends below
   * PAGE_OFFSET. On riscv64 SV39, modules (anchored to kernel _end)
   * can be below the detected PAGE_OFFSET. */
  if (layout.modules_start && layout.modules_start < layout.kernel_vas_start)
    layout.kernel_vas_start = layout.modules_start;

#if !PHYS_VIRT_DECOUPLED
  /* On coupled architectures, kernel text base tracks PAGE_OFFSET */
  layout.kernel_base_min = new_po;
  layout.kaslr_base_min = new_po;
  layout.kernel_text_default = new_po + layout.text_offset;
#endif

  /* Modules shift with PAGE_OFFSET when they sit just below it */
  if (layout.modules_end == old_po) {
    layout.modules_start += delta;
    layout.modules_end = new_po;
  }
}

/* Constants used only by the orchestrator */
#define KASLD_PATH_MAX 4096
#define LINE_LEN 512
#define DEFAULT_TIMEOUT_SECS 30
#define FAST_TIMEOUT_SECS 2
static int component_timeout = DEFAULT_TIMEOUT_SECS;

/* Parallel inference: 0 = sequential (default), N > 1 = N worker threads */
static int parallel_workers = 0;

/* Number of components that will actually run (excludes skipped experimental)
 */
static int num_active_components;

/* Protects results[], num_results, comp_logs[], num_comp_logs, progress_done,
 * and the parallel worker pool counter (pool_next). No-ops when pthread is
 * unavailable (sequential-only mode). */
#ifdef HAVE_PTHREAD
static pthread_mutex_t result_mutex = PTHREAD_MUTEX_INITIALIZER;
#define RESULT_LOCK() pthread_mutex_lock(&result_mutex)
#define RESULT_UNLOCK() pthread_mutex_unlock(&result_mutex)
#else
#define RESULT_LOCK() ((void)0)
#define RESULT_UNLOCK() ((void)0)
#endif

/* Inference worker pool: index list built once, consumed by workers */
static int pool_inf[MAX_COMPONENTS]; /* indices into components[] */
static int pool_inf_n;               /* count of inference components */
static int pool_next;                /* next index in pool_inf[] to claim */

/* -------------------------------------------------------------------------
 * Component execution log (for --verbose --json)
 * -------------------------------------------------------------------------
 */
struct component_log comp_logs[MAX_COMPONENTS];
int num_comp_logs;

/* =========================================================================
 * Component discovery
 * =========================================================================
 */
struct component {
  char path[KASLD_PATH_MAX];
  char name[256];
  char phase[32];      /* scheduling phase: "inference" or "probing".
                        * Set from "phase:" in .kasld_meta; falls back to
                        * method-based inference when "phase:" is absent. */
  int is_experimental; /* set from status:experimental in .kasld_meta */
  int is_filtered;     /* set by apply_skip_filter() from --skip patterns */
};

static struct component components[MAX_COMPONENTS];
static int num_components;

/* State machine execution model.
 * Each state declares a phase key (matched against components[].phase), an
 * entry guard (NULL = always enter), an exit action (NULL = no action), and
 * an execution mode (parallel or sequential).  The loop in main() drives the
 * table; adding a new phase means adding one row, not editing main(). */
typedef int (*state_guard_fn)(void);
typedef void (*state_action_fn)(void);

struct exec_state {
  const char *name;         /* for logging and skip messages */
  const char *phase_key;    /* matches component.phase; NULL = no components */
  state_guard_fn can_enter; /* NULL = always enter */
  state_action_fn on_exit; /* NULL = no action; called once after run_state() */
  int parallel;            /* 1 = use worker pool (inference); 0 = sequential */
};

static int component_cmp(const void *a, const void *b) {
  const struct component *ca = (const struct component *)a;
  const struct component *cb = (const struct component *)b;
  return strcmp(ca->name, cb->name);
}

/* Resolve the directory of the running binary via /proc/self/exe */
static int get_self_dir(char *buf, size_t buflen) {
  ssize_t len = readlink("/proc/self/exe", buf, buflen - 1);
  if (len < 0)
    return -1;
  buf[len] = '\0';

  /* Truncate to directory */
  char *slash = strrchr(buf, '/');
  if (slash)
    *slash = '\0';
  else
    return -1;

  return 0;
}

/* Try to open a component directory. Returns DIR* or NULL. */
static DIR *try_component_dir(const char *base, const char *rel, char *resolved,
                              size_t rlen) {
  int n = snprintf(resolved, rlen, "%s/%s", base, rel);
  if (n < 0 || (size_t)n >= rlen)
    return NULL;
  return opendir(resolved);
}

/* Discover component directory using search order */
static int discover_components(void) {
  char comp_dir[KASLD_PATH_MAX];
  DIR *d = NULL;

  /* 1. KASLD_COMPONENT_DIR env var */
  const char *env = getenv("KASLD_COMPONENT_DIR");
  if (env && env[0]) {
    snprintf(comp_dir, sizeof(comp_dir), "%s", env);
    d = opendir(comp_dir);
  }

  /* 2-3. Resolve relative to binary */
  if (!d) {
    char self_dir[KASLD_PATH_MAX];
    if (get_self_dir(self_dir, sizeof(self_dir)) < 0) {
      fprintf(stderr, "error: cannot resolve binary location\n");
      return -1;
    }

    /* 2. components/ beside the binary */
    d = try_component_dir(self_dir, "components", comp_dir, sizeof(comp_dir));

    /* 3. ../libexec/kasld/ (FHS install) */
    if (!d)
      d = try_component_dir(self_dir, "../libexec/kasld", comp_dir,
                            sizeof(comp_dir));
  }

  if (!d) {
    fprintf(stderr, "error: cannot find component directory\n");
    fprintf(stderr, "  tried: components/ and ../libexec/kasld/ "
                    "relative to binary\n");
    fprintf(stderr, "  hint:  set KASLD_COMPONENT_DIR environment variable\n");
    return -1;
  }

  /* Scan directory for executables */
  struct dirent *ent;
  while ((ent = readdir(d)) != NULL) {
    if (num_components >= MAX_COMPONENTS) {
      if (!quiet)
        fprintf(stderr,
                "warning: component limit (%d) reached, "
                "skipping remaining\n",
                MAX_COMPONENTS);
      break;
    }

    /* Skip dotfiles */
    if (ent->d_name[0] == '.')
      continue;

    char path[KASLD_PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/%s", comp_dir, ent->d_name);
    if (n < 0 || (size_t)n >= sizeof(path))
      continue;

    /* Must be a regular executable file */
    struct stat st;
    if (stat(path, &st) < 0)
      continue;
    if (!S_ISREG(st.st_mode))
      continue;
    if (!(st.st_mode & S_IXUSR))
      continue;

    struct component *c = &components[num_components];
    snprintf(c->path, sizeof(c->path), "%s", path);
    snprintf(c->name, sizeof(c->name), "%s", ent->d_name);
    num_components++;
  }
  closedir(d);

  if (num_components == 0) {
    fprintf(stderr, "error: no components found in %s\n", comp_dir);
    return -1;
  }

  /* Sort alphabetically for deterministic default ordering */
  qsort(components, (size_t)num_components, sizeof(struct component),
        component_cmp);

  return 0;
}

/* =========================================================================
 * System information
 * =========================================================================
 */
static void read_proc_value(const char *label, const char *path) {
  FILE *f = fopen(path, "r");
  if (!f) {
    printf("%-30s%s(unavailable)%s\n", label, c(C_DIM), c(C_RESET));
    return;
  }
  char buf[64];
  if (fgets(buf, sizeof(buf), f)) {
    /* Strip trailing newline */
    buf[strcspn(buf, "\n")] = '\0';
    printf("%-30s%s\n", label, buf);
  }
  fclose(f);
}

/* Read a /proc/sys/ file and return its integer value, or -1 on failure */
static int read_sysctl_int(const char *path) {
  FILE *f = fopen(path, "r");
  if (!f)
    return -1;
  int val = -1;
  if (fscanf(f, "%d", &val) != 1)
    val = -1;
  fclose(f);
  return val;
}

/* Read /sys/kernel/security/lockdown and parse the active mode.
 * Format: "none [integrity] confidentiality" — bracketed word is active. */
static enum lockdown_mode read_lockdown(void) {
  FILE *f = fopen("/sys/kernel/security/lockdown", "r");
  if (!f)
    return LOCKDOWN_UNAVAILABLE;
  char buf[128];
  if (!fgets(buf, sizeof(buf), f)) {
    fclose(f);
    return LOCKDOWN_UNAVAILABLE;
  }
  fclose(f);

  char *open = strchr(buf, '[');
  char *close = open ? strchr(open, ']') : NULL;
  if (!open || !close)
    return LOCKDOWN_NONE;

  size_t len = (size_t)(close - open - 1);
  if (len >= 15 && memcmp(open + 1, "confidentiality", 15) == 0)
    return LOCKDOWN_CONFIDENTIALITY;
  if (len >= 9 && memcmp(open + 1, "integrity", 9) == 0)
    return LOCKDOWN_INTEGRITY;
  if (len >= 4 && memcmp(open + 1, "none", 4) == 0)
    return LOCKDOWN_NONE;
  return LOCKDOWN_NONE;
}

static void print_banner(void) {
  struct utsname u;
  if (uname(&u) < 0) {
    perror("uname");
    return;
  }

  // Delta Corps Priest 1 font from https://www.asciiart.eu/text-to-ascii-art
  printf("\n"
         "     ▄█   ▄█▄    ▄████████    ▄████████  ▄█       ████████▄\n"
         "    ███ ▄███▀   ███    ███   ███    ███ ███       ███   ▀███\n"
         "    ███▐██▀     ███    ███   ███    █▀  ███       ███    ███\n"
         "   ▄█████▀      ███    ███   ███        ███       ███    ███\n"
         "  ▀▀█████▄    ▀███████████ ▀███████████ ███       ███    ███\n"
         "    ███▐██▄     ███    ███          ███ ███       ███    ███\n"
         "    ███ ▀███▄   ███    ███    ▄█    ███ ███▌    ▄ ███   ▄███\n"
         "    ███   ▀█▀   ███    █▀   ▄████████▀  █████▄▄██ ████████▀\n"
         "    ▀                                   ▀ v%s\n\n",
         VERSION);
}

static void print_system_config(void) {
  struct utsname u;
  if (uname(&u) < 0) {
    perror("uname");
    return;
  }

  printf("%-30s%s\n", "Kernel release:", u.release);
  printf("%-30s%s\n", "Kernel version:", u.version);
  printf("%-30s%s\n", "Kernel arch:", u.machine);

  /* Read and store sysctl values */
  sysctl_kptr_restrict = read_sysctl_int("/proc/sys/kernel/kptr_restrict");
  sysctl_dmesg_restrict = read_sysctl_int("/proc/sys/kernel/dmesg_restrict");
  sysctl_perf_event_paranoid =
      read_sysctl_int("/proc/sys/kernel/perf_event_paranoid");
  sysctl_lockdown = read_lockdown();

  printf("\n");
  read_proc_value("kernel.kptr_restrict:", "/proc/sys/kernel/kptr_restrict");
  read_proc_value("kernel.dmesg_restrict:", "/proc/sys/kernel/dmesg_restrict");
  read_proc_value("kernel.panic_on_oops:", "/proc/sys/kernel/panic_on_oops");
  read_proc_value("kernel.perf_event_paranoid:",
                  "/proc/sys/kernel/perf_event_paranoid");

  /* Lockdown status */
  {
    const char *mode_str;
    switch (sysctl_lockdown) {
    case LOCKDOWN_CONFIDENTIALITY:
      mode_str = "confidentiality";
      break;
    case LOCKDOWN_INTEGRITY:
      mode_str = "integrity";
      break;
    case LOCKDOWN_NONE:
      mode_str = "none";
      break;
    default:
      mode_str = NULL;
      break;
    }
    if (mode_str)
      printf("%-30s%s\n", "Kernel lockdown:", mode_str);
    else
      printf("%-30s%s(unavailable)%s\n", "Kernel lockdown:", c(C_DIM),
             c(C_RESET));
  }

  printf("\n");

  const char *check_files[][2] = {
      {"Readable /var/log/dmesg:", "/var/log/dmesg"},
      {"Readable /var/log/kern.log:", "/var/log/kern.log"},
      {"Readable /var/log/syslog:", "/var/log/syslog"},
      {"Readable debugfs:", "/sys/kernel/debug"},
      {NULL, NULL},
  };

  for (int i = 0; check_files[i][0]; i++) {
    int readable = access(check_files[i][1], R_OK) == 0;
    printf("%-30s%s%s%s\n", check_files[i][0], readable ? c(C_GREEN) : c(C_DIM),
           readable ? "yes" : "no", c(C_RESET));
  }

  /* Kernel-release-specific paths */
  char path[KASLD_PATH_MAX];
  int readable;

  snprintf(path, sizeof(path), "/boot/System.map-%s", u.release);
  readable = access(path, R_OK) == 0;
  printf("%-30s%s%s%s\n",
         "Readable /boot/System.map:", readable ? c(C_GREEN) : c(C_DIM),
         readable ? "yes" : "no", c(C_RESET));

  snprintf(path, sizeof(path), "/boot/config-%s", u.release);
  readable = access(path, R_OK) == 0;
  printf("%-30s%s%s%s\n",
         "Readable /boot/config:", readable ? c(C_GREEN) : c(C_DIM),
         readable ? "yes" : "no", c(C_RESET));

  printf("\n");
}

/* =========================================================================
 * Component execution
 * =========================================================================
 */

/* Result storage — defined in kasld_internal.h */

struct result results[MAX_RESULTS];
int num_results;

/* Forward declarations for functions defined in the post-processing section */
static unsigned long align_for_section(char type, const char *section,
                                       unsigned long addr);
static int validate_for_section(char type, const char *section,
                                unsigned long addr);
static void apply_layout_adjustments(void);

/* =========================================================================
 * Inference plugin system
 * =========================================================================
 */

/* ELF section bounds — generated by the linker when any inference plugin is
 * compiled in.  Declared weak so the orchestrator links cleanly with no
 * plugins registered (loop has zero iterations). */
extern const struct kasld_inference *__start_kasld_inferences[]
    __attribute__((weak));
extern const struct kasld_inference *__stop_kasld_inferences[]
    __attribute__((weak));

/* Architecture constants (compile-time, set once before the first state) */
static struct kasld_arch_params g_arch_params;

/* Shared analysis context — passed to every inference plugin */
static struct kasld_analysis_ctx g_ctx;

/* Run all plugins registered for the given phase. */
static void run_inference_phase(struct kasld_analysis_ctx *ctx,
                                enum kasld_inference_phase phase) {
  if (!__start_kasld_inferences || !__stop_kasld_inferences)
    return;
  const struct kasld_inference **p;
  for (p = __start_kasld_inferences; p < __stop_kasld_inferences; p++)
    if ((*p)->phase == phase)
      (*p)->run(ctx);
}

/* Update result_count and fire the state's on_exit action. */
static void fire_on_exit(const struct exec_state *st) {
  if (!st->on_exit)
    return;
  g_ctx.result_count = (size_t)num_results;
  st->on_exit();
}

static int capture_result(const char *line, const char *method,
                          const char *origin) {
  if (line[0] != KASLD_ADDR_VIRT && line[0] != KASLD_ADDR_PHYS &&
      line[0] != KASLD_ADDR_DEFAULT)
    return 0;
  if (line[1] != ' ')
    return 0;

  char type_ch;
  char section[SECTION_LEN];
  unsigned long addr;
  int pos = 0;

  if (sscanf(line, "%c %31s %lx %n", &type_ch, section, &addr, &pos) < 3 ||
      pos == 0)
    return 0;

  const char *region_start = line + pos;
  if (*region_start == '\0')
    return 0;

  /* Claim a result slot under the lock; fill it afterwards without the lock.
   * layout.* is read-only during parallel inference so align/validate are safe
   * outside the critical section. */
  RESULT_LOCK();
  if (num_results >= MAX_RESULTS) {
    static int warned;
    if (!warned) {
      if (!quiet)
        fprintf(
            stderr,
            "warning: result limit (%d) reached, dropping further results\n",
            MAX_RESULTS);
      warned = 1;
    }
    RESULT_UNLOCK();
    return 0;
  }
  int idx = num_results++;
  RESULT_UNLOCK();

  struct result *r = &results[idx];
  r->type = type_ch;
  snprintf(r->section, SECTION_LEN, "%s", section);

  /* Wire format: "<type> <section> <addr> <region>" — common case
   *           or  "<type> <section> <addr> <region>:<name>" — when the
   *               component knows the specific instance at this address
   *               (kernel symbol, ACPI table OEM ID, module name, ...).
   *
   * Split on the FIRST `:` only. The name portion may itself contain
   * colons (e.g. PCI BDF "0000:00:14.0"); only the boundary between
   * region and name needs to be unambiguous, and KASLD_REGION_*
   * constants never contain colons.
   *
   * Origin (provenance) is NOT on the wire — the orchestrator already
   * knows which subprocess produced this line and attaches the
   * component name as origin. Single source of truth: the component's
   * identity is whatever the orchestrator launched, not whatever
   * string the component types into its own kasld_result call. */
  char trailing[REGION_LEN + NAME_LEN + 2];
  snprintf(trailing, sizeof(trailing), "%s", region_start);
  size_t tlen = strlen(trailing);
  if (tlen > 0 && trailing[tlen - 1] == '\n')
    trailing[tlen - 1] = '\0';

  char *colon = strchr(trailing, ':');
  if (colon) {
    *colon = '\0';
    snprintf(r->region, REGION_LEN, "%s", trailing);
    snprintf(r->name, NAME_LEN, "%s", colon + 1);
  } else {
    snprintf(r->region, REGION_LEN, "%s", trailing);
    r->name[0] = '\0';
  }

  const char *org = origin ? origin : "";
  size_t olen = strnlen(org, ORIGIN_LEN - 1);
  memcpy(r->origin, org, olen);
  r->origin[olen] = '\0';

  r->raw = addr;
  r->aligned = align_for_section(type_ch, section, addr);
  r->valid = validate_for_section(type_ch, section, addr);

  const char *meth = method ? method : "parsed";
  strncpy(r->method, meth, METHOD_LEN - 1);
  r->method[METHOD_LEN - 1] = '\0';
  return 1;
}

static long deadline_remaining_ms(const struct timespec *deadline) {
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  long ms = (deadline->tv_sec - now.tv_sec) * 1000 +
            (deadline->tv_nsec - now.tv_nsec) / 1000000;
  return ms > 0 ? ms : 0;
}

/* =========================================================================
 * ELF section extractor
 *
 * Reads a named section from a component ELF binary without executing it.
 * Supports both ELF32 and ELF64.  Returns a malloc'd string (caller must
 * free) or NULL if the section is absent or unreadable.
 * =========================================================================
 */
static char *extract_elf_section(const char *path, const char *section_name) {
  FILE *f = fopen(path, "rb");
  if (!f)
    return NULL;

  unsigned char e_ident[EI_NIDENT];
  if (fread(e_ident, 1, EI_NIDENT, f) != EI_NIDENT)
    goto fail;
  if (e_ident[EI_MAG0] != ELFMAG0 || e_ident[EI_MAG1] != ELFMAG1 ||
      e_ident[EI_MAG2] != ELFMAG2 || e_ident[EI_MAG3] != ELFMAG3)
    goto fail;

  int is64 = (e_ident[EI_CLASS] == ELFCLASS64);

  /* Read ELF header fields we need: e_shoff, e_shentsize, e_shnum,
   * e_shstrndx.  Seek past e_ident which we already consumed. */
  uint64_t e_shoff;
  uint16_t e_shentsize, e_shnum, e_shstrndx;

  if (is64) {
    Elf64_Ehdr hdr;
    rewind(f);
    if (fread(&hdr, 1, sizeof(hdr), f) != sizeof(hdr))
      goto fail;
    e_shoff = hdr.e_shoff;
    e_shentsize = hdr.e_shentsize;
    e_shnum = hdr.e_shnum;
    e_shstrndx = hdr.e_shstrndx;
  } else {
    Elf32_Ehdr hdr;
    rewind(f);
    if (fread(&hdr, 1, sizeof(hdr), f) != sizeof(hdr))
      goto fail;
    e_shoff = hdr.e_shoff;
    e_shentsize = hdr.e_shentsize;
    e_shnum = hdr.e_shnum;
    e_shstrndx = hdr.e_shstrndx;
  }

  if (!e_shoff || !e_shnum || e_shstrndx >= e_shnum)
    goto fail;

  /* Read the section header string table (.shstrtab) to resolve names */
  uint64_t shstrtab_off, shstrtab_size;
  uint64_t shstrtab_hdr_off = e_shoff + (uint64_t)e_shstrndx * e_shentsize;
  if (is64) {
    Elf64_Shdr shdr;
    if (shstrtab_hdr_off > LONG_MAX ||
        fseek(f, (long)shstrtab_hdr_off, SEEK_SET))
      goto fail;
    if (fread(&shdr, 1, sizeof(shdr), f) != sizeof(shdr))
      goto fail;
    shstrtab_off = shdr.sh_offset;
    shstrtab_size = shdr.sh_size;
  } else {
    Elf32_Shdr shdr;
    if (shstrtab_hdr_off > LONG_MAX ||
        fseek(f, (long)shstrtab_hdr_off, SEEK_SET))
      goto fail;
    if (fread(&shdr, 1, sizeof(shdr), f) != sizeof(shdr))
      goto fail;
    shstrtab_off = shdr.sh_offset;
    shstrtab_size = shdr.sh_size;
  }

  if (shstrtab_size > 1024 * 1024) /* sanity limit: 1 MiB */
    goto fail;

  if (shstrtab_off > LONG_MAX)
    goto fail;

  char *strtab = malloc((size_t)shstrtab_size + 1);
  if (!strtab)
    goto fail;
  if (fseek(f, (long)shstrtab_off, SEEK_SET) ||
      fread(strtab, 1, (size_t)shstrtab_size, f) != (size_t)shstrtab_size) {
    free(strtab);
    goto fail;
  }
  strtab[shstrtab_size] = '\0';

  /* Scan section headers for the target section */
  char *result = NULL;

  for (uint16_t i = 0; i < e_shnum; i++) {
    uint64_t sh_offset, sh_size;
    uint32_t sh_name;

    uint64_t shdr_off = e_shoff + (uint64_t)i * e_shentsize;
    if (shdr_off > LONG_MAX || fseek(f, (long)shdr_off, SEEK_SET))
      break;

    if (is64) {
      Elf64_Shdr shdr;
      if (fread(&shdr, 1, sizeof(shdr), f) != sizeof(shdr))
        break;
      sh_name = shdr.sh_name;
      sh_offset = shdr.sh_offset;
      sh_size = shdr.sh_size;
    } else {
      Elf32_Shdr shdr;
      if (fread(&shdr, 1, sizeof(shdr), f) != sizeof(shdr))
        break;
      sh_name = shdr.sh_name;
      sh_offset = shdr.sh_offset;
      sh_size = shdr.sh_size;
    }

    if (sh_name >= shstrtab_size)
      continue;
    if (strcmp(strtab + sh_name, section_name) != 0)
      continue;

    /* Found it — read the section contents */
    if (sh_size == 0 || sh_size > 8192) /* sanity limit */
      break;
    if (sh_offset > LONG_MAX)
      break;
    result = malloc((size_t)sh_size + 1);
    if (!result)
      break;
    if (fseek(f, (long)sh_offset, SEEK_SET) ||
        fread(result, 1, (size_t)sh_size, f) != (size_t)sh_size) {
      free(result);
      result = NULL;
      break;
    }
    result[sh_size] = '\0';
    break;
  }

  free(strtab);
  fclose(f);
  return result;

fail:
  fclose(f);
  return NULL;
}

/* =========================================================================
 * Component metadata parsing (.kasld_meta)
 * =========================================================================
 */

/* Parse a raw .kasld_meta string into a component_meta struct.
 * Format: newline-delimited "key:value" pairs. */
static void parse_meta(const char *raw, struct component_meta *m) {
  m->num_entries = 0;
  if (!raw)
    return;

  const char *p = raw;
  while (*p && m->num_entries < META_MAX_ENTRIES) {
    /* Skip leading whitespace/newlines */
    while (*p == '\n' || *p == '\r' || *p == ' ' || *p == '\t')
      p++;
    if (!*p)
      break;

    /* Find end of line */
    const char *eol = strchr(p, '\n');
    if (!eol)
      eol = p + strlen(p);

    /* Find first colon separator */
    const char *colon = NULL;
    for (const char *c = p; c < eol; c++) {
      if (*c == ':') {
        colon = c;
        break;
      }
    }

    if (colon && colon > p) {
      struct meta_entry *e = &m->entries[m->num_entries];

      /* Copy key (trimmed) */
      size_t klen = (size_t)(colon - p);
      if (klen >= META_KEY_LEN)
        klen = META_KEY_LEN - 1;
      memcpy(e->key, p, klen);
      e->key[klen] = '\0';

      /* Copy value (after colon, trimmed) */
      const char *vstart = colon + 1;
      while (vstart < eol && (*vstart == ' ' || *vstart == '\t'))
        vstart++;
      size_t vlen = (size_t)(eol - vstart);
      /* Trim trailing whitespace */
      while (vlen > 0 && (vstart[vlen - 1] == ' ' || vstart[vlen - 1] == '\t' ||
                          vstart[vlen - 1] == '\r'))
        vlen--;
      if (vlen >= META_VALUE_LEN)
        vlen = META_VALUE_LEN - 1;
      memcpy(e->value, vstart, vlen);
      e->value[vlen] = '\0';

      m->num_entries++;
    }

    p = (*eol) ? eol + 1 : eol;
  }
}

/* Return first value for key, or NULL */
const char *meta_get(const struct component_meta *m, const char *key) {
  for (int i = 0; i < m->num_entries; i++) {
    if (strcmp(m->entries[i].key, key) == 0)
      return m->entries[i].value;
  }
  return NULL;
}

/* Return number of values for key, populate values[] array */
int meta_get_all(const struct component_meta *m, const char *key,
                 const char **values, int max_values) {
  int n = 0;
  for (int i = 0; i < m->num_entries; i++) {
    if (strcmp(m->entries[i].key, key) == 0 && n < max_values)
      values[n++] = m->entries[i].value;
  }
  return n;
}

/* Classify components by reading .kasld_meta from each binary.
 * Sets phase to "inference" or "probing".
 *
 * Phase is read from the "phase:" key in .kasld_meta when present.
 * When absent, it falls back to method-based inference for backward
 * compatibility: method:timing and method:heuristic map to "probing";
 * everything else maps to "inference". */
static void classify_components(void) {
  for (int i = 0; i < num_components; i++) {
    char *meta_raw = extract_elf_section(components[i].path, ".kasld_meta");
    if (!meta_raw) {
      snprintf(components[i].phase, sizeof(components[i].phase), "inference");
      continue;
    }
    struct component_meta m = {0};
    parse_meta(meta_raw, &m);
    free(meta_raw);

    const char *phase = meta_get(&m, "phase");
    if (!phase) {
      /* Backward compat: infer phase from method */
      const char *method = meta_get(&m, "method");
      if (method &&
          (strcmp(method, "timing") == 0 || strcmp(method, "heuristic") == 0))
        phase = "probing";
      else
        phase = "inference";
    }
    snprintf(components[i].phase, sizeof(components[i].phase), "%s", phase);

    const char *status = meta_get(&m, "status");
    if (status && strcmp(status, "experimental") == 0)
      components[i].is_experimental = 1;
  }
}

/* Mark components matching any --skip pattern as filtered.
 * No-op when num_skip_patterns == 0. Called after classify_components(). */
static void apply_skip_filter(void) {
  if (num_skip_patterns == 0)
    return;
  for (int i = 0; i < num_components; i++) {
    for (int j = 0; j < num_skip_patterns; j++) {
      if (fnmatch(skip_patterns[j], components[i].name, 0) == 0) {
        components[i].is_filtered = 1;
        break;
      }
    }
  }
}

static int run_component(const struct component *c) {
  /* Extract explain string before execution (if --explain active or JSON) */
  char *explain_str = NULL;
  if (explain_mode || json_output)
    explain_str = extract_elf_section(c->path, ".kasld_explain");

  /* Extract metadata (always — needed for method and hardening report) */
  char *meta_raw = extract_elf_section(c->path, ".kasld_meta");
  struct component_meta tmp_meta = {0};
  parse_meta(meta_raw, &tmp_meta);
  free(meta_raw);

  /* Set method from metadata (fallback: "parsed") */
  const char *method_val = meta_get(&tmp_meta, "method");
  const char *comp_method = method_val ? method_val : "parsed";

  if (verbose && !json_output)
    printf("--- %s ---\n", c->name);

  if (explain_mode && explain_str && !json_output)
    printf("  %s\n\n", explain_str);

  /* Always allocate a log slot for outcome tracking */
  struct component_log *clog = NULL;
  RESULT_LOCK();
  if (num_comp_logs < MAX_COMPONENTS) {
    int clog_idx = num_comp_logs++;
    RESULT_UNLOCK();
    clog = &comp_logs[clog_idx];
    snprintf(clog->name, sizeof(clog->name), "%s", c->name);
    clog->exit_code = -1;
    clog->outcome = OUTCOME_NO_RESULT;
    clog->num_lines = 0;
    clog->explain = explain_str; /* transfer ownership */
    clog->meta = tmp_meta;       /* copy parsed metadata */
    explain_str = NULL;
    /* Re-point method to the clog copy (stable pointer into clog->meta) */
    method_val = meta_get(&clog->meta, "method");
    comp_method = method_val ? method_val : "parsed";
  } else {
    RESULT_UNLOCK();
  }

  /* Free explain_str if not transferred to clog */
  free(explain_str);

  int pipefd[2];
  if (pipe(pipefd) < 0) {
    perror("pipe");
    return -1;
  }

  pid_t pid = fork();
  if (pid < 0) {
    perror("fork");
    close(pipefd[0]);
    close(pipefd[1]);
    return -1;
  }

  if (pid == 0) {
    /* Child: new process group so we can kill any grandchildren */
    setpgid(0, 0);

    /* Redirect stdout to pipe, merge stderr into stdout */
    close(pipefd[0]);
    dup2(pipefd[1], STDOUT_FILENO);
    dup2(pipefd[1], STDERR_FILENO);
    close(pipefd[1]);

    execl(c->path, c->name, (char *)NULL);
    _exit(127);
  }

  /* Parent: also set child pgid (race-safe double-set with child) */
  setpgid(pid, pid);
  close(pipefd[1]);

  /* Compute deadline */
  struct timespec deadline;
  clock_gettime(CLOCK_MONOTONIC, &deadline);
  deadline.tv_sec += component_timeout;

  /* Non-blocking read with poll() timeout */
  struct pollfd pfd = {.fd = pipefd[0], .events = POLLIN};
  char buf[LINE_LEN];
  size_t buf_pos = 0;
  int timed_out = 0;
  int tagged_this_run = 0;

  while (1) {
    long remaining = deadline_remaining_ms(&deadline);
    if (remaining == 0) {
      timed_out = 1;
      break;
    }

    int pr = poll(&pfd, 1, (int)(remaining > INT_MAX ? INT_MAX : remaining));
    if (pr < 0) {
      if (errno == EINTR)
        continue;
      break;
    }
    if (pr == 0) {
      timed_out = 1;
      break;
    }

    /* Read available data */
    ssize_t n = read(pipefd[0], buf + buf_pos, sizeof(buf) - buf_pos - 1);
    if (n <= 0)
      break; /* EOF or error */

    buf_pos += (size_t)n;
    buf[buf_pos] = '\0';

    /* Process complete lines */
    char *start = buf;
    char *nl;
    while ((nl = strchr(start, '\n')) != NULL) {
      *nl = '\0';
      if (verbose && !json_output)
        printf("%s\n", start);

      /* Capture line for verbose output */
      if (clog && verbose && clog->num_lines < MAX_COMPONENT_LINES) {
        snprintf(clog->lines[clog->num_lines], MAX_LINE_LEN, "%s", start);
        clog->num_lines++;
      }

      /* Re-add newline for capture (region newline stripped in capture_result)
       */
      *nl = '\n';
      char line[LINE_LEN];
      size_t llen = (size_t)(nl - start + 1);
      if (llen < sizeof(line)) {
        memcpy(line, start, llen);
        line[llen] = '\0';
        /* Origin (provenance) is the component name — captured at the
         * orchestrator since it owns the subprocess identity. */
        tagged_this_run += capture_result(line, comp_method, c->name);
      }

      start = nl + 1;
    }

    /* Shift remaining partial line to front of buffer */
    size_t left = buf_pos - (size_t)(start - buf);
    if (left > 0)
      memmove(buf, start, left);
    buf_pos = left;
  }

  close(pipefd[0]);

  if (timed_out) {
    if (!quiet)
      fprintf(stderr, "warning: component '%s' timed out after %ds, killing\n",
              c->name, component_timeout);
    kill(-pid, SIGKILL); /* Kill entire process group */
  }

  int status;
  waitpid(pid, &status, 0);

  int had_tagged = (tagged_this_run > 0);
  int rc = WIFEXITED(status) ? WEXITSTATUS(status) : -1;

  /* Classify outcome from exit code.  Components signal their own status:
   *   exit 0  = ran successfully (results determined by tagged output)
   *   exit 69 = feature/hardware unavailable (EX_UNAVAILABLE)
   *   exit 77 = access denied (EX_NOPERM) */
  if (clog) {
    if (had_tagged)
      clog->outcome = OUTCOME_SUCCESS;
    else if (timed_out)
      clog->outcome = OUTCOME_TIMEOUT;
    else if (rc == KASLD_EXIT_NOPERM)
      clog->outcome = OUTCOME_ACCESS_DENIED;
    else if (rc == KASLD_EXIT_UNAVAILABLE)
      clog->outcome = OUTCOME_UNAVAILABLE;
    else
      clog->outcome = OUTCOME_NO_RESULT;
    clog->exit_code = rc;
  }

  if (timed_out)
    return -1;

  return rc;
}

/* Progress tracking across phases */
static int progress_done;
static struct timespec progress_start;

static void progress_update(void) {
  RESULT_LOCK();
  int done = ++progress_done;
  RESULT_UNLOCK();

  if (quiet || json_output || oneline_output || markdown_output)
    return;
  if (verbose)
    printf("\n");
  else {
    int total =
        num_active_components > 0 ? num_active_components : num_components;
    int pct = total > 0 ? (done * 100) / total : 0;
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    double elapsed = (double)(now.tv_sec - progress_start.tv_sec) +
                     (double)(now.tv_nsec - progress_start.tv_nsec) / 1e9;

    /* Build a small progress bar: [####......] */
    int bar_width = 20;
    int filled = (pct * bar_width) / 100;
    char bar[32];
    for (int i = 0; i < bar_width; i++)
      bar[i] = i < filled ? '#' : '.';
    bar[bar_width] = '\0';

    printf("\r%s[%s]%s %3d%%  %d/%d  %s%.1fs%s", c(C_DIM), bar, c(C_RESET), pct,
           done, total, c(C_DIM), elapsed, c(C_RESET));
    fflush(stdout);
  }
}

/* Worker thread: claims inference components from the pool and runs them. */
static void *inference_worker(void *arg) {
  (void)arg;
  while (1) {
    RESULT_LOCK();
    int slot = (pool_next < pool_inf_n) ? pool_next++ : -1;
    RESULT_UNLOCK();
    if (slot < 0)
      break;
    run_component(&components[pool_inf[slot]]);
    progress_update();
  }
  return NULL;
}

/* Run the components for a single state.
 *
 * Parallel states (st->parallel): worker pool when parallel_workers > 1 and
 *   not verbose; apply_layout_adjustments() after each component in sequential
 *   mode, once after join in parallel mode.  Layout is read-only during
 *   parallel execution so align/validate calls inside capture_result() are
 *   safe without additional locking.
 *
 * Sequential states (!st->parallel): single-threaded loop;
 *   apply_layout_adjustments() once at the end so that PAGE_OFFSET results
 *   from probing components propagate before the on_exit action fires.
 *
 * States with phase_key == NULL (setup) have no associated components; the
 * function returns immediately and on_exit fires in the caller. */
static void run_state(const struct exec_state *st) {
  /* Setup state: no components; fire on_exit once (PRE_COLLECTION plugins). */
  if (!st->phase_key) {
    fire_on_exit(st);
    return;
  }

  int exp_active = experimental_mode || getenv("KASLD_EXPERIMENTAL") != NULL;
  pool_inf_n = 0;
  for (int i = 0; i < num_components; i++) {
    if (strcmp(components[i].phase, st->phase_key) == 0 &&
        (!components[i].is_experimental || exp_active) &&
        !components[i].is_filtered)
      pool_inf[pool_inf_n++] = i;
  }
  if (pool_inf_n == 0)
    return;

  if (!st->parallel) {
    /* Sequential (probing and any future non-parallel states): fire on_exit
     * after each component so PAGE_OFFSET discoveries propagate immediately. */
    for (int i = 0; i < pool_inf_n; i++) {
      run_component(&components[pool_inf[i]]);
      progress_update();
      fire_on_exit(st);
    }
    return;
  }

  /* Parallel (inference): sequential fallback when workers <= 1 or verbose.
   * verbose falls back to sequential to avoid interleaved output. */
  int workers = parallel_workers;
#ifndef HAVE_PTHREAD
  workers = 1;
#endif

  if (workers <= 1 || verbose) {
    for (int i = 0; i < pool_inf_n; i++) {
      run_component(&components[pool_inf[i]]);
      progress_update();
      fire_on_exit(st);
    }
    return;
  }

  if (workers > pool_inf_n)
    workers = pool_inf_n;
  pool_next = 0;

#ifdef HAVE_PTHREAD
  pthread_t threads[MAX_COMPONENTS];
  int i;
  for (i = 0; i < workers; i++)
    pthread_create(&threads[i], NULL, inference_worker, NULL);
  for (i = 0; i < workers; i++)
    pthread_join(threads[i], NULL);
  fire_on_exit(st);
#endif
}

/* =========================================================================
 * Post-processing: validate, align, group, and summarize tagged results
 * =========================================================================
 */
static unsigned long align_for_section(char type, const char *section,
                                       unsigned long addr) {
  if (type == KASLD_ADDR_DEFAULT)
    return addr;

  if (strcmp(section, KASLD_SECTION_TEXT) == 0)
    return addr & -layout.kernel_align;

  /* module, directmap, data, dram, pageoffset: no alignment (report as-is) */
  return addr;
}

static int validate_for_section(char type, const char *section,
                                unsigned long addr) {
  if (type == KASLD_ADDR_DEFAULT)
    return 1;

  if (type == KASLD_ADDR_VIRT) {
    if (strcmp(section, KASLD_SECTION_TEXT) == 0)
      return addr >= layout.kernel_base_min && addr <= layout.kernel_base_max;

    if (strcmp(section, KASLD_SECTION_MODULE) == 0)
      return addr >= layout.modules_start && addr <= layout.modules_end;

    if (strcmp(section, KASLD_SECTION_DIRECTMAP) == 0 ||
        strcmp(section, KASLD_SECTION_DATA) == 0)
      return addr >= layout.kernel_vas_start && addr <= layout.kernel_vas_end;

    if (strcmp(section, KASLD_SECTION_PAGEOFFSET) == 0)
      return 1;
  }

  if (type == KASLD_ADDR_PHYS) {
#ifdef KERNEL_PHYS_MIN
    if (strcmp(section, KASLD_SECTION_TEXT) == 0)
      return addr >= KERNEL_PHYS_MIN && addr <= KERNEL_PHYS_MAX;

    if (strcmp(section, KASLD_SECTION_DRAM) == 0)
      return 1;
#endif
    return 1;
  }

  return 1;
}

/* Re-validate and re-align all results against the current layout */
static void revalidate_results(void) {
  for (int i = 0; i < num_results; i++) {
    results[i].aligned =
        align_for_section(results[i].type, results[i].section, results[i].raw);
    results[i].valid = validate_for_section(results[i].type, results[i].section,
                                            results[i].aligned);
  }
}

#ifdef LEGACY_LAYOUT_BOUNDARY
/* Search virtual text results for an address below the arch-defined legacy
 * layout boundary. Does not require results[i].valid because on arches
 * where the modern KERNEL_BASE_MIN is above the legacy range (arm64), the
 * legacy address will have initially failed validation.  The VAS-range
 * check provides a minimal sanity gate. */
static unsigned long find_legacy_text(void) {
  for (int i = 0; i < num_results; i++) {
    if (results[i].type == KASLD_ADDR_VIRT &&
        strcmp(results[i].section, KASLD_SECTION_TEXT) == 0 &&
        results[i].aligned != 0 && results[i].aligned >= KERNEL_VAS_START &&
        results[i].aligned < LEGACY_LAYOUT_BOUNDARY)
      return results[i].aligned;
  }
  return 0;
}
#endif

/* Apply PAGE_OFFSET adjustment if a pageoffset result overrides the default */
static void apply_layout_adjustments(void) {
  /* Check for conflicting pageoffset sources (e.g., proc-config's
   * CONFIG_PAGE_OFFSET vs proc-cpuinfo's MMU-inferred value). Conflicts
   * indicate a legacy kernel where CONFIG_PAGE_OFFSET was a compile-time
   * constant rather than derived from the active paging mode.
   * Guard against repeated warnings: called after every inference component. */
  static int po_conflict_warned = 0;
  unsigned long po_vals[MAX_RESULTS];
  int po_n = 0;
  for (int i = 0; i < num_results; i++) {
    if (results[i].type == KASLD_ADDR_VIRT &&
        strcmp(results[i].section, KASLD_SECTION_PAGEOFFSET) == 0 &&
        results[i].valid) {
      int dup = 0;
      for (int j = 0; j < po_n; j++) {
        if (po_vals[j] == results[i].aligned) {
          dup = 1;
          break;
        }
      }
      if (!dup && po_n < MAX_RESULTS)
        po_vals[po_n++] = results[i].aligned;
    }
  }
  if (po_n > 1 && !po_conflict_warned) {
    po_conflict_warned = 1;
    if (!quiet) {
      fprintf(stderr, "[!] Conflicting PAGE_OFFSET sources detected "
                      "(possible legacy kernel layout):\n");
      for (int i = 0; i < po_n; i++)
        fprintf(stderr, "    0x%016lx\n", po_vals[i]);
      fprintf(stderr, "    Using 0x%016lx (modern layout assumed)\n",
              po_vals[0] < po_vals[1] ? po_vals[0] : po_vals[1]);
    }
  }

  unsigned long detected_po =
      group_consensus(KASLD_ADDR_VIRT, KASLD_SECTION_PAGEOFFSET);
  if (detected_po && detected_po != layout.page_offset)
    adjust_for_page_offset(detected_po);

#if !PHYS_VIRT_DECOUPLED
  /* On coupled architectures, kernel text lives above PAGE_OFFSET.
   * KERNEL_BASE_MIN may be conservatively low (e.g. x86_32 uses 0x40000000
   * to accept addresses from any CONFIG_VMSPLIT_* at validation time), but
   * must be clamped to PAGE_OFFSET for the final layout so the memory map
   * and KASLR analysis reference the correct text region floor.
   * Also fix kernel_vas_start: on arm32 modules sit just below PAGE_OFFSET,
   * so VAS start is min(page_offset, modules_start). */
  if (layout.kernel_base_min < layout.page_offset) {
    layout.kernel_base_min = layout.page_offset;
    layout.kernel_text_default = layout.page_offset + layout.text_offset;
    layout.kernel_vas_start = layout.page_offset;
    if (layout.modules_start < layout.kernel_vas_start)
      layout.kernel_vas_start = layout.modules_start;
  }
#endif

#ifdef LEGACY_LAYOUT_BOUNDARY
  /* Detect legacy kernel layout: if a validated virtual text address falls
   * below the arch-defined boundary, the kernel is using an older VAS layout.
   *
   * Two modes (selected by the arch header):
   *   LEGACY_COUPLED:  PAGE_OFFSET derived from text; all base fields track
   *                    it (e.g. riscv64 SV39).
   *   Otherwise:       Static constants from LEGACY_* macros replace the
   *                    modern defaults (e.g. arm64 pre-v5.4). */
  {
    unsigned long legacy_text = find_legacy_text();
    if (legacy_text) {
#ifdef LEGACY_COUPLED
      layout.text_offset = LEGACY_TEXT_OFFSET;
      unsigned long legacy_po = legacy_text & LEGACY_PAGE_OFFSET_MASK;
      if (legacy_po != layout.page_offset)
        adjust_for_page_offset(legacy_po);
      /* adjust_for_page_offset handles VAS start and module shifting but,
       * on PHYS_VIRT_DECOUPLED arches, does not update text-tracking fields.
       * Apply them explicitly for the coupled legacy layout. */
      layout.kernel_text_default = legacy_po + layout.text_offset;
      layout.kernel_base_min = legacy_po;
      layout.kaslr_base_min = legacy_po;
#else
      layout.page_offset = LEGACY_PAGE_OFFSET;
      layout.kernel_vas_start = LEGACY_KERNEL_VAS_START;
      layout.modules_start = LEGACY_MODULES_START;
      layout.modules_end = LEGACY_MODULES_END;
      layout.text_offset = LEGACY_TEXT_OFFSET;
      layout.kernel_text_default = LEGACY_KERNEL_TEXT_DEFAULT;
      layout.kernel_base_min = LEGACY_KERNEL_BASE_MIN;
      layout.kaslr_base_min = LEGACY_KASLR_BASE_MIN;
      layout.kaslr_base_max = LEGACY_KASLR_BASE_MAX;
#endif
    }
  }
#endif

  revalidate_results();
}

/* Check parsed results for KASLR-disabled / unsupported indicators.
 *
 * Detection components (default, proc-cmdline, proc-config, boot-config,
 * dmesg_kaslr-disabled, ...) emit DEFAULT-type results carrying a marker
 * in r->name:
 *   ""            — KASLR enabled; address is the compile-time fallback
 *   "text"        — same (legacy "default:text" label, pre-sweep)
 *   "nokaslr"     — KASLR is disabled
 *   "unsupported" — KASLR not supported on this kernel/arch
 *
 * Anything other than "" / "text" indicates KASLR is not active. */
static int detect_kaslr_state(void) {
  for (int i = 0; i < num_results; i++) {
    if (results[i].type == KASLD_ADDR_DEFAULT && results[i].name[0] != '\0' &&
        strcmp(results[i].name, "text") != 0)
      return 1; /* disabled or unsupported */
  }
  return 0;
}

/* Guard for the probing state: enter only when KASLR appears active. */
static int kaslr_appears_active(void) { return !detect_kaslr_state(); }

/* -------------------------------------------------------------------------
 * Analysis helpers: find consensus address for a (type, section) group
 * -------------------------------------------------------------------------
 */
static int method_weight(const char *method) {
  if (strcmp(method, "exact") == 0)
    return 4;
  if (strcmp(method, "timing") == 0)
    return 3;
  if (strcmp(method, "parsed") == 0)
    return 2;
  if (strcmp(method, "heuristic") == 0)
    return 1;
  return 2; /* default: same as parsed */
}

unsigned long group_consensus(char type, const char *section) {
  /* Find the best aligned address in a group using method-weighted scoring.
   * Each result contributes its method weight to the address's total score.
   * Highest score wins; ties break to most sources, then lowest address. */
  unsigned long addrs[MAX_RESULTS];
  int scores[MAX_RESULTS];
  int counts[MAX_RESULTS];
  int n = 0;

  for (int i = 0; i < num_results; i++) {
    struct result *r = &results[i];
    if (r->type != type || strcmp(r->section, section) != 0 || !r->valid)
      continue;

    int w = method_weight(r->method);
    int found = 0;
    for (int j = 0; j < n; j++) {
      if (addrs[j] == r->aligned) {
        scores[j] += w;
        counts[j]++;
        found = 1;
        break;
      }
    }
    if (!found && n < MAX_RESULTS) {
      addrs[n] = r->aligned;
      scores[n] = w;
      counts[n] = 1;
      n++;
    }
  }

  if (n == 0)
    return 0;

  /* Return the address with highest score (ties: most sources, then lowest) */
  int best = 0;
  for (int i = 1; i < n; i++) {
    if (scores[i] > scores[best] ||
        (scores[i] == scores[best] && counts[i] > counts[best]) ||
        (scores[i] == scores[best] && counts[i] == counts[best] &&
         addrs[i] < addrs[best]))
      best = i;
  }
  return addrs[best];
}

void group_consensus_info(char type, const char *section,
                          const char **best_method, int *n_sources,
                          int *n_conflicts) {
  unsigned long consensus = group_consensus(type, section);

  const char *top_method = NULL;
  int top_weight = 0;
  int sources = 0;
  int distinct = 0;

  for (int i = 0; i < num_results; i++) {
    struct result *r = &results[i];
    if (r->type != type || strcmp(r->section, section) != 0 || !r->valid)
      continue;
    if (r->aligned == consensus) {
      sources++;
      int w = method_weight(r->method);
      if (w > top_weight) {
        top_weight = w;
        top_method = r->method;
      }
    } else {
      distinct++;
    }
  }

  if (best_method)
    *best_method = top_method ? top_method : "unknown";
  if (n_sources)
    *n_sources = sources;
  if (n_conflicts)
    *n_conflicts = distinct;
}

/* -------------------------------------------------------------------------
 * KASLR slide and entropy analysis
 * -------------------------------------------------------------------------
 */
static int ilog2(unsigned long v) {
  int r = 0;
  while (v >>= 1)
    r++;
  return r;
}

/* Pure computation: fill kaslr_info from consensus addresses */
void compute_kaslr_info(struct summary *s) {
  s->kaslr.vtext = group_consensus(KASLD_ADDR_VIRT, KASLD_SECTION_TEXT);
  s->kaslr.ptext = group_consensus(KASLD_ADDR_PHYS, KASLD_SECTION_TEXT);
  s->kaslr.has_phys = 0;

  if (s->kaslr.vtext) {
    s->kaslr.vslide = (long)(s->kaslr.vtext - layout.kernel_text_default);
    unsigned long text_range = layout.kaslr_base_max - layout.kaslr_base_min;
    s->kaslr.vslots = layout.kaslr_align ? text_range / layout.kaslr_align : 0;
    s->kaslr.vbits = s->kaslr.vslots > 0 ? ilog2(s->kaslr.vslots) : 0;
    s->kaslr.vslot_valid =
        (layout.kaslr_align > 0 && s->kaslr.vtext >= layout.kaslr_base_min &&
         s->kaslr.vtext < layout.kaslr_base_max);
    if (s->kaslr.vslot_valid)
      s->kaslr.vslot_idx =
          (s->kaslr.vtext - layout.kaslr_base_min) / layout.kaslr_align;
  }

  if (s->kaslr.ptext) {
#ifdef KERNEL_PHYS_DEFAULT
    s->kaslr.has_phys = 1;
    s->kaslr.pslide = (long)(s->kaslr.ptext - KERNEL_PHYS_DEFAULT);
    unsigned long phys_range = KASLR_PHYS_MAX - KASLR_PHYS_MIN;
    s->kaslr.pslots = KASLR_PHYS_ALIGN ? phys_range / KASLR_PHYS_ALIGN : 0;
    s->kaslr.pbits = s->kaslr.pslots > 0 ? ilog2(s->kaslr.pslots) : 0;
#endif
  }

  /* When KASLR is disabled or unsupported, slide and entropy are
   * definitionally zero regardless of what addresses were leaked. */
  if (s->kaslr.disabled || s->kaslr.unsupported) {
    s->kaslr.vslide = 0;
    s->kaslr.vslots = 0;
    s->kaslr.vbits = 0;
    s->kaslr.vslot_valid = 0;
    s->kaslr.pslide = 0;
    s->kaslr.pslots = 0;
    s->kaslr.pbits = 0;
  }
}

/* -------------------------------------------------------------------------
 * Derive cross-section information (compute-then-render)
 * -------------------------------------------------------------------------
 */
static void add_derived(struct summary *s, char type, const char *section,
                        unsigned long addr, unsigned long addr_hi,
                        const char *label, const char *via) {
  if (s->num_derived >= MAX_DERIVED)
    return;
  struct derived_addr *d = &s->derived[s->num_derived++];
  d->type = type;
  strncpy(d->section, section, SECTION_LEN - 1);
  d->section[SECTION_LEN - 1] = '\0';
  d->addr = addr;
  d->addr_hi = addr_hi;
  snprintf(d->label, sizeof(d->label), "%s", label);
  snprintf(d->via, sizeof(d->via), "%s", via);
}

/* Pure computation: derive addresses across sections (no printf) */
void compute_derived_addrs(struct summary *s) {
  s->num_derived = 0;
  unsigned long ptext = group_consensus(KASLD_ADDR_PHYS, KASLD_SECTION_TEXT);
  (void)add_derived; /* conditionally used depending on architecture */

#if !PHYS_VIRT_DECOUPLED
  unsigned long vtext = group_consensus(KASLD_ADDR_VIRT, KASLD_SECTION_TEXT);
  unsigned long vdmap =
      group_consensus(KASLD_ADDR_VIRT, KASLD_SECTION_DIRECTMAP);
  /* Coupled: virtual text <-> physical text <-> directmap */
  if (vtext && !ptext) {
    unsigned long derived = vtext - layout.page_offset + PHYS_OFFSET;
    add_derived(s, KASLD_ADDR_PHYS, KASLD_SECTION_TEXT, derived, 0,
                "Physical text base", "via V text");
  }
  if (ptext && !vtext) {
    unsigned long derived =
        (ptext - PHYS_OFFSET + layout.page_offset + layout.text_offset) &
        -layout.kernel_align;
    if (derived >= layout.kernel_base_min && derived <= layout.kernel_base_max)
      add_derived(s, KASLD_ADDR_VIRT, KASLD_SECTION_TEXT, derived, 0,
                  "Virtual text base", "via P text");
  }
#if PAGE_OFFSET_RANDOMIZED
  if (vdmap && !vtext) {
    unsigned long derived = (vdmap + layout.text_offset) & -layout.kernel_align;
    if (derived >= layout.kernel_base_min && derived <= layout.kernel_base_max)
      add_derived(s, KASLD_ADDR_VIRT, KASLD_SECTION_TEXT, derived, 0,
                  "Virtual text base", "via V directmap");
  }
  if (vtext && !vdmap) {
    unsigned long derived = (vtext - layout.text_offset) & -layout.kernel_align;
    add_derived(s, KASLD_ADDR_VIRT, KASLD_SECTION_DIRECTMAP, derived, 0,
                "Direct map (PAGE_OFFSET)", "via V text");
  }
#endif
#else
  /* Decoupled: phys_to_virt() yields a direct-map address, not the kernel
   * text address. Cannot derive virtual text from physical results. */
  {
    unsigned long vtext = group_consensus(KASLD_ADDR_VIRT, KASLD_SECTION_TEXT);
    unsigned long pdram_lo, pdram_hi;
    group_range(KASLD_ADDR_PHYS, KASLD_SECTION_DRAM, &pdram_lo, &pdram_hi);
    if (!vtext && (ptext || pdram_lo))
      s->decoupled_note = 1;
  }
#endif

  /* Derive approximate text range from module addresses on architectures
   * where the module region is anchored to the kernel image.
   * On riscv64: MODULES_VADDR = _end - 2G, so _end ≈ module_lo + 2G.
   * Kernel image size varies (~5-60 MiB), so we report a range. */
#if MODULES_RELATIVE_TO_TEXT
  {
    unsigned long vtext = group_consensus(KASLD_ADDR_VIRT, KASLD_SECTION_TEXT);
    if (!vtext) {
      unsigned long vmod_lo, vmod_hi;
      group_range(KASLD_ADDR_VIRT, KASLD_SECTION_MODULE, &vmod_lo, &vmod_hi);
      if (vmod_lo) {
        /* _end ≈ module_start + MODULES_END_TO_TEXT_OFFSET */
        unsigned long end_est = vmod_lo + MODULES_END_TO_TEXT_OFFSET;

        /* Estimate text range: small kernel (~4 MiB) to large (~64 MiB) */
        unsigned long text_hi = (end_est - 4 * MB) & -layout.kernel_align;
        unsigned long text_lo = (end_est - 64 * MB) & -layout.kernel_align;

        /* Clamp to valid kernel text region */
        if (text_lo < layout.kernel_base_min)
          text_lo = layout.kernel_base_min;

        if (text_hi <= layout.kernel_base_max && text_lo < text_hi) {
          add_derived(s, KASLD_ADDR_VIRT, KASLD_SECTION_TEXT, end_est, 0,
                      "Kernel _end estimate", "module_lo + 2 GiB");

          /* Cross-reference with physical DRAM leak to narrow the range */
          unsigned long pdram_lo, pdram_hi;
          group_range(KASLD_ADDR_PHYS, KASLD_SECTION_DRAM, &pdram_lo,
                      &pdram_hi);
          if (pdram_lo) {
            unsigned long vtext_from_phys =
                (pdram_lo - PHYS_OFFSET + layout.page_offset +
                 layout.text_offset) &
                -layout.kernel_align;
            if (vtext_from_phys >= text_lo && vtext_from_phys <= text_hi) {
              add_derived(s, KASLD_ADDR_VIRT, KASLD_SECTION_TEXT,
                          vtext_from_phys, 0, "Virtual text base",
                          "P dram + PAGE_OFFSET confirmed by module range");
            } else {
              add_derived(s, KASLD_ADDR_VIRT, KASLD_SECTION_TEXT, text_lo,
                          text_hi, "Virtual text range", "module range");
              add_derived(s, KASLD_ADDR_VIRT, KASLD_SECTION_TEXT,
                          vtext_from_phys, 0, "Virtual text (phys)",
                          "P dram derived, outside module range");
            }
          } else {
            add_derived(s, KASLD_ADDR_VIRT, KASLD_SECTION_TEXT, text_lo,
                        text_hi, "Virtual text range", "module range");
          }
        }
      }
    }
  }
#endif
}

/* -------------------------------------------------------------------------
 * ASCII memory layout map — group_range used by rendering and core
 * -------------------------------------------------------------------------
 */
void group_range(char type, const char *section, unsigned long *lo,
                 unsigned long *hi) {
  *lo = 0;
  *hi = 0;
  int found = 0;
  for (int i = 0; i < num_results; i++) {
    struct result *r = &results[i];
    if (r->type != type || strcmp(r->section, section) != 0 || !r->valid)
      continue;
    if (!found || r->aligned < *lo)
      *lo = r->aligned;
    if (r->aligned > *hi)
      *hi = r->aligned;
    found = 1;
  }
  /* If only one unique address, clear hi */
  if (*lo == *hi)
    *hi = 0;
}

/* -------------------------------------------------------------------------
 * Component statistics: aggregate outcome counts
 * -------------------------------------------------------------------------
 */
void compute_component_stats(struct summary *s) {
  s->stats.total = num_comp_logs;
  s->stats.succeeded = 0;
  s->stats.no_result = 0;
  s->stats.unavailable = 0;
  s->stats.access_denied = 0;
  s->stats.timed_out = 0;

  for (int i = 0; i < num_comp_logs; i++) {
    switch (comp_logs[i].outcome) {
    case OUTCOME_SUCCESS:
      s->stats.succeeded++;
      break;
    case OUTCOME_TIMEOUT:
      s->stats.timed_out++;
      break;
    case OUTCOME_ACCESS_DENIED:
      s->stats.access_denied++;
      break;
    case OUTCOME_UNAVAILABLE:
      s->stats.unavailable++;
      break;
    case OUTCOME_NO_RESULT:
      s->stats.no_result++;
      break;
    }
  }
}

/* -------------------------------------------------------------------------
 * Pre-computation: detect KASLR state and inject default address
 * -------------------------------------------------------------------------
 */
void inject_kaslr_defaults(struct summary *s) {
  s->kaslr.disabled = 0;
  s->kaslr.unsupported = 0;
  s->kaslr.default_addr = 0;

  for (int i = 0; i < num_results; i++) {
    if (results[i].type == KASLD_ADDR_DEFAULT) {
      s->kaslr.default_addr = results[i].aligned;
      /* See detect_kaslr_state() for the marker model:
       *   r->name == "unsupported"  → arch lacks KASLR support
       *   r->name == "nokaslr" or other non-empty/non-"text" → disabled
       *   r->name == "" or "text"   → fallback only (KASLR may be active) */
      if (strcmp(results[i].name, "unsupported") == 0)
        s->kaslr.unsupported = 1;
      else if (results[i].name[0] != '\0' &&
               strcmp(results[i].name, "text") != 0)
        s->kaslr.disabled = 1;
    }
  }

  /* The default component emits the compile-time KERNEL_TEXT_DEFAULT, but
   * runtime layout adjustments (e.g. legacy riscv64 detection) may have
   * changed layout.kernel_text_default. Use the runtime value. */
  if (s->kaslr.default_addr)
    s->kaslr.default_addr = layout.kernel_text_default;

  /* When KASLR is disabled/unsupported, inject the default text address
   * as a virtual text result so it flows into the memory map and
   * cross-section derivation. */
  if ((s->kaslr.disabled || s->kaslr.unsupported) && s->kaslr.default_addr &&
      num_results < MAX_RESULTS) {
    struct result *r = &results[num_results];
    r->type = KASLD_ADDR_VIRT;
    strncpy(r->section, KASLD_SECTION_TEXT, SECTION_LEN - 1);
    r->section[SECTION_LEN - 1] = '\0';
    /* Synthetic injection: region is KERNEL_TEXT (the address points at
     * the kernel text base); name carries the "nokaslr" marker (the
     * synthetic record represents the orchestrator's interpretation,
     * not a fresh leak); origin identifies the synthetic source. */
    strncpy(r->region, KASLD_REGION_KERNEL_TEXT, REGION_LEN - 1);
    r->region[REGION_LEN - 1] = '\0';
    strncpy(r->name, "nokaslr", NAME_LEN - 1);
    r->name[NAME_LEN - 1] = '\0';
    strncpy(r->origin, "kasld", ORIGIN_LEN - 1);
    r->origin[ORIGIN_LEN - 1] = '\0';
    r->raw = s->kaslr.default_addr;
    r->aligned = s->kaslr.default_addr;
    r->valid = 1;
    strncpy(r->method, "exact", METHOD_LEN - 1);
    r->method[METHOD_LEN - 1] = '\0';
    num_results++;
  }
}

/* State on_exit actions --------------------------------------------------- */

static void run_pre_collection_inference(void) {
  run_inference_phase(&g_ctx, KASLD_INFER_PHASE_PRE_COLLECTION);
}

static void run_post_collection_inference(void) {
  apply_layout_adjustments(); /* existing PAGE_OFFSET propagation, unchanged */
  run_inference_phase(&g_ctx, KASLD_INFER_PHASE_POST_COLLECTION);
}

static void run_post_probing_inference(void) {
  apply_layout_adjustments();
  run_inference_phase(&g_ctx, KASLD_INFER_PHASE_POST_PROBING);
}

/* Execution state table --------------------------------------------------- */

/* Each row is one phase.  Adding a new phase = adding one row here. */
static const struct exec_state states[] = {
    {"setup", NULL, NULL, run_pre_collection_inference, 0},
    {"inference", "inference", NULL, run_post_collection_inference, 1},
    {"probing", "probing", kaslr_appears_active, run_post_probing_inference, 0},
};

/* =========================================================================
 * Main
 * =========================================================================
 */
#ifndef KASLD_TESTING
static void usage(const char *progname) {
  printf(
      "Usage: %s [OPTIONS]\n\n"
      "Options:\n"
      "  -j, --json          Machine-readable JSON output\n"
      "  -1, --oneline       Single-line summary output\n"
      "  -m, --markdown      Markdown table output\n"
      "  -c, --color         Colorize text output (auto-detected for TTYs)\n"
      "  -q, --quiet         Suppress banner, progress, and warnings\n"
      "  -v, --verbose       Show component output\n"
      "  -e, --explain       Show technique explanations before each "
      "component\n"
      "  -f, --fast          Use %ds per-component timeout\n"
      "  -w, --workers N     Parallel inference workers (default: nproc; 0 = "
      "sequential)\n"
      "  -x, --experimental  Enable experimental components\n"
      "  -s, --skip PATTERN  Skip matching components (glob, comma-separated;\n"
      "                      multiple --skip flags accumulate)\n"
      "  -H, --hardening     Show post-run hardening assessment\n"
      "  -t, --timeout N     Per-component timeout in seconds (default: %d)\n"
      "  -V, --version       Print version and exit\n"
      "  -h, --help          Show this help\n",
      progname, FAST_TIMEOUT_SECS, DEFAULT_TIMEOUT_SECS);
}

int main(int argc, char *argv[]) {
  /* Default to nproc workers; --workers overrides */
  {
    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    parallel_workers = (ncpu > 1) ? (int)ncpu : 4;
  }

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-j") == 0 || strcmp(argv[i], "--json") == 0) {
      json_output = 1;
      oneline_output = 0;
      markdown_output = 0;
    } else if (strcmp(argv[i], "-1") == 0 ||
               strcmp(argv[i], "--oneline") == 0) {
      oneline_output = 1;
      json_output = 0;
      markdown_output = 0;
    } else if (strcmp(argv[i], "-m") == 0 ||
               strcmp(argv[i], "--markdown") == 0) {
      markdown_output = 1;
      json_output = 0;
      oneline_output = 0;
    } else if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--color") == 0) {
      color_output = 1;
    } else if (strcmp(argv[i], "-q") == 0 || strcmp(argv[i], "--quiet") == 0) {
      quiet = 1;
    } else if (strcmp(argv[i], "-v") == 0 ||
               strcmp(argv[i], "--verbose") == 0) {
      verbose = 1;
    } else if (strcmp(argv[i], "-e") == 0 ||
               strcmp(argv[i], "--explain") == 0) {
      explain_mode = 1;
      verbose = 1; /* --explain implies --verbose */
    } else if (strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "--fast") == 0) {
      fast_mode = 1;
    } else if (strcmp(argv[i], "-w") == 0 ||
               strcmp(argv[i], "--workers") == 0) {
      if (i + 1 >= argc) {
        fprintf(stderr, "--workers requires a value\n");
        return 2;
      }
      parallel_workers = atoi(argv[++i]);
    } else if (strcmp(argv[i], "-x") == 0 ||
               strcmp(argv[i], "--experimental") == 0) {
      experimental_mode = 1;
    } else if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--skip") == 0) {
      if (i + 1 >= argc) {
        fprintf(stderr, "--skip requires a value\n");
        return 2;
      }
      char *val = argv[++i];
      char *tok = strtok(val, ",");
      while (tok) {
        if (num_skip_patterns < MAX_SKIP_PATTERNS) {
          strncpy(skip_patterns[num_skip_patterns], tok, 255);
          skip_patterns[num_skip_patterns][255] = '\0';
          num_skip_patterns++;
        }
        tok = strtok(NULL, ",");
      }
    } else if (strcmp(argv[i], "-H") == 0 ||
               strcmp(argv[i], "--hardening") == 0) {
      hardening_mode = 1;
    } else if (strcmp(argv[i], "-t") == 0 ||
               strcmp(argv[i], "--timeout") == 0) {
      if (i + 1 >= argc) {
        fprintf(stderr, "--timeout requires a value\n");
        return 2;
      }
      component_timeout = atoi(argv[++i]);
      if (component_timeout <= 0) {
        fprintf(stderr, "--timeout must be a positive integer\n");
        return 2;
      }
    } else if (strcmp(argv[i], "-V") == 0 ||
               strcmp(argv[i], "--version") == 0) {
      printf("kasld %s\n", VERSION);
      return 0;
    } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
      usage(argv[0]);
      return 0;
    } else {
      fprintf(stderr, "unknown option: %s\n", argv[i]);
      usage(argv[0]);
      return 2;
    }
  }

  /* Ensure line-buffered stdout so output appears in real-time */
  setvbuf(stdout, NULL, _IOLBF, 0);

  /* Auto-detect color when stdout is a TTY and no structured format selected */
  if (!color_output && plain_output())
    color_output = isatty(STDOUT_FILENO);

  if (!quiet && plain_output()) {
    print_banner();
    print_system_config();
  } else {
    /* Always read system state even when banner is suppressed */
    sysctl_kptr_restrict = read_sysctl_int("/proc/sys/kernel/kptr_restrict");
    sysctl_dmesg_restrict = read_sysctl_int("/proc/sys/kernel/dmesg_restrict");
    sysctl_perf_event_paranoid =
        read_sysctl_int("/proc/sys/kernel/perf_event_paranoid");
    sysctl_lockdown = read_lockdown();
  }

  if (discover_components() < 0)
    return 2;

  classify_components();
  apply_skip_filter();

  /* Verbose: list components excluded by --skip */
  if (verbose && num_skip_patterns > 0 && !json_output) {
    for (int i = 0; i < num_components; i++) {
      if (components[i].is_filtered)
        printf("[.] skipping %s (matched --skip filter)\n", components[i].name);
    }
  }

  /* Component accounting: determine how many will run */
  {
    int exp_env = getenv("KASLD_EXPERIMENTAL") != NULL;
    if (experimental_mode)
      setenv("KASLD_EXPERIMENTAL", "1", 1);
    int exp_active = experimental_mode || exp_env;
    num_active_components = 0;
    for (int i = 0; i < num_components; i++) {
      if (components[i].is_filtered)
        continue;
      if (components[i].is_experimental && !exp_active)
        continue;
      num_active_components++;
    }
  }

  /* --fast: tighten per-component timeout unless user set an explicit -t */
  if (fast_mode && component_timeout == DEFAULT_TIMEOUT_SECS)
    component_timeout = FAST_TIMEOUT_SECS;

  if (!quiet && !verbose && plain_output()) {
    clock_gettime(CLOCK_MONOTONIC, &progress_start);
    int exp_active =
        experimental_mode || (getenv("KASLD_EXPERIMENTAL") != NULL);
    int nf = 0, ne = 0;
    for (int i = 0; i < num_components; i++) {
      if (components[i].is_filtered)
        nf++;
      else if (components[i].is_experimental && !exp_active)
        ne++;
    }
    if (nf > 0 && ne > 0)
      printf("Running %d components (%d skipped by --skip, %d experimental "
             "skipped; use -x to enable)...\n",
             num_active_components, nf, ne);
    else if (nf > 0)
      printf("Running %d components (%d skipped by --skip)...\n",
             num_active_components, nf);
    else if (ne > 0)
      printf("Running %d components (%d experimental skipped; "
             "use -x to enable)...\n",
             num_active_components, ne);
    else
      printf("Running %d components...\n", num_active_components);
    fflush(stdout);
  }

  /* Initialise analysis context before the first state fires on_exit. */
  g_arch_params.kaslr_base_min = layout.kaslr_base_min;
  g_arch_params.kaslr_base_max = layout.kaslr_base_max;
  g_arch_params.kaslr_align = layout.kaslr_align;
  g_ctx.results = results;
  g_ctx.result_count = 0;
  g_ctx.text_base_min = layout.kaslr_base_min;
  g_ctx.text_base_max = layout.kaslr_base_max;
  g_ctx.page_offset_min = layout.kernel_vas_start;
  g_ctx.page_offset_max = layout.kernel_vas_end;
  g_ctx.arch = &g_arch_params;

  for (int s = 0; s < (int)(sizeof(states) / sizeof(states[0])); s++) {
    const struct exec_state *st = &states[s];
    if (st->can_enter && !st->can_enter()) {
      if (!quiet && verbose && plain_output())
        printf("skipping %s phase (KASLR disabled)\n\n", st->name);
      continue;
    }
    run_state(st); /* on_exit is fired inside run_state() */
  }

  if (!quiet && !verbose && plain_output())
    printf("\n\n");

  if (num_results > 0) {
    print_summary();
    return 0;
  }

  if (json_output || oneline_output || markdown_output) {
    print_summary(); /* valid empty structured output */
  } else {
    printf("\n---\n\nno tagged results to process\n");
  }
  return 1;
}
#endif /* !KASLD_TESTING */
