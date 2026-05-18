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
// Tagged line format (full spec: src/include/kasld.h):
//   <type> <region>[:<name>] pos=<pos> conf=<conf>
//       [lo=<hex>] [hi=<hex>|sz=<hex>] [sample=<hex>] [base_align=<hex>]
//
//   type:   P (physical), V (virtual), D (default/KASLR-disabled)
//   region: closed vocabulary (enum kasld_region; snake_case wire names)
//   name:   specific instance, when known (symbol, module, PCI BDF, ...)
//   pos:    base | top | interior | unknown (what `sample` represents)
//   conf:   parsed | derived | inferred | heuristic | timing | brute
// ---
// <bcoles@gmail.com>

#define _POSIX_C_SOURCE 200809L

#include "include/kasld/inference.h"
#include "include/kasld/internal.h"

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
#ifdef KASLR_PHYS_MIN
#define _PHYS_KASLR_BASE_MIN KASLR_PHYS_MIN
#define _PHYS_KASLR_BASE_MAX KASLR_PHYS_MAX
#define _PHYS_KASLR_ALIGN KASLR_PHYS_ALIGN
#else
#define _PHYS_KASLR_BASE_MIN 0ul
#define _PHYS_KASLR_BASE_MAX 0ul
#define _PHYS_KASLR_ALIGN 0ul
#endif

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
    .phys_kaslr_base_min = _PHYS_KASLR_BASE_MIN,
    .phys_kaslr_base_max = _PHYS_KASLR_BASE_MAX,
    .phys_kaslr_align = _PHYS_KASLR_ALIGN,
};

/* Adjust layout when runtime PAGE_OFFSET differs from compile-time default.
 * On 32-bit, the floor shifts with PAGE_OFFSET; the ceiling stays fixed.
 * Modules shift with PAGE_OFFSET on arm32/ppc32 (where modules_end == old PO),
 * but are fixed on x86_32/mips32.
 * On decoupled architectures (x86_64, modern riscv64), kernel text is not at
 * PAGE_OFFSET, so only directmap/VAS bounds change. */
void adjust_for_page_offset(unsigned long new_po) {
  unsigned long old_po = layout.page_offset;
  if (new_po == old_po)
    return;

  long delta = (long)(new_po - old_po);

  if (verbose && !quiet && !json_output)
    printf("[layout] virt_page_offset adjusted: %#lx -> %#lx (delta %+ld)\n",
           old_po, new_po, delta);

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
/* Maximum convergence passes per inference phase group. Plugins within a
 * phase may depend on each other's output (e.g. phys_virt_synth tightens
 * page_offset_min/max, which dram_bound could use for a tighter text_base_min).
 * We re-run until no bound changes, up to this limit as a safety cap. In
 * practice convergence always occurs in ≤ 2 passes with current plugins. */
#define MAX_INFERENCE_PASSES 8
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
 * exit action (NULL = no action), and an execution mode (parallel or
 * sequential). The loop in main() drives the table; adding a new phase means
 * adding one row, not editing main(). */
typedef void (*state_action_fn)(void);

struct exec_state {
  const char *name;        /* for logging and skip messages */
  const char *phase_key;   /* matches component.phase; NULL = no components */
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

/* Result storage — defined in kasld/internal.h */

struct result results[MAX_RESULTS];
int num_results;

/* =========================================================================
 * Inference plugin system
 * =========================================================================
 */

/* ELF section bounds — generated by the linker when any inference plugin is
 * compiled in. Declared weak so the orchestrator links cleanly with no
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
static void sync_inference_bounds_to_layout(void);

static void run_inference_phase(struct kasld_analysis_ctx *ctx,
                                enum kasld_inference_phase phase) {
  if (!__start_kasld_inferences || !__stop_kasld_inferences)
    return;

  /* Forward sync: clamp ctx bounds to the current layout before each phase.
   * Any phase (e.g. LAYOUT_ADJUST) may have widened or shifted the layout's
   * KASLR window; without this, the next phase's plugins would operate
   * against stale bounds from g_ctx initialisation. Clamping preserves
   * tightening already applied by earlier phases. Also refreshes g_arch_params
   * so ctx->arch->kaslr_base_* reads inside plugins stay consistent. */
  if (layout.kaslr_base_min > ctx->text_base_min)
    ctx->text_base_min = layout.kaslr_base_min;
  if (layout.kaslr_base_max < ctx->text_base_max)
    ctx->text_base_max = layout.kaslr_base_max;
  if (layout.kernel_vas_start > ctx->page_offset_min)
    ctx->page_offset_min = layout.kernel_vas_start;
  if (layout.kernel_vas_end < ctx->page_offset_max)
    ctx->page_offset_max = layout.kernel_vas_end;
  g_arch_params.kaslr_base_min = layout.kaslr_base_min;
  g_arch_params.kaslr_base_max = layout.kaslr_base_max;
  g_arch_params.kaslr_align = layout.kaslr_align;
  g_arch_params.phys_kaslr_base_min = layout.phys_kaslr_base_min;
  g_arch_params.phys_kaslr_base_max = layout.phys_kaslr_base_max;
  g_arch_params.phys_kaslr_align = layout.phys_kaslr_align;
  if (layout.phys_kaslr_base_min > ctx->phys_base_min)
    ctx->phys_base_min = layout.phys_kaslr_base_min;
  if (layout.phys_kaslr_base_max < ctx->phys_base_max)
    ctx->phys_base_max = layout.phys_kaslr_base_max;
  ctx->result_count = (size_t)num_results;

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

/* Look up region enum by wire name. Linear scan over region_info[] — under
 * 30 entries, negligible cost. Returns REGION_UNKNOWN on miss. */
static enum kasld_region region_from_wire(const char *s) {
  for (int i = 1; i < REGION__COUNT; i++) {
    if (region_info[i].wire_name && strcmp(region_info[i].wire_name, s) == 0)
      return (enum kasld_region)i;
  }
  return REGION_UNKNOWN;
}

static enum kasld_position pos_from_wire(const char *s) {
  if (strcmp(s, "base") == 0)
    return POS_BASE;
  if (strcmp(s, "top") == 0)
    return POS_TOP;
  if (strcmp(s, "interior") == 0)
    return POS_INTERIOR;
  if (strcmp(s, "unknown") == 0)
    return POS_UNKNOWN;
  /* Unrecognised input also returns POS_UNKNOWN. The caller disambiguates
   * via `strcmp(val, "unknown") != 0` immediately after this call —
   * that guard must be kept co-located with any new call site. */
  return POS_UNKNOWN;
}

static enum kasld_confidence conf_from_wire(const char *s) {
  if (strcmp(s, "parsed") == 0)
    return CONF_PARSED;
  if (strcmp(s, "derived") == 0)
    return CONF_DERIVED;
  if (strcmp(s, "inferred") == 0)
    return CONF_INFERRED;
  if (strcmp(s, "heuristic") == 0)
    return CONF_HEURISTIC;
  if (strcmp(s, "timing") == 0)
    return CONF_TIMING;
  if (strcmp(s, "brute") == 0)
    return CONF_BRUTE;
  return CONF_UNKNOWN;
}

/* Power-of-two test, allowing v=0 to mean "no constraint" but the caller
 * gates on v != 0 separately. */
static int is_pow2(unsigned long v) { return v && !(v & (v - 1)); }

static enum kasld_addr_type type_from_wire(char c) {
  switch (c) {
  case 'P':
    return KASLD_TYPE_PHYS;
  case 'V':
    return KASLD_TYPE_VIRT;
  case 'D':
    return KASLD_TYPE_DEFAULT_VIRT;
  default:
    return KASLD_TYPE_UNKNOWN;
  }
}

static int parse_hex(const char *s, unsigned long *out) {
  if (s[0] != '0' || (s[1] != 'x' && s[1] != 'X'))
    return 0;
  char *end;
  errno = 0;
  unsigned long v = strtoul(s, &end, 16);
  if (errno || *end != '\0')
    return 0;
  *out = v;
  return 1;
}

/* Parse a new-format tagged line into a struct result.
 *
 * Wire format:
 *   <type> <region>[:<name>] pos=<pos> conf=<conf> \
 *       [lo=<hex>] [hi=<hex>|sz=<hex>] [sample=<hex>] [base_align=<hex>]
 *
 * Two-stage:
 *   (1) sscanf the positional prefix "<type> <region>[:<name>]"
 *   (2) tokenise the tail with strtok_r, collecting key/value pairs into a
 *       local struct, then apply sz→hi normalisation and cross-key
 *       validation in a second step.
 *
 * Returns 1 on accept (record appended to results[]), 0 on reject.
 */
static int capture_result(const char *line, const char *method,
                          const char *origin) {
  /* Quick prefix filter. */
  if (line[0] != 'P' && line[0] != 'V' && line[0] != 'D')
    return 0;
  if (line[1] != ' ')
    return 0;

  /* region_field holds the "region[:name]" token. Sized to hold the
   * longest plausible name (NAME_LEN - 1) plus the longest region wire
   * string (~16) plus the separator. Width-restricted sscanf matches the
   * buffer size exactly. */
#define REGION_FIELD_CAP (NAME_LEN + 32)
  char type_ch;
  char region_field[REGION_FIELD_CAP];
  int prefix_consumed = 0;
  /* sscanf width must be strictly less than buffer size — sscanf writes
   * an implicit terminator. NAME_LEN + 31 here for REGION_FIELD_CAP = 80. */
  if (sscanf(line, "%c %79s %n", &type_ch, region_field, &prefix_consumed) <
          2 ||
      prefix_consumed == 0)
    return 0;

  enum kasld_addr_type type = type_from_wire(type_ch);
  if (type == KASLD_TYPE_UNKNOWN)
    return 0;

  /* Split region[:name] on FIRST `:` only. Names may legitimately contain
   * subsequent colons (e.g. PCI BDF "0000:00:14.0"). Region wire names
   * are short identifiers (longest current: "module_region" = 13) and
   * never contain ':', so the split is unambiguous. */
  char region_str[32];
  char name_buf[NAME_LEN];
  name_buf[0] = '\0';
  {
    char *colon = strchr(region_field, ':');
    if (colon) {
      size_t rlen = (size_t)(colon - region_field);
      /* Over-length region string indicates a malformed line. */
      if (rlen >= sizeof(region_str))
        return 0;
      memcpy(region_str, region_field, rlen);
      region_str[rlen] = '\0';

      const char *name_src = colon + 1;
      size_t nlen = strlen(name_src);
      /* Spec: over-length names reject the line (no silent truncation). */
      if (nlen > NAME_LEN - 1)
        return 0;
      memcpy(name_buf, name_src, nlen);
      name_buf[nlen] = '\0';
    } else {
      size_t rlen = strlen(region_field);
      if (rlen >= sizeof(region_str))
        return 0;
      memcpy(region_str, region_field, rlen);
      region_str[rlen] = '\0';
    }
  }
#undef REGION_FIELD_CAP

  enum kasld_region region = region_from_wire(region_str);
  if (region == REGION_UNKNOWN)
    return 0;

  /* --- Tail pass: collect all keys first, then normalise + validate. --- */
  struct {
    int seen_pos, seen_conf, seen_lo, seen_hi, seen_sz, seen_sample;
    int seen_base_align;
    enum kasld_position pos;
    enum kasld_confidence conf;
    unsigned long lo, hi, sz, sample, base_align;
  } p = {0};
  p.pos = POS_UNKNOWN;
  p.conf = CONF_UNKNOWN;

  char tail[MAX_LINE_LEN];
  {
    const char *t = line + prefix_consumed;
    size_t tl = strlen(t);
    if (tl >= sizeof(tail))
      return 0;
    memcpy(tail, t, tl + 1);
    /* Strip trailing newline. */
    if (tl > 0 && tail[tl - 1] == '\n')
      tail[tl - 1] = '\0';
  }

  char *save = NULL;
  for (char *tok = strtok_r(tail, " \t", &save); tok;
       tok = strtok_r(NULL, " \t", &save)) {
    char *eq = strchr(tok, '=');
    if (!eq)
      return 0;
    *eq = '\0';
    const char *key = tok;
    const char *val = eq + 1;

    if (strcmp(key, "pos") == 0) {
      if (p.seen_pos)
        return 0;
      p.seen_pos = 1;
      p.pos = pos_from_wire(val);
      /* pos_from_wire returns POS_UNKNOWN for both unknown literal and
       * unrecognised — distinguish: only "unknown" string is valid here. */
      if (p.pos == POS_UNKNOWN && strcmp(val, "unknown") != 0)
        return 0;
    } else if (strcmp(key, "conf") == 0) {
      if (p.seen_conf)
        return 0;
      p.seen_conf = 1;
      p.conf = conf_from_wire(val);
      if (p.conf == CONF_UNKNOWN)
        return 0;
    } else if (strcmp(key, "lo") == 0) {
      if (p.seen_lo || !parse_hex(val, &p.lo))
        return 0;
      p.seen_lo = 1;
    } else if (strcmp(key, "hi") == 0) {
      if (p.seen_hi || p.seen_sz || !parse_hex(val, &p.hi))
        return 0;
      p.seen_hi = 1;
    } else if (strcmp(key, "sz") == 0) {
      if (p.seen_sz || p.seen_hi || !parse_hex(val, &p.sz))
        return 0;
      p.seen_sz = 1;
    } else if (strcmp(key, "sample") == 0) {
      if (p.seen_sample || !parse_hex(val, &p.sample))
        return 0;
      p.seen_sample = 1;
    } else if (strcmp(key, "base_align") == 0) {
      if (p.seen_base_align || !parse_hex(val, &p.base_align))
        return 0;
      if (!is_pow2(p.base_align))
        return 0;
      p.seen_base_align = 1;
    } else {
      /* Unknown key rejects the line (spec: no forward-compat silence). */
      return 0;
    }
  }

  /* Mandatory fields. */
  if (!p.seen_pos || !p.seen_conf)
    return 0;

  /* sz → hi normalisation. */
  if (p.seen_sz) {
    /* sz requires lo — check before doing arithmetic on p.lo. */
    if (!p.seen_lo)
      return 0;
    if (p.sz == 0 || p.sz - 1 > ULONG_MAX - p.lo)
      return 0;
    p.hi = p.lo + p.sz - 1;
    p.seen_hi = 1;
  }

  /* Cross-key constraints. */
  if (p.seen_lo && p.seen_hi && p.lo > p.hi)
    return 0;
  if (p.seen_sample) {
    if (p.seen_lo && p.sample < p.lo)
      return 0;
    if (p.seen_hi && p.sample > p.hi)
      return 0;
  }

  /* pos-requires-field. */
  switch (p.pos) {
  case POS_BASE:
    if (!p.seen_lo)
      return 0;
    break;
  case POS_TOP:
    if (!p.seen_hi)
      return 0;
    break;
  case POS_INTERIOR:
    if (!p.seen_sample)
      return 0;
    break;
  case POS_UNKNOWN:
    if (!p.seen_lo && !p.seen_hi && !p.seen_sample)
      return 0;
    break;
  }

  /* Parse-time VAS validation against region_info[region].static_vas.
   * Layout-derived regions (derive_vas != NULL) skip parse-time validation
   * — they're validated at runtime via result_in_bounds.
   *
   * Rejections are surfaced under --verbose so a developer porting a
   * component to a new architecture sees the drop instead of a silent
   * "ran but produced nothing". The reject reason names the offending
   * field for actionable triage. */
  const struct region_info *ri = &region_info[region];
  if (ri->derive_vas == NULL &&
      (ri->static_vas.lo != 0 || ri->static_vas.hi != 0)) {
    unsigned long vlo = ri->static_vas.lo;
    unsigned long vhi = ri->static_vas.hi;
    const char *vas_field = NULL;
    unsigned long vas_val = 0;
    if (p.seen_lo && (p.lo < vlo || p.lo > vhi)) {
      vas_field = "lo";
      vas_val = p.lo;
    } else if (p.seen_hi && (p.hi < vlo || p.hi > vhi)) {
      vas_field = "hi";
      vas_val = p.hi;
    } else if (p.seen_sample && (p.sample < vlo || p.sample > vhi)) {
      vas_field = "sample";
      vas_val = p.sample;
    }
    if (vas_field) {
      if (verbose && !quiet)
        fprintf(stderr,
                "[parser] dropped %c %s%s%s: %s=%#lx out of VAS [%#lx, %#lx]"
                " (origin=%s)\n",
                kasld_type_wire(type), kasld_region_wire(region),
                name_buf[0] ? ":" : "", name_buf[0] ? name_buf : "", vas_field,
                vas_val, vlo, vhi, origin && *origin ? origin : "?");
      return 0;
    }
  }

  /* Claim a slot. */
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
  result_init(r);
  r->type = type;
  r->region = region;
  if (name_buf[0]) {
    size_t nl = strlen(name_buf);
    if (nl > NAME_LEN - 1)
      nl = NAME_LEN - 1;
    memcpy(r->name, name_buf, nl);
    r->name[nl] = '\0';
  }
  r->pos = p.pos;
  r->conf = p.conf;
  if (p.seen_lo) {
    r->lo = p.lo;
    r->set_mask |= LO_SET;
  }
  if (p.seen_hi) {
    r->hi = p.hi;
    r->set_mask |= HI_SET;
  }
  if (p.seen_sample) {
    r->sample = p.sample;
    r->set_mask |= SAMPLE_SET;
  }
  if (p.seen_base_align) {
    r->base_align = p.base_align;
    r->set_mask |= BASE_ALIGN_SET;
  }
  /* Provenance: this is the first contributor. */
  if (origin && *origin) {
    size_t ol = strnlen(origin, ORIGIN_LEN - 1);
    memcpy(r->origins[0], origin, ol);
    r->origins[0][ol] = '\0';
  }
  if (method && *method) {
    size_t ml = strnlen(method, METHOD_LEN - 1);
    memcpy(r->methods[0], method, ml);
    r->methods[0][ml] = '\0';
  }
  r->provenance_count = 1;
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
 * Supports both ELF32 and ELF64. Returns a malloc'd string (caller must
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
   * e_shstrndx. Seek past e_ident which we already consumed. */
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
 * Sets phase to the value of the "phase:" key ("inference" or "probing").
 * Defaults to "inference" when the key is absent or the binary has no
 * .kasld_meta section. */
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
    snprintf(components[i].phase, sizeof(components[i].phase), "%s",
             phase ? phase : "inference");

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

  /* Classify outcome from exit code. Components signal their own status:
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
 *   not verbose; on_exit fires once after the parallel join. Layout is
 *   read-only during parallel execution so align/validate calls inside
 *   capture_result() are safe without additional locking.
 *
 * Sequential states (!st->parallel): single-threaded loop; on_exit fires
 *   after each component so PAGE_OFFSET discoveries propagate immediately.
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
 * Post-processing: bounds validation, merging, anchor selection
 * =========================================================================
 *
 * Layout of this section:
 *   - result_in_bounds()  : runtime VAS check (replaces validate_for_section)
 *   - conf_weight()       : trust ranking for merged-record voting
 *   - select_anchor()     : pick the canonical record for (type, region)
 *   - merge_results()     : collapse same-(type, region, name) groups
 *   - compute_kaslr_info(): vtext/ptext + entropy summary
 */

int result_in_bounds(const struct result *r, const struct kasld_layout *ly) {
  if (!r || r->region == REGION_UNKNOWN || r->region >= REGION__COUNT)
    return 0;
  const struct region_info *ri = &region_info[r->region];
  unsigned long vlo, vhi;
  if (ri->derive_vas) {
    ri->derive_vas(ly, &vlo, &vhi);
  } else {
    vlo = ri->static_vas.lo;
    vhi = ri->static_vas.hi;
    /* Open VAS (0..ULONG_MAX) is "accept anything"; full-zero is "no
     * constraint" (used by regions whose VAS spans the whole address
     * space, like REGION_RAM). */
    if (vlo == 0 && vhi == 0)
      return 1;
  }
  if (HAS_LO(r) && (r->lo < vlo || r->lo > vhi))
    return 0;
  if (HAS_HI(r) && (r->hi < vlo || r->hi > vhi))
    return 0;
  if (HAS_SAMPLE(r) && (r->sample < vlo || r->sample > vhi))
    return 0;
  return 1;
}

int conf_weight(enum kasld_confidence c) {
  switch (c) {
  case CONF_PARSED:
    return 6;
  case CONF_DERIVED:
    return 5;
  case CONF_INFERRED:
    return 4;
  case CONF_HEURISTIC:
    return 3;
  case CONF_TIMING:
    return 2;
  case CONF_BRUTE:
    return 1;
  default:
    return 0;
  }
}

const struct result *select_anchor(enum kasld_addr_type type,
                                   enum kasld_region region) {
  const struct result *best_no_name = NULL;
  int best_no_name_w = -1;
  const struct result *best_named = NULL;
  int best_named_w = -1;

  for (int i = 0; i < num_results; i++) {
    const struct result *r = &results[i];
    if (r->type != type || r->region != region)
      continue;
    if (!result_in_bounds(r, &layout))
      continue;
    int w = conf_weight(r->conf);
    if (r->name[0] == '\0') {
      if (w > best_no_name_w) {
        best_no_name = r;
        best_no_name_w = w;
      }
    } else {
      if (w > best_named_w) {
        best_named = r;
        best_named_w = w;
      }
    }
  }
  return best_no_name ? best_no_name : best_named;
}

/* -------------------------------------------------------------------------
 * Merge pass — collapse same-(type, region, name) records into one.
 * -------------------------------------------------------------------------
 */

/* Dedup key is origin only — same origin with a different method means
 * the second method is silently dropped. This is intentional: the method
 * field is an attribute of the contribution, not a discriminator for
 * identity. Two contributions from the same component are one provenance
 * entry regardless of method. */
static int provenance_has(const struct result *r, const char *s) {
  if (!s || !*s)
    return 1;
  for (int i = 0; i < r->provenance_count; i++)
    if (strncmp(r->origins[i], s, ORIGIN_LEN) == 0)
      return 1;
  return 0;
}

static void provenance_add(struct result *r, const char *origin,
                           const char *method) {
  if (origin && *origin && provenance_has(r, origin))
    return;
  if (r->provenance_count >= MAX_PROVENANCE) {
    static int warned;
    if (!warned && !quiet) {
      fprintf(stderr,
              "warning: merged record provenance capped at MAX_PROVENANCE=%d; "
              "later contributors dropped\n",
              MAX_PROVENANCE);
      warned = 1;
    }
    return;
  }
  int slot = r->provenance_count++;
  if (origin && *origin) {
    size_t ol = strnlen(origin, ORIGIN_LEN - 1);
    memcpy(r->origins[slot], origin, ol);
    r->origins[slot][ol] = '\0';
  } else {
    r->origins[slot][0] = '\0';
  }
  if (method && *method) {
    size_t ml = strnlen(method, METHOD_LEN - 1);
    memcpy(r->methods[slot], method, ml);
    r->methods[slot][ml] = '\0';
  } else {
    r->methods[slot][0] = '\0';
  }
}

static void merge_into(struct result *a, const struct result *b,
                       int *sample_owner_w) {
  if (HAS_LO(b)) {
    if (!HAS_LO(a) || b->lo > a->lo)
      a->lo = b->lo;
    a->set_mask |= LO_SET;
  }
  if (HAS_HI(b)) {
    if (!HAS_HI(a) || b->hi < a->hi)
      a->hi = b->hi;
    a->set_mask |= HI_SET;
  }
  if (HAS_SAMPLE(b)) {
    int wb = conf_weight(b->conf);
    if (!HAS_SAMPLE(a) || wb > *sample_owner_w) {
      a->sample = b->sample;
      a->set_mask |= SAMPLE_SET;
      *sample_owner_w = wb;
      /* pos is bound to whichever contributor provided the surviving
       * sample. */
      a->pos = b->pos;
    }
  }
  if (HAS_BASE_ALIGN(b)) {
    if (!HAS_BASE_ALIGN(a) || b->base_align > a->base_align)
      a->base_align = b->base_align;
    a->set_mask |= BASE_ALIGN_SET;
  }
  if (conf_weight(b->conf) > conf_weight(a->conf))
    a->conf = b->conf;
  for (int i = 0; i < b->provenance_count; i++)
    provenance_add(a, b->origins[i], b->methods[i]);
}

static int merge_consistent(const struct result *a) {
  if (HAS_LO(a) && HAS_HI(a) && a->lo > a->hi)
    return 0;
  return 1;
}

/* Sample-conflict predicate: two contributors both carry HAS_SAMPLE but
 * point at different addresses. Spec rationale: same-(type, region, name)
 * with differing samples almost always means different instances (e.g. two
 * distinct swiotlb buffers, two initrd-witness pointers from different
 * subsystems) — silently collapsing them would lose data. Treated the same
 * as a bound conflict: keep both records separate. Records without a sample
 * pair are always sample-compatible. */
static int samples_conflict(const struct result *a, const struct result *b) {
  if (!HAS_SAMPLE(a) || !HAS_SAMPLE(b))
    return 0;
  return a->sample != b->sample;
}

static void clamp_sample(struct result *a) {
  if (HAS_SAMPLE(a)) {
    if (HAS_LO(a) && a->sample < a->lo)
      a->sample = a->lo;
    if (HAS_HI(a) && a->sample > a->hi)
      a->sample = a->hi;
  }
  if (a->pos == POS_UNKNOWN) {
    if (HAS_LO(a))
      a->pos = POS_BASE;
    else if (HAS_HI(a))
      a->pos = POS_TOP;
  }
}

void merge_results(void) {
  int alive[MAX_RESULTS];
  for (int i = 0; i < num_results; i++)
    alive[i] = 1;

  for (int i = 0; i < num_results; i++) {
    if (!alive[i])
      continue;
    int merged_any = 0;
    struct result acc = results[i];
    int sample_owner_w =
        HAS_SAMPLE(&results[i]) ? conf_weight(results[i].conf) : -1;
    int contribs[MAX_RESULTS];
    int n_contribs = 0;
    contribs[n_contribs++] = i;

    for (int j = i + 1; j < num_results; j++) {
      if (!alive[j])
        continue;
      const struct result *b = &results[j];
      if (b->type != acc.type || b->region != acc.region)
        continue;
      if (strncmp(b->name, acc.name, NAME_LEN) != 0)
        continue;
      /* Sample-conflict gate: different samples for the same merge key are
       * almost certainly different instances of the region (two swiotlb
       * buffers, two initrd witnesses, ...). Keep both records. */
      if (samples_conflict(&acc, b))
        continue;
      struct result trial = acc;
      int trial_w = sample_owner_w;
      merge_into(&trial, b, &trial_w);
      if (!merge_consistent(&trial))
        continue;
      acc = trial;
      sample_owner_w = trial_w;
      contribs[n_contribs++] = j;
      merged_any = 1;
    }

    if (!merged_any)
      continue;

    clamp_sample(&acc);
    results[i] = acc;
    for (int k = 1; k < n_contribs; k++)
      alive[contribs[k]] = 0;
  }

  int w = 0;
  for (int i = 0; i < num_results; i++) {
    if (!alive[i])
      continue;
    if (w != i)
      results[w] = results[i];
    w++;
  }
  num_results = w;
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

static unsigned long derive_vtext_from_data(void) {
#ifdef DATA_OFFSET
  const struct result *r = select_anchor(KASLD_TYPE_VIRT, REGION_KERNEL_DATA);
  if (!r || !HAS_LO(r) || r->lo < (unsigned long)DATA_OFFSET)
    return 0;
  return r->lo - (unsigned long)DATA_OFFSET;
#else
  return 0;
#endif
}

static unsigned long derive_ptext_from_data(void) {
#ifdef DATA_OFFSET
  const struct result *r = select_anchor(KASLD_TYPE_PHYS, REGION_KERNEL_DATA);
  if (!r || !HAS_LO(r) || r->lo < (unsigned long)DATA_OFFSET)
    return 0;
  return r->lo - (unsigned long)DATA_OFFSET;
#else
  return 0;
#endif
}

void compute_kaslr_info(struct summary *s) {
  const struct result *r_vt =
      select_anchor(KASLD_TYPE_VIRT, REGION_KERNEL_IMAGE);
  if (!r_vt)
    r_vt = select_anchor(KASLD_TYPE_VIRT, REGION_KERNEL_TEXT);
  unsigned long vtext = anchor_addr(r_vt);
  if (vtext == 0)
    vtext = derive_vtext_from_data();
  s->kaslr.vtext = vtext;

  const struct result *r_pt =
      select_anchor(KASLD_TYPE_PHYS, REGION_KERNEL_IMAGE);
  if (!r_pt)
    r_pt = select_anchor(KASLD_TYPE_PHYS, REGION_KERNEL_TEXT);
  unsigned long ptext = anchor_addr(r_pt);
  if (ptext == 0)
    ptext = derive_ptext_from_data();
  s->kaslr.ptext = ptext;
  s->kaslr.has_phys = 0;

  unsigned long text_range = layout.kaslr_base_max - layout.kaslr_base_min;
  s->kaslr.vslots = layout.kaslr_align ? text_range / layout.kaslr_align : 0;
  s->kaslr.vbits = s->kaslr.vslots > 0 ? ilog2(s->kaslr.vslots) : 0;

#ifdef KASLR_PHYS_MIN
  {
    unsigned long phys_range =
        layout.phys_kaslr_base_max - layout.phys_kaslr_base_min;
    s->kaslr.pslots =
        layout.phys_kaslr_align ? phys_range / layout.phys_kaslr_align : 0;
    s->kaslr.pbits = s->kaslr.pslots > 0 ? ilog2(s->kaslr.pslots) : 0;
  }
#endif

  if (s->kaslr.vtext) {
    s->kaslr.vslide = (long)(s->kaslr.vtext - layout.kernel_text_default);
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
#endif
  }

  if (s->kaslr.disabled || s->kaslr.unsupported) {
    s->kaslr.vslide = 0;
    s->kaslr.vslots = 0;
    s->kaslr.vbits = 0;
    s->kaslr.vslot_valid = 0;
    s->kaslr.pslide = 0;
    s->kaslr.pslots = 0;
    s->kaslr.pbits = 0;
  }

  s->kaslr.page_offset_min =
      (g_ctx.page_offset_min != (unsigned long)PAGE_OFFSET)
          ? g_ctx.page_offset_min
          : 0;
  s->kaslr.page_offset_max =
      (g_ctx.page_offset_max != (unsigned long)KERNEL_VAS_END)
          ? g_ctx.page_offset_max
          : 0;
  s->kaslr.vmalloc_min =
      (g_ctx.vmalloc_base_min != 0) ? g_ctx.vmalloc_base_min : 0;
  s->kaslr.vmalloc_max =
      (g_ctx.vmalloc_base_max != ULONG_MAX) ? g_ctx.vmalloc_base_max : 0;
  s->kaslr.vmemmap_min =
      (g_ctx.vmemmap_base_min != 0) ? g_ctx.vmemmap_base_min : 0;
  s->kaslr.vmemmap_max =
      (g_ctx.vmemmap_base_max != ULONG_MAX) ? g_ctx.vmemmap_base_max : 0;

#if PHYS_VIRT_DECOUPLED
  /* On decoupled arches (x86_64, arm64, riscv64, s390): note when physical
   * leaks exist but no virtual text base — physical leaks don't reveal the
   * virtual text base under decoupling, so the user shouldn't assume vtext
   * can be derived from them. */
  if (!s->kaslr.vtext) {
    int have_phys_landmark = (s->kaslr.ptext != 0);
    if (!have_phys_landmark) {
      /* Check for any PHYS RAM landmark — same condition the old
       * compute_derived_addrs used. */
      for (int i = 0; i < num_results; i++) {
        const struct result *r = &results[i];
        if (r->type == KASLD_TYPE_PHYS &&
            (r->region == REGION_RAM || r->region == REGION_DMA ||
             r->region == REGION_DMA32) &&
            result_in_bounds(r, &layout)) {
          have_phys_landmark = 1;
          break;
        }
      }
    }
    if (have_phys_landmark)
      s->decoupled_note = 1;
  }
#endif
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

  /* Marker model (see "default" component):
   *   r->name == "unsupported"  → arch lacks KASLR support
   *   r->name == "nokaslr" or other non-empty/non-"text" → disabled
   *   r->name == "" or "text"   → fallback only (KASLR may be active) */
  for (int i = 0; i < num_results; i++) {
    const struct result *r = &results[i];
    if (r->type != KASLD_TYPE_DEFAULT_VIRT)
      continue;
    s->kaslr.default_addr = HAS_LO(r) ? r->lo : (HAS_SAMPLE(r) ? r->sample : 0);
    if (strcmp(r->name, "unsupported") == 0)
      s->kaslr.unsupported = 1;
    else if (r->name[0] != '\0' && strcmp(r->name, "text") != 0)
      s->kaslr.disabled = 1;
  }

  /* The default component emits the compile-time KERNEL_TEXT_DEFAULT, but
   * runtime layout adjustments (e.g. legacy riscv64 detection) may have
   * changed layout.kernel_text_default. Use the runtime value. */
  if (s->kaslr.default_addr)
    s->kaslr.default_addr = layout.kernel_text_default;

  /* When KASLR is disabled/unsupported, inject the default text address as a
   * synthesised VIRT/KERNEL_TEXT result so it flows into render and
   * downstream derivation. */
  if ((s->kaslr.disabled || s->kaslr.unsupported) && s->kaslr.default_addr &&
      num_results < MAX_RESULTS) {
    struct result *r = &results[num_results++];
    result_init(r);
    r->type = KASLD_TYPE_VIRT;
    r->region = REGION_KERNEL_TEXT;
    snprintf(r->name, NAME_LEN, "nokaslr");
    r->pos = POS_BASE;
    r->conf = CONF_PARSED;
    r->lo = s->kaslr.default_addr;
    r->set_mask |= LO_SET;
    snprintf(r->origins[0], ORIGIN_LEN, "kasld");
    snprintf(r->methods[0], METHOD_LEN, "parsed");
    r->provenance_count = 1;
  }
}

/* Convergence detection --------------------------------------------------- */

/* Snapshot of every bound the convergence loop tracks. */
struct bounds_snap {
  unsigned long text_min, text_max;
  unsigned long po_min, po_max;
  unsigned long phys_min, phys_max;
  unsigned long vmalloc_min, vmalloc_max;
  unsigned long vmemmap_min, vmemmap_max;
};

static void snap_bounds(struct bounds_snap *s) {
  s->text_min = g_ctx.text_base_min;
  s->text_max = g_ctx.text_base_max;
  s->po_min = g_ctx.page_offset_min;
  s->po_max = g_ctx.page_offset_max;
  s->phys_min = g_ctx.phys_base_min;
  s->phys_max = g_ctx.phys_base_max;
  s->vmalloc_min = g_ctx.vmalloc_base_min;
  s->vmalloc_max = g_ctx.vmalloc_base_max;
  s->vmemmap_min = g_ctx.vmemmap_base_min;
  s->vmemmap_max = g_ctx.vmemmap_base_max;
}

/* Returns 1 if any bound differs from the snapshot, 0 if stable. */
static int bounds_changed(const struct bounds_snap *s) {
  return g_ctx.text_base_min != s->text_min ||
         g_ctx.text_base_max != s->text_max ||
         g_ctx.page_offset_min != s->po_min ||
         g_ctx.page_offset_max != s->po_max ||
         g_ctx.phys_base_min != s->phys_min ||
         g_ctx.phys_base_max != s->phys_max ||
         g_ctx.vmalloc_base_min != s->vmalloc_min ||
         g_ctx.vmalloc_base_max != s->vmalloc_max ||
         g_ctx.vmemmap_base_min != s->vmemmap_min ||
         g_ctx.vmemmap_base_max != s->vmemmap_max;
}

/* State on_exit actions --------------------------------------------------- */

static void run_pre_collection_inference(void) {
  unsigned long init_text_max = layout.kernel_base_max;
  unsigned long init_phys_max = layout.phys_kaslr_base_max;
  struct bounds_snap snap;

  for (int pass = 0; pass < MAX_INFERENCE_PASSES; pass++) {
    snap_bounds(&snap);
    run_inference_phase(&g_ctx, KASLD_INFER_PHASE_PRE_COLLECTION);
    sync_inference_bounds_to_layout();
    if (!bounds_changed(&snap))
      break;
  }

  if (verbose && !quiet && !json_output) {
    if (layout.kernel_base_max < init_text_max)
      printf("[layout] virt_kernel_base_max tightened: %#lx -> %#lx\n",
             init_text_max, layout.kernel_base_max);
    if (layout.phys_kaslr_base_max < init_phys_max)
      printf("[layout] phys_kaslr_base_max tightened: %#lx -> %#lx\n",
             init_phys_max, layout.phys_kaslr_base_max);
  }
}

static void sync_inference_bounds_to_layout(void) {
  if (g_ctx.text_base_max < layout.kernel_base_max) {
    layout.kernel_base_max = g_ctx.text_base_max;
    layout.kaslr_base_max = g_ctx.text_base_max;
  }
  if (g_ctx.text_base_min > layout.kernel_base_min) {
    layout.kernel_base_min = g_ctx.text_base_min;
    layout.kaslr_base_min = g_ctx.text_base_min;
  }
  if (g_ctx.page_offset_min > layout.kernel_vas_start)
    layout.kernel_vas_start = g_ctx.page_offset_min;
  if (g_ctx.page_offset_max < layout.kernel_vas_end)
    layout.kernel_vas_end = g_ctx.page_offset_max;
  if (g_ctx.phys_base_max < layout.phys_kaslr_base_max)
    layout.phys_kaslr_base_max = g_ctx.phys_base_max;
  if (g_ctx.phys_base_min > layout.phys_kaslr_base_min)
    layout.phys_kaslr_base_min = g_ctx.phys_base_min;
}

static void run_post_collection_inference(void) {
  struct bounds_snap snap;

  /* Merge before the first inference pass so plugins see deduplicated
   * records (one per (type, region, name)). */
  merge_results();

  /* LAYOUT_ADJUST: apply PAGE_OFFSET and VAS discoveries to layout (once).
   * Runs before the convergence loop because it mutates layout directly
   * rather than tightening ctx bounds; the forward sync at the start of
   * the first POST_COLLECTION pass picks up those mutations. */
  run_inference_phase(&g_ctx, KASLD_INFER_PHASE_LAYOUT_ADJUST);

  for (int pass = 0; pass < MAX_INFERENCE_PASSES; pass++) {
    snap_bounds(&snap);
    run_inference_phase(&g_ctx, KASLD_INFER_PHASE_POST_COLLECTION);
    sync_inference_bounds_to_layout();
    /* Re-run merge so any derived results emitted by this pass collapse
     * into existing same-(type, region, name) records before the next
     * pass reads them. */
    merge_results();
    if (!bounds_changed(&snap))
      break;
  }
}

static void run_post_probing_inference(void) {
  struct bounds_snap snap;

  merge_results();
  run_inference_phase(&g_ctx, KASLD_INFER_PHASE_LAYOUT_ADJUST);

  for (int pass = 0; pass < MAX_INFERENCE_PASSES; pass++) {
    snap_bounds(&snap);
    run_inference_phase(&g_ctx, KASLD_INFER_PHASE_POST_PROBING);
    sync_inference_bounds_to_layout();
    merge_results();
    if (!bounds_changed(&snap))
      break;
  }
}

/* Execution state table --------------------------------------------------- */

/* Each row is one phase. Adding a new phase = adding one row here. */
static const struct exec_state states[] = {
    {"setup", NULL, run_pre_collection_inference, 0},
    {"inference", "inference", run_post_collection_inference, 1},
    {"probing", "probing", run_post_probing_inference, 0},
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
      char *workers_end;
      long workers_val = strtol(argv[++i], &workers_end, 10);
      if (*workers_end != '\0' || workers_val < 0 || workers_val > 65535) {
        fprintf(stderr, "--workers must be a non-negative integer\n");
        return 2;
      }
      parallel_workers = (int)workers_val;
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
  g_arch_params.phys_kaslr_base_min = layout.phys_kaslr_base_min;
  g_arch_params.phys_kaslr_base_max = layout.phys_kaslr_base_max;
  g_arch_params.phys_kaslr_align = layout.phys_kaslr_align;
  g_arch_params.phys_virt_decoupled = PHYS_VIRT_DECOUPLED;
  g_arch_params.phys_offset = PHYS_OFFSET;
  g_arch_params.page_offset = PAGE_OFFSET;
  g_arch_params.text_offset = TEXT_OFFSET;
  g_ctx.results = results;
  g_ctx.result_count = 0;
  g_ctx.text_base_min = layout.kaslr_base_min;
  g_ctx.text_base_max = layout.kaslr_base_max;
  g_ctx.page_offset_min = layout.kernel_vas_start;
  g_ctx.page_offset_max = layout.kernel_vas_end;
  g_ctx.phys_base_min = layout.phys_kaslr_base_min;
  g_ctx.phys_base_max = layout.phys_kaslr_base_max;
  g_ctx.vmalloc_base_min = 0;
  g_ctx.vmalloc_base_max = ULONG_MAX;
  g_ctx.vmemmap_base_min = 0;
  g_ctx.vmemmap_base_max = ULONG_MAX;
  g_ctx.arch = &g_arch_params;
  g_ctx.layout = &layout;

  for (int s = 0; s < (int)(sizeof(states) / sizeof(states[0])); s++)
    run_state(&states[s]); /* on_exit is fired inside run_state() */

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
