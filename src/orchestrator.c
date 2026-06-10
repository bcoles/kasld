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
// Tagged line format (full spec: src/include/kasld/api.h):
//   <type> <region>[:<name>] pos=<pos> conf=<conf>
//       [lo=<hex>] [hi=<hex>|sz=<hex>] [sample=<hex>] [base_align=<hex>]
//
//   type:   P (physical), V (virtual)
//   region: closed vocabulary (enum kasld_region; snake_case wire names)
//   name:   specific instance, when known (symbol, module, PCI BDF, ...)
//   pos:    base | top | interior | unknown (what `sample` represents)
//   conf:   parsed | derived | inferred | heuristic | timing | brute
// ---
// <bcoles@gmail.com>

#define _POSIX_C_SOURCE 200809L

#include "include/kasld/engine.h"
#include "include/kasld/engine_rules.h"
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

/* Kernel pointer hashing: 1 = %p/%pK hashed (the default — mitigating), 0 =
 * no_hash_pointers / hash_pointers=never on the boot cmdline (raw addresses),
 * -1 = /proc/cmdline unreadable. */
int hashed_pointers = -1;

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
#define _PHYS_KASLR_TEXT_MIN KASLR_PHYS_MIN
#define _PHYS_KASLR_TEXT_MAX KASLR_PHYS_MAX
#define _PHYS_KASLR_ALIGN KASLR_PHYS_ALIGN
#else
#define _PHYS_KASLR_TEXT_MIN 0ul
#define _PHYS_KASLR_TEXT_MAX 0ul
#define _PHYS_KASLR_ALIGN 0ul
#endif

struct kasld_layout layout = {
    .virt_page_offset = PAGE_OFFSET,
    .virt_kernel_vas_start = KERNEL_VIRT_VAS_START,
    .virt_kernel_vas_end = KERNEL_VIRT_VAS_END,
    .virt_kernel_text_min = KERNEL_VIRT_TEXT_MIN,
    .virt_kernel_text_max = KERNEL_VIRT_TEXT_MAX,
    .modules_start = MODULES_START,
    .modules_end = MODULES_END,
    .image_align = IMAGE_ALIGN,
    .text_offset = TEXT_OFFSET,
    .virt_kernel_text_default = KERNEL_VIRT_TEXT_DEFAULT,
    .virt_kaslr_text_min = KASLR_VIRT_TEXT_MIN,
    .virt_kaslr_text_max = KASLR_VIRT_TEXT_MAX,
    .virt_kaslr_align = KASLR_VIRT_ALIGN,
    .phys_kaslr_text_min = _PHYS_KASLR_TEXT_MIN,
    .phys_kaslr_text_max = _PHYS_KASLR_TEXT_MAX,
    .phys_kaslr_align = _PHYS_KASLR_ALIGN,
};

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

/* -------------------------------------------------------------------------
 * Orchestrator-side saturation flags. Parallels engine.saturation (which
 * covers the inference layer's fixed-size caps): bits are set when a
 * fixed-size buffer in the orchestrator truncates evidence. Surfaced
 * under --verbose by orchestrator_report_saturation() so a dropped-info
 * case is observable rather than silent. None of these caps bind on
 * realistic workloads; the bits exist so growth can be detected.
 * -------------------------------------------------------------------------
 */
enum orchestrator_saturation {
  ORCH_SAT_RESULTS_FULL = 1u << 0, /* MAX_RESULTS hit; drops new records */
  ORCH_SAT_PROVENANCE_FULL =
      1u << 1, /* MAX_PROVENANCE hit; drops later contributors */
  ORCH_SAT_COMPONENT_LINES_DROPPED =
      1u << 2, /* alloc failure during verbose-line capture */
};
static unsigned int orchestrator_saturation;

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

/* Phase table.
 * Each row declares a phase key (matched against components[].phase) and an
 * execution mode (parallel or sequential). The loop in main() iterates the
 * table; adding a new phase means adding one row, not editing main(). Every
 * phase runs merge_results() once after its components finish — that step
 * lives in run_phase() rather than as a per-row callback because no consumer
 * has needed differentiated post-actions. */
struct phase {
  const char *key; /* matches component.phase (non-NULL on every row) */
  int parallel;    /* 1 = use worker pool (inference); 0 = sequential */
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
#ifndef KASLD_TESTING
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
#endif /* !KASLD_TESTING */

/* =========================================================================
 * System information
 * =========================================================================
 */
static void read_proc_value(const char *label, const char *path) {
  FILE *f = kasld_fopen(path, "r");
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
  FILE *f = kasld_fopen(path, "r");
  if (!f)
    return -1;
  int val = -1;
  if (fscanf(f, "%d", &val) != 1)
    val = -1;
  fclose(f);
  return val;
}

/* Detect kernel pointer hashing from /proc/cmdline. %pK (and %p) print a hashed
 * id unless no_hash_pointers / hash_pointers=never is on the boot cmdline.
 * Returns 1 (hashed — the default), 0 (raw), or -1 (cmdline unreadable). */
static int read_pointer_hashing(void) {
  FILE *f = kasld_fopen("/proc/cmdline", "r");
  if (!f)
    return -1;
  char buf[4096];
  size_t n = fread(buf, 1, sizeof(buf) - 1, f);
  fclose(f);
  buf[n] = '\0';
  if (strstr(buf, "no_hash_pointers") || strstr(buf, "hash_pointers=never"))
    return 0;
  return 1;
}

/* Read /sys/kernel/security/lockdown and parse the active mode.
 * Format: "none [integrity] confidentiality" — bracketed word is active. */
static enum lockdown_mode read_lockdown(void) {
  FILE *f = kasld_fopen("/sys/kernel/security/lockdown", "r");
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

#ifndef KASLD_TESTING
static void print_banner(void) {
  struct utsname u;
  if (kasld_uname(&u) < 0) {
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
  if (kasld_uname(&u) < 0) {
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
  hashed_pointers = read_pointer_hashing();

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
    int readable = kasld_access(check_files[i][1], R_OK) == 0;
    printf("%-30s%s%s%s\n", check_files[i][0], readable ? c(C_GREEN) : c(C_DIM),
           readable ? "yes" : "no", c(C_RESET));
  }

  /* Kernel-release-specific paths */
  char path[KASLD_PATH_MAX];
  int readable;

  snprintf(path, sizeof(path), "/boot/System.map-%s", u.release);
  readable = kasld_access(path, R_OK) == 0;
  printf("%-30s%s%s%s\n",
         "Readable /boot/System.map:", readable ? c(C_GREEN) : c(C_DIM),
         readable ? "yes" : "no", c(C_RESET));

  snprintf(path, sizeof(path), "/boot/config-%s", u.release);
  readable = kasld_access(path, R_OK) == 0;
  printf("%-30s%s%s%s\n",
         "Readable /boot/config:", readable ? c(C_GREEN) : c(C_DIM),
         readable ? "yes" : "no", c(C_RESET));

  printf("\n");
}
#endif /* !KASLD_TESTING */

/* =========================================================================
 * Component execution
 * =========================================================================
 */

/* Result storage — defined in kasld/internal.h */

struct result results[MAX_RESULTS];
int num_results;

/* scalar_fact_record + scalar_facts[]/num_scalar_facts declared in
 * include/kasld/internal.h; the engine bridge copies these to OBS_SCALAR
 * observations and inject_kaslr_defaults / render also read them directly. */
struct scalar_fact_record scalar_facts[MAX_SCALAR_FACTS];
int num_scalar_facts;

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
  if (line[0] != 'P' && line[0] != 'V')
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
    /* hi = lo + sz - 1, rejecting an empty or wrapping extent in one step. */
    if (p.sz == 0 || kasld_add_ovf(p.lo, p.sz - 1, &p.hi))
      return 0;
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
    orchestrator_saturation |= ORCH_SAT_RESULTS_FULL;
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

/* Parse one `S <fact> conf=<c> value=0x<hex>` scalar-fact wire record into
 * scalar_facts[]. Returns 1 on capture, 0 on reject (unknown fact, bad conf or
 * value). Sibling of capture_result(); same validate-or-reject discipline. */
static int capture_scalar(const char *line, const char *origin) {
  if (line[0] != 'S' || line[1] != ' ')
    return 0;
  char name[32], conf_str[16], val_str[40];
  if (sscanf(line, "S %31s conf=%15s value=%39s", name, conf_str, val_str) != 3)
    return 0;
  enum kasld_scalar_fact f = kasld_scalar_fact_from_wire(name);
  if (f == SF_NONE)
    return 0;
  enum kasld_confidence c = conf_from_wire(conf_str);
  if (c == CONF_UNKNOWN)
    return 0;
  unsigned long v;
  if (!parse_hex(val_str, &v))
    return 0;
  /* Cap check + slot reservation under the same lock as capture_result —
   * the inference worker pool can call this from any thread, so a naked
   * num_scalar_facts++ is racy. Once the slot is reserved, this thread is
   * the only writer of that slot, so the field assignments below run
   * outside the lock. */
  RESULT_LOCK();
  if (num_scalar_facts >= MAX_SCALAR_FACTS) {
    RESULT_UNLOCK();
    return 0;
  }
  int idx = num_scalar_facts++;
  RESULT_UNLOCK();
  struct scalar_fact_record *s = &scalar_facts[idx];
  s->fact = f;
  s->value = v;
  s->conf = c;
  snprintf(s->origin, ORIGIN_LEN, "%.*s", (int)(ORIGIN_LEN - 1),
           origin ? origin : "");
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
  FILE *f = kasld_fopen(path, "rb");
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
#ifndef KASLD_TESTING
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
#endif /* !KASLD_TESTING */

/* Process one component output line (content only, no trailing newline): stream
 * it to verbose stdout, capture it into the per-component log, and feed it to
 * the address/scalar parser. Returns the number of records tagged (0 or 1).
 * `content` need not be NUL-terminated; exactly `len` bytes are used. Input
 * longer than the line buffer is truncated (the parser rejects malformed
 * lines), so the single fixed copy never overflows. Called for each complete
 * line, the unterminated EOF tail, and an over-long line that fills the read
 * buffer without a newline — one place, no synthetic delimiters. */
static int handle_component_line(struct component_log *clog,
                                 const char *comp_method, const char *origin,
                                 const char *content, size_t len) {
  char line[LINE_LEN];
  if (len >= sizeof(line))
    len = sizeof(line) - 1;
  memcpy(line, content, len);
  line[len] = '\0';

  if (verbose && !json_output)
    printf("%s\n", line);

  /* Capture line for verbose / JSON-with-output. Allocated on first use and
   * grown geometrically — no fixed cap, so noisy components do not silently
   * lose their tail. Non-verbose runs never enter this branch and never
   * allocate. Allocation failures degrade gracefully: the line is dropped (and
   * counts as truncated), but capture continues for subsequent lines. clog is
   * per-thread, so its realloc/malloc need no lock; only the shared saturation
   * flag does (this runs from any worker thread). */
  if (clog && verbose) {
    int dropped = 0;
    if (clog->num_lines >= clog->lines_cap) {
      int new_cap =
          clog->lines_cap ? clog->lines_cap * 2 : COMPONENT_LINES_INITIAL_CAP;
      char **bigger = realloc(clog->lines, (size_t)new_cap * sizeof(char *));
      if (bigger) {
        clog->lines = bigger;
        clog->lines_cap = new_cap;
      } else {
        dropped = 1;
      }
    }
    if (clog->num_lines < clog->lines_cap) {
      char *copy = malloc(MAX_LINE_LEN);
      if (copy) {
        snprintf(copy, MAX_LINE_LEN, "%s", line);
        clog->lines[clog->num_lines++] = copy;
      } else {
        dropped = 1;
      }
    }
    if (dropped) {
      RESULT_LOCK();
      orchestrator_saturation |= ORCH_SAT_COMPONENT_LINES_DROPPED;
      RESULT_UNLOCK();
    }
  }

  /* Origin (provenance) is the component name — captured at the orchestrator
   * since it owns the subprocess identity. `S` lines are scalar system facts;
   * everything else is an address record. */
  if (line[0] == 'S')
    return capture_scalar(line, origin);
  return capture_result(line, comp_method, origin);
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
    clog->lines = NULL;
    clog->num_lines = 0;
    clog->lines_cap = 0;
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

    /* Redirect stdout to pipe, merge stderr into stdout. If either dup2
     * fails the child cannot communicate results back; abort. dup2 only
     * fails on EBADF (pipefd[1] invalid — impossible here, the pipe()
     * succeeded above) or EINVAL (target fd out of range, also impossible
     * for STDOUT/STDERR), so this is purely defensive — but cheap. */
    close(pipefd[0]);
    if (dup2(pipefd[1], STDOUT_FILENO) < 0 ||
        dup2(pipefd[1], STDERR_FILENO) < 0)
      _exit(127);
    close(pipefd[1]);

    /* KASLD_EXEC_WRAPPER (optional): when set, the child execve's this
     * wrapper path with the component path as argv[1] instead of the
     * component directly. Intended for nested-emulation scenarios where
     * the parent kasld is a guest-arch ELF running under qemu-user and
     * cannot directly execve another guest-arch binary — the host kernel
     * refuses with ENOEXEC unless binfmt_misc is registered. Pointing
     * the wrapper at the host-arch qemu-<guest> binary lets the child
     * cross the ABI boundary correctly. Inherited env (including
     * KASLD_SYSROOT) propagates through.
     * Empty / unset → direct execve of the component (the normal path). */
    const char *wrap = getenv("KASLD_EXEC_WRAPPER");
    if (wrap && *wrap) {
      execl(wrap, wrap, c->path, (char *)NULL);
      /* fall-through to _exit on failure */
    } else {
      execl(c->path, c->name, (char *)NULL);
    }
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

    /* Read available data into the free tail of the buffer. */
    ssize_t n = read(pipefd[0], buf + buf_pos, sizeof(buf) - buf_pos);
    if (n <= 0) {
      /* EOF or error. Flush any unterminated tail as a final line so it
       * reaches the parser — which rejects malformed input cleanly (return 0),
       * surfacing a segfault-mid-line as a recordable parse failure rather than
       * a silent drop — plus the verbose / per-component-log path. A cleanly
       * terminated stream ends on a newline that the loop below already
       * consumed, leaving buf_pos == 0 and nothing to flush. */
      if (buf_pos > 0)
        tagged_this_run +=
            handle_component_line(clog, comp_method, c->name, buf, buf_pos);
      break;
    }
    buf_pos += (size_t)n;

    /* Hand off each complete (newline-terminated) line; the newline itself is
     * not part of the content. memchr is length-bounded, so buf needs no NUL
     * terminator and an embedded NUL cannot truncate a line. */
    size_t start = 0;
    char *nl;
    while ((nl = memchr(buf + start, '\n', buf_pos - start)) != NULL) {
      size_t llen = (size_t)(nl - (buf + start));
      tagged_this_run +=
          handle_component_line(clog, comp_method, c->name, buf + start, llen);
      start = (size_t)(nl - buf) + 1;
    }
    size_t left = buf_pos - start;

    /* A line longer than the whole buffer has no newline to split on — the
     * only way `left` can reach the buffer size. Flush the buffered prefix as a
     * (truncated) line so the reader makes progress instead of stalling on a
     * zero-length read, then keep reading the rest of the line. */
    if (left == sizeof(buf)) {
      tagged_this_run +=
          handle_component_line(clog, comp_method, c->name, buf, left);
      left = 0;
    }

    /* Shift any remaining partial line to the front of the buffer. */
    if (left > 0 && start > 0)
      memmove(buf, buf + start, left);
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
    /* Progress bar uses \r to overwrite itself; only useful on a TTY. Sent
     * to stderr so `kasld | grep` / `kasld > out` don't capture overwrites. */
    if (!isatty(STDERR_FILENO))
      return;
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

    fprintf(stderr, "\r%s[%s]%s %3d%%  %d/%d  %s%.1fs%s", c(C_DIM), bar,
            c(C_RESET), pct, done, total, c(C_DIM), elapsed, c(C_RESET));
    fflush(stderr);
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

/* Run the components for a single phase. After every component has
 * finished, merge_results() is called once to deduplicate emitted records.
 *
 * Parallel phases (p->parallel): real worker pool when parallel_workers > 1
 *   and not verbose. Layout is read-only during parallel execution so
 *   align/validate calls inside capture_result() are safe without
 *   additional locking. Falls back to a sequential loop when workers <= 1
 *   or verbose (verbose forces sequential to avoid interleaved output).
 *
 * Sequential phases (!p->parallel): always a single-threaded loop. */
#ifndef KASLD_TESTING
static void run_phase(const struct phase *p) {
  int exp_active = experimental_mode || getenv("KASLD_EXPERIMENTAL") != NULL;
  pool_inf_n = 0;
  for (int i = 0; i < num_components; i++) {
    if (strcmp(components[i].phase, p->key) == 0 &&
        (!components[i].is_experimental || exp_active) &&
        !components[i].is_filtered)
      pool_inf[pool_inf_n++] = i;
  }
  if (pool_inf_n == 0)
    return;

  if (!p->parallel) {
    for (int i = 0; i < pool_inf_n; i++) {
      run_component(&components[pool_inf[i]]);
      progress_update();
    }
    merge_results();
    return;
  }

  int workers = parallel_workers;
#ifndef HAVE_PTHREAD
  workers = 1;
#endif

  if (workers <= 1 || verbose) {
    for (int i = 0; i < pool_inf_n; i++) {
      run_component(&components[pool_inf[i]]);
      progress_update();
    }
    merge_results();
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
  merge_results();
#endif
}
#endif /* !KASLD_TESTING */

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
    orchestrator_saturation |= ORCH_SAT_PROVENANCE_FULL;
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
      /* pos follows the surviving sample owner unless a stronger claim
       * (POS_BASE: lo IS the base) is already on the record from another
       * contributor. POS_BASE > POS_INTERIOR; the merged record represents
       * the strongest mutually consistent pos claim across contributors. */
      if (a->pos != POS_BASE)
        a->pos = b->pos;
    }
  }
  /* Promote pos to POS_BASE when any contributor carries that claim. The
   * lo/hi/sample fields are merged independently above; this only updates
   * the categorical pos tag so downstream rules that gate on it (notably
   * text_pin_from_observation) fire on the merged record. */
  if (b->pos == POS_BASE && a->pos != POS_BASE)
    a->pos = POS_BASE;
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

/* LO-only-point conflict: two contributors are each POS_BASE-style point
 * witnesses (LO set, HI not set) disagreeing on the address. Same rationale
 * as samples_conflict — these are independent observations of distinct
 * points, not refinements of a single range. Without this guard,
 * merge_into's `max(lo)` semantics (which makes sense for intersecting
 * extents) silently discards the lower witness, losing data. Exposed in
 * the wild on ppc64-no-KASLR where two components legitimately emit
 * different base witnesses for the direct map (sysfs_devicetree_memory at
 * PAGE_OFFSET vs sysfs_memory_blocks at PAGE_OFFSET + DRAM_base). */
static int lo_only_conflict(const struct result *a, const struct result *b) {
  int a_point = HAS_LO(a) && !HAS_HI(a);
  int b_point = HAS_LO(b) && !HAS_HI(b);
  if (!a_point || !b_point)
    return 0;
  return a->lo != b->lo;
}

/* Sample-vs-LO clamp conflict: merging would force clamp_sample() to shift
 * an existing sample to satisfy a contributor's lo (sample below it) or hi
 * (sample above it). The clamp silently rewrites the sample address — the
 * source observation's true address is then lost from the merged record
 * AND reattributed to whichever component contributed the conflicting
 * bound. Symmetric in (acc, b) by inspection. */
static int sample_bound_clamp_conflict(const struct result *a,
                                       const struct result *b) {
  if (HAS_SAMPLE(a) && HAS_LO(b) && a->sample < b->lo)
    return 1;
  if (HAS_SAMPLE(a) && HAS_HI(b) && a->sample > b->hi)
    return 1;
  if (HAS_SAMPLE(b) && HAS_LO(a) && b->sample < a->lo)
    return 1;
  if (HAS_SAMPLE(b) && HAS_HI(a) && b->sample > a->hi)
    return 1;
  return 0;
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

/* Collapse same-(type, region, name) records into one. Called by run_phase()
 * once after every component in the phase has finished, so compute_kaslr_info()
 * — and the engine evidence built from results[] — see deduplicated records.
 * The engine itself runs later, in compute_kaslr_info(); nothing infers here.
 *
 * IDEMPOTENT: safe to call repeatedly. The merge collapses (type, region, name)
 * groups by keeping the highest-confidence record's sample/pos and taking the
 * narrowest interval intersection; calling it again on the already-merged set
 * is a no-op (every potential merge has already been applied). Test code (and
 * the per-phase wiring in run_phase) relies on this — a future edit that
 * introduced cross-call state would break both. */
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
      /* Independent-witness gates: different samples / LO-only points /
       * sample-vs-bound combinations for the same merge key are almost
       * certainly different instances (two swiotlb buffers, two initrd
       * witnesses, two base witnesses on a coupled arch) — silently
       * collapsing them would lose data. Keep both records. */
      if (samples_conflict(&acc, b))
        continue;
      if (lo_only_conflict(&acc, b))
        continue;
      if (sample_bound_clamp_conflict(&acc, b))
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
/* Bits-of-entropy from a candidate count: ceil(log2(v)) for v >= 1, 0 for
 * v == 0. CEIL (not floor) because the user-facing question is "how much
 * brute-force work remains?" — 13 candidates is ~4 bits of worst-case
 * work, not 3. Power-of-2 inputs are unaffected (ceil == floor). */
static int ilog2(unsigned long v) {
  if (v <= 1)
    return 0;
  int r = 0;
  unsigned long n = v;
  while (n >>= 1)
    r++;
  if ((v & (v - 1)) != 0)
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

/* The layered engine is the sole inference path: resolve every quantity from
 * the collected evidence and write the result into `layout`, which the
 * summary below is computed from (defined after engine_build_evidence). Guarded
 * out of the KASLD_TESTING build, which excludes the engine entirely. */
/* engine_sync_authoritative is compiled in every build (it is a pure
 * projection the unit tests call); engine_resolve and its engine instance are
 * engine-only (they drive the components + engine.c machinery). */
static void engine_sync_authoritative(const struct engine *e);
#ifndef KASLD_TESTING
static void engine_resolve(struct engine *e);
static struct engine g_auth_engine;
#endif

void compute_kaslr_info(struct summary *s) {
#ifndef KASLD_TESTING
  /* The layered engine is the sole inference path: resolve every quantity from
   * the collected evidence and write the result into `layout`, which
   * the rest of this function reads. */
  engine_resolve(&g_auth_engine);
  engine_sync_authoritative(&g_auth_engine);
#endif

  const struct result *r_vt =
      select_anchor(KASLD_TYPE_VIRT, REGION_KERNEL_IMAGE);
  if (!r_vt)
    r_vt = select_anchor(KASLD_TYPE_VIRT, REGION_KERNEL_TEXT);
  unsigned long vtext = anchor_addr(r_vt);
  if (vtext == 0)
    vtext = derive_vtext_from_data();
  /* No result for the kernel text but the engine pinned Q_VIRT_TEXT_BASE to a
   * point (e.g. virt_/phys_kaslr_disabled_pin landed) → that pinned value IS
   * the text base. engine_sync projects the resolved window onto
   * virt_kaslr_text_min/max, so equality of the two means "pinned". */
  if (vtext == 0 && layout.virt_kaslr_text_min == layout.virt_kaslr_text_max)
    vtext = layout.virt_kaslr_text_min;
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

  /* Hole-aware slot count: route via quantity_slots() so interior C_EXCLUDE
   * holes and any C_STRIDE residue class are reflected in the headline entropy
   * number. Flat (hi-lo)/align is the no-constraints fallback for KASLD_TESTING
   * builds (the engine instance is compiled out there). */
#ifndef KASLD_TESTING
  s->kaslr.vslots =
      quantity_slots(Q_VIRT_TEXT_BASE, &g_auth_engine.est[Q_VIRT_TEXT_BASE],
                     g_auth_engine.constraints, g_auth_engine.n_constraints,
                     layout.virt_kaslr_align);
#else
  {
    unsigned long text_range =
        layout.virt_kaslr_text_max - layout.virt_kaslr_text_min;
    s->kaslr.vslots =
        layout.virt_kaslr_align ? text_range / layout.virt_kaslr_align : 0;
  }
#endif
  s->kaslr.vbits = s->kaslr.vslots > 0 ? ilog2(s->kaslr.vslots) : 0;

#ifdef KASLR_PHYS_MIN
  {
#ifndef KASLD_TESTING
    s->kaslr.pslots =
        quantity_slots(Q_PHYS_TEXT_BASE, &g_auth_engine.est[Q_PHYS_TEXT_BASE],
                       g_auth_engine.constraints, g_auth_engine.n_constraints,
                       layout.phys_kaslr_align);
#else
    unsigned long phys_range =
        layout.phys_kaslr_text_max - layout.phys_kaslr_text_min;
    s->kaslr.pslots =
        layout.phys_kaslr_align ? phys_range / layout.phys_kaslr_align : 0;
#endif
    s->kaslr.pbits = s->kaslr.pslots > 0 ? ilog2(s->kaslr.pslots) : 0;
  }
#endif

  if (s->kaslr.vtext) {
    s->kaslr.vslide = (long)(s->kaslr.vtext - layout.virt_kernel_text_default);
    s->kaslr.vslot_valid = (layout.virt_kaslr_align > 0 &&
                            s->kaslr.vtext >= layout.virt_kaslr_text_min &&
                            s->kaslr.vtext < layout.virt_kaslr_text_max);
    if (s->kaslr.vslot_valid)
      s->kaslr.vslot_idx = (s->kaslr.vtext - layout.virt_kaslr_text_min) /
                           layout.virt_kaslr_align;
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

  s->kaslr.virt_page_offset_min =
      (layout.virt_page_offset_min != (unsigned long)PAGE_OFFSET)
          ? layout.virt_page_offset_min
          : 0;
  s->kaslr.virt_page_offset_max =
      (layout.virt_page_offset_max != (unsigned long)KERNEL_VIRT_VAS_END)
          ? layout.virt_page_offset_max
          : 0;
  s->kaslr.virt_vmalloc_min =
      (layout.virt_vmalloc_base_min != 0) ? layout.virt_vmalloc_base_min : 0;
  s->kaslr.virt_vmalloc_max = (layout.virt_vmalloc_base_max != ULONG_MAX)
                                  ? layout.virt_vmalloc_base_max
                                  : 0;
  s->kaslr.virt_vmemmap_min =
      (layout.virt_vmemmap_base_min != 0) ? layout.virt_vmemmap_base_min : 0;
  s->kaslr.virt_vmemmap_max = (layout.virt_vmemmap_base_max != ULONG_MAX)
                                  ? layout.virt_vmemmap_base_max
                                  : 0;

#if !TEXT_TRACKS_DIRECTMAP
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
  /* "Unsupported" is a compile-time property of the arch (KASLR_SUPPORTED=0 on
   * arm32 / ppc64 / riscv32 / sparc); no runtime signal needed. Surface it for
   * the renderer banner, and seed the informational default address from the
   * statically-initialised layout (= KERNEL_VIRT_TEXT_DEFAULT). */
  s->kaslr.unsupported = !KASLR_SUPPORTED;
  s->kaslr.default_addr = layout.virt_kernel_text_default;

#if !KASLR_SUPPORTED
  /* Surface the compile-time arch-off as SF_VIRT_KASLR_DISABLED +
   * SF_PHYS_KASLR_DISABLED so the engine sees it like any runtime detector
   * signal. Inert today on the four !KASLR_SUPPORTED arches (none satisfies
   * KASLR_DISABLED_PINS_VIRT_TEXT/PHYS — all four are relocating, bootloader
   * can still place the image), so no unsound text-base pin: the renderer's
   * "KASLR not supported" banner + default-addr line shows, the engine
   * refuses to pin. A future !KASLR_SUPPORTED arch that does satisfy one of
   * those macros would pin correctly via the same rule path. */
  if (num_scalar_facts + 1 < MAX_SCALAR_FACTS) {
    struct scalar_fact_record *fv = &scalar_facts[num_scalar_facts++];
    fv->fact = SF_VIRT_KASLR_DISABLED;
    fv->value = 1;
    fv->conf = CONF_PARSED;
    snprintf(fv->origin, ORIGIN_LEN, "arch-no-kaslr");
    struct scalar_fact_record *fp = &scalar_facts[num_scalar_facts++];
    fp->fact = SF_PHYS_KASLR_DISABLED;
    fp->value = 1;
    fp->conf = CONF_PARSED;
    snprintf(fp->origin, ORIGIN_LEN, "arch-no-kaslr");
  }
#endif

  /* "Disabled" is a runtime signal from any detector that observed virtual
   * KASLR off (nokaslr cmdline, no CONFIG_RANDOMIZE_BASE, dmesg "KASLR
   * disabled", hibernation override, riscv64 no FDT seed, loongarch
   * kexec_file token, s390 elfcorehdr=, or the compile-time !KASLR_SUPPORTED
   * synth above). The summary flag drives the renderer's "kernel sits at
   * default text base" status line; that user-facing claim is about virt
   * text, so it tracks SF_VIRT_KASLR_DISABLED specifically. A phys-only
   * disable (e.g. EFI_RNG_PROTOCOL unavailable with virt KASLR intact via
   * DTB seed) wouldn't set this flag — the renderer would still show "KASLR
   * active" because virt randomisation succeeded. */
  s->kaslr.disabled = 0;
  s->kaslr.randomization_failed = 0;
  for (int i = 0; i < num_scalar_facts; i++) {
    if (scalar_facts[i].fact == SF_VIRT_KASLR_DISABLED &&
        scalar_facts[i].value != 0)
      s->kaslr.disabled = 1;
    else if (scalar_facts[i].fact == SF_VIRT_KASLR_RANDOMIZATION_FAILED &&
             scalar_facts[i].value != 0)
      /* Track the virt-side failure: the renderer's "0 entropy / kernel
       * at firmware-determined position" claim is about virt text. A
       * phys-only randomization failure (future EFI_RNG_PROTOCOL detector)
       * wouldn't trip this — virt KASLR via DTB seed could still have
       * full entropy. */
      s->kaslr.randomization_failed = 1;
  }
}

/* Phase table ------------------------------------------------------------- */

/* Each row is one phase. Adding a new phase = adding one row here. */
static const struct phase phases[] = {
    {"inference", 1},
    {"probing", 0},
};

/* A component runs only if its `phase` matches some row's key; a typo or
 * unknown phase value would otherwise drop it silently from every phase. Warn
 * loudly and reassign it to the first (inference) phase so a misconfigured
 * component still runs rather than vanishing. Validated against phases[] so a
 * newly added phase needs no second list to update. */
#ifndef KASLD_TESTING
static void validate_component_phases(void) {
  const int n_phases = (int)(sizeof(phases) / sizeof(phases[0]));
  for (int i = 0; i < num_components; i++) {
    int known = 0;
    for (int p = 0; p < n_phases; p++)
      if (strcmp(components[i].phase, phases[p].key) == 0) {
        known = 1;
        break;
      }
    if (!known) {
      fprintf(stderr,
              "[!] component '%s' has unknown phase '%s'; running it as '%s' "
              "(check its .kasld_meta phase: key)\n",
              components[i].name, components[i].phase, phases[0].key);
      snprintf(components[i].phase, sizeof(components[i].phase), "%s",
               phases[0].key);
    }
  }
}
#endif /* !KASLD_TESTING */

/* =========================================================================
 * Main
 * =========================================================================
 */
#ifndef KASLD_TESTING

/* Arch-specific normalisation of one copied result, at the ingestion boundary.
 * Keeps the generic copy loop free of per-arch `#if` blocks. */
static void bridge_normalize_arch(struct observation *o,
                                  const struct result *r) {
#if defined(__mips64) || defined(__mips64__)
  /* MIPS64 XKPHYS: a leaked VIRT address in the XKPHYS window is really a
   * direct physical mapping. Reclassify it to PHYS/RAM with the decoded
   * physical address before any rule sees it, so phys_virt_synth never pairs
   * it as a directmap VIRT leak. */
  if (o->type == KASLD_TYPE_VIRT && kasld_addr_is_xkphys(anchor_addr(r))) {
    o->type = KASLD_TYPE_PHYS;
    o->region = REGION_RAM;
    if (o->set_mask & LO_SET)
      o->lo = kasld_xkphys_to_phys(o->lo);
    if (o->set_mask & HI_SET)
      o->hi = kasld_xkphys_to_phys(o->hi);
    if (o->set_mask & SAMPLE_SET)
      o->sample = kasld_xkphys_to_phys(o->sample);
  }
#else
  (void)o;
  (void)r;
#endif
}

/* Build the engine's evidence set: a pure copy of what the components produced
 * — the collected address results into address observations, and the collected
 * scalar facts into scalar observations. The orchestrator performs no
 * measurement itself; every fact comes from a component (meminfo_facts,
 * firmware_memmap, riscv64_no_seed, mmap_s390_va_bits, ...). */
static void engine_build_evidence(struct evidence_set *ev) {
  for (int i = 0; i < num_results; i++) {
    const struct result *r = &results[i];
    struct observation o;
    memset(&o, 0, sizeof(o));
    o.value_kind = OBS_ADDRESS;
    o.type = r->type;
    o.region = r->region;
    o.lo = r->lo;
    o.hi = r->hi;
    o.sample = r->sample;
    o.base_align = r->base_align;
    o.set_mask = r->set_mask;
    o.pos = r->pos;
    o.conf = r->conf;
    snprintf(o.name, NAME_LEN, "%s", r->name);
    if (r->provenance_count > 0)
      snprintf(o.origin, ORIGIN_LEN, "%s", r->origins[0]);

    bridge_normalize_arch(&o, r);
    evidence_add(ev, &o);
  }

  /* Scalar system facts collected from component `S` records. */
  for (int i = 0; i < num_scalar_facts; i++) {
    struct observation o;
    memset(&o, 0, sizeof(o));
    o.value_kind = OBS_SCALAR;
    o.scalar_fact = scalar_facts[i].fact;
    o.scalar_value = scalar_facts[i].value;
    o.conf = scalar_facts[i].conf;
    snprintf(o.origin, ORIGIN_LEN, "%s", scalar_facts[i].origin);
    evidence_add(ev, &o);
  }
}

/* Resolve the engine over the bridged evidence with the full rule registry. */
static const char *constraint_op_name(enum constraint_op op) {
  switch (op) {
  case C_LOWER_BOUND:
    return ">=";
  case C_UPPER_BOUND:
    return "<=";
  case C_EQUALS:
    return "==";
  case C_AT_LEAST_ALIGN:
    return "align>=";
  case C_MEMBER:
    return "member";
  case C_EXCLUDE:
    return "exclude";
  case C_STRIDE:
    return "stride";
  }
  return "?";
}

/* Report constraints the resolver rejected as contradictory, so a noisy or
 * adversarial input that drops evidence is explainable rather than silent.
 * Diagnostic only (stderr, --verbose) — the resolved estimates are unchanged.
 */
static void engine_report_conflicts(const struct engine *e) {
  for (int q = 0; q < Q__COUNT; q++) {
    for (int c = 0; c < e->n_conflicts[q]; c++) {
      uint32_t id = e->conflicts[q][c];
      const struct constraint *cc = NULL;
      for (int i = 0; i < e->n_constraints; i++)
        if (e->constraints[i].id == id) {
          cc = &e->constraints[i];
          break;
        }
      if (cc)
        fprintf(stderr,
                "[engine] %s: rejected '%s 0x%lx' from %s — contradicts "
                "higher-priority evidence\n",
                quantities[q].name, constraint_op_name(cc->op), cc->value,
                cc->origin[0] ? cc->origin : "rule");
    }
  }
}

/* Report, per quantity, how many distinct origins contributed constraints the
 * resolver accepted — a corroboration signal orthogonal to confidence: a
 * quantity bound by several independent sources is harder to spoof than one
 * bound by a single (possibly forgeable) source. Counts distinct origins of
 * accepted (non-rejected) constraints; reports only when >= 2. Diagnostic only
 * (stderr, --verbose). */
static void engine_report_corroboration(const struct engine *e) {
  for (int q = 0; q < Q__COUNT; q++) {
    const char *origins[64];
    int n = 0;
    for (int i = 0; i < e->n_constraints; i++) {
      const struct constraint *cc = &e->constraints[i];
      if ((int)cc->q != q)
        continue;
      int rejected = 0;
      for (int c = 0; c < e->n_conflicts[q]; c++)
        if (e->conflicts[q][c] == cc->id) {
          rejected = 1;
          break;
        }
      if (rejected)
        continue;
      const char *o = cc->origin[0] ? cc->origin : "rule";
      int seen = 0;
      for (int k = 0; k < n; k++)
        if (strcmp(origins[k], o) == 0) {
          seen = 1;
          break;
        }
      if (!seen && n < (int)(sizeof(origins) / sizeof(origins[0])))
        origins[n++] = o;
    }
    if (n < 2)
      continue; /* 0 or 1 source: nothing to corroborate */
    fprintf(stderr, "[engine] %s: constrained by %d independent sources:",
            quantities[q].name, n);
    for (int k = 0; k < n; k++)
      fprintf(stderr, " %s", origins[k]);
    fputc('\n', stderr);
  }
}

/* Report any resolver saturation flags. None of the caps bind on realistic
 * deduped workloads; surfacing a hit makes the dropped-info case observable
 * rather than silent if scale ever grows. Diagnostic only (stderr, --verbose).
 */
static void engine_report_saturation(const struct engine *e) {
  if (!e->saturation)
    return;
  if (e->saturation & ENGINE_SAT_CONSTRAINTS_FULL)
    fprintf(stderr,
            "[engine] saturation: ENGINE_MAX_CONSTRAINTS (%d) reached; "
            "subsequent rule emissions in the same pass were dropped\n",
            ENGINE_MAX_CONSTRAINTS);
  if (e->saturation & ENGINE_SAT_RULE_EMIT_OVERFLOW)
    fprintf(stderr,
            "[engine] saturation: a constraint rule returned > "
            "ENGINE_RULE_MAX_EMIT (%d); excess constraints dropped\n",
            ENGINE_RULE_MAX_EMIT);
  if (e->saturation & ENGINE_SAT_VRULE_EMIT_OVERFLOW)
    fprintf(stderr,
            "[engine] saturation: a verdict rule returned > "
            "ENGINE_RULE_MAX_EMIT (%d); excess verdicts dropped\n",
            ENGINE_RULE_MAX_EMIT);
  if (e->saturation & ENGINE_SAT_ESTIMATE_WORK_FULL)
    fprintf(stderr,
            "[engine] saturation: ESTIMATE_MAX_WORK reached in the resolver's "
            "per-quantity gather; constraints beyond the cap were dropped in "
            "insertion order\n");
  if (e->saturation & ENGINE_SAT_CONFLICTS_FULL)
    fprintf(stderr,
            "[engine] saturation: ESTIMATE_MAX_CONFLICTS (%d) reached; "
            "additional rejected constraints were not recorded\n",
            ESTIMATE_MAX_CONFLICTS);
}

/* Sibling reporter for orchestrator-side caps (results[], merged-record
 * provenance, per-component verbose-line capture). Same diagnostic shape
 * as engine_report_saturation; surfaces under --verbose. */
static void orchestrator_report_saturation(void) {
  if (!orchestrator_saturation)
    return;
  if (orchestrator_saturation & ORCH_SAT_RESULTS_FULL)
    fprintf(stderr,
            "[orchestrator] saturation: MAX_RESULTS (%d) reached; "
            "further leak/scalar observations were dropped at capture\n",
            MAX_RESULTS);
  if (orchestrator_saturation & ORCH_SAT_PROVENANCE_FULL)
    fprintf(stderr,
            "[orchestrator] saturation: MAX_PROVENANCE (%d) reached on at "
            "least one merged record; additional contributors were not "
            "recorded (the record's resolved value is unaffected)\n",
            MAX_PROVENANCE);
  if (orchestrator_saturation & ORCH_SAT_COMPONENT_LINES_DROPPED)
    fprintf(stderr,
            "[orchestrator] saturation: allocation failure while capturing "
            "component stdout for --verbose; at least one line was dropped\n");
}

static void engine_resolve(struct engine *e) {
  int n_rules = 0, n_vrules = 0;
  const rule_fn *rules = engine_rules(&n_rules);
  const verdict_fn *vrules = engine_verdict_rules(&n_vrules);
  engine_init(e);
  engine_build_evidence(&e->ev);
  engine_run_full(e, rules, n_rules, vrules, n_vrules);
  if (verbose && !json_output) {
    engine_report_conflicts(e);
    engine_report_corroboration(e);
    engine_report_saturation(e);
    orchestrator_report_saturation();
  }
}
#endif /* !KASLD_TESTING (engine_resolve/build need the components+engine.c)   \
        */

/* Write the engine's resolved estimates into the bound state that
 * compute_kaslr_info() reads (`layout`). Where a quantity is not
 * resolved beyond its honest compile-time window the reported window is simply
 * that window — the engine never commits to an unproven default.
 * vmalloc/vmemmap are synced only when actually constrained (lo/hi_binding
 * set), preserving compute_kaslr_info's unset-sentinel logic.
 *
 * NOT gated out of KASLD_TESTING: this is a pure projection from engine
 * estimates (engine.h types, available everywhere) onto the layout
 * globals — it links no engine.c symbols and can be called wherever the
 * engine→layout contract needs pinning.
 *
 * Every quantity that has a reported sink must be projected here. Map of
 * Q_* -> sink:
 *     Q_VIRT_TEXT_BASE   -> layout.kaslr_base_* AND layout.kernel_base_*
 *     Q_KASLR_ALIGN      -> layout.virt_kaslr_align
 *     Q_PAGE_OFFSET      -> layout.page_offset_* (+ layout.virt_page_offset,
 * decoupled) Q_PHYS_TEXT_BASE   -> layout.phys_kaslr_base_*        (decoupled
 * arches) Q_PHYS_KASLR_ALIGN -> layout.phys_kaslr_align         (decoupled
 * arches) Q_VMALLOC_BASE     -> layout.vmalloc_base_*            (when
 * constrained) Q_VMEMMAP_BASE     -> layout.vmemmap_base_*            (when
 * constrained) Q_VA_BITS          -> (none) intermediate: rules consume it to
 * bound Q_VIRT_TEXT_BASE; it has no layout sink. The compile-time check below
 * trips when Q__COUNT changes — forcing whoever adds a quantity to decide its
 * sink (or document it as intermediate) and bump the count, rather than
 * silently leaving it unprojected. */
typedef char engine_sync_projects_every_quantity[(Q__COUNT == 8) ? 1 : -1];

static void engine_sync_authoritative(const struct engine *e) {
  const struct estimate *vt = &e->est[Q_VIRT_TEXT_BASE];
  /* Project the resolved virtual-text window onto BOTH the KASLR window
   * (kaslr_base_*, read by the entropy/slot math in compute_kaslr_info) and the
   * kernel image-placement range (kernel_base_*, read by the rendered memory
   * map). They must stay equal post-resolution or the diagram's "kernel text"
   * band disagrees with the reported "Inferred text range". */
  layout.virt_kaslr_text_min = vt->lo;
  layout.virt_kaslr_text_max = vt->hi;
  layout.virt_kernel_text_min = vt->lo;
  layout.virt_kernel_text_max = vt->hi;
  if (e->est[Q_KASLR_ALIGN].lo)
    layout.virt_kaslr_align = e->est[Q_KASLR_ALIGN].lo;

#if TEXT_TRACKS_DIRECTMAP
  /* On coupled arches phys and virt text-base KASLR offsets are locked, so
   * the same slot granularity applies to both. Mirror the resolved virt
   * align into the phys-side field so entropy/slot reporting on coupled
   * arches reflects the actual CONFIG_PHYSICAL_ALIGN rather than the
   * compile-time default. (The !TEXT_TRACKS_DIRECTMAP branch below syncs
   * Q_PHYS_KASLR_ALIGN independently on decoupled arches.) */
  if (e->est[Q_KASLR_ALIGN].lo)
    layout.phys_kaslr_align = e->est[Q_KASLR_ALIGN].lo;
#endif

  layout.virt_page_offset_min = e->est[Q_PAGE_OFFSET].lo;
  layout.virt_page_offset_max = e->est[Q_PAGE_OFFSET].hi;

#if !TEXT_TRACKS_DIRECTMAP
  /* On decoupled arches the direct-map base (PAGE_OFFSET) is randomised away
   * from the compile-time floor (x86_64 RANDOMIZE_MEMORY). Anchor the rendered
   * memory map's direct-map band at the engine's best-known base (pinned, or
   * the proven lower bound). Gated on lo having actually been raised above the
   * compile-time default, so we never claim more than the engine proved.
   *
   * Only layout.virt_page_offset moves — NOT layout.virt_kernel_vas_start. On a
   * decoupled arch the direct-map base is the lowest kernel *mapping* but NOT
   * the VAS floor: the architectural KERNEL_VIRT_VAS_START (the canonical-hole
   * top) sits far below it, and the map's bottom should show that floor with
   * the directmap-base-uncertainty gap above it, not pretend the address space
   * begins at the directmap base. */
  {
    const struct estimate *po = &e->est[Q_PAGE_OFFSET];
    if (po->lo > (unsigned long)PAGE_OFFSET)
      layout.virt_page_offset = po->lo;
  }

  const struct estimate *pt = &e->est[Q_PHYS_TEXT_BASE];
  layout.phys_kaslr_text_min = pt->lo;
  layout.phys_kaslr_text_max = pt->hi;
  if (e->est[Q_PHYS_KASLR_ALIGN].lo)
    layout.phys_kaslr_align = e->est[Q_PHYS_KASLR_ALIGN].lo;
#endif

  if (e->est[Q_VMALLOC_BASE].lo_binding)
    layout.virt_vmalloc_base_min = e->est[Q_VMALLOC_BASE].lo;
  if (e->est[Q_VMALLOC_BASE].hi_binding)
    layout.virt_vmalloc_base_max = e->est[Q_VMALLOC_BASE].hi;
  if (e->est[Q_VMEMMAP_BASE].lo_binding)
    layout.virt_vmemmap_base_min = e->est[Q_VMEMMAP_BASE].lo;
  if (e->est[Q_VMEMMAP_BASE].hi_binding)
    layout.virt_vmemmap_base_max = e->est[Q_VMEMMAP_BASE].hi;

#if MODULES_RELATIVE_TO_TEXT
  /* Modules region shifts with kernel text on this arch (riscv64, s390).
   * The static layout.modules_start/end loaded at init are the wide
   * validation range — useful to bound observations, but misleading as the
   * rendered/JSON modules location once the engine has narrowed the text
   * base. Project the band onto the resolved text window so the memory map
   * shows it in its actual neighborhood.
   *
   * Two cases, controlled by MODULES_BELOW_TEXT_START:
   *   - unset (riscv64, "Case A"): MODULES_END is anchored near the kernel
   *     image's _end (≈ text + image_size). For rendering, use the text
   *     window's *upper* edge as a usable approximation (within image_size,
   *     a few MiB on real kernels). Band low edge = upper edge − 2 GiB.
   *   - set (s390, "Case B"): MODULES_END sits below the image start by up
   *     to _SEGMENT_SIZE; band high edge ≈ text_min − TEXT_OFFSET.
   *
   * 2 GiB is the MODULES_LEN on both arches; absent a per-arch macro, use
   * the literal constant with this rationale. Gated on virt_kernel_text_max
   * being a meaningful (narrowed-or-pinned) value — we keep the static
   * band when the engine has not narrowed text. */
#define KASLD_MODULES_LEN (2ul * 1024 * 1024 * 1024)
  if (vt->hi > vt->lo || vt->lo > (unsigned long)KASLR_VIRT_TEXT_MIN) {
#if MODULES_BELOW_TEXT_START
    unsigned long band_end = vt->lo > (unsigned long)TEXT_OFFSET
                                 ? vt->lo - (unsigned long)TEXT_OFFSET
                                 : vt->lo;
#else
    unsigned long band_end = vt->hi;
#endif
    unsigned long band_start =
        (band_end > KASLD_MODULES_LEN) ? (band_end - KASLD_MODULES_LEN) : 0ul;
    layout.modules_start = band_start;
    layout.modules_end = band_end;
  }
#undef KASLD_MODULES_LEN
#endif

  /* Runtime module-band anchoring (every arch).
   *
   * The compile-time MODULES_START/END is the validation UNION across all
   * in-scope kernel-version layouts -- wide on purpose so no real module
   * leak is silently rejected. When proc_modules or sysfs_module_sections
   * have given us actual module addresses (emitted as VIRT REGION_MODULE
   * or REGION_MODULE_REGION observations), the runtime band lives in a
   * much smaller span. Tightening the rendered/JSON layout to that
   * observed span makes the diagram reflect reality on this kernel, and
   * replaces the static MODULES_START/END display for arches whose true
   * region is a fraction of the union (currently arm64 v6.2+ at ~2 GiB
   * within a ~128 TiB static union).
   *
   * Soundness: the observed bounds are clamped to the validation union;
   * we never widen past what MODULES_START/END allows. If observations
   * fall entirely outside the union (would indicate a kernel layout we
   * don't yet know about), keep the static window — surfacing the
   * discrepancy via the wider rendering is more useful than silently
   * shrinking to a single bogus point. */
  {
    unsigned long obs_lo = ULONG_MAX, obs_hi = 0;
    for (int i = 0; i < e->ev.n_obs; i++) {
      const struct observation *o = &e->ev.obs[i];
      if (!o->valid || o->value_kind != OBS_ADDRESS ||
          o->eff_type != KASLD_TYPE_VIRT)
        continue;
      if (o->eff_region != REGION_MODULE &&
          o->eff_region != REGION_MODULE_REGION)
        continue;
      if (HAS_LO(o) && o->lo < obs_lo)
        obs_lo = o->lo;
      if (HAS_HI(o) && o->hi > obs_hi)
        obs_hi = o->hi;
      /* POS_BASE without HI / interior samples still pin the anchor. */
      unsigned long a = obs_anchor(o);
      if (a && a < obs_lo)
        obs_lo = a;
      if (a > obs_hi)
        obs_hi = a;
    }
    if (obs_lo != ULONG_MAX && obs_lo <= obs_hi &&
        obs_lo >= (unsigned long)MODULES_START &&
        obs_hi <= (unsigned long)MODULES_END) {
      layout.modules_start = obs_lo;
      layout.modules_end = obs_hi;
    }
  }
}
#ifndef KASLD_TESTING

/* -------------------------------------------------------------------------
 * Argument parsing: table-driven.
 *
 * One row per option. The handler receives the value string for arg-bearing
 * options (NULL for flags) and returns 0 on success or non-zero (the desired
 * process exit code) on failure. The same table drives usage(): rows are
 * printed in registration order, grouped by `section` headings.
 * -------------------------------------------------------------------------
 */
enum opt_section {
  OPT_SECT_FORMAT = 0, /* mutually-exclusive output formats */
  OPT_SECT_DETAIL,     /* output detail toggles */
  OPT_SECT_COMPONENT,  /* component selection / scheduling */
  OPT_SECT_MISC,       /* version, help */
  OPT_SECT__COUNT,
};

static const char *const opt_section_titles[OPT_SECT__COUNT] = {
    [OPT_SECT_FORMAT] = "Output format (mutually exclusive)",
    [OPT_SECT_DETAIL] = "Output detail",
    [OPT_SECT_COMPONENT] = "Component control",
    [OPT_SECT_MISC] = "Misc",
};

/* Handlers. Each sets one or more globals, optionally consuming `val`. */
static int set_json(const char *val) {
  (void)val;
  json_output = 1;
  oneline_output = 0;
  markdown_output = 0;
  return 0;
}
static int set_oneline(const char *val) {
  (void)val;
  oneline_output = 1;
  json_output = 0;
  markdown_output = 0;
  return 0;
}
static int set_markdown(const char *val) {
  (void)val;
  markdown_output = 1;
  json_output = 0;
  oneline_output = 0;
  return 0;
}
static int set_color(const char *val) {
  (void)val;
  color_output = 1;
  return 0;
}
static int set_quiet(const char *val) {
  (void)val;
  quiet = 1;
  return 0;
}
static int set_verbose(const char *val) {
  (void)val;
  verbose = 1;
  return 0;
}
static int set_explain(const char *val) {
  (void)val;
  explain_mode = 1;
  verbose = 1; /* --explain implies --verbose */
  return 0;
}
static int set_fast(const char *val) {
  (void)val;
  fast_mode = 1;
  return 0;
}
static int set_workers(const char *val) {
  char *end;
  long n = strtol(val, &end, 10);
  if (*end != '\0' || n < 0 || n > 65535) {
    fprintf(stderr, "--workers must be a non-negative integer\n");
    return 2;
  }
  parallel_workers = (int)n;
  return 0;
}
static int set_experimental(const char *val) {
  (void)val;
  experimental_mode = 1;
  return 0;
}
static int set_skip(const char *val) {
  /* Comma-separated globs; multiple --skip flags accumulate. */
  char buf[1024];
  snprintf(buf, sizeof(buf), "%s", val);
  for (char *tok = strtok(buf, ","); tok; tok = strtok(NULL, ",")) {
    if (num_skip_patterns < MAX_SKIP_PATTERNS) {
      strncpy(skip_patterns[num_skip_patterns], tok, 255);
      skip_patterns[num_skip_patterns][255] = '\0';
      num_skip_patterns++;
    }
  }
  return 0;
}
static int set_hardening(const char *val) {
  (void)val;
  hardening_mode = 1;
  return 0;
}
static int set_timeout(const char *val) {
  /* strtol with end-pointer + errno check — atoi accepts trailing garbage
   * silently (atoi("5junk") == 5), which lets a typo land a degraded value. */
  errno = 0;
  char *end;
  long t = strtol(val, &end, 10);
  if (errno || end == val || *end != '\0' || t <= 0 || t > INT_MAX) {
    fprintf(stderr, "--timeout must be a positive integer\n");
    return 2;
  }
  component_timeout = (int)t;
  return 0;
}

/* Sentinel handlers used by main() to detect early-exit flags after the
 * table walk; the actual --version/--help output is printed there so the
 * usage() helper still has access to `argv[0]` for the program name. */
static int wants_version;
static int wants_help;
static int set_want_version(const char *val) {
  (void)val;
  wants_version = 1;
  return 0;
}
static int set_want_help(const char *val) {
  (void)val;
  wants_help = 1;
  return 0;
}

struct opt {
  const char *short_name; /* "-j" or NULL */
  const char *long_name;  /* "--json" */
  int takes_arg;          /* 1 if a value follows */
  const char *arg_name;   /* display name in usage, e.g. "N" */
  enum opt_section section;
  int (*set)(const char *val); /* applies the option; returns exit code or 0 */
  const char *help; /* one-line description (printf-style %d/%s allowed) */
  /* Optional printf argument for `help` — only one slot, to keep the table
   * data-driven without resorting to varargs per row. NULL means no
   * substitution. */
  int help_arg_int;
  int help_has_int_arg;
};

/* The table. New flags: add a row here, nothing else changes. */
static const struct opt opts[] = {
    /* ── Output format (mutually exclusive) ──────────────────────────── */
    {"-j", "--json", 0, NULL, OPT_SECT_FORMAT, set_json,
     "Machine-readable JSON output", 0, 0},
    {"-1", "--oneline", 0, NULL, OPT_SECT_FORMAT, set_oneline,
     "Single-line summary output", 0, 0},
    {"-m", "--markdown", 0, NULL, OPT_SECT_FORMAT, set_markdown,
     "Markdown table output", 0, 0},

    /* ── Output detail ───────────────────────────────────────────────── */
    {"-v", "--verbose", 0, NULL, OPT_SECT_DETAIL, set_verbose,
     "Show component output, KASLR analysis, memory map", 0, 0},
    {"-e", "--explain", 0, NULL, OPT_SECT_DETAIL, set_explain,
     "Show technique explanations before each component (implies --verbose)", 0,
     0},
    {"-q", "--quiet", 0, NULL, OPT_SECT_DETAIL, set_quiet,
     "Suppress banner, progress, and warnings", 0, 0},
    {"-c", "--color", 0, NULL, OPT_SECT_DETAIL, set_color,
     "Colourize text output (auto-detected for TTYs)", 0, 0},
    {"-H", "--hardening", 0, NULL, OPT_SECT_DETAIL, set_hardening,
     "Append a hardening assessment to the report", 0, 0},

    /* ── Component control ───────────────────────────────────────────── */
    {"-x", "--experimental", 0, NULL, OPT_SECT_COMPONENT, set_experimental,
     "Enable experimental components", 0, 0},
    {"-s", "--skip", 1, "PATTERN", OPT_SECT_COMPONENT, set_skip,
     "Skip matching components (glob, comma-separated; flag may repeat)", 0, 0},
    {"-t", "--timeout", 1, "N", OPT_SECT_COMPONENT, set_timeout,
     "Per-component timeout in seconds (default: %d)", DEFAULT_TIMEOUT_SECS, 1},
    {"-f", "--fast", 0, NULL, OPT_SECT_COMPONENT, set_fast,
     "Shortcut for a %ds per-component timeout (--timeout wins if both given)",
     FAST_TIMEOUT_SECS, 1},
    {"-w", "--workers", 1, "N", OPT_SECT_COMPONENT, set_workers,
     "Parallel component workers (default: nproc; 0 = sequential)", 0, 0},

    /* ── Misc ────────────────────────────────────────────────────────── */
    {"-V", "--version", 0, NULL, OPT_SECT_MISC, set_want_version,
     "Print version and exit", 0, 0},
    {"-h", "--help", 0, NULL, OPT_SECT_MISC, set_want_help, "Show this help", 0,
     0},
};
static const int n_opts = (int)(sizeof(opts) / sizeof(opts[0]));

/* Render one section's worth of rows. `col` is the left-column width for
 * the "  -x, --long ARG  " prefix; computed once before the first section
 * so columns align across sections. */
static void usage_print_section(enum opt_section sect, int col) {
  int printed_heading = 0;
  for (int i = 0; i < n_opts; i++) {
    const struct opt *o = &opts[i];
    if (o->section != sect)
      continue;
    if (!printed_heading) {
      printf("%s:\n", opt_section_titles[sect]);
      printed_heading = 1;
    }
    char prefix[64];
    if (o->arg_name)
      snprintf(prefix, sizeof(prefix), "  %s, %s %s", o->short_name,
               o->long_name, o->arg_name);
    else
      snprintf(prefix, sizeof(prefix), "  %s, %s", o->short_name, o->long_name);
    if (o->help_has_int_arg)
      printf("%-*s  " /*help*/, col, prefix), printf(o->help, o->help_arg_int),
          printf("\n");
    else
      printf("%-*s  %s\n", col, prefix, o->help);
  }
  printf("\n");
}

static void usage(const char *progname) {
  /* Compute the longest "  -x, --long ARG" prefix so all sections share
   * one description column. */
  int col = 0;
  for (int i = 0; i < n_opts; i++) {
    int len = (int)strlen("  ") + (int)strlen(opts[i].short_name) +
              (int)strlen(", ") + (int)strlen(opts[i].long_name);
    if (opts[i].arg_name)
      len += 1 + (int)strlen(opts[i].arg_name);
    if (len > col)
      col = len;
  }
  printf("Usage: %s [OPTIONS]\n\n", progname);
  for (int s = 0; s < OPT_SECT__COUNT; s++)
    usage_print_section((enum opt_section)s, col);
}

/* Look up an option by its short or long name. Returns NULL if no match. */
static const struct opt *opt_find(const char *arg) {
  for (int i = 0; i < n_opts; i++) {
    if ((opts[i].short_name && strcmp(arg, opts[i].short_name) == 0) ||
        (opts[i].long_name && strcmp(arg, opts[i].long_name) == 0))
      return &opts[i];
  }
  return NULL;
}

/* Orchestration-layer summary emit: build the summary, run resolution (stats,
 * defaults, then the engine via compute_kaslr_info), and hand the finished
 * summary to the renderer. Resolution lives here, not in render.c — the
 * renderer is a pure consumer. */
static void emit_summary(void) {
  struct summary s = {0};
  compute_component_stats(&s);
  inject_kaslr_defaults(&s);
  compute_kaslr_info(&s); /* engine resolution + sync to layout */
  /* cross-region derivations arrive as ordinary CONF_DERIVED component results;
   * there is no separate derive pass. */
  render_summary(&s);
}

int main(int argc, char *argv[]) {
  /* Default to nproc workers; --workers overrides */
  {
    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    parallel_workers = (ncpu > 1) ? (int)ncpu : 4;
  }

  /* Table-driven option walk. Each match either runs the handler with the
   * option's value (NULL for flags) or — for early-exit options like
   * --version / --help — sets a sentinel checked after the loop. */
  for (int i = 1; i < argc; i++) {
    const struct opt *o = opt_find(argv[i]);
    if (!o) {
      fprintf(stderr, "unknown option: %s\n", argv[i]);
      usage(argv[0]);
      return 2;
    }
    const char *val = NULL;
    if (o->takes_arg) {
      if (i + 1 >= argc) {
        fprintf(stderr, "%s requires a value\n", o->long_name);
        return 2;
      }
      val = argv[++i];
    }
    int rc = o->set(val);
    if (rc != 0)
      return rc;
  }

  if (wants_version) {
    printf("kasld %s\n", VERSION);
    return 0;
  }
  if (wants_help) {
    usage(argv[0]);
    return 0;
  }

  /* Conflict check: at most one of the OPT_SECT_FORMAT flags may be
   * effective. Each format setter already clears its siblings, so this is
   * a courtesy diagnostic — surfacing "you asked for two formats" before
   * silently going with whichever came last. */
  if (json_output + oneline_output + markdown_output > 1) {
    /* Unreachable today because setters clear siblings, but kept as a
     * forward-compatible guard: if format flags ever become additive
     * (or get other modifiers stacked on), the check fires here. */
    fprintf(stderr, "conflicting output format flags: pick one of "
                    "--json / --oneline / --markdown\n");
    return 2;
  }

  /* Ensure line-buffered stdout so output appears in real-time */
  setvbuf(stdout, NULL, _IOLBF, 0);

  /* Auto-detect color when stdout is a TTY and no structured format selected */
  if (!color_output && plain_output())
    color_output = isatty(STDOUT_FILENO);

  /* Banner + system-config block live behind --verbose (or --hardening,
   * which consumes the sysctl/lockdown state in its own report). The
   * default text mode renders a tight readout instead. */
  if (verbose && !quiet && plain_output()) {
    print_banner();
    print_system_config();
  } else {
    /* Always read system state — the readout's "KASLR disabled" branch and
     * the hardening report both depend on these values. */
    sysctl_kptr_restrict = read_sysctl_int("/proc/sys/kernel/kptr_restrict");
    sysctl_dmesg_restrict = read_sysctl_int("/proc/sys/kernel/dmesg_restrict");
    sysctl_perf_event_paranoid =
        read_sysctl_int("/proc/sys/kernel/perf_event_paranoid");
    sysctl_lockdown = read_lockdown();
    hashed_pointers = read_pointer_hashing();
  }

  if (discover_components() < 0)
    return 2;

  classify_components();
  validate_component_phases();
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
    /* Tool + target header — printed BEFORE "Running..." so the user
     * knows what's running and against what host before the progress
     * bar starts (header → work → results). The readout that follows
     * the progress bar omits this block; see render_readout(). */
    printf("%sKASLD %s%s  --  Kernel ASLR derandomisation\n", c(C_BOLD),
           VERSION, c(C_RESET));
    struct utsname u;
    if (kasld_uname(&u) == 0)
      printf("%sTarget: %s / %s%s\n", c(C_DIM), u.machine, u.release,
             c(C_RESET));
    printf("\n");

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

  /* Seed the engine-bounds carrier with the honest compile-time window.
   * engine_sync_authoritative() (run from compute_kaslr_info) overwrites the
   * resolved quantities; the vmalloc/vmemmap *_max sentinels (ULONG_MAX = "no
   * upper bound known") must start set because the engine writes those edges
   * only when actually constrained. */
  layout.virt_page_offset_min = layout.virt_kernel_vas_start;
  layout.virt_page_offset_max = layout.virt_kernel_vas_end;
  layout.virt_vmalloc_base_min = 0;
  layout.virt_vmalloc_base_max = ULONG_MAX;
  layout.virt_vmemmap_base_min = 0;
  layout.virt_vmemmap_base_max = ULONG_MAX;

  for (int p = 0; p < (int)(sizeof(phases) / sizeof(phases[0])); p++)
    run_phase(&phases[p]); /* merges results after each phase */

  if (!quiet && !verbose && plain_output())
    printf("\n\n");

  if (num_results > 0) {
    emit_summary();
    return 0;
  }

  if (json_output || oneline_output || markdown_output) {
    emit_summary(); /* valid empty structured output */
  } else {
    printf("\n---\n\nno tagged results to process\n");
  }
  return 1;
}
#endif /* !KASLD_TESTING */
