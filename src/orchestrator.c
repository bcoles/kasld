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
#include "include/kasld/outcome.h"
#include "include/kasld/randomize_memory.h"
#include "include/kasld/render_internal.h"
#include "include/kasld/target_width.h"

#include <dirent.h>
#include <errno.h>
#include <fnmatch.h>
#include <langinfo.h>
#include <limits.h>
#include <locale.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
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
int unicode_output = 1; /* Unicode glyphs on by default; main() lowers it for a
                         * non-UTF-8 locale, --ascii forces it off. */
int explain_mode;
static int fast_mode;
int hardening_mode;
/* --map: draw the address-space diagram without the per-component narration
 * --verbose also turns on. Implied by --verbose, which keeps showing it. */
int map_mode;
static int experimental_mode;

#define MAX_SKIP_PATTERNS 64
static char skip_patterns[MAX_SKIP_PATTERNS][256];
static int num_skip_patterns;

/* The observing environment. Unknown until kasld_env_snapshot() takes it, so a
 * consumer that runs before the snapshot — or in a harness that never takes one
 * — sees "not observed" and not "not hardened". */
struct kasld_environment kasld_env = KASLD_ENV_UNKNOWN;

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
    .virt_image_base_min = KERNEL_VIRT_TEXT_MIN,
    .virt_image_base_max = KERNEL_VIRT_TEXT_MAX,
    .modules_start = MODULES_START,
    .modules_end = MODULES_END,
    .image_align = IMAGE_ALIGN,
    .virt_image_base_default = KERNEL_VIRT_TEXT_DEFAULT,
    .virt_kaslr_text_min = KASLR_VIRT_TEXT_MIN,
    .virt_kaslr_text_max = KASLR_VIRT_TEXT_MAX,
    .virt_kaslr_align = KASLR_VIRT_ALIGN,
    .phys_kaslr_text_min = _PHYS_KASLR_TEXT_MIN,
    .phys_kaslr_text_max = _PHYS_KASLR_TEXT_MAX,
    .phys_kaslr_align = _PHYS_KASLR_ALIGN,
};

/* Constants used only by the orchestrator */
#define KASLD_PATH_MAX 4096
#define DEFAULT_TIMEOUT_SECS 30
#define FAST_TIMEOUT_SECS 2
static int component_timeout = DEFAULT_TIMEOUT_SECS;

/* Parallel inference: 0 = sequential (default), N > 1 = N worker threads */
/* Ceiling on the inference worker pool. Bounds the per-phase pthread_t array
 * independently of MAX_COMPONENTS: the pool is sized from the online CPU count
 * (or --workers), never from how many components exist, so the two caps have no
 * reason to track each other. --workers above this clamps. */
#define KASLD_MAX_WORKERS 256

static int parallel_workers = 0;

/* Number of components that will actually run (excludes skipped experimental)
 */
static int num_active_components;

/* Protects results[], num_results, progress_done,
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

/* -------------------------------------------------------------------------
 * Progress display
 *
 * The bar repaints in place with a carriage return and leaves the cursor on
 * its line, so anything else written to stderr while it is painted would be
 * appended to that line. `output_mutex` makes the bar the sole owner of that
 * line: every other diagnostic goes through progress_note(), which erases the
 * bar, writes the message, and repaints. progress_finish() retires the bar by
 * erasing it from the stream it was painted on.
 *
 * Deliberately separate from result_mutex, which protects data structures and
 * is never held across I/O. Lock order is result_mutex -> output_mutex;
 * nothing acquires them in the other order.
 * -------------------------------------------------------------------------
 */
#ifdef HAVE_PTHREAD
static pthread_mutex_t output_mutex = PTHREAD_MUTEX_INITIALIZER;
#define OUTPUT_LOCK() pthread_mutex_lock(&output_mutex)
#define OUTPUT_UNLOCK() pthread_mutex_unlock(&output_mutex)
#else
#define OUTPUT_LOCK() ((void)0)
#define OUTPUT_UNLOCK() ((void)0)
#endif

static int progress_done; /* components finished */
static struct timespec progress_start;
static int progress_painted;  /* highest `done` a frame was drawn for */
static int progress_width;    /* visible columns of the drawn frame */
static int progress_live;     /* a frame is currently on screen */
static int progress_total;    /* components the bar is counting up to */
static int progress_inflight; /* claimed but not yet reaped */

/* How long a worker waits on its child before repainting. The bar is redrawn
 * only when a component finishes, so during a stall its elapsed field freezes
 * -- a stopped clock, which reads as "nothing is happening" rather than
 * "something is stuck". Ticking from the wait keeps it moving. */
#define PROGRESS_TICK_MS 250

/* Erase the drawn frame, leaving the cursor at column 0 of a blank line.
 * Overwrites with spaces rather than an erase escape so the result is the same
 * on a terminal that does not interpret them. Caller holds output_mutex. */
static void progress_erase(void) {
  if (!progress_live)
    return;
  fputc('\r', stderr);
  for (int i = 0; i < progress_width; i++)
    fputc(' ', stderr);
  fputc('\r', stderr);
  progress_live = 0;
  progress_width = 0;
}

/* Draw the frame for `done` of `total`. The three segments are built
 * separately so the visible width is known exactly: colour escapes carry no
 * width, and progress_erase() must overwrite the visible columns only. Caller
 * holds output_mutex. */
/* `inflight` is snapshotted by the caller: progress_paint runs under
 * output_mutex, and taking result_mutex here would invert the one-way
 * result_mutex -> output_mutex order the rest of this file relies on. */
static void progress_paint(int done, int total, int inflight) {
  int pct = total > 0 ? (done * 100) / total : 0;
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  double elapsed = (double)(now.tv_sec - progress_start.tv_sec) +
                   (double)(now.tv_nsec - progress_start.tv_nsec) / 1e9;

  const int bar_width = 20;
  int filled = (pct * bar_width) / 100;
  char bar[32];
  for (int i = 0; i < bar_width; i++)
    bar[i] = i < filled ? '#' : '.';
  bar[bar_width] = '\0';

  /* Counter padded to the width of `total` so the elapsed-time column holds
   * still as the count grows into more digits. */
  int tw = 1;
  for (int t = total; t >= 10; t /= 10)
    tw++;

  /* In-flight count, and how long since anything finished. Together they say
   * what a bare percentage cannot: whether the pool is working through a queue
   * or has drained to one stuck component. The stall figure only appears once
   * it exceeds the tick threshold, so a healthy run reads as before. */
  char seg_bar[40], seg_mid[80], seg_time[40];
  int w = 0;
  w += snprintf(seg_bar, sizeof(seg_bar), "[%s]", bar);
  if (inflight > 0)
    w += snprintf(seg_mid, sizeof(seg_mid), " %3d%%  %*d/%d  %d running  ", pct,
                  tw, done, total, inflight);
  else
    w += snprintf(seg_mid, sizeof(seg_mid), " %3d%%  %*d/%d  ", pct, tw, done,
                  total);
  w += snprintf(seg_time, sizeof(seg_time), "%.1fs", elapsed);

  int prev = progress_width;
  fprintf(stderr, "\r%s%s%s%s%s%s%s", c(C_DIM), seg_bar, c(C_RESET), seg_mid,
          c(C_DIM), seg_time, c(C_RESET));
  /* A frame narrower than the one it replaces leaves the old frame's tail on
   * screen: \r rewinds but does not clear, and the next erase only blanks the
   * new (shorter) width. Blank the difference here so the recorded width is
   * always the full extent of what is visible. Frames vary in width because
   * the in-flight and stall figures appear and disappear. */
  for (int i = w; i < prev; i++)
    fputc(' ', stderr);
  progress_width = w;
  progress_live = 1;
}

/* Emit a diagnostic on its own line without corrupting the bar. Safe from any
 * thread, and a plain stderr write when no bar is drawn. */
static void progress_note(const char *fmt, ...) {
  va_list ap;
  RESULT_LOCK();
  int inflight = progress_inflight;
  RESULT_UNLOCK();
  OUTPUT_LOCK();
  int repaint = progress_live;
  int done = progress_painted;
  progress_erase();
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
  fputc('\n', stderr);
  if (repaint)
    progress_paint(done, progress_total, inflight);
  fflush(stderr);
  OUTPUT_UNLOCK();
}

/* Repaint the current frame without advancing the count. Called from a worker
 * waiting on its child, so the elapsed and stall figures keep moving while no
 * component completes. Snapshots the counters under result_mutex and releases
 * it before taking output_mutex, preserving the one-way lock order. */
static void progress_tick(void) {
  if (quiet || json_output || oneline_output || markdown_output || verbose)
    return;
  if (!isatty(STDERR_FILENO))
    return;
  RESULT_LOCK();
  int done = progress_painted;
  int inflight = progress_inflight;
  RESULT_UNLOCK();
  OUTPUT_LOCK();
  if (progress_live) {
    progress_paint(done, progress_total, inflight);
    fflush(stderr);
  }
  OUTPUT_UNLOCK();
}

/* Retire the bar, erasing it from the stream it was painted on. */
static void progress_finish(void) {
  OUTPUT_LOCK();
  progress_erase();
  fflush(stderr);
  OUTPUT_UNLOCK();
}

/* Inference worker pool: index list built once, consumed by workers */
static int pool_inf[MAX_COMPONENTS]; /* indices into components[] */
static int pool_inf_n;               /* count of inference components */
static int pool_next;                /* next index in pool_inf[] to claim */

/* -------------------------------------------------------------------------
 * Component execution log (for --verbose --json)
 * -------------------------------------------------------------------------
 */
struct component_log comp_logs[MAX_COMPONENTS];

/* -------------------------------------------------------------------------
 * The discard ledger's storage. Every path that drops evidence records here,
 * whichever layer it belongs to: the orchestrator's fixed-size buffers write
 * directly, and the engine's caps and rulings are projected in after the run by
 * discard_project_engine() so the engine stays pure.
 *
 * None of the orchestrator caps bind on realistic workloads; they are recorded
 * so growth is detected rather than absorbed.
 * -------------------------------------------------------------------------
 */
static struct kasld_discard discard_ledger[MAX_DISCARDS];
static int n_discards;
static int discards_truncated;
static unsigned int discards_total;

/* Store names used as the `source` of a DISCARD_CAPACITY entry. Spelled once
 * here because report_discards() matches on them to choose which cap's prose to
 * print: a typo would silently degrade a specific diagnostic into the generic
 * line, which is the failure this ledger exists to stop. */
#define DSRC_RESULTS "results"
#define DSRC_SCALARS "scalar-facts"
#define DSRC_COMPONENTS "components"
#define DSRC_COMPONENT_LINES "component-log"
#define DSRC_CONSTRAINTS "constraints"
#define DSRC_CONSTRAINT_FACTS "constraint-facts"
#define DSRC_VERDICTS "verdicts"
#define DSRC_RULE_EMIT "rule-emit"
#define DSRC_VRULE_EMIT "verdict-rule-emit"
#define DSRC_ESTIMATE_WORK "estimate-work"
#define DSRC_CONFLICT_STORE "conflict-store"
#define DSRC_CURATION_ROUNDS "curation-rounds"

/* Defined after the lock below so it can take it: reset is a mutator like any
 * other, and a public one, so it does not rely on its callers happening to be
 * single-threaded. */

/* The ledger is written from the component worker threads (a rejected wire
 * line, an out-of-VAS address) as well as from single-threaded phases, so it
 * carries its own mutex.
 *
 * A LEAF: nothing here takes another lock or does I/O, so the only ordering in
 * play is result_mutex -> discard_mutex, taken by append_result() recording a
 * full results table. Nothing acquires result_mutex while holding this one, so
 * that edge cannot close into a cycle — the same one-way discipline the
 * result_mutex -> output_mutex pair already follows. */
#ifdef HAVE_PTHREAD
static pthread_mutex_t discard_mutex = PTHREAD_MUTEX_INITIALIZER;
#define DISCARD_LOCK() pthread_mutex_lock(&discard_mutex)
#define DISCARD_UNLOCK() pthread_mutex_unlock(&discard_mutex)
#else
#define DISCARD_LOCK() ((void)0)
#define DISCARD_UNLOCK() ((void)0)
#endif

void kasld_discard_reset(void) {
  DISCARD_LOCK();
  n_discards = 0;
  discards_truncated = 0;
  discards_total = 0;
  memset(discard_ledger, 0, sizeof(discard_ledger));
  DISCARD_UNLOCK();
}

void kasld_discard_record(enum kasld_discard_reason reason,
                          const char *source) {
  const char *src = (source && *source) ? source : "";
  if (reason < 0 || reason >= DISCARD__COUNT)
    return;
  DISCARD_LOCK();
  /* Counted before the aggregation cap, so the total stays truthful even once
   * the ledger stops taking new (reason, source) pairs. */
  discards_total++;
  for (int i = 0; i < n_discards; i++) {
    if (discard_ledger[i].reason == reason &&
        strncmp(discard_ledger[i].source, src, ORIGIN_LEN) == 0) {
      if (discard_ledger[i].count != UINT_MAX)
        discard_ledger[i].count++;
      DISCARD_UNLOCK();
      return;
    }
  }
  if (n_discards >= MAX_DISCARDS) {
    discards_truncated = 1;
    DISCARD_UNLOCK();
    return;
  }
  discard_ledger[n_discards].reason = reason;
  snprintf(discard_ledger[n_discards].source, ORIGIN_LEN, "%s", src);
  discard_ledger[n_discards].count = 1;
  n_discards++;
  DISCARD_UNLOCK();
}

int kasld_discard_count(void) { return n_discards; }

const struct kasld_discard *kasld_discard_at(int i) {
  if (i < 0 || i >= n_discards)
    return NULL;
  return &discard_ledger[i];
}

int kasld_discard_truncated(void) { return discards_truncated; }

unsigned int kasld_discard_total(void) { return discards_total; }

/* Wire names for the reason enum. Closed set; a new reason must be added here,
 * and the compiler's -Wswitch flags the omission. */
const char *kasld_discard_reason_name(enum kasld_discard_reason r) {
  switch (r) {
  case DISCARD_PARSE:
    return "parse";
  case DISCARD_BOUNDS:
    return "bounds";
  case DISCARD_CURATED:
    return "curated";
  case DISCARD_CONFLICT:
    return "conflict";
  case DISCARD_CAPACITY:
    return "capacity";
  case DISCARD__COUNT:
    break;
  }
  return "unknown";
}

/* =========================================================================
 * Component discovery
 * =========================================================================
 */
struct component {
  char name[256];
  char phase[32];      /* scheduling phase: "inference" or "probing".
                        * Set from "phase:" in .kasld_meta; falls back to
                        * method-based inference when "phase:" is absent. */
  int is_experimental; /* set from status:experimental in .kasld_meta */
  int is_live;         /* set from live:1 in .kasld_meta — result comes from
                        * live runtime state of the executing kernel/CPU, so it
                        * cannot be reproduced from a captured tree. */
  int is_filtered;     /* set by apply_skip_filter() from --skip patterns, or by
                        * apply_sysroot_filter() for live probes under
                        * KASLD_SYSROOT */
};

/* Every component lives in the one directory discovery settled on, so a full
 * path is that directory plus the name — held once here rather than repeated
 * per component. Set by discover_components() before any component runs. */
static char component_dir[KASLD_PATH_MAX];

static struct component components[MAX_COMPONENTS];
int num_components;

/* Compose a component's executable path. Returns buf, or NULL if the composed
 * path would not fit (the caller then skips the component rather than acting on
 * a truncated path). */
static const char *component_path(const struct component *c, char *buf,
                                  size_t bufsz) {
  int n = snprintf(buf, bufsz, "%s/%s", component_dir, c->name);
  if (n < 0 || (size_t)n >= bufsz)
    return NULL;
  return buf;
}

const char *kasld_origin_name(int idx) {
  if (idx == ORIGIN_ARCH_SYNTH)
    return "arch-no-kaslr";
  if (idx < 0 || idx >= num_components)
    return "";
  return components[idx].name;
}

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

  snprintf(component_dir, sizeof(component_dir), "%s", comp_dir);

  /* Scan directory for executables */
  struct dirent *ent;
  int truncated = 0;
  while ((ent = readdir(d)) != NULL) {
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

    struct component *c;
    if (num_components < MAX_COMPONENTS) {
      c = &components[num_components++];
    } else {
      /* Full: keep the alphabetically-first MAX_COMPONENTS entries by evicting
       * the current maximum when this name sorts below it. Which components a
       * too-large directory drops is then a property of the directory, not of
       * readdir order — the same set on every filesystem and every run. */
      truncated = 1;
      int max_i = 0;
      for (int i = 1; i < num_components; i++)
        if (strcmp(components[i].name, components[max_i].name) > 0)
          max_i = i;
      if (strcmp(ent->d_name, components[max_i].name) >= 0)
        continue;
      c = &components[max_i];
      memset(c, 0, sizeof(*c));
    }
    snprintf(c->name, sizeof(c->name), "%s", ent->d_name);
  }
  closedir(d);

  /* Truncation means the run gathered a subset of the available evidence, so
   * its residual-entropy figure overstates what KASLR retains. Report it on
   * both channels — the ledger entry reaches --verbose and the JSON `discarded`
   * block, and the warning below is printed even under --quiet, which
   * suppresses progress noise rather than a caveat on the answer. */
  if (truncated) {
    kasld_discard_record(DISCARD_CAPACITY, DSRC_COMPONENTS);
    fprintf(stderr,
            "warning: component limit (%d) reached in %s; ran the first %d by "
            "name and skipped the rest\n",
            MAX_COMPONENTS, comp_dir, MAX_COMPONENTS);
  }

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
 * Component execution
 * =========================================================================
 */

/* Result storage — defined in kasld/internal.h */

struct result results[MAX_RESULTS];
int num_results;

/* scalar_fact_record + scalar_facts[]/num_scalar_facts declared in
 * include/kasld/internal.h; the engine bridge copies these to OBS_SCALAR
 * observations and summarize_kaslr_state / render also read them directly. */
struct scalar_fact_record scalar_facts[MAX_SCALAR_FACTS];
int num_scalar_facts;

/* constraint_fact_record + constraint_facts[]/num_constraint_facts declared in
 * include/kasld/internal.h; the engine bridge copies these to OBS_CONSTRAINT
 * observations, which a passthrough rule folds into the meet. */
struct constraint_fact_record constraint_facts[MAX_CONSTRAINT_FACTS];
int num_constraint_facts;

/* Look up region enum by wire name. Linear scan over region_info[] — a table
 * of a few dozen, negligible cost. Returns REGION_UNKNOWN on miss. */
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
  if (strcmp(s, "extent") == 0)
    return POS_EXTENT;
  if (strcmp(s, "unknown") == 0)
    return POS_UNKNOWN;
  /* Unrecognized input also returns POS_UNKNOWN. The caller disambiguates
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

/* Map a method: meta value to its bit in struct result.method_set (0 if the
 * value is empty or unrecognized). Mirrors the closed set in enum kasld_method.
 */
static uint16_t method_bit(const char *s) {
  int m = -1;
  if (!s || !*s)
    return 0;
  if (strcmp(s, "parsed") == 0)
    m = KM_PARSED;
  else if (strcmp(s, "derived") == 0)
    m = KM_DERIVED;
  else if (strcmp(s, "inferred") == 0)
    m = KM_INFERRED;
  else if (strcmp(s, "heuristic") == 0)
    m = KM_HEURISTIC;
  else if (strcmp(s, "timing") == 0)
    m = KM_TIMING;
  else if (strcmp(s, "brute") == 0)
    m = KM_BRUTE;
  else if (strcmp(s, "detection") == 0)
    m = KM_DETECTION;
  return m < 0 ? 0u : (uint16_t)(1u << m);
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

/* Collected key/value fields from a tagged line's tail (pos= conf= lo= hi=
 * sz= sample= base_align=), after sz→hi normalization. Filled by
 * parse_result_tail(); consumed by the VAS check and the slot append. */
struct parsed_tail {
  int seen_pos, seen_conf, seen_lo, seen_hi, seen_sz, seen_sample;
  int seen_base_align;
  enum kasld_position pos;
  enum kasld_confidence conf;
  unsigned long lo, hi, sz, sample, base_align;
};

/* Split a "region[:name]" wire token into a resolved region + name_buf (sized
 * NAME_LEN). The split is on the FIRST `:` only — names may contain subsequent
 * colons (e.g. PCI BDF "0000:00:14.0"); region wire names are short
 * identifiers without ':' (the longest, "virt_page_offset" and
 * "efi_loader_image", are 16). Returns REGION_UNKNOWN on a malformed,
 * over-length, or unrecognized token. */
static enum kasld_region parse_region_field(const char *region_field,
                                            char *name_buf) {
  char region_str[32];
  name_buf[0] = '\0';
  const char *colon = strchr(region_field, ':');
  if (colon) {
    size_t rlen = (size_t)(colon - region_field);
    if (rlen >= sizeof(region_str)) /* over-length region = malformed line */
      return REGION_UNKNOWN;
    memcpy(region_str, region_field, rlen);
    region_str[rlen] = '\0';

    const char *name_src = colon + 1;
    size_t nlen = strlen(name_src);
    if (nlen >
        NAME_LEN - 1) /* over-length name rejects (no silent truncation) */
      return REGION_UNKNOWN;
    memcpy(name_buf, name_src, nlen);
    name_buf[nlen] = '\0';
  } else {
    size_t rlen = strlen(region_field);
    if (rlen >= sizeof(region_str))
      return REGION_UNKNOWN;
    memcpy(region_str, region_field, rlen);
    region_str[rlen] = '\0';
  }
  return region_from_wire(region_str);
}

/* Tokenise the key=value tail (everything after "<type> <region>[:<name>] ")
 * into *p, then apply sz→hi normalization plus cross-key and
 * pos-requires-field validation. Returns 1 if the tail is well-formed and
 * self-consistent, 0 to reject the line. */
static int parse_result_tail(const char *tail_start, struct parsed_tail *p) {
  memset(p, 0, sizeof(*p));
  p->pos = POS_UNKNOWN;
  p->conf = CONF_UNKNOWN;

  char tail[MAX_LINE_LEN];
  size_t tl = strlen(tail_start);
  if (tl >= sizeof(tail))
    return 0;
  memcpy(tail, tail_start, tl + 1);
  /* Strip trailing newline. */
  if (tl > 0 && tail[tl - 1] == '\n')
    tail[tl - 1] = '\0';

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
      if (p->seen_pos)
        return 0;
      p->seen_pos = 1;
      p->pos = pos_from_wire(val);
      /* pos_from_wire returns POS_UNKNOWN for both unknown literal and
       * unrecognized — distinguish: only "unknown" string is valid here. */
      if (p->pos == POS_UNKNOWN && strcmp(val, "unknown") != 0)
        return 0;
    } else if (strcmp(key, "conf") == 0) {
      if (p->seen_conf)
        return 0;
      p->seen_conf = 1;
      p->conf = conf_from_wire(val);
      if (p->conf == CONF_UNKNOWN)
        return 0;
    } else if (strcmp(key, "lo") == 0) {
      if (p->seen_lo || !parse_hex(val, &p->lo))
        return 0;
      p->seen_lo = 1;
    } else if (strcmp(key, "hi") == 0) {
      if (p->seen_hi || p->seen_sz || !parse_hex(val, &p->hi))
        return 0;
      p->seen_hi = 1;
    } else if (strcmp(key, "sz") == 0) {
      if (p->seen_sz || p->seen_hi || !parse_hex(val, &p->sz))
        return 0;
      p->seen_sz = 1;
    } else if (strcmp(key, "sample") == 0) {
      if (p->seen_sample || !parse_hex(val, &p->sample))
        return 0;
      p->seen_sample = 1;
    } else if (strcmp(key, "base_align") == 0) {
      if (p->seen_base_align || !parse_hex(val, &p->base_align))
        return 0;
      if (!is_pow2(p->base_align))
        return 0;
      p->seen_base_align = 1;
    } else {
      /* Unknown key rejects the line (spec: no forward-compat silence). */
      return 0;
    }
  }

  /* Mandatory fields. */
  if (!p->seen_pos || !p->seen_conf)
    return 0;

  /* sz → hi normalization. */
  if (p->seen_sz) {
    /* sz requires lo — check before doing arithmetic on p->lo. */
    if (!p->seen_lo)
      return 0;
    /* hi = lo + sz - 1, rejecting an empty or wrapping extent in one step. */
    if (p->sz == 0 || kasld_add_ovf(p->lo, p->sz - 1, &p->hi))
      return 0;
    p->seen_hi = 1;
  }

  /* Cross-key constraints. */
  if (p->seen_lo && p->seen_hi && p->lo > p->hi)
    return 0;
  if (p->seen_sample) {
    if (p->seen_lo && p->sample < p->lo)
      return 0;
    if (p->seen_hi && p->sample > p->hi)
      return 0;
  }

  /* pos-requires-field. */
  switch (p->pos) {
  case POS_BASE:
    if (!p->seen_lo)
      return 0;
    break;
  case POS_TOP:
    if (!p->seen_hi)
      return 0;
    break;
  case POS_INTERIOR:
    if (!p->seen_sample)
      return 0;
    break;
  case POS_EXTENT:
    /* A covering member is a closed extent — both edges required. The value
     * lives in the gaps between extents, so a half-open extent is meaningless
     * to the map rules that consume it. */
    if (!p->seen_lo || !p->seen_hi)
      return 0;
    break;
  case POS_UNKNOWN:
    if (!p->seen_lo && !p->seen_hi && !p->seen_sample)
      return 0;
    break;
  }
  return 1;
}

/* Parse-time VAS validation against region_info[region].static_vas. Returns 1
 * if in-bounds (or the region is runtime-derived / has no static window), 0 to
 * reject. Layout-derived regions (derive_vas != NULL) are validated at runtime
 * via result_in_bounds instead. A rejection is surfaced under --verbose so a
 * developer porting a component to a new arch sees the drop (naming the
 * offending field) rather than a silent "ran but produced nothing". */
static int result_vas_ok(enum kasld_region region, const struct parsed_tail *p,
                         enum kasld_addr_type type, const char *name_buf,
                         int origin) {
  const struct region_info *ri = &region_info[region];
  if (ri->derive_vas != NULL ||
      (ri->static_vas.lo == 0 && ri->static_vas.hi == 0))
    return 1;

  unsigned long vlo = ri->static_vas.lo;
  unsigned long vhi = ri->static_vas.hi;
  const char *vas_field = NULL;
  unsigned long vas_val = 0;
  if (p->seen_lo && (p->lo < vlo || p->lo > vhi)) {
    vas_field = "lo";
    vas_val = p->lo;
  } else if (p->seen_hi && (p->hi < vlo || p->hi > vhi)) {
    vas_field = "hi";
    vas_val = p->hi;
  } else if (p->seen_sample && (p->sample < vlo || p->sample > vhi)) {
    vas_field = "sample";
    vas_val = p->sample;
  }
  if (!vas_field)
    return 1;

  if (verbose && !quiet)
    fprintf(stderr,
            "[parser] dropped %c %s%s%s: %s=%#lx out of VAS [%#lx, %#lx]"
            " (origin=%s)\n",
            kasld_type_wire(type), kasld_region_wire(region),
            name_buf[0] ? ":" : "", name_buf[0] ? name_buf : "", vas_field,
            vas_val, vlo, vhi,
            kasld_origin_name(origin)[0] ? kasld_origin_name(origin) : "?");
  kasld_discard_record(DISCARD_BOUNDS, kasld_origin_name(origin));
  return 0;
}

/* Claim a results[] slot and populate it from the validated line. Returns 1 on
 * success, 0 if the result table is full (warning emitted once). */
static int append_result(enum kasld_addr_type type, enum kasld_region region,
                         const char *name_buf, const struct parsed_tail *p,
                         const char *method, int origin) {
  RESULT_LOCK();
  if (num_results >= MAX_RESULTS) {
    kasld_discard_record(DISCARD_CAPACITY, DSRC_RESULTS);
    static int warned;
    int first = !warned;
    warned = 1;
    RESULT_UNLOCK();
    /* Reported outside the lock: progress_note() takes output_mutex, and the
     * one-way result_mutex -> output_mutex order is what keeps the two from
     * ever forming a cycle. */
    if (first && !quiet)
      progress_note("[-] result limit (%d) reached, dropping further results",
                    MAX_RESULTS);
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
  r->pos = p->pos;
  r->conf = p->conf;
  if (p->seen_lo) {
    r->lo = p->lo;
    r->set_mask |= LO_SET;
  }
  if (p->seen_hi) {
    r->hi = p->hi;
    r->set_mask |= HI_SET;
  }
  if (p->seen_sample) {
    r->sample = p->sample;
    r->set_mask |= SAMPLE_SET;
  }
  if (p->seen_base_align) {
    r->base_align = p->base_align;
    r->set_mask |= BASE_ALIGN_SET;
  }
  /* Provenance: this is the first contributor. */
  origin_set_add(&r->origins, origin);
  r->method_set = method_bit(method);
  return 1;
}

/* Parse a new-format tagged line into a struct result and append it.
 *
 * Wire format:
 *   <type> <region>[:<name>] pos=<pos> conf=<conf> \
 *       [lo=<hex>] [hi=<hex>|sz=<hex>] [sample=<hex>] [base_align=<hex>]
 *
 * Pipeline: sscanf the positional prefix, then parse_region_field (region +
 * name), parse_result_tail (key/value tail + normalization + validation),
 * result_vas_ok (static-VAS bounds), append_result (slot claim + populate).
 *
 * Returns 1 on accept (record appended to results[]), 0 on reject.
 */
static int capture_result(const char *line, const char *method, int origin) {
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
  /* sscanf width must be strictly less than the buffer size — sscanf writes an
   * implicit terminator. The width is a literal (scanf cannot take a computed
   * one), so a _Static_assert locks it to the buffer: if NAME_LEN ever shrinks
   * enough to make REGION_FIELD_CAP <= 80, the build fails here rather than
   * silently overflowing region_field on component-controlled input. */
  /* __extension__ silences -Wpedantic: _Static_assert is a C11 keyword gcc
   * accepts as an extension on the -std=c99 build path. */
  __extension__ _Static_assert(REGION_FIELD_CAP > 79,
                               "sscanf width 79 must stay < REGION_FIELD_CAP");
  if (sscanf(line, "%c %79s %n", &type_ch, region_field, &prefix_consumed) <
          2 ||
      prefix_consumed == 0)
    return 0;
#undef REGION_FIELD_CAP

  enum kasld_addr_type type = type_from_wire(type_ch);
  if (type == KASLD_TYPE_UNKNOWN)
    goto reject;

  char name_buf[NAME_LEN];
  enum kasld_region region = parse_region_field(region_field, name_buf);
  if (region == REGION_UNKNOWN)
    goto reject;

  struct parsed_tail p;
  if (!parse_result_tail(line + prefix_consumed, &p))
    goto reject;

  /* The two below reject for reasons of their own and record them, so they do
   * not fall through to the parse label. */
  if (!result_vas_ok(region, &p, type, name_buf, origin))
    return 0;

  return append_result(type, region, name_buf, &p, method, origin);

  /* Past the prefix filter the line CLAIMED to be a record, so a rejection here
   * is a component reporting something this build does not accept, and the
   * record it carried never reaches the engine. Recorded at the point of
   * decision rather than inferred by the caller: inference would have to ask
   * whether anything else recorded meanwhile, which is not a question with a
   * stable answer while worker threads share the ledger. */
reject:
  kasld_discard_record(DISCARD_PARSE, kasld_origin_name(origin));
  return 0;
}

/* Parse one `S <fact> conf=<c> value=0x<hex>` scalar-fact wire record into
 * scalar_facts[]. Returns 1 on capture, 0 on reject (unknown fact, bad conf or
 * value). Sibling of capture_result(); same validate-or-reject discipline. */
static int capture_scalar(const char *line, int origin) {
  /* Not an `S` record at all — prose off the shared pipe. Not a rejection, and
   * deliberately ahead of the reject label below. */
  if (line[0] != 'S' || line[1] != ' ')
    return 0;
  char name[32], conf_str[16], val_str[40];
  if (sscanf(line, "S %31s conf=%15s value=%39s", name, conf_str, val_str) != 3)
    goto reject;
  enum kasld_scalar_fact f = kasld_scalar_fact_from_wire(name);
  if (f == SF_NONE)
    goto reject;
  enum kasld_confidence c = conf_from_wire(conf_str);
  if (c == CONF_UNKNOWN)
    goto reject;
  unsigned long v;
  if (!parse_hex(val_str, &v))
    goto reject;
  /* Cap check + slot reservation under the same lock as capture_result —
   * the inference worker pool can call this from any thread, so a naked
   * num_scalar_facts++ is racy. Once the slot is reserved, this thread is
   * the only writer of that slot, so the field assignments below run
   * outside the lock. */
  RESULT_LOCK();
  if (num_scalar_facts >= MAX_SCALAR_FACTS) {
    kasld_discard_record(DISCARD_CAPACITY, DSRC_SCALARS);
    RESULT_UNLOCK();
    return 0;
  }
  int idx = num_scalar_facts++;
  RESULT_UNLOCK();
  struct scalar_fact_record *s = &scalar_facts[idx];
  s->fact = f;
  s->value = v;
  s->conf = c;
  s->origin = origin;
  return 1;

  /* Same discipline as capture_result, and in the same place: past the prefix
   * filter the component meant to report a fact, and this build did not accept
   * it. The full-table path above records its own reason and returns without
   * reaching here. */
reject:
  kasld_discard_record(DISCARD_PARSE, kasld_origin_name(origin));
  return 0;
}

/* Parse one `C <quantity> <op> conf=<c> value=0x<hex>` record into
 * constraint_facts[]. Returns 1 on capture, 0 on reject (unknown quantity,
 * unsupported/unknown op, bad conf or value, full table). Mirrors
 * capture_scalar; the channel carries inequality bounds only (>=, <=). */
static int capture_constraint(const char *line, int origin) {
  if (line[0] != 'C' || line[1] != ' ')
    return 0;
  char qname[32], opname[16], conf_str[16], val_str[40];
  if (sscanf(line, "C %31s %15s conf=%15s value=%39s", qname, opname, conf_str,
             val_str) != 4)
    goto reject;
  enum kasld_quantity q = kasld_quantity_from_wire(qname);
  if (q >= Q__COUNT)
    goto reject;
  enum constraint_op op;
  if (!kasld_constraint_op_from_wire(opname, &op))
    goto reject;
  /* Whitelist the inequality-bound ops (matches kasld_emit_constraint); an
   * exact or value2-carrying op reaching here is not carried on this channel.
   */
  if (op != C_LOWER_BOUND && op != C_UPPER_BOUND)
    goto reject;
  enum kasld_confidence c = conf_from_wire(conf_str);
  if (c == CONF_UNKNOWN)
    goto reject;
  unsigned long v;
  if (!parse_hex(val_str, &v))
    goto reject;
  /* Same lock discipline as capture_scalar. */
  RESULT_LOCK();
  if (num_constraint_facts >= MAX_CONSTRAINT_FACTS) {
    kasld_discard_record(DISCARD_CAPACITY, DSRC_CONSTRAINT_FACTS);
    RESULT_UNLOCK();
    return 0;
  }
  int idx = num_constraint_facts++;
  RESULT_UNLOCK();
  struct constraint_fact_record *cf = &constraint_facts[idx];
  cf->q = q;
  cf->op = op;
  cf->value = v;
  cf->conf = c;
  cf->origin = origin;
  return 1;

reject:
  kasld_discard_record(DISCARD_PARSE, kasld_origin_name(origin));
  return 0;
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
  /* Raw fopen(), NOT kasld_fopen(): `path` is the component's own binary, which
   * the orchestrator executes from its real location (execl below). It is a
   * runtime artifact, not a captured fact, so it must be read from the live
   * tree regardless of KASLD_SYSROOT — see sysroot.h on runtime-primitive
   * escapes. Under replay this would otherwise resolve into the fixture (where
   * the binary does not exist), returning empty meta and silently disabling
   * every meta- driven hardening section. */
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

  /* Read the ELF header fields used below: e_shoff, e_shentsize, e_shnum,
   * e_shstrndx. Seek past e_ident, already consumed. */
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
    char cpath[KASLD_PATH_MAX];
    const char *cp = component_path(&components[i], cpath, sizeof(cpath));
    char *meta_raw = cp ? extract_elf_section(cp, ".kasld_meta") : NULL;
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

    const char *live = meta_get(&m, "live");
    if (live && strcmp(live, "1") == 0)
      components[i].is_live = 1;
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

/* Under KASLD_SYSROOT (offline analysis against a captured tree), filter out
 * components tagged live:1 in .kasld_meta. Their result comes from live
 * runtime state of the executing kernel/CPU — a syscall, a CPU instruction, a
 * timing measurement, a setuid helper, or a self-referential /proc/self
 * pseudo-file — so against a copied tree it describes the wrong (host) kernel
 * or cannot be produced at all. Reusing is_filtered excludes them from
 * scheduling and accounting exactly as --skip does. No-op on a live system
 * (KASLD_SYSROOT unset). Called after apply_skip_filter(). */
static void apply_sysroot_filter(void) {
  const char *root = getenv("KASLD_SYSROOT");
  if (!root || !*root)
    return;
  for (int i = 0; i < num_components; i++) {
    if (components[i].is_live)
      components[i].is_filtered = 1;
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
/* Parse the body of an `R` line (everything after "R ") into a disposition.
 * Grammar: `cat=<category> [gate=<token>] [msg="<text>"]`, emitted in that
 * order by kasld_disposition() (api.h). gate is a space-delimited token; msg is
 * quoted and always last, so a `gate=`/`cat=` substring inside the message text
 * cannot be mistaken for a real field (each field is only sought before msg).
 * An unknown category, or a mitigation with no gate, is malformed and leaves
 * the disposition at DISP_NONE. */
/* Parse one `cat=<category> [gate=<token>] [msg="<text>"]` disposition body —
 * the bytes after the leading "R ". Returns 1 and fills *d on a well-formed
 * record; returns 0 leaving *d untouched otherwise.
 *
 * Validate-then-commit, matching the address and scalar parsers. A component
 * is contracted to emit at most one R line, but the record already captured
 * must not depend on every component honouring that: a second line that fails
 * to parse leaves the first standing rather than erasing it.
 *
 * Strict for the same reasons those two are: an unknown key, a repeated key, an
 * over-length token or an unterminated quote rejects the line rather than being
 * silently ignored or truncated. The category comes from a parsed key rather
 * than a search, so no text inside a message can supply one. */
static int parse_disposition(const char *s, struct component_disposition *d) {
  struct component_disposition tmp;
  int seen_cat = 0, seen_gate = 0, seen_msg = 0;

  memset(&tmp, 0, sizeof(tmp));

  while (*s) {
    while (*s == ' ' || *s == '\t')
      s++;
    if (!*s)
      break;

    const char *key = s;
    while (*s && *s != '=' && *s != ' ' && *s != '\t')
      s++;
    if (*s != '=')
      return 0; /* a bare token is not a key=value field */
    size_t klen = (size_t)(s - key);
    s++;

    if (klen == 3 && memcmp(key, "cat", 3) == 0) {
      char tok[32];
      size_t n = 0;
      if (seen_cat)
        return 0;
      seen_cat = 1;
      while (*s && *s != ' ' && *s != '\t') {
        if (n >= sizeof(tok) - 1)
          return 0;
        tok[n++] = *s++;
      }
      tok[n] = '\0';
      tmp.category = kasld_disp_parse(tok);
      if (tmp.category == DISP_NONE)
        return 0;
    } else if (klen == 4 && memcmp(key, "gate", 4) == 0) {
      size_t n = 0;
      if (seen_gate)
        return 0;
      seen_gate = 1;
      while (*s && *s != ' ' && *s != '\t') {
        if (n >= sizeof(tmp.gate) - 1)
          return 0;
        tmp.gate[n++] = *s++;
      }
      tmp.gate[n] = '\0';
      if (n == 0)
        return 0; /* gate= naming nothing */
    } else if (klen == 3 && memcmp(key, "msg", 3) == 0) {
      size_t n = 0;
      if (seen_msg)
        return 0;
      seen_msg = 1;
      if (*s != '"')
        return 0; /* the message is always quoted */
      s++;
      while (*s && *s != '"') {
        if (n >= sizeof(tmp.message) - 1)
          return 0;
        tmp.message[n++] = *s++;
      }
      if (*s != '"')
        return 0; /* unterminated */
      s++;
      tmp.message[n] = '\0';
    } else {
      return 0; /* unknown key (spec: no forward-compat silence) */
    }
  }

  if (!seen_cat)
    return 0;
  /* A mitigation names the control that fired; without a gate the claim is
   * unusable to the hardening report, so drop it rather than record a
   * gate-less mitigation. */
  if (tmp.category == DISP_MITIGATION && tmp.gate[0] == '\0')
    return 0;

  *d = tmp;
  return 1;
}

static int handle_component_line(struct component_log *clog,
                                 const char *comp_method, int origin,
                                 const char *content, size_t len) {
  char line[MAX_LINE_LEN];
  if (len >= sizeof(line))
    len = sizeof(line) - 1;
  memcpy(line, content, len);
  line[len] = '\0';

  if (verbose && plain_output())
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
      kasld_discard_record(DISCARD_CAPACITY, DSRC_COMPONENT_LINES);
      RESULT_UNLOCK();
    }
  }

  /* `R` lines are a disposition (why the component produced no result). They
   * carry no address, so they are stored on the per-component log — always, not
   * only under --verbose — and never reach the address/scalar parsers. */
  if (line[0] == 'R') {
    if (clog && line[1] == ' ' && line[2] &&
        !parse_disposition(line + 2, &clog->disposition) && verbose && !quiet)
      fprintf(stderr, "[parser] dropped malformed R line (origin=%s)\n",
              kasld_origin_name(origin));
    return 0;
  }

  /* Origin (provenance) is the component's discovery slot — captured at the
   * orchestrator since it owns the subprocess identity. `S` lines are scalar
   * system facts; everything else is an address record. */
  /* Rejections are recorded by whichever site decides them, not here. stdout
   * and stderr share one pipe, so most lines reaching this point are a
   * component's human-readable output and are turned away by a prefix filter
   * inside the capture functions — prose is not discarded evidence and must not
   * be counted as any. Only a line past that filter can be rejected in the
   * sense that matters, and only the rejecting site knows whether it was
   * malformed, out of bounds, or refused by a full table. */
  if (line[0] == 'S')
    return capture_scalar(line, origin);
  if (line[0] == 'C')
    return capture_constraint(line, origin);
  return capture_result(line, comp_method, origin);
}

/* Verbose: open a component's output block with a labelled rule, so its
 * header + explanation + streamed lines read as one unit rather than being
 * set off only by "--- name ---". The component's own lines stay at column 0
 * (the echoed V/P/S wire lines are a documented interface parsed by
 * extra/check-results); the rule alone delimits the block. */
static void print_component_banner(const char *name, const char *method) {
  const int width = 64;
  /* Box-drawing rule + middle-dot separator, ASCII fallbacks in a non-UTF-8
   * locale (--ascii). Each fallback is the same display width as its glyph, so
   * the column accounting below is unchanged. */
  const char *bar2 = kasld_glyph("\xe2\x94\x80\xe2\x94\x80", "--"); /* ── */
  const char *bar1 = kasld_glyph("\xe2\x94\x80", "-");              /* ─  */
  const char *dot = kasld_glyph("\xc2\xb7", "-");                   /* ·  */
  int cols = 3 + (int)strlen(name); /* bar2 + name */
  printf("\n%s%s%s %s%s%s", c(C_DIM), bar2, c(C_RESET), c(C_BOLD), name,
         c(C_RESET));
  if (method && *method) {
    printf(" %s%s%s %s%s%s", c(C_DIM), dot, c(C_RESET), c(C_DIM), method,
           c(C_RESET));
    cols += 3 + (int)strlen(method); /* " . " + method */
  }
  putchar(' ');
  cols += 1;
  printf("%s", c(C_DIM));
  for (; cols < width; cols++)
    printf("%s", bar1);
  printf("%s\n", c(C_RESET));
}

static int run_component(const struct component *c) {
  /* The component's discovery slot is its identity: it indexes comp_logs[] and
   * is the provenance recorded on every result it emits. Derived from the
   * table rather than a counter, so it does not depend on completion order. */
  const int slot = (int)(c - components);
  char cpath[KASLD_PATH_MAX];
  const char *cp = component_path(c, cpath, sizeof(cpath));
  if (!cp)
    return -1;

  /* Extract explain string before execution (if --explain active or JSON) */
  char *explain_str = NULL;
  if (explain_mode || json_output)
    explain_str = extract_elf_section(cp, ".kasld_explain");

  /* Extract metadata (always — needed for method and hardening report) */
  char *meta_raw = extract_elf_section(cp, ".kasld_meta");
  struct component_meta tmp_meta = {0};
  parse_meta(meta_raw, &tmp_meta);
  free(meta_raw);

  /* Set method from metadata (fallback: "parsed") */
  const char *method_val = meta_get(&tmp_meta, "method");
  const char *comp_method = method_val ? method_val : "parsed";

  if (verbose && plain_output())
    print_component_banner(c->name, comp_method);

  if (explain_mode && explain_str && plain_output()) {
    /* `c` names the component parameter in this function, shadowing the c()
     * colour helper, so reference the colour codes directly. */
    const char *dim = color_output ? C_DIM : "";
    const char *rst = color_output ? C_RESET : "";
    printf("%s  %s%s\n\n", dim, explain_str, rst);
  }

  /* Always allocate a log slot for outcome tracking */
  /* One log slot per component, addressed by its discovery slot rather than
   * claimed from a counter: each running component owns a distinct slot by
   * construction, so no lock is needed and the array's order is discovery
   * order on every run instead of the order components happened to finish. */
  struct component_log *clog = &comp_logs[slot];
  clog->ran = 1;
  snprintf(clog->name, sizeof(clog->name), "%s", c->name);
  clog->exit_code = -1;
  clog->outcome = OUTCOME_NO_RESULT;
  clog->disposition = (struct component_disposition){0};
  clog->lines = NULL;
  clog->num_lines = 0;
  clog->lines_cap = 0;
  clog->explain = explain_str; /* ownership transfers to the log slot */
  clog->meta = tmp_meta;       /* copy parsed metadata */
  explain_str = NULL;
  /* Re-point method to the clog copy (stable pointer into clog->meta) */
  method_val = meta_get(&clog->meta, "method");
  comp_method = method_val ? method_val : "parsed";

  free(explain_str); /* NULL after the transfer above */

  int pipefd[2];
  if (pipe(pipefd) < 0) {
    if (!quiet)
      progress_note("[-] %s: pipe: %s", c->name, strerror(errno));
    return -1;
  }

  pid_t pid = fork();
  if (pid < 0) {
    if (!quiet)
      progress_note("[-] %s: fork: %s", c->name, strerror(errno));
    close(pipefd[0]);
    close(pipefd[1]);
    return -1;
  }

  if (pid == 0) {
    /* Child: new process group, so any grandchildren die with it */
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
      execl(wrap, wrap, cp, (char *)NULL);
      /* fall-through to _exit on failure */
    } else {
      execl(cp, c->name, (char *)NULL);
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
  char buf[MAX_LINE_LEN];
  size_t buf_pos = 0;
  int timed_out = 0;
  int tagged_this_run = 0;

  while (1) {
    long remaining = deadline_remaining_ms(&deadline);
    if (remaining == 0) {
      timed_out = 1;
      break;
    }

    /* Cap the wait so a worker blocked on a silent child still repaints. The
     * real timeout is the `remaining == 0` test at the top of the loop, so a
     * poll expiry here is just a tick, not an expiry. */
    long wait = remaining > PROGRESS_TICK_MS ? PROGRESS_TICK_MS : remaining;
    int pr = poll(&pfd, 1, (int)wait);
    if (pr < 0) {
      if (errno == EINTR)
        continue;
      break;
    }
    if (pr == 0) {
      progress_tick();
      continue;
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
            handle_component_line(clog, comp_method, slot, buf, buf_pos);
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
          handle_component_line(clog, comp_method, slot, buf + start, llen);
      start = (size_t)(nl - buf) + 1;
    }
    size_t left = buf_pos - start;

    /* A line longer than the whole buffer has no newline to split on — the
     * only way `left` can reach the buffer size. Flush the buffered prefix as a
     * (truncated) line so the reader makes progress instead of stalling on a
     * zero-length read, then keep reading the rest of the line. */
    if (left == sizeof(buf)) {
      tagged_this_run +=
          handle_component_line(clog, comp_method, slot, buf, left);
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
      progress_note("[-] component '%s' timed out after %ds, killing", c->name,
                    component_timeout);
    kill(-pid, SIGKILL); /* Kill entire process group */
  }

  int status;
  waitpid(pid, &status, 0);

  int had_tagged = (tagged_this_run > 0);
  int rc = WIFEXITED(status) ? WEXITSTATUS(status) : -1;

  /* Classify the reaped component. See kasld_classify_outcome (outcome.h) for
   * the precedence (tagged > timeout > SIGSYS-denial > exit 77/69 > no result),
   * factored out as a pure function so it is unit-tested (tests/test_outcome).
   * exit_code keeps the raw exit code (-1 for a signal death). */
  if (clog) {
    clog->outcome = kasld_classify_outcome(status, timed_out, had_tagged);
    clog->exit_code = rc;
  }

  if (timed_out)
    return -1;

  return rc;
}

static void progress_update(void) {
  RESULT_LOCK();
  int done = ++progress_done;
  if (progress_inflight > 0)
    progress_inflight--;
  int inflight = progress_inflight;
  RESULT_UNLOCK();

  if (quiet || json_output || oneline_output || markdown_output)
    return;
  if (verbose) {
    printf("\n");
    return;
  }
  /* The bar overwrites itself with \r, which only means anything on a TTY.
   * Drawn on stderr so `kasld | grep` / `kasld > out` don't capture frames. */
  if (!isatty(STDERR_FILENO))
    return;

  OUTPUT_LOCK();
  /* Workers finish concurrently and can reach here out of order; never draw a
   * lower count over a higher one. */
  if (done > progress_painted) {
    progress_painted = done;
    progress_paint(done, progress_total, inflight);
    fflush(stderr);
  }
  OUTPUT_UNLOCK();
}

/* Bump the in-flight count around a component run. progress_update() does the
 * matching decrement, and it is called on every path -- including the
 * sequential ones that never claim a pool slot -- so the increment has to live
 * beside the call, not beside the claim. */
static void progress_enter_component(void) {
  RESULT_LOCK();
  progress_inflight++;
  RESULT_UNLOCK();
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
    progress_enter_component();
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
      progress_enter_component();
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
      progress_enter_component();
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
  /* One entry per worker, not per component: `workers` is already clamped to
   * the online CPU count and to the number of components in this phase. */
  pthread_t threads[KASLD_MAX_WORKERS];
  if (workers > KASLD_MAX_WORKERS)
    workers = KASLD_MAX_WORKERS;
  int started = 0;
  for (int i = 0; i < workers; i++)
    if (pthread_create(&threads[started], NULL, inference_worker, NULL) == 0)
      started++;
  /* On a create failure, only the threads that started are valid to join.
   * Work-stealing (each worker claims from the shared pool_next) means any
   * single started worker drains every remaining component, so no work is
   * lost. If none started, drain the queue on this thread. */
  if (started == 0)
    inference_worker(NULL);
  for (int i = 0; i < started; i++)
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
  a->method_set |= b->method_set;
  /* Contributors are a set of component slots, so the union is a word-wise OR:
   * membership is idempotent and no de-duplication pass is needed. */
  origin_set_union(&a->origins, &b->origins);
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

/* Cross-tier edge conflict: the WEAKER contributor would supply an edge that
 * survives the intersection.
 *
 * merge_into takes the tightest edge from any contributor and the strongest
 * confidence across all of them, and nothing requires those to be the same
 * contributor. A merged record carries ONE confidence, so a weaker record's
 * tighter edge is published at the stronger record's tier — and the engine's
 * sound floor then admits a bound nothing proved at that tier. The measured
 * edge it displaced is gone from the record entirely.
 *
 * Agreement is not a conflict. A weaker record holding the SAME value moves no
 * edge, which is the corroboration this merge exists for; those still collapse,
 * so the consensus-source counting downstream is unaffected.
 *
 * Refusing costs nothing: both records reach the engine, each carrying its own
 * confidence, and the two resolutions separate them without further help — the
 * guaranteed run is floored above the weaker constraint and never sees it,
 * while the likely run applies both and keeps the tighter claim.
 *
 * Symmetric in (a, b): weak and strong are chosen by confidence, never by which
 * record happens to be the accumulator, so the canonical sort's choice of
 * anchor cannot change the outcome.
 *
 * EDGES ONLY, and the limit is deliberate. merge_into refuses to let a weaker
 * contributor displace a sample another already holds, but adopts one freely
 * where the accumulator holds none, so a weak sample can still reach a record
 * that publishes it at a stronger tier. Extending this predicate to cover that
 * also refuses the merge a weak interior sample makes into a strong extent,
 * which is a refinement worth keeping and is the shape
 * test_merge_sample_inside_extent_collapses pins down. The asymmetry is
 * defensible because only the EDGES become bounds: the merged record keeps the
 * strong contributor's pos, so the sample is carried rather than read as the
 * anchor. Revisit if a consumer is found that turns a sample into a bound at
 * the record's confidence. */
static int conf_edge_conflict(const struct result *a, const struct result *b) {
  int wa = conf_weight(a->conf);
  int wb = conf_weight(b->conf);
  if (wa == wb)
    return 0;
  const struct result *weak = (wa < wb) ? a : b;
  const struct result *strong = (wa < wb) ? b : a;
  if (HAS_LO(weak) && (!HAS_LO(strong) || weak->lo > strong->lo))
    return 1;
  if (HAS_HI(weak) && (!HAS_HI(strong) || weak->hi < strong->hi))
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

/* Total order over a record's own content, for the canonical sort below.
 * Compares only value fields — never provenance or array position — so two
 * records that tie here are identical as evidence, and no refusal predicate can
 * reject their merge. Their relative order is therefore immaterial, which is
 * what lets an unstable qsort produce a stable result. Addresses compare by
 * relation rather than subtraction: they are unsigned long and a difference
 * would wrap. */
static int result_canonical_cmp(const void *va, const void *vb) {
  const struct result *a = (const struct result *)va;
  const struct result *b = (const struct result *)vb;
  if (a->type != b->type)
    return (int)a->type - (int)b->type;
  if (a->region != b->region)
    return (int)a->region - (int)b->region;
  int n = strncmp(a->name, b->name, NAME_LEN);
  if (n != 0)
    return n;
  if (a->pos != b->pos)
    return (int)a->pos - (int)b->pos;
  if (a->conf != b->conf)
    return (int)a->conf - (int)b->conf;
  if (a->set_mask != b->set_mask)
    return a->set_mask < b->set_mask ? -1 : 1;
  if (a->lo != b->lo)
    return a->lo < b->lo ? -1 : 1;
  if (a->hi != b->hi)
    return a->hi < b->hi ? -1 : 1;
  if (a->sample != b->sample)
    return a->sample < b->sample ? -1 : 1;
  if (a->base_align != b->base_align)
    return a->base_align < b->base_align ? -1 : 1;
  return 0;
}

/* Collapse same-(type, region, name) records into one. Called by run_phase()
 * once after every component in the phase has finished, so compute_kaslr_info()
 * — and the engine evidence built from results[] — see deduplicated records.
 * The engine itself runs later, in emit_summary(); nothing infers here.
 *
 * ORDER-INDEPENDENT: results[] arrives in component completion order, which
 * under the worker pool varies between runs. The pass opens by sorting into a
 * canonical content order, so both the grouping and the surviving records are a
 * function of the record SET alone. That matters beyond presentation: the
 * refusal predicates are not transitive (a record carrying no sample is
 * sample-compatible with every other), so which contributor anchors a group can
 * decide which later candidates join it. Sorting fixes the anchor by content
 * instead of by arrival. It also makes every consumer that walks results[] in
 * index order — the JSON and markdown record lists, the text evidence rows, the
 * covering order handed to the engine — reproducible across runs.
 *
 * IDEMPOTENT: safe to call repeatedly. The merge collapses (type, region, name)
 * groups by keeping the highest-confidence record's sample/pos and taking the
 * narrowest interval intersection; calling it again on the already-merged set
 * is a no-op (every potential merge has already been applied). The compaction
 * below preserves relative order, so the array stays sorted and the second
 * call's sort is a no-op too. Test code (and the per-phase wiring in run_phase)
 * relies on this — a future edit that introduced cross-call state would break
 * both. */
void merge_results(void) {
  if (num_results > 1)
    qsort(results, (size_t)num_results, sizeof(results[0]),
          result_canonical_cmp);

  int alive[MAX_RESULTS];
  for (int i = 0; i < num_results; i++)
    alive[i] = 1;

  for (int i = 0; i < num_results; i++) {
    if (!alive[i])
      continue;
    /* Covering members (pos=extent) bypass the merge: they belong to a
     * complete, single-source map whose value lives in the gaps between
     * extents (see struct covering). Collapsing them by (type, region, name)
     * would mix two sources' maps or melt adjacent extents of one map,
     * destroying the gaps the map rules depend on. They are routed to the
     * engine's coverings[] at evidence build; here they pass through untouched
     * as neither anchor nor candidate. */
    if (results[i].pos == POS_EXTENT)
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
      if (b->pos == POS_EXTENT)
        continue; /* covering members never merge — see the anchor guard */
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
      if (conf_edge_conflict(&acc, b))
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
 * brute-force work remains?" - 13 candidates is ~4 bits of worst-case
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

/* The layered engine is the sole inference path: resolve every quantity from
 * the collected evidence and write the result into `layout`, which the summary
 * is computed from. Both steps run at emit_summary(), the single caller -- the
 * summary builder consumes the result and does not decide when it is produced.
 *
 * engine_sync_authoritative is compiled in every build (a pure projection with
 * no engine dependencies); engine_resolve and the engine instances are
 * engine-only, since they drive the components and the engine.c machinery that
 * the KASLD_TESTING translation unit does not link. That split is why the
 * snapshots reach the summary builder as parameters: the type is universal, the
 * instances are not, and passing them keeps the whole projection compiled --
 * and reachable from a test -- in a build with no engine. */
static void engine_sync_authoritative(const struct engine *e);

/* Sound floor for the guaranteed window: inputs below this are out of scope, so
 * the window is derived purely from >= floor signals. CONF_INFERRED admits
 * parsed/derived/inferred (proven); heuristic/timing/brute reach the likely
 * window only. The two-window POLICY (which floors, what they mean) lives here;
 * the engine is floor-agnostic.
 *
 * Outside the engine-only block: this names a confidence level and has no
 * engine dependency, and the projection above -- which every build compiles --
 * counts candidates at this floor. */
#define KASLD_SOUND_FLOOR CONF_INFERRED

/* Candidate count over q's honest compile-time top — the entropy this
 * architecture's KASLR had before any evidence narrowed it. Counted through
 * quantity_slots() at the same alignment as the residual, so the two are
 * directly comparable. Its inputs are the quantity table and the sound floor;
 * no engine state, so every build has it. */
static unsigned long quantity_top_slots(enum kasld_quantity q,
                                        unsigned long align) {
  if (!align || !quantities[q].init_top)
    return 0;
  struct estimate top;
  quantities[q].init_top(&top);
  return quantity_slots(q, &top, KASLD_SOUND_FLOOR, NULL, 0, align);
}

/* Snapshot of the LIKELY resolution (floor CONF_BRUTE — all signals): the est +
 * constraints quantity_slots() needs, plus the resolver's rejected-constraint
 * (conflict) set so the likely window's conflicts can be reported symmetrically
 * with the guaranteed window's (the floored run overwrites the engine's own
 * copy). g_auth_engine holds the guaranteed resolution after engine_resolve();
 * this holds likely so compute_kaslr_info can report the speculative window
 * alongside it. */
struct engine_resolution {
  struct estimate est[Q__COUNT];
  struct constraint constraints[ENGINE_MAX_CONSTRAINTS];
  int n_constraints;
  int n_conflicts[Q__COUNT];
  uint32_t conflicts[Q__COUNT][ESTIMATE_MAX_CONFLICTS];
};
/* The instances and the resolver stay engine-only: they drive the components
 * and the engine.c machinery, which the KASLD_TESTING translation unit does not
 * link. The TYPE above is plain data (estimates + constraints) and is compiled
 * in every build, so compute_kaslr_info can name it in its signature and take
 * the snapshot as a parameter instead of reaching for a global that does not
 * exist there. That is what lets the whole projection compile -- and be tested
 * -- rather than 200 lines of it vanishing under the gate. */
#ifndef KASLD_TESTING
static void engine_resolve(struct engine *e);
static struct engine g_auth_engine; /* the GUARANTEED (primary) resolution */
static struct engine_resolution g_likely;
static int g_have_likely;
#endif

/* Fill a memory-KASLR region's speculative "likely" sub-window from the
 * all-signals snapshot. Emits only when the likely estimate is strictly tighter
 * than the guaranteed engine window [g_lo, g_hi] — otherwise there is nothing
 * to add. A set window is signalled to callers via out_lo and out_hi (both 0 =
 * none).
 *
 * The CLAMP is what makes likely ⊆ guaranteed structural, exactly as at the
 * vtext/ptext boundary: the result is confined to [g_lo, g_hi] and reported
 * only when non-empty and strictly tighter. Nothing else is needed for the
 * invariant.
 *
 * There was formerly an additional `shown` gate here, set by callers to whether
 * the region's GUARANTEED row had been narrowed. It was redundant against the
 * clamp and wrong in effect: it suppressed every likely-only narrowing of these
 * three quantities, whatever the source. That is precisely what a
 * range-classified witness produces — REGION_DIRECTMAP_BAND is barred from the
 * guaranteed window by design, so the likely window is the only one it may
 * shape, and the gate hid the one contribution it was allowed to make. Its
 * comment also claimed to test for "no guaranteed row", but render.c adds the
 * memory-KASLR guaranteed rows unconditionally wherever
 * RANDOMIZE_MEMORY_ALIGN > 0, so no such case existed.
 *
 * A likely row may therefore now sit beside a guaranteed row reading "not
 * narrowed". That is already how the image base behaves, the row carries
 * GRADE_LIKELY, and it is strictly more than showing nothing. */
static void fill_mem_likely(const struct estimate *l, unsigned long g_lo,
                            unsigned long g_hi, unsigned long *out_lo,
                            unsigned long *out_hi) {
  *out_lo = 0;
  *out_hi = 0;
  if (l->lo > l->hi) /* a bottom estimate */
    return;
  kasld_clamp_likely_window(l->lo, l->hi, g_lo, g_hi, out_lo, out_hi);
}

/* The reported text base is the IMAGE BASE (_text). A KERNEL_IMAGE anchor is
 * the image base directly; a KERNEL_TEXT anchor is _stext, normalized down by
 * the head gap the arch declares in STEXT_OFFSET (a no-op where that is 0).
 * Returns 0 when no kernel-image/text base anchor exists.
 */
static unsigned long anchor_image_base(enum kasld_addr_type type) {
  const struct result *r = select_anchor(type, REGION_KERNEL_IMAGE);
  int is_stext = 0;
  if (!r) {
    r = select_anchor(type, REGION_KERNEL_TEXT);
    is_stext = 1;
  }
  return kasld_image_base_from(anchor_addr(r), is_stext);
}

/* _stext for display: prefer the real observed KERNEL_TEXT base witness
 * (/proc/kallsyms _stext, /proc/iomem "Kernel code"); else project from the
 * image base with the compile-time head gap. select_anchor() is unusable here —
 * it prefers unnamed results, so an unnamed interior kernel_text sample would
 * shadow the _stext base; scan for the base witness directly. */
static unsigned long observed_stext_base(enum kasld_addr_type type,
                                         unsigned long image_base) {
  for (int i = 0; i < num_results; i++) {
    const struct result *r = &results[i];
    if (r->type == type && r->region == REGION_KERNEL_TEXT &&
        r->pos == POS_BASE && HAS_LO(r))
      return r->lo;
  }
  return image_base ? image_base + (unsigned long)STEXT_OFFSET : 0;
}

/* Did evidence move either edge of Q_PAGE_OFFSET off the architecture's own
 * bracket? The reference is the quantity's honest top, read back through the
 * same accessor as the resolved estimate so the two cannot describe the lattice
 * differently. Both the rendered singular base and the reported window key off
 * this, so they cannot disagree about whether anything was learned. */
/* Guarded to its only caller's condition: the coupled-arch branch in
 * compute_kaslr_info() below. Elsewhere the window is projected whole and
 * unconditionally, so nothing asks whether it moved. */
#if TEXT_TRACKS_DIRECTMAP
static int page_offset_narrowed(void) {
  struct estimate top;
  unsigned long top_lo = 0, top_hi = 0;
  quantities[Q_PAGE_OFFSET].init_top(&top);
  quantity_window(Q_PAGE_OFFSET, &top, &top_lo, &top_hi);
  return layout.virt_page_offset_min > top_lo ||
         layout.virt_page_offset_max < top_hi;
}
#endif

void compute_kaslr_info(struct summary *s, const struct engine *auth,
                        const struct engine_resolution *likely) {
  if (auth) {
    /* The layered engine is the sole inference path: resolve every quantity
     * from the collected evidence and write the result into `layout`, which the
     * rest of this function reads. */

    /* The singular rendered direct-map base follows the LIKELY resolution
     * wherever the sound one stopped at a window rather than a value. It is a
     * best-single-answer field — the renderers are its only readers, and the
     * guaranteed edges travel separately as virt_page_offset_{min,max} — so the
     * alternative to a likely value is not a sounder one, it is the
     * compile-time seed: the analysing build's split presented as the target's.
     * On a moved-VMSPLIT kernel that reads 0xc0000000 beside a guaranteed
     * window of [0x80000000, 0xbfffffff], which is the one number in the
     * readout that the evidence contradicts. */
    {
      unsigned long po_auth, po_likely;
      if (!quantity_pinned(Q_PAGE_OFFSET, &auth->est[Q_PAGE_OFFSET],
                           &po_auth)) {
        if (likely &&
            quantity_pinned(Q_PAGE_OFFSET, &likely->est[Q_PAGE_OFFSET],
                            &po_likely) &&
            po_likely != 0) {
          layout.virt_page_offset = po_likely;
        }
#if TEXT_TRACKS_DIRECTMAP
        /* No single likely value either: show the proven FLOOR, the lowest base
         * the evidence still admits.
         *
         * Only where evidence actually narrowed the bracket. With nothing
         * learned the floor is the architecture's theoretical minimum and no
         * window is reported beside it to say so, which on arm32 or x86_32
         * would present 0x40000000 — a split almost no kernel is built with —
         * as the answer. The seed is a poorer claim but a better default, and
         * an unnarrowed window is exactly the case the field is informational
         * for.
         *
         * Coupled arches only. There the split is a build choice the evidence
         * can contradict downward, so a measured floor below the analysing
         * build's PAGE_OFFSET is the better answer. Decoupled arches randomize
         * the base UPWARD from their compile-time default, so a floor below it
         * says nothing — engine_sync_authoritative already moves the field
         * there, and only once the floor rises above that default. Applying
         * this branch to them would undo that gate wherever the bracket's own
         * minimum sits lower than PAGE_OFFSET, which on riscv64 it does. */
        else if (page_offset_narrowed() && layout.virt_page_offset_min &&
                 layout.virt_page_offset_min <= layout.virt_page_offset_max) {
          layout.virt_page_offset = layout.virt_page_offset_min;
        }
#endif
      }
    }
  }

  /* Virtual image base (_text). Fall back to the engine's pinned singleton
   * (virt_kaslr_disabled_pin etc. land there — engine_sync projects the
   * resolved window onto virt_kaslr_text_min/max, so min==max means "pinned").
   */
  unsigned long vtext = anchor_image_base(KASLD_TYPE_VIRT);
  if (vtext == 0 && layout.virt_kaslr_text_min == layout.virt_kaslr_text_max)
    vtext = layout.virt_kaslr_text_min;
  unsigned long ptext = anchor_image_base(KASLD_TYPE_PHYS);
  if (auth) {
    /* The raw anchor scan above is verdict-blind (it reads results[], not the
     * curated evidence set); reconcile it with the engine so the headline base
     * is never one a verdict rejected. The engine's pinned singleton wins; a
     * raw pick outside the all-signals window is dropped. */
    {
      /* A zeroed stand-in where no likely resolution exists: the helper reads
       * l_lo/l_hi only under have_likely, so the edges are inert then. */
      static const struct estimate kNoLikely;
      const struct estimate *gv = &auth->est[Q_VIRT_IMAGE_BASE];
      const struct estimate *lv =
          likely ? &likely->est[Q_VIRT_IMAGE_BASE] : &kNoLikely;
      vtext = kasld_reconcile_concrete_base(vtext, gv->lo, gv->hi,
                                            likely != NULL, lv->lo, lv->hi);
      const struct estimate *gp = &auth->est[Q_PHYS_IMAGE_BASE];
      const struct estimate *lp =
          likely ? &likely->est[Q_PHYS_IMAGE_BASE] : &kNoLikely;
      ptext = kasld_reconcile_concrete_base(ptext, gp->lo, gp->hi,
                                            likely != NULL, lp->lo, lp->hi);
    }
  }
  s->kaslr.vtext = vtext;
  s->kaslr.vstext = observed_stext_base(KASLD_TYPE_VIRT, vtext);

  s->kaslr.ptext = ptext;
  s->kaslr.has_phys = 0;
  s->kaslr.pstext = observed_stext_base(KASLD_TYPE_PHYS, ptext);

  /* Hole-aware slot counts, projected beside the windows they count (see
   * struct kasld_layout). Interior C_EXCLUDE holes and any C_STRIDE residue
   * class are already reflected, so the headline entropy follows the estimate
   * rather than the width of its convex hull. */
  s->kaslr.vslots = layout.virt_kaslr_slots;
  s->kaslr.vbits = s->kaslr.vslots > 0 ? ilog2(s->kaslr.vslots) : 0;
  {
    /* The starting candidate count, from the window the kernel draws the image
     * base from -- KASLR_VIRT_TEXT_MIN..MAX, not the quantity's honest top.
     * The honest top is deliberately widened to admit configurations the model
     * cannot rule out (a sub-48 arm64 VA, a smaller CONFIG_PHYSICAL_START), so
     * it is not a window the kernel ever used: on arm64 it over-states the
     * count fourfold, on riscv64 by 127x. The tight pair is exactly what
     * find_random_virt_addr() draws from on x86_64.
     *
     * A resolved estimate can be WIDER than this window, since the estimate
     * uses the honest top -- a kernel built below the default
     * CONFIG_PHYSICAL_START, say. The renderer prints "of N" only where N
     * exceeds the count, so that degrades to a bare count rather than an
     * incoherent ratio. */
    unsigned long a = layout.virt_kaslr_align;
    unsigned long lo = (unsigned long)KASLR_VIRT_TEXT_MIN;
    unsigned long hi = (unsigned long)KASLR_VIRT_TEXT_MAX;
    unsigned long top = (a && hi > lo) ? (hi - lo) / a + 1 : 0;
    s->kaslr.vtop_slots = top;
    s->kaslr.vbits_top = top > 0 ? ilog2(top) : 0;
    s->kaslr.varch_slots = quantity_top_slots(Q_VIRT_IMAGE_BASE, a);
  }

#ifdef KASLR_PHYS_MIN
  {
    s->kaslr.pslots = layout.phys_kaslr_slots;
    s->kaslr.pbits = s->kaslr.pslots > 0 ? ilog2(s->kaslr.pslots) : 0;
    s->kaslr.parch_slots =
        quantity_top_slots(Q_PHYS_IMAGE_BASE, layout.phys_kaslr_align);
  }
#endif

  if (s->kaslr.vtext) {
    s->kaslr.vslide = (long)(s->kaslr.vtext - layout.virt_image_base_default);
  }

  if (s->kaslr.ptext) {
#ifdef KERNEL_PHYS_DEFAULT
    s->kaslr.has_phys = 1;
    s->kaslr.pslide = (long)(s->kaslr.ptext - KERNEL_PHYS_DEFAULT);
#endif
  }

  if (s->kaslr.disabled || s->kaslr.unsupported) {
    /* KASLR off: no slide, and no slot/entropy count even when the base
     * resolves to a *range* rather than a single address (legacy riscv64:
     * linear-map text at a build-specific, non-randomized offset). A candidate
     * count there would dress KASLD's uncertainty about a deterministic offset
     * up as brute-force entropy it does not have. The range is still shown. */
    s->kaslr.vslide = 0;
    s->kaslr.vslots = 0;
    s->kaslr.vbits = 0;
    s->kaslr.pslide = 0;
    s->kaslr.pslots = 0;
    s->kaslr.pbits = 0;
  }

  /* Speculative "likely" window from the all-signals snapshot.
   * The guaranteed window above is layout.{virt,phys}_kaslr_text_{min,max}
   * (`auth` = the sound resolution). likely is clamped INTO guaranteed
   * at this boundary so likely ⊆ guaranteed holds structurally (not merely "by
   * construction" assuming rule monotonicity); the clamp also gates on the
   * result being non-empty and strictly tighter than guaranteed. */
  if (likely && !s->kaslr.disabled && !s->kaslr.unsupported) {
    unsigned long clo, chi;
    if (kasld_clamp_likely_window(likely->est[Q_VIRT_IMAGE_BASE].lo,
                                  likely->est[Q_VIRT_IMAGE_BASE].hi,
                                  layout.virt_kaslr_text_min,
                                  layout.virt_kaslr_text_max, &clo, &chi)) {
      struct estimate lv = likely->est[Q_VIRT_IMAGE_BASE]; /* clamped copy */
      lv.lo = clo;
      lv.hi = chi;
      s->kaslr.vlikely_min = clo;
      s->kaslr.vlikely_max = chi;
      s->kaslr.vlikely_slots = quantity_slots(
          Q_VIRT_IMAGE_BASE, &lv, CONF_BRUTE, likely->constraints,
          likely->n_constraints, layout.virt_kaslr_align);
      s->kaslr.vlikely_bits =
          s->kaslr.vlikely_slots > 0 ? ilog2(s->kaslr.vlikely_slots) : 0;
    }
#ifdef KASLR_PHYS_MIN
    if (kasld_clamp_likely_window(likely->est[Q_PHYS_IMAGE_BASE].lo,
                                  likely->est[Q_PHYS_IMAGE_BASE].hi,
                                  layout.phys_kaslr_text_min,
                                  layout.phys_kaslr_text_max, &clo, &chi)) {
      struct estimate lp = likely->est[Q_PHYS_IMAGE_BASE]; /* clamped copy */
      lp.lo = clo;
      lp.hi = chi;
      s->kaslr.plikely_min = clo;
      s->kaslr.plikely_max = chi;
      s->kaslr.plikely_slots = quantity_slots(
          Q_PHYS_IMAGE_BASE, &lp, CONF_BRUTE, likely->constraints,
          likely->n_constraints, layout.phys_kaslr_align);
      s->kaslr.plikely_bits =
          s->kaslr.plikely_slots > 0 ? ilog2(s->kaslr.plikely_slots) : 0;
    }
#endif
  }

  /* The resolved linear-map window, reported when evidence narrowed it from the
   * architecture's own bracket and suppressed when it did not. The reference
   * for "narrowed" is the quantity's honest top, read back through the same
   * accessor as the resolved estimate so the two cannot describe the lattice
   * differently.
   *
   * Not a comparison against the compile-time PAGE_OFFSET: that answers a
   * question about the TARGET with a property of the analysing build, and hides
   * a resolved edge wherever the two happen to coincide. Nor against
   * KERNEL_VIRT_VAS_END, which is a different quantity — on the architectures
   * whose kernel address space starts or ends outside the linear map, an
   * untouched upper edge compares unequal and reports a bound nothing
   * established.
   *
   * Both edges move together, as they do for the vmalloc / vmemmap fields
   * below: each of these windows is seeded from its own quantity's honest top,
   * so an untightened edge is STILL A BOUND and there is no sentinel to test
   * for. The window is projected whole and unconditionally, exactly as the
   * image base projects layout.virt_kaslr_text_{min,max}.
   *
   * How much the engine learned is carried by the slot counts layout_add()
   * already takes — "N of M" says some of it was, "M" alone says none of it
   * was, the way every other row reports it. Nulling an edge to signal the same
   * thing would instead report a real bracket as no bracket, since fmt_range()
   * prints "not narrowed" only when both edges are 0, its no-information
   * fallback. */
  s->kaslr.virt_page_offset_min = layout.virt_page_offset_min;
  s->kaslr.virt_page_offset_max = layout.virt_page_offset_max;
  /* Projected whole, as virt_page_offset is: the seed above is a real bracket,
   * so there is no sentinel to test for and nothing to null. */
  s->kaslr.virt_vmalloc_min = layout.virt_vmalloc_base_min;
  s->kaslr.virt_vmalloc_max = layout.virt_vmalloc_base_max;
  s->kaslr.virt_vmemmap_min = layout.virt_vmemmap_base_min;
  s->kaslr.virt_vmemmap_max = layout.virt_vmemmap_base_max;
  s->kaslr.virt_module_min = layout.virt_module_base_min;
  s->kaslr.virt_module_max = layout.virt_module_base_max;

  /* Residual slot counts for the memory-KASLR regions, mirroring the headline
   * vslots/pslots: the projected count already reflects interior C_EXCLUDE
   * holes and any stride class, so the entropy the renderer prints follows the
   * estimate rather than the width of its hull. Only a both-sided window
   * displays a count, so gate on min && max -- a presentation rule, asked here
   * where those edges are in hand. */
  s->kaslr.virt_page_offset_slots =
      (s->kaslr.virt_page_offset_min && s->kaslr.virt_page_offset_max)
          ? layout.virt_page_offset_slots
          : 0;
  s->kaslr.virt_vmalloc_slots =
      (s->kaslr.virt_vmalloc_min && s->kaslr.virt_vmalloc_max)
          ? layout.virt_vmalloc_slots
          : 0;
  s->kaslr.virt_vmemmap_slots =
      (s->kaslr.virt_vmemmap_min && s->kaslr.virt_vmemmap_max)
          ? layout.virt_vmemmap_slots
          : 0;
  s->kaslr.virt_module_slots =
      (s->kaslr.virt_module_min && s->kaslr.virt_module_max)
          ? layout.virt_module_slots
          : 0;
  s->kaslr.virt_page_offset_bits = s->kaslr.virt_page_offset_slots > 0
                                       ? ilog2(s->kaslr.virt_page_offset_slots)
                                       : 0;
  s->kaslr.virt_vmalloc_bits =
      s->kaslr.virt_vmalloc_slots > 0 ? ilog2(s->kaslr.virt_vmalloc_slots) : 0;
  s->kaslr.virt_vmemmap_bits =
      s->kaslr.virt_vmemmap_slots > 0 ? ilog2(s->kaslr.virt_vmemmap_slots) : 0;

  if (auth) {
    /* Baseline for the direct-map residual, the counterpart of vbits_top. The
     * denominator is NOT Q_PAGE_OFFSET's honest top (an addressable range,
     * which would read as entropy the kernel never had) but the window
     * kernel_randomize_memory() actually draws page_offset_base from, counted
     * at the same PUD grain as the residual so the two are comparable.
     *
     * The budget window cannot be read back off the resolved estimate: the rule
     * that models it deliberately emits no page_offset lower bound (the x86_64
     * direct-map floor is held at the canonical half boundary so low
     * static-layout addresses are not rejected), so it is re-derived from the
     * shared model here.
     *
     * Gated on the model's own confidence cap reaching the sound floor, not
     * merely on max_pfn being present: the whole window is sized from that
     * observation, and a heuristic one would put a sub-floor denominator under
     * a guaranteed-window numerator — mixing trust levels in a single ratio.
     * Left at 0 (renderers show the bare residual) whenever the model is
     * unavailable: off x86_64, unresolved paging level, no max_pfn, or a
     * sub-floor one. */
    {
      struct kasld_rm_budget b;
      if (kasld_rm_budget_from_evidence(&auth->ev, auth->est, &b) &&
          kasld_conf_min(CONF_INFERRED, b.pfn_conf) >= KASLD_SOUND_FLOOR) {
        struct estimate budget;
        memset(&budget, 0, sizeof(budget));
        budget.lo = b.lo;
        budget.hi = b.hi;
        unsigned long top =
            quantity_slots(Q_PAGE_OFFSET, &budget, KASLD_SOUND_FLOOR, NULL, 0,
                           RANDOMIZE_MEMORY_ALIGN);
        s->kaslr.virt_page_offset_top_slots = top;
        s->kaslr.virt_page_offset_bits_top = top > 0 ? ilog2(top) : 0;
      }
    }
  }

  /* Speculative "likely" sub-windows for the memory-KASLR regions: the engine's
   * all-signals snapshot may narrow a region below the sound floor -- a
   * range-classified REGION_DIRECTMAP_BAND witness, which is barred from the
   * guaranteed window by design, or a future directmap/vmalloc side-channel.
   * Each is a refinement of the guaranteed window because fill_mem_likely()
   * clamps it into layout.virt_*_base_{min,max} (what engine_sync_authoritative
   * wrote from `auth`) and reports only when strictly tighter. */
  if (likely && !s->kaslr.disabled && !s->kaslr.unsupported) {
    /* Each region's likely sub-window is signalled by its own *_likely_max != 0
     * (set by fill_mem_likely only when clamped strictly tighter); renderers
     * gate per-region on that. */
    fill_mem_likely(&likely->est[Q_PAGE_OFFSET], layout.virt_page_offset_min,
                    layout.virt_page_offset_max,
                    &s->kaslr.virt_page_offset_likely_min,
                    &s->kaslr.virt_page_offset_likely_max);
    fill_mem_likely(&likely->est[Q_VMALLOC_BASE], layout.virt_vmalloc_base_min,
                    layout.virt_vmalloc_base_max,
                    &s->kaslr.virt_vmalloc_likely_min,
                    &s->kaslr.virt_vmalloc_likely_max);
    fill_mem_likely(&likely->est[Q_VMEMMAP_BASE], layout.virt_vmemmap_base_min,
                    layout.virt_vmemmap_base_max,
                    &s->kaslr.virt_vmemmap_likely_min,
                    &s->kaslr.virt_vmemmap_likely_max);

    /* Hole-aware slot count for each likely sub-window: count over the
     * all-signals estimate clamped to the region's likely [min, max]
     * (quantity_ranges carves holes against that clamped interval). */
    if (s->kaslr.virt_page_offset_likely_max) {
      struct estimate le = likely->est[Q_PAGE_OFFSET];
      le.lo = s->kaslr.virt_page_offset_likely_min;
      le.hi = s->kaslr.virt_page_offset_likely_max;
      s->kaslr.virt_page_offset_likely_slots =
          quantity_slots(Q_PAGE_OFFSET, &le, CONF_BRUTE, likely->constraints,
                         likely->n_constraints, RANDOMIZE_MEMORY_ALIGN);
    }
    if (s->kaslr.virt_vmalloc_likely_max) {
      struct estimate le = likely->est[Q_VMALLOC_BASE];
      le.lo = s->kaslr.virt_vmalloc_likely_min;
      le.hi = s->kaslr.virt_vmalloc_likely_max;
      s->kaslr.virt_vmalloc_likely_slots =
          quantity_slots(Q_VMALLOC_BASE, &le, CONF_BRUTE, likely->constraints,
                         likely->n_constraints, RANDOMIZE_MEMORY_ALIGN);
    }
    if (s->kaslr.virt_vmemmap_likely_max) {
      struct estimate le = likely->est[Q_VMEMMAP_BASE];
      le.lo = s->kaslr.virt_vmemmap_likely_min;
      le.hi = s->kaslr.virt_vmemmap_likely_max;
      s->kaslr.virt_vmemmap_likely_slots =
          quantity_slots(Q_VMEMMAP_BASE, &le, CONF_BRUTE, likely->constraints,
                         likely->n_constraints, RANDOMIZE_MEMORY_ALIGN);
    }
  }

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
  s->stats.total = 0;
  s->stats.succeeded = 0;
  s->stats.no_result = 0;
  s->stats.unavailable = 0;
  s->stats.access_denied = 0;
  s->stats.timed_out = 0;

  /* comp_logs[] is indexed by discovery slot and sparse: a filtered component,
   * or one whose phase did not run, leaves its slot untouched. */
  for (int i = 0; i < num_components; i++) {
    if (!comp_logs[i].ran)
      continue;
    s->stats.total++;
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
 * Pre-computation: what the arch settles before anything is observed
 * -------------------------------------------------------------------------
 */

/* Seed the facts the architecture settles at compile time, before any
 * component runs.
 *
 * Called first because these depend on nothing observed: a component's output
 * cannot change whether the arch supports KASLR. Seeding into an empty table
 * also means they cannot be crowded out of it — appended last, they competed
 * for whatever room components had left, and a full table dropped them with no
 * record, the one evidence loss that did not reach the ledger. Any overflow
 * now belongs to a component, where capture_scalar() caps and records it. */
void seed_arch_kaslr_facts(void) {
#if !KASLR_SUPPORTED
  /* Surface the compile-time arch-off as SF_VIRT_KASLR_DISABLED +
   * SF_PHYS_KASLR_DISABLED so the engine sees it like any runtime detector
   * signal.
   *
   * Emitting the facts is not pinning. Whether a KASLR-off fact fixes the text
   * base is KASLR_DISABLED_PINS_VIRT_TEXT / KASLR_DISABLED_PINS_PHYS, which
   * default to 0 and are raised per arch with the rationale beside them; api.h
   * states the contract and what obliges an arch to stay at the default. An
   * arch at the default gets the renderer's "KASLR not supported" banner and
   * default-addr line while the engine refuses to pin; an arch that raises one
   * pins through the same rule path a runtime detector uses.
   *
   * The pair is a single claim -- a virt disable without its phys partner says
   * something else -- so both slots are taken together or neither is.
   *
   * Room is settled by the call ordering, not by the test below: seeded into an
   * empty table, the pair always fits. The test is kept for what it protects
   * against, which is not a full table but a future caller moving this after
   * capture -- unconditional writes would then run off the end of one. It
   * records rather than returns quietly, so a broken ordering shows up in the
   * ledger instead of corrupting memory.
   *
   * __extension__ silences -Wpedantic: _Static_assert is a C11 keyword gcc
   * accepts under -std=c99 as an extension, matching REGION_FIELD_CAP above. */
  __extension__ _Static_assert(MAX_SCALAR_FACTS >= 2,
                               "the arch-off pair is seeded into an empty "
                               "scalar_facts[] and must always fit");
  if (num_scalar_facts + 1 >= MAX_SCALAR_FACTS) {
    kasld_discard_record(DISCARD_CAPACITY, DSRC_SCALARS);
    return;
  }
  struct scalar_fact_record *fv = &scalar_facts[num_scalar_facts++];
  fv->fact = SF_VIRT_KASLR_DISABLED;
  fv->value = 1;
  fv->conf = CONF_PARSED;
  fv->origin = ORIGIN_ARCH_SYNTH;
  struct scalar_fact_record *fp = &scalar_facts[num_scalar_facts++];
  fp->fact = SF_PHYS_KASLR_DISABLED;
  fp->value = 1;
  fp->conf = CONF_PARSED;
  fp->origin = ORIGIN_ARCH_SYNTH;
#endif
}

/* Project the collected facts onto the summary's KASLR state. Runs at summary
 * time, after components: the scan below reads the whole table, so running it
 * earlier would see only what the arch seeded and miss every detector. */
void summarize_kaslr_state(struct summary *s) {
  /* "Unsupported" is a compile-time property of the arch; no runtime signal
   * needed. Surface it for the renderer banner, and seed the informational
   * default address from the statically-initialised layout
   * (= KERNEL_VIRT_TEXT_DEFAULT). */
  s->kaslr.unsupported = !KASLR_SUPPORTED;
  s->kaslr.default_addr = layout.virt_image_base_default;

  /* "Disabled" is a runtime signal from any detector that observed virtual
   * KASLR off (nokaslr cmdline, no CONFIG_RANDOMIZE_BASE, dmesg "KASLR
   * disabled", hibernation override, riscv64 no FDT seed, loongarch
   * kexec_file token, s390 elfcorehdr=, or the compile-time !KASLR_SUPPORTED
   * synth above). The summary flag drives the renderer's "kernel sits at
   * default text base" status line; that user-facing claim is about virt
   * text, so it tracks SF_VIRT_KASLR_DISABLED specifically. A phys-only
   * disable (e.g. EFI_RNG_PROTOCOL unavailable with virt KASLR intact via
   * DTB seed) wouldn't set this flag — the renderer would still show "KASLR
   * active" because virt randomization succeeded. */
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
/* Compiled in every build: a pure projection over the engine handed to it,
 * with no engine-global dependency, so the unit tests can drive it directly.
 * The classification below is subtle enough that it needs them. */
/* Project the engine's own record of what it discarded into the ledger. The
 * engine is pure and cannot write a global, so it accumulates caps in
 * e->saturation and rulings in ev->verdicts, and this carries them across the
 * same seam engine_sync_authoritative uses for estimates.
 *
 * Curation is recorded per RULE, not per observation: the question a reader has
 * is which curator removed evidence, and the verdict's origin answers it. That
 * is also the field the failing test names, so a live run and a failing build
 * point at the same place. */
static void discard_project_engine(const struct engine *e) {
  static const struct {
    unsigned int bit;
    const char *src;
  } caps[] = {
      {ENGINE_SAT_CONSTRAINTS_FULL, DSRC_CONSTRAINTS},
      {ENGINE_SAT_RULE_EMIT_OVERFLOW, DSRC_RULE_EMIT},
      {ENGINE_SAT_VRULE_EMIT_OVERFLOW, DSRC_VRULE_EMIT},
      {ENGINE_SAT_ESTIMATE_WORK_FULL, DSRC_ESTIMATE_WORK},
      {ENGINE_SAT_CONFLICTS_FULL, DSRC_CONFLICT_STORE},
      {ENGINE_SAT_VERDICTS_FULL, DSRC_VERDICTS},
      {ENGINE_SAT_CURATION_UNSETTLED, DSRC_CURATION_ROUNDS},
  };
  for (size_t i = 0; i < sizeof(caps) / sizeof(caps[0]); i++)
    if (e->saturation & caps[i].bit)
      kasld_discard_record(DISCARD_CAPACITY, caps[i].src);

  /* One entry per observation a CURATOR removed, attributed to the rule that
   * removed it.
   *
   * An invalid observation is not enough on its own: resolve_evidence() also
   * clears the bit for everything below the run's confidence floor, and that is
   * the two-window design working, not evidence loss — the observation is out
   * of scope for the guaranteed answer and still shapes the likely one. Only a
   * verdict actually targeting the observation makes this a discard, so the
   * lookup is the test, not merely the attribution.
   *
   * Curators can agree: a direct-map address tagged as kernel text is both
   * outside text's VA band and an outlier from the text cluster, and draws a
   * ruling from each. The observation is lost once, so it is counted once, and
   * attributed to the first verdict found. The count is the number that has to
   * be right; the attribution names a rule that did rule on it, not necessarily
   * the only one. */
  for (int i = 0; i < e->ev.n_obs; i++) {
    if (e->ev.obs[i].valid)
      continue;
    for (int v = 0; v < e->ev.n_verdicts; v++)
      if (e->ev.verdicts[v].observation_id == e->ev.obs[i].id) {
        kasld_discard_record(DISCARD_CURATED, e->ev.verdicts[v].origin);
        break;
      }
  }

  /* Constraints the resolver refused. conflicts[] holds ids, so the emitting
   * rule comes from the constraint store — the same lookup
   * engine_report_conflicts does. A conflict whose constraint has aged out of
   * the store is still counted, under an empty source, rather than dropped:
   * the ledger's job is that the discard is visible even when its provenance
   * is not. */
  for (int q = 0; q < Q__COUNT; q++)
    for (int c = 0; c < e->n_conflicts[q]; c++) {
      uint32_t id = e->conflicts[q][c];
      const char *by = NULL;
      for (int i = 0; i < e->n_constraints; i++)
        if (e->constraints[i].id == id) {
          by = e->constraints[i].origin;
          break;
        }
      kasld_discard_record(DISCARD_CONFLICT, by);
    }
}

#ifndef KASLD_TESTING

/* Arch-specific normalization of one copied result, at the ingestion boundary.
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

/* Resolve a name-keyed exclude list into a set of component slots, for the
 * counterfactual posture projection. Names that match no discovered component
 * are ignored. exclude may be NULL. */
static void origin_exclude_set(const char *const *exclude, int n_exclude,
                               struct origin_set *out) {
  memset(out, 0, sizeof(*out));
  if (!exclude)
    return;
  for (int i = 0; i < n_exclude; i++) {
    if (!exclude[i])
      continue;
    for (int c = 0; c < num_components; c++)
      if (strcmp(components[c].name, exclude[i]) == 0) {
        origin_set_add(out, c);
        break;
      }
  }
}

/* True when every component that contributed `origins` is excluded — the
 * record then has no surviving witness and drops out of the projection. A
 * record corroborated by an excluded component AND a retained one stays: the
 * retained component still witnesses it, which is exactly what the
 * counterfactual asks. An empty contributor set is never excluded. */
static int origins_all_excluded(const struct origin_set *origins,
                                const struct origin_set *excluded) {
  int any = 0;
  for (int i = origin_set_next(origins, 0); i >= 0;
       i = origin_set_next(origins, i + 1)) {
    any = 1;
    if (!origin_set_has(excluded, i))
      return 0;
  }
  return any;
}

/* Build the engine's evidence set: a pure copy of what the components produced
 * — the collected address results into address observations, and the collected
 * scalar facts into scalar observations. The orchestrator performs no
 * measurement itself; every fact comes from a component (meminfo_facts,
 * firmware_memmap, riscv64_no_seed, mmap_s390_va_bits, ...). Observations whose
 * producing component is in `exclude` are dropped — the hardening advisor's
 * "what if this leak were closed" projection; pass NULL/0 for the full set. */
static void engine_build_evidence(struct evidence_set *ev,
                                  const char *const *exclude, int n_exclude) {
  struct origin_set excluded;
  origin_exclude_set(exclude, n_exclude, &excluded);

  for (int i = 0; i < num_results; i++) {
    const struct result *r = &results[i];
    if (origins_all_excluded(&r->origins, &excluded))
      continue;
    /* The engine carries one representative origin per observation. Take the
     * lowest contributor slot: discovery order, so the choice is the same on
     * every run regardless of which component finished first. */
    int origin = origin_set_next(&r->origins, 0);

    /* Covering members (pos=extent) are routed to the engine's coverings[],
     * not obs[]: they are complete single-source maps that bypass the
     * cross-source merge (see struct covering and merge_results). They keep
     * their own single origin — the merge never touched them — which is
     * exactly what the map rules group on. */
    if (r->pos == POS_EXTENT) {
      struct covering cv;
      memset(&cv, 0, sizeof(cv));
      cv.type = r->type;
      cv.region = r->region;
      cv.lo = r->lo;
      cv.hi = r->hi;
      cv.conf = r->conf;
      snprintf(cv.origin, ORIGIN_LEN, "%s", kasld_origin_name(origin));
      evidence_add_covering(ev, &cv);
      continue;
    }

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
    snprintf(o.origin, ORIGIN_LEN, "%s", kasld_origin_name(origin));

    bridge_normalize_arch(&o, r);
    evidence_add(ev, &o);
  }

  /* Scalar system facts collected from component `S` records. */
  for (int i = 0; i < num_scalar_facts; i++) {
    if (origin_set_has(&excluded, scalar_facts[i].origin))
      continue;
    struct observation o;
    memset(&o, 0, sizeof(o));
    o.value_kind = OBS_SCALAR;
    o.scalar_fact = scalar_facts[i].fact;
    o.scalar_value = scalar_facts[i].value;
    o.conf = scalar_facts[i].conf;
    snprintf(o.origin, ORIGIN_LEN, "%s",
             kasld_origin_name(scalar_facts[i].origin));
    evidence_add(ev, &o);
  }

  /* Direct constraints collected from component `C` records. */
  for (int i = 0; i < num_constraint_facts; i++) {
    if (origin_set_has(&excluded, constraint_facts[i].origin))
      continue;
    struct observation o;
    memset(&o, 0, sizeof(o));
    o.value_kind = OBS_CONSTRAINT;
    o.c_quantity = constraint_facts[i].q;
    o.c_op = constraint_facts[i].op;
    o.scalar_value = constraint_facts[i].value;
    o.conf = constraint_facts[i].conf;
    snprintf(o.origin, ORIGIN_LEN, "%s",
             kasld_origin_name(constraint_facts[i].origin));
    evidence_add(ev, &o);
  }
}

/* Human/wire token for a constraint op. The single source of truth is the wire
 * table in constraint.h, so the conflict and verbose reporters cannot drift
 * from the token the channel parses. */
static const char *constraint_op_name(enum constraint_op op) {
  const char *w = kasld_constraint_op_wire(op);
  return w ? w : "?";
}

/* Print one rejected constraint, tagged with its window (guaranteed / likely).
 */
static void report_one_conflict(const char *window, int q,
                                const struct constraint *cc) {
  fprintf(stderr,
          "[engine %s] %s: rejected '%s 0x%lx' from %s - contradicts "
          "higher-priority evidence\n",
          window, quantities[q].name, constraint_op_name(cc->op), cc->value,
          cc->origin[0] ? cc->origin : "rule");
}

/* Report the constraints each window's resolver rejected as contradictory, so a
 * noisy or adversarial input that drops evidence is explainable rather than
 * silent. Both windows are reported, labeled: a GUARANTEED conflict is
 * soundness-critical (two at-or-above-floor facts disagree); a LIKELY conflict
 * is usually the resolver correctly overruling a speculative signal with a
 * stronger one. The floored (guaranteed) run overwrites the engine's own
 * conflict set, so the likely window's is read from the g_likely snapshot.
 * Diagnostic only (stderr, --verbose) — the resolved estimates are unchanged.
 */
static void engine_report_conflicts(const struct engine *e) {
  for (int q = 0; q < Q__COUNT; q++)
    for (int c = 0; c < e->n_conflicts[q]; c++) {
      uint32_t id = e->conflicts[q][c];
      for (int i = 0; i < e->n_constraints; i++)
        if (e->constraints[i].id == id) {
          report_one_conflict("guaranteed", q, &e->constraints[i]);
          break;
        }
    }
  if (!g_have_likely)
    return;
  for (int q = 0; q < Q__COUNT; q++)
    for (int c = 0; c < g_likely.n_conflicts[q]; c++) {
      uint32_t id = g_likely.conflicts[q][c];
      for (int i = 0; i < g_likely.n_constraints; i++)
        if (g_likely.constraints[i].id == id) {
          report_one_conflict("likely", q, &g_likely.constraints[i]);
          break;
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

/* Per-constraint dump: every constraint on each quantity, with its op,
 * operand(s), emitting rule, and whether the resolver rejected it. Shows WHAT
 * each source bounds, not just that it does — the way to see which rule pins a
 * quantity's lo/hi. Opt-in via KASLD_DEBUG_CONSTRAINTS so normal --verbose
 * stays uncluttered. Diagnostic only (stderr). */
static void engine_report_constraints(const struct engine *e) {
  if (!getenv("KASLD_DEBUG_CONSTRAINTS"))
    return;
  for (int q = 0; q < Q__COUNT; q++) {
    int header = 0;
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
      if (!header) {
        fprintf(stderr, "[engine] %s constraints:\n", quantities[q].name);
        header = 1;
      }
      const char *o = cc->origin[0] ? cc->origin : "rule";
      const char *tag = rejected ? " [rejected]" : "";
      /* Two-operand ops carry a range / modulus; the rest are a single value
       * against the op symbol from constraint_op_name(). */
      if (cc->op == C_EXCLUDE)
        fprintf(stderr, "[engine]   exclude [0x%016lx, 0x%016lx]  (%s)%s\n",
                cc->value, cc->value2, o, tag);
      else if (cc->op == C_STRIDE)
        fprintf(stderr, "[engine]   stride %lu mod %lu  (%s)%s\n", cc->value,
                cc->value2, o, tag);
      else
        fprintf(stderr, "[engine]   %s 0x%016lx  (%s)%s\n",
                constraint_op_name(cc->op), cc->value, o, tag);
    }
  }
}

/* Report any resolver saturation flags. None of the caps bind on realistic
 * deduped workloads; surfacing a hit makes the dropped-info case observable
 * rather than silent if scale ever grows. Diagnostic only (stderr, --verbose).
 */
/* One reporter for everything the run discarded, rendered from the ledger.
 *
 * The per-cap sentences live here rather than in the ledger because they are
 * prose about a specific store, and prose belongs to the renderer. The ledger
 * holds the fact — reason, source, count — and this maps a source to the
 * sentence that explains what filling it costs. A source with no sentence still
 * prints, generically; nothing is silently skipped. */
static const char *discard_capacity_detail(const char *src) {
  if (strcmp(src, DSRC_RESULTS) == 0)
    return "MAX_RESULTS reached; further observations were dropped at capture";
  if (strcmp(src, DSRC_SCALARS) == 0)
    return "MAX_SCALAR_FACTS reached; further scalar system facts were dropped "
           "at capture";
  if (strcmp(src, DSRC_CONSTRAINT_FACTS) == 0)
    return "MAX_CONSTRAINT_FACTS reached; further direct constraints were "
           "dropped at capture";
  if (strcmp(src, DSRC_COMPONENTS) == 0)
    return "MAX_COMPONENTS reached; the component directory holds more "
           "executables and only the first by name ran";
  if (strcmp(src, DSRC_COMPONENT_LINES) == 0)
    return "allocation failure while capturing component stdout for --verbose";
  if (strcmp(src, DSRC_CONSTRAINTS) == 0)
    return "ENGINE_MAX_CONSTRAINTS reached; later rule emissions in the same "
           "pass were dropped";
  if (strcmp(src, DSRC_RULE_EMIT) == 0)
    return "a constraint rule returned more than ENGINE_RULE_MAX_EMIT; the "
           "excess was dropped";
  if (strcmp(src, DSRC_VRULE_EMIT) == 0)
    return "a verdict rule returned more than ENGINE_RULE_MAX_EMIT; the excess "
           "was dropped";
  if (strcmp(src, DSRC_ESTIMATE_WORK) == 0)
    return "ESTIMATE_MAX_WORK reached in the resolver gather; constraints "
           "beyond the cap were dropped in insertion order";
  if (strcmp(src, DSRC_CONFLICT_STORE) == 0)
    return "ESTIMATE_MAX_CONFLICTS reached; further rejected constraints were "
           "not recorded";
  /* The two below leave the engine reading evidence it had ruled on, so the
   * estimates are not merely looser — they may rest on rejected evidence. */
  if (strcmp(src, DSRC_VERDICTS) == 0)
    return "MAX_VERDICTS reached; a curation ruling was not applied and its "
           "observation stayed in the effective set";
  if (strcmp(src, DSRC_CURATION_ROUNDS) == 0)
    return "curation still emitting after ENGINE_MAX_CURATION_ROUNDS; the "
           "constraint rules ran against partially curated evidence";
  return NULL;
}

static void report_discards(void) {
  int n = kasld_discard_count();
  if (n == 0)
    return;
  fprintf(stderr,
          "[discarded] %u item(s) left the pipeline; the residual entropy "
          "below is an upper bound on what remained reachable\n",
          kasld_discard_total());
  for (int i = 0; i < n; i++) {
    const struct kasld_discard *d = kasld_discard_at(i);
    if (!d) /* bounded by kasld_discard_count(); honour the contract anyway */
      continue;
    const char *detail = d->reason == DISCARD_CAPACITY
                             ? discard_capacity_detail(d->source)
                             : NULL;
    fprintf(stderr, "  %-9s %-20s x%u", kasld_discard_reason_name(d->reason),
            d->source[0] ? d->source : "-", d->count);
    if (detail)
      fprintf(stderr, " — %s", detail);
    fprintf(stderr, "\n");
  }
  if (kasld_discard_truncated())
    fprintf(stderr,
            "  (ledger full at %d distinct kinds; the count above is complete "
            "but the breakdown is not)\n",
            MAX_DISCARDS);
}

static void engine_resolve(struct engine *e) {
  int n_rules = 0, n_vrules = 0;
  const rule_fn *rules = engine_rules(&n_rules);
  const verdict_fn *vrules = engine_verdict_rules(&n_vrules);
  engine_init(e);
  engine_build_evidence(&e->ev, NULL, 0);

  /* Two resolutions are computed from one evidence build (below). Both are pure
   * rule evaluation over the already-collected evidence — no component re-runs,
   * no I/O — so the doubled fixpoint cost is negligible beside the one-shot
   * component execution that produced the evidence. Keep rules cheap: a future
   * rule doing heavy per-pass work would pay that cost twice.
   *
   * Likely window: all signals, floor CONF_BRUTE (the primary resolution).
   * Snapshot its est + constraints for the speculative report. */
  engine_run_full(e, rules, n_rules, vrules, n_vrules);
  memcpy(g_likely.est, e->est, sizeof(g_likely.est));
  g_likely.n_constraints = e->n_constraints;
  memcpy(g_likely.constraints, e->constraints,
         (size_t)e->n_constraints * sizeof(e->constraints[0]));
  /* Capture the likely run's conflicts now, before the guaranteed run below
   * overwrites the engine's own n_conflicts/conflicts. */
  memcpy(g_likely.n_conflicts, e->n_conflicts, sizeof(g_likely.n_conflicts));
  memcpy(g_likely.conflicts, e->conflicts, sizeof(g_likely.conflicts));
  g_have_likely = 1;

  /* Guaranteed window (primary): re-resolve at the sound floor. Clear the
   * likely run's curation first so each run curates only from its own in-scope
   * evidence. Leaves e (= g_auth_engine) holding the guaranteed resolution that
   * engine_sync_authoritative() and compute_kaslr_info() read. */
  e->ev.n_verdicts = 0;
  engine_run_full_floored(e, KASLD_SOUND_FLOOR, rules, n_rules, vrules,
                          n_vrules);

  /* Project after the GUARANTEED run, and only that one. The likely run admits
   * every signal, so it curates and conflicts more freely by design; counting
   * both would present the all-signals view's discards as losses from the
   * answer this tool leads with. */
  discard_project_engine(e);

  if (verbose && plain_output()) {
    engine_report_conflicts(e);
    engine_report_corroboration(e);
    report_discards();
  }
  engine_report_constraints(e); /* opt-in via KASLD_DEBUG_CONSTRAINTS */
}

/* Counterfactual posture for the hardening advisor: re-resolve the guaranteed
 * window over the collected evidence minus the excluded components' leaks, and
 * report the residual entropy. Pure fixpoint re-run (no component
 * re-execution). The engine is ~1.3 MiB — static rather than on the stack; the
 * caller is single-threaded and engine_init() fully resets it each call. Uses
 * the same aligns as the live headline, so kasld_project_posture(NULL, 0)
 * reproduces the displayed current entropy exactly. */
void kasld_project_posture(const char *const *exclude, int n_exclude,
                           struct projected_posture *out) {
  static struct engine pe;
  int n_rules = 0, n_vrules = 0;
  const rule_fn *rules = engine_rules(&n_rules);
  const verdict_fn *vrules = engine_verdict_rules(&n_vrules);
  memset(out, 0, sizeof(*out));
  engine_init(&pe);
  engine_build_evidence(&pe.ev, exclude, n_exclude);
  engine_run_full_floored(&pe, KASLD_SOUND_FLOOR, rules, n_rules, vrules,
                          n_vrules);
  out->available = 1;
  out->vslots = quantity_slots(Q_VIRT_IMAGE_BASE, &pe.est[Q_VIRT_IMAGE_BASE],
                               KASLD_SOUND_FLOOR, pe.constraints,
                               pe.n_constraints, layout.virt_kaslr_align);
  out->vbits = out->vslots > 0 ? ilog2(out->vslots) : 0;
#ifdef KASLR_PHYS_MIN
  out->pslots = quantity_slots(Q_PHYS_IMAGE_BASE, &pe.est[Q_PHYS_IMAGE_BASE],
                               KASLD_SOUND_FLOOR, pe.constraints,
                               pe.n_constraints, layout.phys_kaslr_align);
  out->pbits = out->pslots > 0 ? ilog2(out->pslots) : 0;
#endif
}
#endif /* !KASLD_TESTING (engine_resolve/build need the components+engine.c)   \
        */

#ifdef KASLD_TESTING
/* Engine compiled out: the projection is unavailable by default, so the
 * advisor's projected-posture rows are suppressed (readers gate on
 * out->available). A render test can set kasld_test_projection to make the stub
 * report an available projection:
 *   1 = entropy grows with the exclude-set size (monotone) — exercises the
 *       exposure / load-bearing rows;
 *   2 = entropy is a constant regardless of exclusions — models a base that is
 *       never recoverable, so every suggestion forfeits 0 (the speculative-only
 *       verdict rows);
 *   3 = set-membership: one component ("c_critical") is the sole base pin, so
 *       the base is recoverable (9 bits) only when it is excluded and other
 *       leaks are redundant — exercises the load-bearing and not-required
 *       verdicts in one report. */
int kasld_test_projection = 0;
void kasld_project_posture(const char *const *exclude, int n_exclude,
                           struct projected_posture *out) {
  memset(out, 0, sizeof(*out));
  if (!kasld_test_projection)
    return;
  out->available = 1;
  out->pbits = kasld_test_projection == 3 ? 9 : 8;
  if (kasld_test_projection == 2) {
    out->vbits = 9;
  } else if (kasld_test_projection == 3) {
    int critical_removed = 0;
    for (int i = 0; i < n_exclude; i++)
      if (exclude[i] && strcmp(exclude[i], "c_critical") == 0) {
        critical_removed = 1;
        break;
      }
    out->vbits = critical_removed ? 9 : 0;
  } else {
    out->vbits = 4 + n_exclude;
  }
  out->vslots = 1UL << out->vbits;
  out->pslots = 1UL << out->pbits;
}
#endif

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
 * Every quantity with a reported sink must be projected here. Map of Q_* ->
 * sink (all fields of the global `layout`):
 *   Q_VIRT_IMAGE_BASE  -> virt_kaslr_text_* and virt_image_base_*
 *   Q_VIRT_KASLR_ALIGN -> virt_kaslr_align
 *   Q_PAGE_OFFSET      -> virt_page_offset_* (and virt_page_offset)
 *   Q_PHYS_IMAGE_BASE  -> phys_kaslr_text_*   (decoupled arches)
 *   Q_PHYS_KASLR_ALIGN -> phys_kaslr_align    (decoupled arches)
 *   Q_VMALLOC_BASE     -> virt_vmalloc_base_* (when constrained)
 *   Q_VMEMMAP_BASE     -> virt_vmemmap_base_* (when constrained)
 *   Q_MODULE_BASE      -> virt_module_base_*  (when constrained)
 *   Q_VA_BITS          -> virt_page_offset_unrandomized (via the paging level
 *                         it names; also bounds Q_VIRT_IMAGE_BASE)
 * The compile-time check below trips when Q__COUNT changes — forcing whoever
 * adds a quantity to decide its sink (or document it as intermediate) and bump
 * the count, rather than silently leaving it unprojected. */
typedef char engine_sync_projects_every_quantity[(Q__COUNT == 9) ? 1 : -1];

static void engine_sync_authoritative(const struct engine *e) {
  const struct estimate *vt = &e->est[Q_VIRT_IMAGE_BASE];
  /* Project the resolved virtual-text window onto BOTH the KASLR window
   * (virt_kaslr_text_*, read by the entropy/slot math in compute_kaslr_info)
   * and the kernel image-placement range (virt_image_base_*, read by the
   * rendered memory map). They must stay equal post-resolution or the diagram's
   * "kernel text" band disagrees with the reported "Virtual Image Base" (grade
   * "guaranteed") range. */
  layout.virt_kaslr_text_min = vt->lo;
  layout.virt_kaslr_text_max = vt->hi;
  layout.virt_image_base_min = vt->lo;
  layout.virt_image_base_max = vt->hi;
  if (e->est[Q_VIRT_KASLR_ALIGN].lo)
    layout.virt_kaslr_align = e->est[Q_VIRT_KASLR_ALIGN].lo;

#if TEXT_TRACKS_DIRECTMAP
  /* On coupled arches phys and virt text-base KASLR offsets are locked, so
   * the same slot granularity applies to both. Mirror the resolved virt
   * align into the phys-side field so entropy/slot reporting on coupled
   * arches reflects the actual CONFIG_PHYSICAL_ALIGN rather than the
   * compile-time default. (The !TEXT_TRACKS_DIRECTMAP branch below syncs
   * Q_PHYS_KASLR_ALIGN independently on decoupled arches.) */
  if (e->est[Q_VIRT_KASLR_ALIGN].lo)
    layout.phys_kaslr_align = e->est[Q_VIRT_KASLR_ALIGN].lo;
#endif

  /* The rendered min/max are the window CONTAINING every admitted value, which
   * is what the map draws as the direct-map band's uncertainty. On a lattice
   * that can hold gaps this is wider than the live set — the right direction
   * for a band, which must not appear narrower than the evidence supports. */
  quantity_window(Q_PAGE_OFFSET, &e->est[Q_PAGE_OFFSET],
                  &layout.virt_page_offset_min, &layout.virt_page_offset_max);

  /* Project the resolved direct-map base onto the rendered singular field
   * whenever the engine has pinned it. On coupled arches PAGE_OFFSET equals
   * the compile-time default on the common configuration, so this is normally
   * a no-op — but a runtime-detected VMSPLIT (arm32 vmsplit_text_base) can pin
   * it to a different boundary, and the render must follow the engine rather
   * than show the compile-time seed. (The decoupled, possibly-unpinned
   * RANDOMIZE_MEMORY case is handled by the block below.) */
  {
    unsigned long po_pin;
    if (quantity_pinned(Q_PAGE_OFFSET, &e->est[Q_PAGE_OFFSET], &po_pin) &&
        po_pin != 0)
      layout.virt_page_offset = po_pin;
  }

#if RANDOMIZE_MEMORY_ALIGN > 0
  /* The base the direct map slid away from, selected by the paging level the
   * engine resolved. Q_VA_BITS is read here rather than the budget model's
   * b.lo, which is the same address: the budget also declines when
   * SF_PHYS_MAX_PFN is missing or below the floor, and neither says anything
   * about which level is in force. Taking the level directly gives the sharper
   * gate -- this base whenever the level is known, the budget's denominator
   * only when the whole model holds.
   *
   * e is the guaranteed resolution, so the level arrives at the sound floor
   * without asking, which is the right bar for a fact about the machine. Left
   * at 0 where the level is unresolved; nothing downstream measures from a
   * default. */
  {
    unsigned long va_bits;
    struct kasld_rm_level lv;
    if (estimate_finset_value(&quantities[Q_VA_BITS], &e->est[Q_VA_BITS],
                              &va_bits) &&
        kasld_rm_level_for(va_bits, &lv))
      layout.virt_page_offset_unrandomized = lv.vaddr_start;
  }
#endif

#if !TEXT_TRACKS_DIRECTMAP
  /* On decoupled arches the direct-map base (PAGE_OFFSET) is randomized away
   * from the compile-time floor (x86_64 RANDOMIZE_MEMORY). Anchor the rendered
   * memory map's direct-map band at the engine's best-known base (pinned, or
   * the proven lower bound). Gated on lo having actually been raised above the
   * compile-time default, so the claim never exceeds what the engine proved.
   *
   * Only layout.virt_page_offset moves — NOT layout.virt_kernel_vas_start. On a
   * decoupled arch the direct-map base is the lowest kernel *mapping* but NOT
   * the VAS floor: the architectural KERNEL_VIRT_VAS_START (the canonical-hole
   * top) sits far below it, and the map's bottom should show that floor with
   * the directmap-base-uncertainty gap above it, not pretend the address space
   * begins at the directmap base. */
  {
    const struct estimate *po = &e->est[Q_PAGE_OFFSET];
    unsigned long po_lo;
    if (quantity_window(Q_PAGE_OFFSET, po, &po_lo, NULL) &&
        po_lo > (unsigned long)PAGE_OFFSET)
      layout.virt_page_offset = po_lo;
  }

  const struct estimate *pt = &e->est[Q_PHYS_IMAGE_BASE];
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
  if (e->est[Q_MODULE_BASE].lo_binding)
    layout.virt_module_base_min = e->est[Q_MODULE_BASE].lo;
  if (e->est[Q_MODULE_BASE].hi_binding)
    layout.virt_module_base_max = e->est[Q_MODULE_BASE].hi;

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
   *     to _SEGMENT_SIZE; band high edge ≈ text_min − IMAGE_BASE_OFFSET.
   *
   * 2 GiB is the MODULES_LEN on both arches; absent a per-arch macro, use
   * the literal constant with this rationale. Gated on virt_image_base_max
   * being a meaningful (narrowed-or-pinned) value — the static band stays
   * when the engine has not narrowed text. */
#define KASLD_MODULES_LEN (2ul * 1024 * 1024 * 1024)
  if (vt->hi > vt->lo || vt->lo > (unsigned long)KASLR_VIRT_TEXT_MIN) {
#if MODULES_BELOW_TEXT_START
    unsigned long band_end = vt->lo > (unsigned long)IMAGE_BASE_OFFSET
                                 ? vt->lo - (unsigned long)IMAGE_BASE_OFFSET
                                 : vt->lo;
#else
    unsigned long band_end = vt->hi;
#endif
    unsigned long band_start =
        (band_end > KASLD_MODULES_LEN) ? (band_end - KASLD_MODULES_LEN) : 0ul;
    /* A projection is only worth adopting when it lands somewhere. When the
     * text window still reaches the bottom of the arch's kernel VAS the
     * subtractions above saturate -- on MODULES_BELOW_TEXT_START arches
     * IMAGE_BASE_OFFSET is itself the default text floor, so an unnarrowed
     * vt->lo drives band_end to 0 and band_start with it -- and adopting that
     * writes a degenerate band the map then draws as `modules (pinned)` at
     * address 0: a pin claim at an address nothing was proven about, and a
     * validation range that rejects every real module leak. Reject any
     * projection that collapses (inverted, empty, or anchored at 0) and keep
     * the static band instead; per the output contract an absent narrowing
     * says nothing was proven, which is exactly the state here. Stated as a
     * general well-formedness test, not an arch case: the same saturation is
     * reachable on any arch whose text floor sits at the VAS floor. */
    if (band_start && band_end > band_start) {
      layout.modules_start = band_start;
      layout.modules_end = band_end;
    }
  }
#undef KASLD_MODULES_LEN
#endif

  /* The module region's validation union. Compile-time by default. */
  unsigned long mod_union_lo = (unsigned long)MODULES_START;
  unsigned long mod_union_hi = (unsigned long)MODULES_END;

#if MODULES_RELATIVE_TO_PAGE_OFFSET
  /* Re-derive the module band once the engine has something to say about
   * PAGE_OFFSET. The arch defines the band as a delta from PAGE_OFFSET, so the
   * compile-time MODULES_START/END describe where the modules sit under the
   * COMPILE-TIME split only. On arm32 a runtime VMSPLIT of 0x80000000 leaves
   * them 1 GiB high -- the map drew the module band inside what the same map
   * labelled user space -- and, because region_info validates module addresses
   * against this band, every genuine module leak from such a kernel is
   * rejected. The band must follow the resolved PAGE_OFFSET.
   *
   * Uncertainty is inherited, not discarded. The engine's PAGE_OFFSET estimate
   * is a window; the derived band is that window's image, so:
   *   - pinned  (lo == hi): the band collapses to the exact placement;
   *   - a proven floor/window that EXCLUDES the compile-time PAGE_OFFSET: the
   *     split provably moved but the engine has not said where, so the band is
   *     the union over the whole window -- wider, correspondingly less precise,
   *     and still guaranteed to contain the real band. Drawing the
   *     compile-time band here would state a location that was just disproved.
   *   - a window that still admits the compile-time PAGE_OFFSET: nothing has
   *     been proven and nothing contradicted, so the band is left alone.
   * The derived union is never narrower than the truth, so it cannot silently
   * reject a real module leak -- the failure mode the union contract guards. */
  {
    const struct estimate *po = &e->est[Q_PAGE_OFFSET];
    unsigned long po_lo = 0, po_hi = 0, po_pin = 0;
    int have = quantity_window(Q_PAGE_OFFSET, po, &po_lo, &po_hi);
    int pinned = quantity_pinned(Q_PAGE_OFFSET, po, &po_pin) && po_pin != 0;
    /* Ask the estimate whether the compile-time split is still admitted rather
     * than comparing it against the window edges: on a lattice that can hold
     * gaps, an edge comparison still calls an excluded interior value
     * possible, and this test is what decides whether the band may move off
     * that split at all. */
    int default_excluded =
        !quantity_admits(Q_PAGE_OFFSET, po, (unsigned long)PAGE_OFFSET);
    if (have && po_lo && (pinned || default_excluded)) {
      unsigned long lo = MODULES_START_FOR(po_lo);
      unsigned long hi = MODULES_END_FOR(po_hi);
      /* Reject a wrapped floor; do NOT clamp it to KERNEL_VIRT_VAS_START. On
       * every arch that carves the module band out of vmalloc the band
       * legitimately sits BELOW PAGE_OFFSET, and on those KERNEL_VIRT_VAS_START
       * *is* PAGE_OFFSET -- clamping there would discard the whole band and
       * reject every genuine module leak, the exact failure the union contract
       * above exists to prevent. Same wrap test that
       * rules/module_base_bounds.c applies to these edges. */
      if (kasld_module_band_floor_sane(po_lo, lo) && hi > lo) {
        mod_union_lo = lo;
        mod_union_hi = hi;
        layout.modules_start = lo;
        layout.modules_end = hi;
      }
    }
  }
#endif

  /* Runtime module-band anchoring (every arch).
   *
   * The compile-time MODULES_START/END is the validation UNION across all
   * in-scope kernel-version layouts -- wide on purpose so no real module
   * leak is silently rejected. When proc_modules or sysfs_module_sections
   * have supplied actual module addresses (emitted as VIRT REGION_MODULE
   * or REGION_MODULE_BAND observations), the runtime band lives in a
   * much smaller span. Tightening the rendered/JSON layout to that
   * observed span makes the diagram reflect reality on this kernel, and
   * replaces the static MODULES_START/END display for arches whose true
   * region is a fraction of the union (currently arm64 v6.2+ at ~2 GiB
   * within a ~128 TiB static union).
   *
   * Soundness: the observed bounds are clamped to the validation union;
   * the bounds never widen past what MODULES_START/END allows. If
   * observations fall entirely outside the union (which would indicate an
   * unmodelled kernel layout), keep the static window — surfacing the
   * discrepancy via the wider rendering is more useful than silently
   * shrinking to a single bogus point. */
  {
    unsigned long obs_lo = ULONG_MAX, obs_hi = 0;
    for (int i = 0; i < e->ev.n_obs; i++) {
      const struct observation *o = &e->ev.obs[i];
      if (!o->valid || o->value_kind != OBS_ADDRESS ||
          o->eff_type != KASLD_TYPE_VIRT)
        continue;
      if (o->eff_region != REGION_MODULE && o->eff_region != REGION_MODULE_BAND)
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
    /* Clamped to the validation union, which on a PAGE_OFFSET-relative arch is
     * the re-derived one above rather than the compile-time macros: gating a
     * runtime observation on the compile-time band is what dropped genuine
     * module leaks from a moved-split kernel. mod_union_lo is a variable, so
     * the s390 case (union floor 0, making the lower clause vacuous) no longer
     * needs a preprocessor gate to avoid -Wtype-limits. */
    int in_modules = obs_lo != ULONG_MAX && obs_lo <= obs_hi &&
                     obs_hi <= mod_union_hi && obs_lo >= mod_union_lo;
    if (in_modules) {
      layout.modules_start = obs_lo;
      layout.modules_end = obs_hi;
    }
  }

  /* Candidate counts, last: every window and alignment this reads is final by
   * here, and the count must be taken from the same resolution as the window it
   * counts. quantity_slots() is the only answer that carves the estimate's
   * interior C_EXCLUDE holes; the alignments are the engine-resolved ones
   * projected above, not the compile-time defaults.
   *
   * Counted unconditionally. Whether a count is worth PRESENTING is a question
   * about the window's shape -- both edges known, and so on -- which the
   * summary builder asks where those edges are in hand. Gating here instead
   * would put a presentation rule in the projection and answer it from fields
   * that do not exist yet. */
  layout.virt_kaslr_slots = quantity_slots(
      Q_VIRT_IMAGE_BASE, &e->est[Q_VIRT_IMAGE_BASE], KASLD_SOUND_FLOOR,
      e->constraints, e->n_constraints, layout.virt_kaslr_align);
  /* Both image-base counts are taken here, on every arch. The phys window is
   * projected under !TEXT_TRACKS_DIRECTMAP above because only a decoupled arch
   * resolves it separately; the count is still meaningful on a coupled arch,
   * where the estimate carries the locked-to-virt window. */
  layout.phys_kaslr_slots = quantity_slots(
      Q_PHYS_IMAGE_BASE, &e->est[Q_PHYS_IMAGE_BASE], KASLD_SOUND_FLOOR,
      e->constraints, e->n_constraints, layout.phys_kaslr_align);
  layout.virt_page_offset_slots =
      quantity_slots(Q_PAGE_OFFSET, &e->est[Q_PAGE_OFFSET], KASLD_SOUND_FLOOR,
                     e->constraints, e->n_constraints, RANDOMIZE_MEMORY_ALIGN);
  layout.virt_vmalloc_slots =
      quantity_slots(Q_VMALLOC_BASE, &e->est[Q_VMALLOC_BASE], KASLD_SOUND_FLOOR,
                     e->constraints, e->n_constraints, RANDOMIZE_MEMORY_ALIGN);
  layout.virt_vmemmap_slots =
      quantity_slots(Q_VMEMMAP_BASE, &e->est[Q_VMEMMAP_BASE], KASLD_SOUND_FLOOR,
                     e->constraints, e->n_constraints, RANDOMIZE_MEMORY_ALIGN);
  /* The module base is page-granular on every arch that randomizes it (x86_64
   * draws a whole number of pages; the arm64 bounding box and the
   * PAGE_OFFSET-derived bands are page-aligned), so PAGE_SIZE is the pitch
   * rather than RANDOMIZE_MEMORY_ALIGN, which is an x86_64 memory-KASLR
   * constant and 0 elsewhere. */
  layout.virt_module_slots =
      quantity_slots(Q_MODULE_BASE, &e->est[Q_MODULE_BASE], KASLD_SOUND_FLOOR,
                     e->constraints, e->n_constraints, PAGE_SIZE);
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
static int set_ascii(const char *val) {
  (void)val;
  unicode_output = 0;
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
static int set_map(const char *val) {
  (void)val;
  map_mode = 1;
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
     "Show component output, KASLR analysis, address-space diagram", 0, 0},
    {"-e", "--explain", 0, NULL, OPT_SECT_DETAIL, set_explain,
     "Show technique explanations before each component (implies --verbose)", 0,
     0},
    {"-q", "--quiet", 0, NULL, OPT_SECT_DETAIL, set_quiet,
     "Suppress banner, progress, and warnings", 0, 0},
    {"-c", "--color", 0, NULL, OPT_SECT_DETAIL, set_color,
     "Colourize text output (auto for TTYs; honours NO_COLOR / CLICOLOR)", 0,
     0},
    {"-a", "--ascii", 0, NULL, OPT_SECT_DETAIL, set_ascii,
     "ASCII-only output: no Unicode glyphs or banner (auto in a non-UTF-8 "
     "locale)",
     0, 0},
    {"-H", "--hardening", 0, NULL, OPT_SECT_DETAIL, set_hardening,
     "Append the hardening assessment to text/markdown output", 0, 0},
    /* Long form only: -m is --markdown, and a -m/-M pair between two flags
     * that both reshape output is a shift-slip away from silently swapping a
     * diagram for a Markdown document. */
    {NULL, "--map", 0, NULL, OPT_SECT_DETAIL, set_map,
     "Draw the address-space diagram (implied by --verbose)", 0, 0},

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
    /* A long-only option has no short_name; indent its long form to the column
     * the long forms occupy so the list stays aligned. */
    if (!o->short_name)
      snprintf(prefix, sizeof(prefix), "      %s%s%s", o->long_name,
               o->arg_name ? " " : "", o->arg_name ? o->arg_name : "");
    else if (o->arg_name)
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
    /* short_name is NULL for a long-only option (see the struct comment); it
     * occupies the same indent width its "-x, " prefix would have. */
    int len = (int)strlen("  ") +
              (opts[i].short_name
                   ? (int)strlen(opts[i].short_name) + (int)strlen(", ")
                   : (int)strlen("    ")) +
              (int)strlen(opts[i].long_name);
    if (opts[i].arg_name)
      len += 1 + (int)strlen(opts[i].arg_name);
    if (len > col)
      col = len;
  }
  printf("Usage: %s [OPTIONS]\n\n", progname);
  for (int s = 0; s < OPT_SECT__COUNT; s++)
    usage_print_section((enum opt_section)s, col);
  printf("Short flags may be bundled: -fq is -f -q. A value-taking flag "
         "(-s/-t/-w)\nmay appear only last in a bundle, taking the next "
         "argument.\n");
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

/* Apply option `o`, consuming argv[*i + 1] as its value if it takes one (and
 * advancing *i past it). Returns the handler's exit code (0 = ok), or 2 if a
 * value-taking option is missing its value. Shared by the whole-token and the
 * bundled-short-flag paths in main(). */
static int apply_opt(const struct opt *o, int *i, int argc, char *argv[]) {
  const char *val = NULL;
  if (o->takes_arg) {
    if (*i + 1 >= argc) {
      fprintf(stderr, "%s requires a value\n", o->long_name);
      return 2;
    }
    val = argv[++(*i)];
  }
  return o->set(val);
}

/* Name the components the orchestrator killed, so a run with kills is
 * distinguishable from a clean one in the report itself rather than only in
 * the run narration the progress bar scrolls past. Silent when every component
 * was reaped normally. Names beyond the first three fold into a count, the
 * same way leak provenance does.
 *
 * Subdued rather than coloured as a caution: a kill costs coverage, never
 * soundness. Only whole lines a component emitted before it died are read, so
 * one that is killed contributes fewer observations and the resolved windows
 * come back wider -- never wrong. A warning colour here would rank a note
 * about this tool's own run alongside the findings, and imply the values above
 * it are suspect. */
static void report_killed_components(void) {
  const char *names[3];
  int shown = 0, n = 0;
  for (int i = 0; i < num_components; i++) {
    if (!comp_logs[i].ran || comp_logs[i].outcome != OUTCOME_TIMEOUT)
      continue;
    if (shown < (int)(sizeof(names) / sizeof(names[0])))
      names[shown++] = comp_logs[i].name;
    n++;
  }
  if (n == 0)
    return;

  printf("%s%d component%s timed out after %ds and %s killed (", c(C_DIM), n,
         n == 1 ? "" : "s", component_timeout, n == 1 ? "was" : "were");
  for (int i = 0; i < shown; i++)
    printf("%s%s", i ? ", " : "", names[i]);
  if (n > shown)
    printf(", +%d more", n - shown);
  printf(")%s\n", c(C_RESET));
}

/* Orchestration-layer summary emit: build the summary, run resolution (stats,
 * defaults, then the engine via compute_kaslr_info), and hand the finished
 * summary to the renderer. Resolution lives here, not in render.c — the
 * renderer is a pure consumer. */
static void emit_summary(void) {
  struct summary s = {0};
  compute_component_stats(&s);
  summarize_kaslr_state(&s);
  /* Resolution runs HERE, at the single caller, not inside the summary builder:
   * a function named for building a summary should not also own when the engine
   * runs. compute_kaslr_info() is then a pure layout+snapshot -> summary
   * projection, which is what lets it compile (and be tested) whole rather than
   * with its engine-dependent two thirds cut out by the preprocessor. */
#ifndef KASLD_TESTING
  engine_resolve(&g_auth_engine);
  engine_sync_authoritative(&g_auth_engine);
  compute_kaslr_info(&s, &g_auth_engine, g_have_likely ? &g_likely : NULL);
#else
  compute_kaslr_info(&s, NULL, NULL);
#endif
  /* cross-region derivations arrive as ordinary CONF_DERIVED component results;
   * there is no separate derive pass. */
  render_summary(&s);
}

int main(int argc, char *argv[]) {
  /* Statics start zeroed, so this is a no-op for the process that runs once.
   * It is here so the ledger's lifetime is stated rather than inherited from
   * BSS, which is what a test driving several runs in one process relies on. */
  kasld_discard_reset();

  /* Default to nproc workers; --workers overrides */
  {
    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    parallel_workers = (ncpu > 1) ? (int)ncpu : 4;
  }

  /* Unicode vs ASCII output. Honour the locale codeset: a non-UTF-8 locale
   * (C/POSIX, or a legacy 8-bit terminal) cannot render the box-art banner or
   * the check/cross/arrow glyphs, so fall back to ASCII. --ascii forces this
   * regardless of locale (e.g. a screen reader on a UTF-8 system). The machine
   * formats (-j/-1) carry no glyphs and are unaffected. */
  setlocale(LC_CTYPE, "");
  {
    const char *cs = nl_langinfo(CODESET);
    unicode_output = cs && (strstr(cs, "UTF-8") || strstr(cs, "UTF8"));
  }

  /* Table-driven option walk. Each match either runs the handler with the
   * option's value (NULL for flags) or — for early-exit options like
   * --version / --help — sets a sentinel checked after the loop. */
  for (int i = 1; i < argc; i++) {
    const char *arg = argv[i];
    const struct opt *o = opt_find(arg);
    if (o) {
      int rc = apply_opt(o, &i, argc, argv);
      if (rc != 0)
        return rc;
      continue;
    }
    /* Bundled single-dash short flags: "-fq" == "-f" "-q". Only a single-dash
     * token of length >= 3 that did not match as a whole (long "--" options and
     * two-char short flags took the path above). A value-taking flag (-s/-t/-w)
     * may appear only as the last char, taking the next argument. */
    if (arg[0] == '-' && arg[1] != '-' && arg[1] != '\0' && arg[2] != '\0') {
      int bad = 0;
      for (int k = 1; arg[k] != '\0'; k++) {
        char sh[3] = {'-', arg[k], '\0'};
        const struct opt *so = opt_find(sh);
        if (!so) {
          fprintf(stderr, "unknown option: -%c (in '%s')\n", arg[k], arg);
          bad = 1;
          break;
        }
        if (so->takes_arg && arg[k + 1] != '\0') {
          fprintf(stderr, "-%c takes a value, so it must be last in '%s'\n",
                  arg[k], arg);
          bad = 1;
          break;
        }
        int rc = apply_opt(so, &i, argc, argv);
        if (rc != 0)
          return rc;
      }
      if (bad) {
        usage(argv[0]);
        return 2;
      }
      continue;
    }
    fprintf(stderr, "unknown option: %s\n", arg);
    usage(argv[0]);
    return 2;
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
   * a courtesy diagnostic — surfacing that two formats were asked for before
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

  /* Colour policy for text output (the machine formats never colour, so this is
   * gated on plain_output()). Precedence, highest first:
   *   --color / CLICOLOR_FORCE (non-empty, != "0"): force on. An explicit
   *     request is deliberate intent, so it beats NO_COLOR.
   *   NO_COLOR present (any value, incl. empty): off (https://no-color.org).
   *   CLICOLOR=0: off (BSD convention).
   *   otherwise: on when stdout is a TTY. */
  if (plain_output()) {
    const char *clicolor_force = getenv("CLICOLOR_FORCE");
    const char *clicolor = getenv("CLICOLOR");
    if (color_output || (clicolor_force && clicolor_force[0] &&
                         strcmp(clicolor_force, "0") != 0))
      color_output = 1;
    else if (getenv("NO_COLOR") != NULL)
      color_output = 0;
    else if (clicolor && strcmp(clicolor, "0") == 0)
      color_output = 0;
    else
      color_output = isatty(STDOUT_FILENO);
  }

  /* Take the environment before anything else looks at the system: every
   * format's readout, the "KASLR disabled" branch and the hardening advisor
   * read it, and the advisor weighs a component's denial against the settings
   * that were in force while that component ran. Taken here, they were.
   *
   * The banner and the system-config block live behind --verbose (or
   * --hardening, which consumes the same state in its own report); the default
   * text mode renders a tight readout instead. Both render the snapshot. */
  kasld_env_snapshot();
  if (verbose && !quiet && plain_output()) {
    render_banner();
    render_system_config();
  }

  /* A build narrower than the target kernel cannot model it. The arch header is
   * selected by THIS binary's architecture, so every window resolved from here
   * would describe an address space the kernel does not have — and on a coupled
   * architecture correctly-read physical bounds would be projected through the
   * wrong linear map into a virtual window that cannot contain the base. The
   * parse layer already refuses individual addresses it cannot represent; this
   * refuses the analysis. */
  {
    const char *sysroot_env = getenv("KASLD_SYSROOT");
    struct kasld_width_check w =
        kasld_check_target_width(sysroot_env && *sysroot_env);
    if (w.verdict == KASLD_WIDTH_MISMATCH) {
      char detail[160];
      if (w.signal == KASLD_WIDTH_SIGNAL_TASK_SIZE)
        snprintf(detail, sizeof(detail),
                 "%s: %#lx, above this architecture's highest split (%#lx)",
                 kasld_width_signal_name(w.signal), w.task_size,
                 (unsigned long)PAGE_OFFSET_MAX);
      else
        snprintf(detail, sizeof(detail),
                 "%s: %d hex digits, a %d-bit kernel pointer",
                 kasld_width_signal_name(w.signal), w.kallsyms_hex_digits,
                 w.kallsyms_hex_digits * 4);

      fprintf(stderr,
              "[-] target kernel addresses more widely than this build can "
              "represent\n");
      fprintf(stderr, "[-]   %s\n", detail);
      fprintf(stderr, "[-] run the build matching the kernel's word size\n");

      /* What the machine formats emit here is decided per format, because the
       * right answer differs:
       *
       * json      an object carrying ONLY the refusal. It has no `kaslr` or
       *           `layout` key, because a document describing this build's
       *           address space would describe one the kernel does not have,
       *           which is the whole reason for declining. A consumer reaching
       *           for a layout field finds nothing, exactly as before, but one
       *           that logs the document now learns why.
       * markdown  a short section, for the same reason a human reading the
       *           text mode gets the message on stderr.
       * oneline   nothing at all. Its schema fixes the key set on every line,
       *           so a partial line would break that contract, and a full
       *           line of `na` values is indistinguishable from the hardened
       *           host that yields nothing (exit 1) — the one distinction that
       *           matters here. Absence plus the exit code stays honest. */
      if (json_output) {
        printf("{\n  \"error\": {\n    \"code\": \"target_width_mismatch\",");
        printf("\n    \"message\": ");
        json_print_escaped("target kernel addresses more widely than this "
                           "build can represent");
        printf(",\n    \"detail\": ");
        json_print_escaped(detail);
        printf(",\n    \"action\": ");
        json_print_escaped("run the build matching the kernel's word size");
        printf("\n  }\n}\n");
      } else if (markdown_output) {
        printf("# KASLD\n\n## Analysis declined\n\n");
        printf("The target kernel addresses more widely than this build can "
               "represent, so no layout is reported: the model comes from this "
               "binary's architecture and would describe an address space the "
               "kernel does not have.\n\n");
        printf("- Observed: %s\n", detail);
        printf("- Action: run the build matching the kernel's word size\n");
      }
      return 3;
    }
  }

  if (discover_components() < 0)
    return 2;

  classify_components();
  validate_component_phases();
  apply_skip_filter();
  apply_sysroot_filter();

  /* Verbose: list components excluded by --skip or, under KASLD_SYSROOT, by the
   * offline live-probe filter (apply_sysroot_filter). */
  if (verbose && plain_output()) {
    const char *sysroot = getenv("KASLD_SYSROOT");
    int offline = sysroot && *sysroot;
    for (int i = 0; i < num_components; i++) {
      if (!components[i].is_filtered)
        continue;
      if (offline && components[i].is_live)
        printf("[.] skipping %s (live probe, not replayable under "
               "KASLD_SYSROOT)\n",
               components[i].name);
      else
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
    printf("%sKASLD %s%s  --  Kernel ASLR derandomization\n", c(C_BOLD),
           VERSION, c(C_RESET));
    struct utsname u;
    if (kasld_uname(&u) == 0)
      printf("%sTarget: %s / %s%s\n", c(C_DIM), u.machine, u.release,
             c(C_RESET));
    printf("\n");

    clock_gettime(CLOCK_MONOTONIC, &progress_start);
    progress_total =
        num_active_components > 0 ? num_active_components : num_components;
    int exp_active =
        experimental_mode || (getenv("KASLD_EXPERIMENTAL") != NULL);
    int nf = 0, ne = 0;
    for (int i = 0; i < num_components; i++) {
      if (components[i].is_filtered)
        nf++;
      else if (components[i].is_experimental && !exp_active)
        ne++;
    }
    /* Under KASLD_SYSROOT the filtered set also includes live probes skipped
     * for offline analysis (not just --skip), so word the count neutrally. */
    const char *sysroot = getenv("KASLD_SYSROOT");
    const char *skipped_by =
        (sysroot && *sysroot) ? "skipped" : "skipped by --skip";
    /* "N of M" rather than a bare N: the skipped counts that follow are
     * excluded from N, so a bare count reads either way. */
    if (num_active_components == 0) {
      /* Every discovered component was filtered out, so the result below is
       * the engine's leak-free structural inference rather than a scan. Name
       * which filter emptied the set: the three causes (--skip, experimental
       * gating, KASLD_SYSROOT dropping live probes) need different responses.
       * A component directory that is missing or empty cannot reach here --
       * discover_components() fails the run before any output. */
      if (nf > 0 && ne > 0)
        printf("Structural baseline: no components ran (%d %s, %d experimental;"
               " use -x to enable)\n",
               nf, skipped_by, ne);
      else if (nf > 0)
        printf("Structural baseline: no components ran (all %d %s)\n", nf,
               skipped_by);
      else if (ne > 0)
        printf("Structural baseline: no components ran (all %d experimental;"
               " use -x to enable)\n",
               ne);
      else
        printf("Structural baseline: no components ran\n");
    } else if (nf > 0 && ne > 0)
      printf("Running %d of %d components (%d %s, %d experimental "
             "skipped; use -x to enable)...\n",
             num_active_components, num_components, nf, skipped_by, ne);
    else if (nf > 0)
      printf("Running %d of %d components (%d %s)...\n", num_active_components,
             num_components, nf, skipped_by);
    else if (ne > 0)
      printf("Running %d of %d components (%d experimental skipped; "
             "use -x to enable)...\n",
             num_active_components, num_components, ne);
    else
      printf("Running %d components...\n", num_active_components);
    fflush(stdout);
  }

  /* Seed the engine-bounds carrier with the honest compile-time window.
   * engine_sync_authoritative() (run from compute_kaslr_info) then overwrites
   * each edge a rule actually bound, and only those — so what is seeded here is
   * exactly what an unconstrained edge goes on to report. */
  /* The linear-map base's own bracket, not the kernel VAS. Those are different
   * quantities: loongarch64's address space starts a full exabyte below the
   * lowest base it admits, and reading the VAS edge as "the lowest admissible
   * PAGE_OFFSET" is the conflation this model exists to remove. Seeding from
   * the quantity's honest top also makes "nothing was learned" mean exactly
   * "still at the top", which is what page_offset_narrowed() tests. */
  layout.virt_page_offset_min = (unsigned long)PAGE_OFFSET_MIN;
  layout.virt_page_offset_max = (unsigned long)PAGE_OFFSET_MAX;
  /* Seeded from each quantity's honest top, exactly as virt_page_offset above,
   * so an untightened edge is a real bound rather than a sentinel. A sentinel
   * cannot express "no bound known" for these quantities at all:
   * KERNEL_VIRT_VAS_END IS ULONG_MAX on x86_64, so any marker outside the
   * address space is indistinguishable from a legitimate upper bound.
   *
   * The module region is seeded on every architecture: all of them place
   * modules somewhere, and every format names the quantity unconditionally.
   *
   * vmalloc and vmemmap are seeded only where the architecture randomizes them.
   * Elsewhere they are not quantities at all — the engine never constrains them
   * (see top_kernel_vas_window), and the formats name them only under this same
   * RANDOMIZE_MEMORY_ALIGN, so a window here would have the machine formats
   * report a quantity the readout does not. Both stay at their static zero,
   * which every format omits alike. */
  {
    struct estimate t;
    quantities[Q_MODULE_BASE].init_top(&t);
    quantity_window(Q_MODULE_BASE, &t, &layout.virt_module_base_min,
                    &layout.virt_module_base_max);
#if RANDOMIZE_MEMORY_ALIGN > 0
    quantities[Q_VMALLOC_BASE].init_top(&t);
    quantity_window(Q_VMALLOC_BASE, &t, &layout.virt_vmalloc_base_min,
                    &layout.virt_vmalloc_base_max);
    quantities[Q_VMEMMAP_BASE].init_top(&t);
    quantity_window(Q_VMEMMAP_BASE, &t, &layout.virt_vmemmap_base_min,
                    &layout.virt_vmemmap_base_max);
#endif
  }

  /* Before the first component: what the arch settles at compile time goes in
   * while the table is empty and cannot be crowded out of it. */
  seed_arch_kaslr_facts();

  for (int p = 0; p < (int)(sizeof(phases) / sizeof(phases[0])); p++)
    run_phase(&phases[p]); /* merges results after each phase */

  if (!quiet && !verbose && plain_output()) {
    progress_finish();
    printf("\n");
    report_killed_components();
    printf("\n");
  }

  /* The KASLR default-window analysis and, with -H, the hardening assessment
   * are meaningful even with zero leaks — a hardened host that yields nothing
   * is the success case, not an error — so every format renders the summary.
   * The exit code still distinguishes "found leaks" (0) from "none" (1). */
  emit_summary();
  return num_results > 0 ? 0 : 1;
}
#endif /* !KASLD_TESTING */
