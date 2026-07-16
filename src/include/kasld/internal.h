// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Internal header for kasld orchestrator. Shared types and extern
// declarations between orchestrator.c, render.c, and the region_info table.
//
// Components don't include this — they only need kasld/api.h.
// ---
// <bcoles@gmail.com>

#ifndef KASLD_INTERNAL_H
#define KASLD_INTERNAL_H

#include "api.h"
#include "regions.h" /* canonical is_phys_dram_region / is_kernel_image_region */

#include <stddef.h>
#include <stdint.h>

#ifndef VERSION
#define VERSION "unknown"
#endif

/* =========================================================================
 * Constants
 * =========================================================================
 */
#define MAX_COMPONENTS 128
#define MAX_RESULTS 4096
#define NAME_LEN 48   /* specific instance: kernel symbol, ACPI ID, BDF, ... */
#define ORIGIN_LEN 64 /* component name (orchestrator-filled) */
/* A merged record can be corroborated by at most every component, so size its
 * provenance to the structural maximum — overflow is impossible by
 * construction. */
#define MAX_PROVENANCE MAX_COMPONENTS
/* Captured-stdout lines are kept only for --verbose / --json output. The log
 * is grown geometrically on demand from this initial capacity; there is no
 * hard cap (the previous fixed cap of 64 silently truncated noisy components).
 * Non-verbose runs never allocate. */
#define COMPONENT_LINES_INITIAL_CAP 16
#define MAX_LINE_LEN 512

/* =========================================================================
 * ANSI color helpers (gated by color_output flag)
 * =========================================================================
 */
#define C_RESET "\033[0m"
#define C_BOLD "\033[1m"
#define C_DIM "\033[2m"
#define C_GREEN "\033[32m"
#define C_YELLOW "\033[33m"
#define C_RED "\033[31m"
#define C_CYAN "\033[36m"
#define C_MAGENTA "\033[35m"

extern int color_output; /* forward declaration for c() */
static inline const char *c(const char *code) {
  return color_output ? code : "";
}

/* =========================================================================
 * Runtime memory layout: initialized from compile-time arch constants, then
 * overwritten with the engine's resolved estimates by
 * engine_sync_authoritative.
 * =========================================================================
 */
struct kasld_layout {
  unsigned long virt_page_offset;
  unsigned long virt_kernel_vas_start;
  unsigned long virt_kernel_vas_end;
  unsigned long virt_image_base_min;
  unsigned long virt_image_base_max;
  unsigned long modules_start;
  unsigned long modules_end;
  unsigned long image_align;
  unsigned long virt_image_base_default;
  unsigned long virt_kaslr_text_min;
  unsigned long virt_kaslr_text_max;
  unsigned long virt_kaslr_align;
  /* Physical KASLR range (!TEXT_TRACKS_DIRECTMAP arches only; zero otherwise).
   */
  unsigned long phys_kaslr_text_min;
  unsigned long phys_kaslr_text_max;
  unsigned long phys_kaslr_align;
  /* Engine-resolved direct-map / RANDOMIZE_MEMORY region bounds. Distinct
   * from layout.virt_page_offset (a single rendered anchor): these are the
   * [min, max] window the engine proved. Folded in here so the seam between
   * engine_sync_authoritative() and compute_kaslr_info() is one global
   * (layout) instead of two (layout + an orchestrator-private g_ctx). */
  unsigned long virt_page_offset_min;
  unsigned long virt_page_offset_max;
  unsigned long virt_vmalloc_base_min;
  unsigned long virt_vmalloc_base_max;
  unsigned long virt_vmemmap_base_min;
  unsigned long virt_vmemmap_base_max;
};

/* =========================================================================
 * Result: (extent, position, confidence) over a typed region
 *
 * Optionality is via set_mask bits, never sentinel values — lo=0 and
 * hi=ULONG_MAX are both legitimate addresses. HAS_LO/HAS_HI/HAS_SAMPLE/
 * HAS_BASE_ALIGN are the only correct "is this field meaningful?" checks.
 *
 * `pos` describes what `sample` represents (BASE/TOP/INTERIOR/UNKNOWN).
 * It is NEVER a check for "do we have a known base?" — that is HAS_LO(r).
 *
 * Provenance is owned, fixed-cap arrays. The struct lives in a static
 * results[] table; pointer-to-transient-buffer fields would dangle.
 * ========================================================================= */

/* #ifndef-guarded so this and observation.h's identical definition coexist;
 * whichever header is included first defines the enum. */
#ifndef KASLD_SET_BITS_DEFINED
#define KASLD_SET_BITS_DEFINED 1
enum kasld_set_bits {
  LO_SET = 1u << 0,
  HI_SET = 1u << 1,
  SAMPLE_SET = 1u << 2,
  BASE_ALIGN_SET = 1u << 3,
};
#endif

/* Analytical method a component claims for a leak (the `method:` meta value).
 * Closed set, ordered weakest->strongest so the strongest member of a set is
 * the highest bit. A merged record stores the union of its contributors'
 * methods as a bitmask (method_set); this is the only place the names live. */
enum kasld_method {
  KM_DETECTION = 0,
  KM_BRUTE,
  KM_TIMING,
  KM_HEURISTIC,
  KM_INFERRED,
  KM_DERIVED,
  KM_PARSED,
  KM_COUNT
};

static inline const char *kasld_method_name(enum kasld_method m) {
  switch (m) {
  case KM_DETECTION:
    return "detection";
  case KM_BRUTE:
    return "brute";
  case KM_TIMING:
    return "timing";
  case KM_HEURISTIC:
    return "heuristic";
  case KM_INFERRED:
    return "inferred";
  case KM_DERIVED:
    return "derived";
  case KM_PARSED:
    return "parsed";
  case KM_COUNT:
    break;
  }
  return "unknown";
}

/* Strongest method present in a set, as a display string ("unknown" if empty).
 */
static inline const char *kasld_method_set_strongest(uint16_t set) {
  for (int m = KM_COUNT - 1; m >= 0; m--)
    if (set & (1u << m))
      return kasld_method_name((enum kasld_method)m);
  return "unknown";
}

/* Format a method set strongest-first as "parsed+timing" into buf ("unknown" if
 * empty). Surfaces method diversity where a single line has room (verbose). */
static inline void kasld_method_set_str(uint16_t set, char *buf, size_t sz) {
  if (sz == 0)
    return;
  buf[0] = '\0';
  size_t o = 0;
  for (int m = KM_COUNT - 1; m >= 0; m--) {
    if (!(set & (1u << m)))
      continue;
    int w = snprintf(buf + o, sz - o, "%s%s", o ? "+" : "",
                     kasld_method_name((enum kasld_method)m));
    if (w < 0 || (size_t)w >= sz - o)
      break;
    o += (size_t)w;
  }
  if (o == 0)
    snprintf(buf, sz, "unknown");
}

struct result {
  enum kasld_addr_type type;
  enum kasld_region region;
  char name[NAME_LEN]; /* "" if no specific instance */

  kasld_addr_t lo, hi;
  kasld_addr_t sample;
  kasld_addr_t base_align;
  uint32_t set_mask;

  enum kasld_position pos;
  enum kasld_confidence conf;

  /* Provenance: the components that corroborate this record (origins[0] is the
   * earliest contributor) and method_set, the union of their methods. Sized to
   * the structural max (MAX_COMPONENTS) so it can never overflow. */
  char origins[MAX_PROVENANCE][ORIGIN_LEN];
  uint16_t method_set; /* bitmask over enum kasld_method */
  uint8_t provenance_count;
};

#define HAS_LO(r) ((r)->set_mask & LO_SET)
#define HAS_HI(r) ((r)->set_mask & HI_SET)
#define HAS_SAMPLE(r) ((r)->set_mask & SAMPLE_SET)
#define HAS_BASE_ALIGN(r) ((r)->set_mask & BASE_ALIGN_SET)

/* Zero-initialise a result. set_mask=0, provenance_count=0, all enums to
 * their _UNKNOWN values, empty strings — all the correct unset state. */
static inline void result_init(struct result *r) { memset(r, 0, sizeof(*r)); }

/* is_phys_dram_region and is_kernel_image_region are defined once, in
 * kasld/regions.h (included above). Rules and the orchestrator share the
 * single definition so the two cannot drift apart silently. */

/* Pick the most representative address from a result. Prefers a known
 * base (when pos=BASE and lo is set), else any interior sample, else
 * any set bound, else 0. Used by the engine bridge and the renderer
 * when they need a single representative address. */
static inline unsigned long anchor_addr(const struct result *r) {
  if (!r)
    return 0;
  if (r->pos == POS_BASE && HAS_LO(r))
    return r->lo;
  if (HAS_SAMPLE(r))
    return r->sample;
  if (HAS_LO(r))
    return r->lo;
  if (HAS_HI(r))
    return r->hi;
  return 0;
}

/* =========================================================================
 * Region info table
 *
 * Per-region: canonical section name (for render grouping), default base
 * alignment, and VAS-bound resolver. derive_vas != NULL means the region's
 * bounds are a function of runtime layout; otherwise static_vas applies.
 *
 * derive_vas implementations must produce valid bounds for any layout
 * state, including initial defaults — never crash, never return inverted
 * ranges. Compiled per-arch via the arch header pattern.
 * ========================================================================= */
struct region_info {
  const char *wire_name;    /* token on the wire (also kasld_region_wire) */
  const char *section_name; /* render grouping; "" allowed */
  /* VAS resolution. derive_vas != NULL → use it; else use static_vas.
   * REGION_UNKNOWN: both zero/NULL — result_in_bounds short-circuits. */
  struct {
    unsigned long lo, hi;
  } static_vas;
  void (*derive_vas)(const struct kasld_layout *, unsigned long *lo,
                     unsigned long *hi);
};

extern const struct region_info region_info[REGION__COUNT];

/* =========================================================================
 * Runtime helpers
 * ========================================================================= */

/* True iff every set bound on `r` lies within the region's runtime VAS
 * (resolved per region_info[r->region]). Returns false for REGION_UNKNOWN
 * (forgotten-region-assignment safe). */
int result_in_bounds(const struct result *r, const struct kasld_layout *ly);

/* Trust ranking for confidences. PARSED=6, DERIVED=5, INFERRED=4,
 * HEURISTIC=3, TIMING=2, BRUTE=1, UNKNOWN=0. */
int conf_weight(enum kasld_confidence c);

/* Walk the result set; return the record best matching (type, region).
 * Preference: no-name first (canonical region anchor), then any name —
 * within each tier the highest-confidence record wins, ties broken by
 * earliest record index. Returns NULL when no match. Safe pre- or post-
 * merge. */
const struct result *select_anchor(enum kasld_addr_type type,
                                   enum kasld_region region);

/* Run the merge pass over results[]. Idempotent on its own output; called
 * after each collection state to deduplicate before the engine reads them. */
void merge_results(void);

/* =========================================================================
 * Component metadata, logs, outcomes.
 *
 * KASLD_EXIT_UNAVAILABLE / KASLD_EXIT_NOPERM are defined in api.h (the
 * component-side ABI surface) and reach this header via the api.h include
 * above.
 * ========================================================================= */

enum component_outcome {
  OUTCOME_SUCCESS,
  OUTCOME_NO_RESULT,
  OUTCOME_UNAVAILABLE,
  OUTCOME_ACCESS_DENIED,
  OUTCOME_TIMEOUT,
};

#define META_MAX_ENTRIES 32
#define META_KEY_LEN 32
#define META_VALUE_LEN 256

struct meta_entry {
  char key[META_KEY_LEN];
  char value[META_VALUE_LEN];
};

struct component_meta {
  struct meta_entry entries[META_MAX_ENTRIES];
  int num_entries;
};

struct component_log {
  char name[256];
  int exit_code;
  enum component_outcome outcome;
  /* Captured stdout lines for verbose/JSON output. Dynamically allocated
   * by run_component() only when verbose mode is active; non-verbose runs
   * leave `lines` == NULL and `lines_cap` == 0 so the per-component overhead
   * is a few pointers rather than 32 KiB. Each `lines[i]` is a malloc'd
   * NUL-terminated string (up to MAX_LINE_LEN-1 bytes of payload). */
  char **lines;
  int num_lines;
  int lines_cap;
  char *explain;
  struct component_meta meta;
};

struct component_stats {
  int total;
  int succeeded;
  int no_result;
  int unavailable;
  int access_denied;
  int timed_out;
};

/* =========================================================================
 * KASLR analysis summary
 * ========================================================================= */
struct kaslr_info {
  int disabled;
  int unsupported;
  /* Boot stub attempted KASLR but could not produce a random offset
   * (no entropy seed / no PRNG / insufficient memory). Kernel was
   * relocated to a firmware- or boot-stub-deterministic position —
   * NOT the link-time default. Distinct from `disabled` (opt-out):
   * `default_addr` is NOT the kernel's actual position when this is
   * set. Driven by SF_VIRT_KASLR_RANDOMIZATION_FAILED. */
  int randomization_failed;
  unsigned long default_addr;
  /* Virtual KASLR */
  unsigned long vtext; /* image base (_text) */
  unsigned long
      vstext; /* _stext for display: observed symbol, else _text + head gap */
  long vslide;
  unsigned long vslots;
  int vbits;
  unsigned long vslot_idx;
  int vslot_valid;
  /* Physical KASLR */
  unsigned long ptext;  /* phys image base (_text) */
  unsigned long pstext; /* phys _stext for display: observed symbol, else _text
                           + head gap */
  long pslide;
  unsigned long pslots;
  int pbits;
  int has_phys;
  /* Speculative "likely" window: the engine resolved a second time with ALL
   * signals, including those below the sound floor (timing/heuristic/brute).
   * It is a subset of the guaranteed window in the vtext/ptext fields above and
   * MAY be wrong. Each window's presence is signalled by its own *_max != 0
   * sentinel (set only when clamped strictly tighter than guaranteed);
   * renderers gate per-window on that. */
  unsigned long vlikely_min, vlikely_max;
  unsigned long vlikely_slots;
  int vlikely_bits;
  unsigned long plikely_min, plikely_max;
  unsigned long plikely_slots;
  int plikely_bits;
  /* Memory KASLR (x86_64 CONFIG_RANDOMIZE_MEMORY) */
  unsigned long virt_page_offset_min;
  unsigned long virt_page_offset_max;
  unsigned long virt_vmalloc_min;
  unsigned long virt_vmalloc_max;
  unsigned long virt_vmemmap_min;
  unsigned long virt_vmemmap_max;
  /* Speculative "likely" sub-windows for the memory-KASLR regions above, from
   * the all-signals snapshot (engine_resolve). Each is a subset of its region's
   * guaranteed min/max and MAY be wrong. 0/0 = none (no sub-floor signal
   * narrowed the region beyond its guaranteed window). */
  unsigned long virt_page_offset_likely_min, virt_page_offset_likely_max;
  unsigned long virt_vmalloc_likely_min, virt_vmalloc_likely_max;
  unsigned long virt_vmemmap_likely_min, virt_vmemmap_likely_max;
  /* Hole-aware residual slot counts for the memory-KASLR regions above, from
   * quantity_slots() over the resolved estimates (so interior C_EXCLUDE holes
   * are excluded, matching the headline vslots/pslots). Renderers derive bits
   * via ilog2. 0 when the region is unresolved / not a both-sided window. */
  unsigned long virt_page_offset_slots, virt_page_offset_likely_slots;
  unsigned long virt_vmalloc_slots, virt_vmalloc_likely_slots;
  unsigned long virt_vmemmap_slots, virt_vmemmap_likely_slots;
};

struct summary {
  struct kaslr_info kaslr;
  int decoupled_note;
  struct component_stats stats;
};

/* Counterfactual "projected posture" for the hardening advisor: the residual
 * KASLR entropy the guaranteed window would have if a set of components' leaks
 * were removed (e.g. those a sysctl would silence). Computed by re-resolving
 * the engine over the collected evidence minus the excluded components — a pure
 * fixpoint re-run, no component re-execution. `available` is 0 when the engine
 * is compiled out (KASLD_TESTING); readers must gate on it. */
struct projected_posture {
  int available;
  int vbits, pbits; /* guaranteed residual entropy, bits (virt / phys base) */
  unsigned long vslots, pslots;
};

/* Re-resolve the guaranteed window with the named component origins'
 * observations excluded, and report the residual posture. exclude may be NULL
 * (n_exclude 0) to re-derive the current posture. Defined in orchestrator.c. */
void kasld_project_posture(const char *const *exclude, int n_exclude,
                           struct projected_posture *out);

#ifdef KASLD_TESTING
/* Render-test seam: with the engine compiled out kasld_project_posture is a
 * stub reporting available == 0; set this to make it report an available
 * projection (entropy monotone in the exclude-set size) so the advisor's
 * projected-delta rows can be exercised by the render tests. */
extern int kasld_test_projection;
#endif

/* =========================================================================
 * Shared globals (defined in orchestrator.c)
 * ========================================================================= */
extern int verbose;
extern int quiet;
extern int json_output;
extern int oneline_output;
extern int markdown_output;
extern int explain_mode;
extern int hardening_mode;
extern int sysctl_kptr_restrict;
extern int sysctl_dmesg_restrict;
extern int sysctl_perf_event_paranoid;
extern int hashed_pointers;

enum lockdown_mode {
  LOCKDOWN_UNAVAILABLE = -1,
  LOCKDOWN_NONE = 0,
  LOCKDOWN_INTEGRITY,
  LOCKDOWN_CONFIDENTIALITY,
};
extern enum lockdown_mode sysctl_lockdown;

/* Recon vantage / container-confinement facts, gathered once and shared by the
 * text (verbose system-config block), JSON, and markdown renderers so they
 * can't diverge. All fields are unprivileged /proc reads
 * (SYSROOT-redirectable). */
#define KASLD_N_ORACLES 4
extern const char *const
    kasld_oracle_paths[KASLD_N_ORACLES]; /* /proc/kallsyms… */
extern const char *const
    kasld_oracle_labels[KASLD_N_ORACLES]; /* "Readable …:" */

struct kasld_vantage {
  const char *container; /* runtime name, or NULL if not containerized */
  int seccomp;           /* -1 unknown; 0 none, 1 strict, 2 filter */
  int no_new_privs;      /* -1 unknown; 0/1 */
  int have_caps;         /* 1 if cap_eff/cap_bnd are valid */
  unsigned long long cap_eff, cap_bnd;
  int oracle_readable[KASLD_N_ORACLES]; /* per kasld_oracle_paths[] */
};
void kasld_gather_vantage(struct kasld_vantage *v);
/* Confined = the confinement detail is meaningful (else the values are the
 * unprivileged defaults). Renderers use this to suppress a misleading block. */
int kasld_vantage_confined(const struct kasld_vantage *v);
/* Format cap_eff as "none"/"full"/"0x…"; out must hold >= 19 bytes. */
const char *kasld_vantage_caps(const struct kasld_vantage *v, char *out,
                               size_t outsz);
/* seccomp mode 0/1/2 → "none"/"strict"/"filter" (else "unknown"). */
const char *kasld_vantage_seccomp_str(int seccomp);

/* Effective-capability → the kasld leak source it unlocks. Reported from the
 * vantage cap_eff so the confinement view also answers "which cap-gated leaks
 * are reachable here" — the recon complement to the readable-oracle matrix,
 * covering the non-file leaks (perf / bpf) too. `bit` is the capability number
 * (linux/capability.h, stable ABI). */
struct kasld_cap_leak {
  int bit;
  const char *cap;    /* "CAP_SYS_RAWIO" */
  const char *source; /* the kasld source it grants */
};
#define KASLD_N_CAP_LEAKS 5
extern const struct kasld_cap_leak kasld_cap_leaks[KASLD_N_CAP_LEAKS];

extern struct kasld_layout layout;
extern struct result results[MAX_RESULTS];
extern int num_results;
extern struct component_log comp_logs[MAX_COMPONENTS];
extern int num_comp_logs;

/* Scalar system facts collected from components' `S` wire records, parallel to
 * results[]. The engine bridge copies these to OBS_SCALAR observations; the
 * orchestrator and renderer also read them directly (e.g.
 * SF_VIRT_KASLR_DISABLED drives s->kaslr.disabled and the "Detected by:" list).
 */
struct scalar_fact_record {
  enum kasld_scalar_fact fact;
  unsigned long value;
  enum kasld_confidence conf;
  char origin[ORIGIN_LEN];
};
#define MAX_SCALAR_FACTS 64
extern struct scalar_fact_record scalar_facts[MAX_SCALAR_FACTS];
extern int num_scalar_facts;

/* =========================================================================
 * Shared functions (defined in orchestrator.c)
 * ========================================================================= */
const char *meta_get(const struct component_meta *m, const char *key);
int meta_get_all(const struct component_meta *m, const char *key,
                 const char **values, int max_values);
void inject_kaslr_defaults(struct summary *s);
void compute_component_stats(struct summary *s);
void compute_kaslr_info(struct summary *s);

/* =========================================================================
 * Rendering (defined in render.c)
 * ========================================================================= */
/* Pure consumer: render an already-resolved summary. The orchestrator runs
 * the engine (compute_kaslr_info) before calling this, so the renderer never
 * triggers inference. */
void render_summary(const struct summary *s);

#endif /* KASLD_INTERNAL_H */
