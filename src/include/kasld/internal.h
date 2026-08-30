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
#include "constraint.h" /* struct constraint_fact_record enums */
#include "regions.h" /* canonical is_phys_dram_region / is_kernel_image_region */

#include <limits.h>
#include <stddef.h>
#include <stdint.h>

#ifndef VERSION
#define VERSION "unknown"
#endif

/* =========================================================================
 * Constants
 * =========================================================================
 */
/* Upper bound on components discovered in the component directory. Overridable
 * at build time (-DMAX_COMPONENTS=...) for an install carrying a larger set,
 * matching the engine-side caps. tests/check-component-cap fails the build when
 * the in-tree component count leaves too little headroom beneath it. A
 * directory holding more than this many executables runs the first
 * MAX_COMPONENTS in discovery order and reports the truncation. */
#ifndef MAX_COMPONENTS
#define MAX_COMPONENTS 512
#endif
#define MAX_RESULTS 4096
/* NAME_LEN / ORIGIN_LEN are the wire-field widths, defined once in api.h. */
/* Captured-stdout lines are kept only for --verbose / --json output. The log
 * is grown geometrically on demand from this initial capacity; there is no
 * hard cap (the previous fixed cap of 64 silently truncated noisy components).
 * Non-verbose runs never allocate. */
#define COMPONENT_LINES_INITIAL_CAP 16

/* Ceiling on the stdout one component's captured lines may retain under
   --verbose. Bytes rather than a line count: the two are only the same thing if
   every line is the same length, and the resource being bounded is memory. The
   busiest component in the tree emits about 80 lines averaging 40 characters,
   so a megabyte is four orders of magnitude of headroom; what it bounds is a
   component that loops, or one written to make the orchestrator grow. Reaching
   it stops the capture and records a DISCARD_CAPACITY entry, so a truncated log
   says so rather than being silently short. */
#define COMPONENT_LINES_MAX_BYTES (1024UL * 1024UL)
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
 * Output glyphs: Unicode when the terminal can render it, ASCII otherwise.
 * unicode_output is set from the locale codeset (a non-UTF-8 locale cannot
 * render the box-art banner or the check/cross/arrow glyphs) and forced off
 * by --ascii. kasld_glyph() mirrors c(): pick per output mode; the GLYPH_*
 * macros pair each Unicode glyph with its ASCII fallback in one place.
 * =========================================================================
 */
extern int unicode_output; /* forward declaration for kasld_glyph() */
static inline const char *kasld_glyph(const char *uni, const char *ascii) {
  return unicode_output ? uni : ascii;
}
#define GLYPH_OK kasld_glyph("\xe2\x9c\x93", "[ok]")     /* U+2713 check */
#define GLYPH_WARN kasld_glyph("\xe2\x9a\xa0", "[warn]") /* U+26A0 warning */
#define GLYPH_FAIL kasld_glyph("\xe2\x9c\x97", "[fail]") /* U+2717 cross */
#define GLYPH_ARROW kasld_glyph("\xe2\x86\x92", "->")    /* U+2192 arrow */

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
  /* Q_MODULE_BASE's resolved window: where the module region can START. Kept
   * apart from modules_start/end, which is the band the map draws — the base
   * is bounded by the lowest module seen, while the band spans every address
   * modules may occupy. Conflating them would report an observed allocation as
   * the region's origin. */
  unsigned long virt_module_base_min;
  unsigned long virt_module_base_max;

  /* The direct map's un-randomized base -- __PAGE_OFFSET_BASE for the paging
   * level in force, 0xffff888000000000 at 4 levels and 0xff11000000000000 at
   * 5. The reference a rendered RANDOMIZE_MEMORY offset is measured from: the
   * address the kernel would have used had it not slid the region.
   *
   * Selected from the resolved Q_VA_BITS rather than named by a compile-time
   * constant, because a build cannot know which level its target runs and the
   * two bases sit 59.6 PiB apart -- far enough that measuring from the wrong
   * one yields a large negative number that still reads as a measurement.
   *
   * Zero where the level is unresolved, or where the architecture randomizes
   * no memory regions at all. Renderers omit the annotation at zero rather
   * than measure from a guess. */
  unsigned long virt_page_offset_unrandomized;

  /* Candidate counts, projected beside the windows they belong to.
   *
   * How many placements a quantity still admits is not (hi - lo) / align: the
   * estimate's interior C_EXCLUDE holes are carved at READ time, so only
   * quantity_slots() over the estimate AND its constraint set can answer it. A
   * flat division is hole-blind and over-counts.
   *
   * They live here because that answer needs the engine, and the summary
   * builder is a consumer of this struct rather than of the engine. Projecting
   * them at the same moment as the window they count keeps the two describing
   * one resolution -- and leaves no computation for a build without an engine
   * to substitute a second, hole-blind definition for.
   *
   * Zero means "no count resolved", which is also the value a caller that seeds
   * this struct directly gets without asking. */
  unsigned long virt_kaslr_slots;
  unsigned long phys_kaslr_slots;
  unsigned long virt_page_offset_slots;
  unsigned long virt_vmalloc_slots;
  unsigned long virt_vmemmap_slots;
  unsigned long virt_module_slots;
  /* Slot pitch the module-band count was taken at: the target's page size
     where it is known, PAGE_SIZE_MIN where it is not. Carried rather than
     recomputed so the count and the pitch shown beside it cannot disagree. */
  unsigned long virt_module_align;
};

/* =========================================================================
 * Discard ledger — what this run threw away, and why.
 *
 * Evidence leaves the pipeline in several places: a wire line that fails
 * validation, an address outside its region's address space, a fixed-size
 * store that fills, a curation rule that invalidates an observation, the
 * resolver rejecting a conflicting constraint. Each was previously reported
 * (or not) by its own mechanism, on its own channel, which is how curation
 * came to be reported nowhere at all.
 *
 * A discarded record matters to the answer: the run resolved from a subset of
 * the available evidence, so its residual-entropy figure OVERSTATES what KASLR
 * retains. A consumer that cannot see the discard reads a bounded answer as a
 * complete one.
 *
 * So this is the single source of truth for the fact, and the renderers are its
 * only readers. Entries aggregate by (reason, source) — a hundred rejected
 * lines from one component are one entry with a count, not a hundred entries.
 *
 * The engine does not write here: it is pure, records its own caps in
 * engine.saturation, and is projected in after the run — the same shape as
 * engine_sync_authoritative projecting estimates onto the layout.
 * =========================================================================
 */
enum kasld_discard_reason {
  DISCARD_PARSE = 0, /* a wire line failed validation and was rejected */
  DISCARD_BOUNDS,    /* an address fell outside its region's address space */
  DISCARD_CURATED,   /* a curation rule invalidated an observation */
  DISCARD_CONFLICT,  /* the resolver rejected a constraint that conflicted */
  DISCARD_CAPACITY,  /* a fixed-size store was full; the record was dropped */
  DISCARD__COUNT
};

/* Distinct (reason, source) pairs kept. Sources are components, rules or store
 * names, so this binds only on a pathological run; kasld_discard_truncated()
 * reports it when it does, rather than the ledger quietly under-counting the
 * thing it exists to count. */
#define MAX_DISCARDS 64

struct kasld_discard {
  enum kasld_discard_reason reason;
  /* Component origin, emitting rule, or the store that filled — whichever
   * names the discard usefully for its reason. */
  char source[ORIGIN_LEN];
  unsigned int count;
};

/* Record one discarded item. Aggregates by (reason, source). `source` may be
 * NULL where the site has no meaningful one. */
void kasld_discard_record(enum kasld_discard_reason reason, const char *source);

/* Read side, for renderers and tests.
 *
 * Callable once the component workers have joined, which is where every reader
 * sits: the renderers and the verbose breakdown all run after collection. They
 * take no lock, and kasld_discard_at() hands back a pointer into the ledger, so
 * one taken during collection would be racing whatever a worker records next.
 */
int kasld_discard_count(void);
const struct kasld_discard *kasld_discard_at(int i);
int kasld_discard_truncated(void);
unsigned int kasld_discard_total(void);
const char *kasld_discard_reason_name(enum kasld_discard_reason r);

/* Drop every entry. Tests drive several runs in one process; production calls
 * it once at start so a re-entry cannot inherit a previous run's ledger. */
void kasld_discard_reset(void);

/* =========================================================================
 * Result: (extent, position, confidence) over a typed region
 *
 * Optionality is via set_mask bits, never sentinel values — lo=0 and
 * hi=ULONG_MAX are both legitimate addresses. HAS_LO/HAS_HI/HAS_SAMPLE/
 * HAS_BASE_ALIGN are the only correct "is this field meaningful?" checks.
 *
 * `pos` describes what `sample` represents (BASE/TOP/INTERIOR/UNKNOWN).
 * It is NEVER a check for "is there a known base?" — that is HAS_LO(r).
 *
 * Provenance is an owned, fixed-width bitset. The struct lives in a static
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

/* Provenance: which components contributed a record.
 *
 * A component's identity is its slot in the discovery table, assigned once
 * after discovery sorts that table — so it is fixed for the run and does not
 * depend on the order components finish in. A record carries its contributors
 * as a bitset over those slots: union is a word-wise OR, membership a bit test,
 * and the contributor count a popcount. Names are resolved for display through
 * kasld_origin_name(), so a record can never name a component that was not
 * discovered.
 *
 * The set is sized to the structural maximum (every component corroborating one
 * record), which costs one bit per component rather than a name per component,
 * so raising MAX_COMPONENTS stays cheap. */
#define ORIGIN_WORDS ((MAX_COMPONENTS + 31) / 32)

struct origin_set {
  uint32_t w[ORIGIN_WORDS];
};

static inline void origin_set_add(struct origin_set *s, int idx) {
  if (idx >= 0 && idx < MAX_COMPONENTS)
    s->w[idx / 32] |= 1u << (idx % 32);
}

static inline int origin_set_has(const struct origin_set *s, int idx) {
  if (idx < 0 || idx >= MAX_COMPONENTS)
    return 0;
  return (s->w[idx / 32] & (1u << (idx % 32))) != 0;
}

static inline void origin_set_union(struct origin_set *a,
                                    const struct origin_set *b) {
  for (int i = 0; i < ORIGIN_WORDS; i++)
    a->w[i] |= b->w[i];
}

/* Index of the lowest contributor at or above `from`, or -1 when none remains.
 * Iterating from 0 walks the contributors in discovery order:
 *   for (int i = origin_set_next(&r->origins, 0); i >= 0;
 *        i = origin_set_next(&r->origins, i + 1))
 */
static inline int origin_set_next(const struct origin_set *s, int from) {
  if (from < 0)
    from = 0;
  for (int i = from; i < MAX_COMPONENTS; i++)
    if (s->w[i / 32] & (1u << (i % 32)))
      return i;
  return -1;
}

static inline int origin_set_count(const struct origin_set *s) {
  int n = 0;
  for (int i = 0; i < ORIGIN_WORDS; i++) {
    uint32_t v = s->w[i];
    while (v) {
      v &= v - 1;
      n++;
    }
  }
  return n;
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

  /* The components that corroborate this record, and method_set, the union of
   * their methods. */
  struct origin_set origins;
  uint16_t method_set; /* bitmask over enum kasld_method */
};

/* Origin slots below zero name a producer that is not a discovered component.
 * A result's provenance only ever holds real component slots (every result
 * arrives on a component's wire channel); the sentinels exist for the scalar
 * facts the orchestrator synthesises itself, which still need a display name.
 */
#define ORIGIN_NONE (-1)       /* unattributed */
#define ORIGIN_ARCH_SYNTH (-2) /* synthesised from compile-time arch facts */

/* Display name of a discovered component or of an origin sentinel; "" for an
 * index outside both. Defined in orchestrator.c, which owns the discovery
 * table. */
const char *kasld_origin_name(int idx);

#define HAS_LO(r) ((r)->set_mask & LO_SET)
#define HAS_HI(r) ((r)->set_mask & HI_SET)
#define HAS_SAMPLE(r) ((r)->set_mask & SAMPLE_SET)
#define HAS_BASE_ALIGN(r) ((r)->set_mask & BASE_ALIGN_SET)

/* Zero-initialise a result. set_mask=0, no contributors, all enums to their
 * _UNKNOWN values, empty strings — all the correct unset state. */
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
  /* Died on a fatal signal that was not the seccomp SIGSYS (which is a denial,
   * not a fault) and was not this orchestrator's own timeout kill. Separate
   * from OUTCOME_NO_RESULT because the two are otherwise indistinguishable in
   * every output: a component that faulted part-way through has not "found
   * nothing", and the input that killed it may be reproducible. */
  OUTCOME_CRASHED,
};

/* Cap on `key:value` lines kept from one component's .kasld_meta section. The
 * busiest component in the tree declares 8. Overflow is reported through the
 * discard ledger rather than dropped quietly: a lost `phase:` reassigns a
 * component's scheduling and a lost mitigation key changes the hardening
 * report, so a component that outgrew this must not do so in silence. */
#define META_MAX_ENTRIES 16

/* One `key:value` pair, as pointers INTO the raw section the component's log
 * slot owns — not copies. parse_meta() terminates each field in place, so the
 * whole table costs two pointers per entry over the section itself (under 150
 * bytes for every component in the tree) instead of a fixed key and value
 * buffer per slot. Both stay valid for as long as that raw section does, which
 * is the lifetime of the log slot holding it, so a pointer handed out by
 * meta_get() is good for the run. */
struct meta_entry {
  const char *key;
  const char *value;
};

struct component_meta {
  struct meta_entry entries[META_MAX_ENTRIES];
  int num_entries;
};

/* A component's self-reported disposition, parsed from an `R` wire line (see
 * kasld_disposition in api.h): why it produced no tagged result, as a closed
 * category plus, for a mitigation, the specific control that fired and an
 * optional human string. Short by design — a triage hint, not prose. `gate`
 * and `message` are empty unless the wire line carried them; `category` is
 * DISP_NONE when no `R` line was emitted. */
#define DISP_GATE_LEN 64
#define DISP_MSG_LEN 192
struct component_disposition {
  enum kasld_disp category;
  char gate[DISP_GATE_LEN];
  char message[DISP_MSG_LEN];
};

/* Per-component execution record, indexed by the component's discovery slot —
 * comp_logs[i] describes components[i]. The array is therefore sparse: a
 * component that was filtered out, or that belongs to a phase that did not run,
 * leaves its slot untouched. `ran` marks a populated slot; consumers iterate
 * 0..num_components and skip the rest. */
struct component_log {
  int ran; /* 0 for a slot no component wrote to */
  char name[256];
  int exit_code;
  enum component_outcome outcome;
  /* Why the component did not produce a result. Recorded in default output too,
   * so a gated leak's disposition shows without re-running under --verbose. */
  struct component_disposition disposition;
  /* Captured stdout lines for verbose/JSON output. Dynamically allocated
   * by run_component() only when verbose mode is active; non-verbose runs
   * leave `lines` == NULL and `lines_cap` == 0 so the per-component overhead
   * is a few pointers rather than 32 KiB. Each `lines[i]` is a malloc'd
   * NUL-terminated string sized to its own content, not to MAX_LINE_LEN: a
   * component line averages ~40 characters, so a fixed slot would spend an
   * order of magnitude more than it holds. `lines_bytes` is the running total
   * those allocations account for, bounded by COMPONENT_LINES_MAX_BYTES. */
  char **lines;
  int num_lines;
  int lines_cap;
  size_t lines_bytes;
  char *explain;
  /* The component's .kasld_meta section, owned here. `meta` points into it, so
   * it outlives every meta_get() the renderers make. */
  char *meta_raw;
  struct component_meta meta;
};

struct component_stats {
  int total;
  int succeeded;
  int no_result;
  int unavailable;
  int access_denied;
  int timed_out;
  int crashed;
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
  /* Physical KASLR */
  unsigned long ptext;  /* phys image base (_text) */
  unsigned long pstext; /* phys _stext for display: observed symbol, else _text
                           + head gap */
  long pslide;
  unsigned long pslots;
  int has_phys;
  /* Entropy the virtual KASLR window started with, counted over
   * Q_VIRT_IMAGE_BASE's honest top at the same alignment as vbits. The
   * baseline that makes vbits interpretable: "5 bits remain" says nothing
   * without it. 0 means not computed, and every format then reports the
   * residual alone.
   *
   * Virtual only, deliberately. That quantity's honest top IS the arch's
   * KASLR window, so the ratio means what a reader will take it to mean. The
   * physical and direct-map tops are addressable-range bounds rather than
   * randomization windows, so a denominator drawn from them would read as
   * KASLR entropy the kernel never had. (The direct map does get a baseline —
   * see virt_page_offset_bits_top — but from the RANDOMIZE_MEMORY budget
   * model, not from Q_PAGE_OFFSET's top.) */
  /* The same baseline as a raw candidate count. ilog2 rounds up, so
   * 2^vbits_top over-states it and cannot stand in for "N of M". */
  unsigned long vtop_slots;
  /* Candidates spanned by each image base's architectural top. That top is
   * widened to admit configurations the model cannot rule out, so a count equal
   * to it means nothing was narrowed at all -- and the figure is a limit of the
   * address space rather than a search space, so it is withheld. */
  unsigned long varch_slots, parch_slots;
  /* Memory KASLR (x86_64 CONFIG_RANDOMIZE_MEMORY) */
  unsigned long virt_page_offset_min;
  unsigned long virt_page_offset_max;
  unsigned long virt_vmalloc_min;
  unsigned long virt_vmalloc_max;
  unsigned long virt_vmemmap_min;
  unsigned long virt_vmemmap_max;
  /* Q_MODULE_BASE: where the module region can start. Distinct from the
   * modules_start/end band the map draws (see struct layout). */
  unsigned long virt_module_min;
  unsigned long virt_module_max;
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
  /* Residual entropy over each window, derived from the hole-aware slot counts
   * at the engine boundary. Carried here rather than recomputed in a renderer:
   * the same quantity must not be derived two ways. */
  int virt_page_offset_bits, virt_vmalloc_bits, virt_vmemmap_bits;
  /* The direct map's starting candidate count, from the same budget window
   * virt_page_offset_bits_top is taken from. Carried raw as well as in bits:
   * ilog2 rounds up, so 2^bits_top over-states the baseline and cannot be used
   * to say "N of M". 0 where the budget model could not be evaluated. */
  unsigned long virt_page_offset_top_slots;
  /* Entropy the direct-map base started with, i.e. the baseline that makes
   * virt_page_offset_bits interpretable, counted the same way (PUD-granular
   * candidates through quantity_slots, then ilog2).
   *
   * NOT Q_PAGE_OFFSET's honest top, which is an addressable range rather than
   * a randomization window: the denominator is the window
   * kernel_randomize_memory() actually draws page_offset_base from, modelled
   * in randomize_memory.h. x86_64-only (RANDOMIZE_MEMORY is), and 0 whenever
   * that model cannot be evaluated soundly — no max_pfn, unresolved paging
   * level, or a max_pfn observation below the sound floor, which would put a
   * sub-floor denominator under a guaranteed-window numerator. Renderers
   * degrade to the bare residual at 0. */
  int virt_page_offset_bits_top;
  unsigned long virt_vmalloc_slots, virt_vmalloc_likely_slots;
  unsigned long virt_vmemmap_slots, virt_vmemmap_likely_slots;
  unsigned long virt_module_slots;
  unsigned long virt_module_align;
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
extern int map_mode; /* --map: draw the address-space diagram */
/* A hardening value that could not be read, and one whose read was refused.
 * The refusal is kept apart because these knobs are world-readable: a refusal
 * is not ordinary file permissions, but something above DAC withholding the
 * system's own settings.
 *
 * Both are the extreme low ints rather than small negatives, because a small
 * negative is a real setting: kernel.perf_event_paranoid reports -1 for
 * "unrestricted", and a marker colliding with it would present the most
 * permissive value the kernel has as "unknown" — the two conclusions this
 * file works to keep apart. Nothing the kernel reports can reach either.
 *
 * Both stay negative, so a `>= threshold` test still reads them as inactive. */
#define KASLD_SYSCTL_UNREAD (INT_MIN)
#define KASLD_SYSCTL_DENIED (INT_MIN + 1)

/* 1 when a hardening value was actually observed, whatever it turned out to
 * be. Prefer this to a sign test: a negative value is not necessarily an
 * unread one. */
static inline int kasld_hardening_known(int v) {
  return v != KASLD_SYSCTL_UNREAD && v != KASLD_SYSCTL_DENIED;
}

enum lockdown_mode {
  LOCKDOWN_UNAVAILABLE = -1,
  LOCKDOWN_NONE = 0,
  LOCKDOWN_INTEGRITY,
  LOCKDOWN_CONFIDENTIALITY,
};

/* Runtime hardening state: system-wide settings that gate what any process can
 * read, whoever it is. Every value carries an "unread" state distinct from a
 * permissive one, because the two are opposite conclusions and only one of them
 * was observed. `panic_on_oops` is reported but gates nothing; which of these
 * are gates is stated by the hardening advisor's own table, not by which
 * happen to be here. */
struct kasld_hardening {
  int kptr_restrict;
  int dmesg_restrict;
  /* -1 is a real value here ("unrestricted"), which is why the unread markers
   * above are not small negatives. */
  int perf_event_paranoid;
  /* 0 = unprivileged bpf() allowed, >= 1 = disabled, which blocks the
   * unprivileged bpf leak components. */
  int unprivileged_bpf_disabled;
  int panic_on_oops; /* reported only; gates nothing */
  /* 1 = %p/%pK print a hashed id (the default, and mitigating); 0 =
   * no_hash_pointers / hash_pointers=never on the boot cmdline, so pointers
   * print raw. */
  int hashed_pointers;
  enum lockdown_mode lockdown;
};

/* Recon vantage / container-confinement facts, shared by the text (verbose
 * system-config block), JSON, and markdown renderers so they can't diverge.
 * All fields come from unprivileged reads through the SYSROOT layer. */
/* Supplementary groups kept for the report. A process with more than this is
 * far outside anything the vantage model reasons about; the overflow is
 * reported as a count rather than silently dropped. */
/* The readout's line budget, matched to the width the render guard enforces
 * (tests/check-render-width). Wrapping keeps a long list inside it rather than
 * dropping entries. */
#define KASLD_READOUT_COLS 108
#define KASLD_N_GROUPS 24
#define KASLD_N_ORACLES 4
extern const char *const
    kasld_oracle_paths[KASLD_N_ORACLES]; /* /proc/kallsyms… */

/* SELinux runtime mode, read from /sys/fs/selinux/enforce. Absent covers both
 * "SELinux is not built in" and "selinuxfs is not reachable from here" — which
 * are indistinguishable from an unprivileged vantage, so the value never
 * asserts that no LSM is present. */
enum selinux_mode {
  SELINUX_UNAVAILABLE = -1,
  SELINUX_PERMISSIVE = 0,
  SELINUX_ENFORCING = 1,
};

struct kasld_vantage {
  const char *container; /* runtime name, or NULL if not containerized */
  int seccomp;           /* -1 unknown; 0 none, 1 strict, 2 filter */
  int no_new_privs;      /* -1 unknown; 0/1 */
  int have_caps;         /* 1 if cap_eff/cap_bnd are valid */
  unsigned long long cap_eff, cap_bnd;
  int oracle_readable[KASLD_N_ORACLES]; /* per kasld_oracle_paths[] */
  /* Mandatory access control. `lsm_list` is securityfs's active-LSM list when
   * readable and "" otherwise (it is unreachable under some policies, so an
   * empty list is "unknown", never "no LSM"). `sec_context` is this process's
   * own label — an SELinux context or an AppArmor profile, from the one path
   * both expose. */
  enum selinux_mode selinux;
  char lsm_list[160];    /* "lockdown,capability,yama,apparmor" or "" */
  char sec_context[192]; /* "u:r:shell:s0", "vscode (unconfined)", or "" */
  /* Discretionary identity. Between the MAC label above and the capability set
   * below sits the plainest gate of all, and several sources answer only to it:
   * /proc/cmdline is 0440 root:radio on Android, the /sys/module section files
   * are 0400, and /proc mounted hidepid=invisible,gid=N hides every other
   * task's entry from a process outside that group. A reader cannot tell why
   * such a source was denied without seeing the identity that was refused.
   *
   * Read from /proc/self/status alongside the capability sets above, not from
   * getuid()/getgroups(): the file resolves through the sysroot layer, so a
   * captured tree reports the identity it was collected under. The syscalls
   * answer for the machine running the analysis, and being syscalls they are
   * invisible to anything that watches which paths a fact came from. They
   * remain the fallback for a live run whose status file cannot be read. */
  int have_ids; /* 1 if uid/euid/gid/egid are valid */
  unsigned long uid, euid, gid, egid;
  int ngroups; /* -1 unknown; else count in `groups` */
  unsigned long groups[KASLD_N_GROUPS];
  int groups_truncated; /* more groups than the array holds */
  /* Each held group's name, resolved when the vantage is taken so no renderer
   * has to reach for the group database while formatting — and so the database
   * is walked once for the whole membership rather than once per member. An
   * entry is empty when nothing could name that id; the number alone is then
   * reported, which is what the kernel checks anyway. */
  char group_names[KASLD_N_GROUPS][64];
};
void kasld_gather_vantage(struct kasld_vantage *v);
/* Confined = the confinement detail is meaningful (else the values are the
 * unprivileged defaults). Renderers use this to suppress a misleading block. */
int kasld_vantage_confined(const struct kasld_vantage *v);
/* Format cap_eff as "none"/"full"/"0x…"; out must hold >= 19 bytes. */
const char *kasld_vantage_caps(const struct kasld_vantage *v, char *out,
                               size_t outsz);
/* 1 when a mandatory access control policy is actively confining this process:
 * SELinux enforcing, or an AppArmor profile in enforce mode. A permissive
 * policy logs but does not deny, so it is not confinement. Unknown reads as 0 —
 * the tool never claims a denial came from an LSM it could not observe. */
int kasld_vantage_mac_enforcing(const struct kasld_vantage *v);
/* Format the MAC posture for display: the securityfs LSM list when readable,
 * else the SELinux mode, else "unknown" — never "none", which an unprivileged
 * vantage cannot establish. Returns out. */
const char *kasld_vantage_lsm_str(const struct kasld_vantage *v, char *out,
                                  size_t outsz);
/* seccomp mode 0/1/2 → "none"/"strict"/"filter" (else "unknown"). */
const char *kasld_vantage_seccomp_str(int seccomp);

/* Group → the kasld leak source it gates. The complement to kasld_cap_leaks
 * for the discretionary half: several sources answer to group membership alone,
 * and on Android the ids that matter cannot be named by a name lookup at all —
 * /etc/group is present but EMPTY there, the ids being compiled into bionic, so
 * a build against any other libc resolves nothing. This table names the ones
 * whose absence or presence changes what kasld can read; every other group is
 * reported by number, which is what the kernel checks anyway. */
struct kasld_group_gate {
  unsigned long gid;
  const char *name;
  const char *gates;
};
#define KASLD_N_GROUP_GATES 6
extern const struct kasld_group_gate kasld_group_gates[KASLD_N_GROUP_GATES];

/* The name of the vantage's `i`th supplementary group, or NULL when nothing
 * could name it and the caller should print the number alone. Resolved when the
 * vantage was taken — from /etc/group in the tree being analysed (so an offline
 * replay names THAT tree's groups, which getgrgid would not), falling back to
 * the gate table above for the ids kasld knows gate one of its own sources, the
 * set Android cannot name with its /etc/group empty. Shared so the text and
 * markdown documents cannot drift apart on what they name. */
const char *kasld_group_name(const struct kasld_vantage *v, int i);

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

/* The observing environment, taken once before the first component runs.
 *
 * One instant for both halves. The advisor attributes a component's denial by
 * weighing the hardening settings that were in force against the confinement
 * the process was under, and those have to describe the same moment for the
 * attribution to mean anything. Reading them at the two ends of a scan — the
 * settings before it, the confinement after — describes two.
 *
 * Taking it once is also what lets a renderer read it: formatting reaches for
 * no file, so no output depends on the filesystem still answering the way it
 * did when the analysis ran. */
struct kasld_environment {
  struct kasld_hardening hardening;
  struct kasld_vantage vantage;
};

/* Unknown in every field that has an unknown, so an environment that was never
 * taken reports as unobserved rather than as unconfined. Zeroed storage would
 * not: SELINUX_PERMISSIVE and LOCKDOWN_NONE are both 0, and a permissive
 * default is the dangerous direction — it asserts an absence of confinement
 * that nothing established, which is how "could not look" becomes "nothing
 * there". */
#define KASLD_ENV_UNKNOWN                                                      \
  {                                                                            \
      .hardening = {.kptr_restrict = KASLD_SYSCTL_UNREAD,                      \
                    .dmesg_restrict = KASLD_SYSCTL_UNREAD,                     \
                    .perf_event_paranoid = KASLD_SYSCTL_UNREAD,                \
                    .unprivileged_bpf_disabled = KASLD_SYSCTL_UNREAD,          \
                    .panic_on_oops = KASLD_SYSCTL_UNREAD,                      \
                    .hashed_pointers = KASLD_SYSCTL_UNREAD,                    \
                    .lockdown = LOCKDOWN_UNAVAILABLE},                         \
      .vantage = {.seccomp = -1,                                               \
                  .no_new_privs = -1,                                          \
                  .selinux = SELINUX_UNAVAILABLE,                              \
                  .ngroups = -1},                                              \
  }

extern struct kasld_environment kasld_env;

/* Take the environment: the hardening settings and this process's vantage
 * within them, at one instant. Called once, before any component runs. */
void kasld_env_snapshot(void);

extern struct kasld_layout layout;
extern struct result results[MAX_RESULTS];
extern int num_results;
/* Indexed by discovery slot; see struct component_log. Iterate against
 * num_components and skip slots whose `ran` is 0. */
extern struct component_log comp_logs[MAX_COMPONENTS];
extern int num_components;

/* Scalar system facts collected from components' `S` wire records, parallel to
 * results[]. The engine bridge copies these to OBS_SCALAR observations; the
 * orchestrator and renderer also read them directly (e.g.
 * SF_VIRT_KASLR_DISABLED drives s->kaslr.disabled and the "Detected by:" list).
 */
struct scalar_fact_record {
  enum kasld_scalar_fact fact;
  unsigned long value;
  enum kasld_confidence conf;
  int origin; /* discovery slot of the producing component; -1 if unattributed
               */
};
#define MAX_SCALAR_FACTS 64
extern struct scalar_fact_record scalar_facts[MAX_SCALAR_FACTS];
extern int num_scalar_facts;

/* Direct constraints collected from components' `C` wire records, parallel to
 * scalar_facts[]. The engine bridge copies these to OBS_CONSTRAINT
 * observations, which a passthrough rule folds into the meet as the named C_*
 * constraint. A component uses this channel for a bound on a known quantity it
 * cannot state as a located address (see kasld_emit_constraint). */
struct constraint_fact_record {
  enum kasld_quantity q;
  enum constraint_op op;
  unsigned long value;
  enum kasld_confidence conf;
  int origin; /* discovery slot of the producing component; -1 if unattributed
               */
};
#define MAX_CONSTRAINT_FACTS 64
extern struct constraint_fact_record constraint_facts[MAX_CONSTRAINT_FACTS];
extern int num_constraint_facts;

/* =========================================================================
 * Shared functions (defined in orchestrator.c)
 * ========================================================================= */
const char *meta_get(const struct component_meta *m, const char *key);
int meta_get_all(const struct component_meta *m, const char *key,
                 const char **values, int max_values);
/* Seeded before any component runs; projected onto the summary after. */
void seed_arch_kaslr_facts(void);
void summarize_kaslr_state(struct summary *s);
void compute_component_stats(struct summary *s);
/* Declared at file scope: first naming these inside the parameter list below
 * would give them PROTOTYPE scope -- a distinct type from the definition in
 * orchestrator.c, which the compiler then reports as a conflicting declaration.
 */
struct engine;
struct engine_resolution;

struct kasld_report; /* kasld/report.h; a pointer is all this needs */

/* Projects `layout` plus the engine's two resolutions into the summary, and
 * builds the report model from them. The snapshots and the report are
 * PARAMETERS, not globals: the resolution itself belongs to the caller, and
 * passing them keeps this whole function compiled -- and testable -- in the
 * build that does not link the engine, where a caller passes NULL. */
void compute_kaslr_info(struct summary *s, const struct engine *auth,
                        const struct engine_resolution *likely,
                        struct kasld_report *report);

/* =========================================================================
 * Rendering (defined in render.c)
 * ========================================================================= */
/* Pure consumer: render an already-resolved summary. The orchestrator runs
 * the engine (compute_kaslr_info) before calling this, so the renderer never
 * triggers inference. */
void render_summary(const struct summary *s, const struct kasld_report *rep);

#endif /* KASLD_INTERNAL_H */
