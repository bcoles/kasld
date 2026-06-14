// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Per-quantity definitions: lattice kind + honest top, compiled per-arch
// (init_top reads the arch constants via api.h).
//
// Honest tops are constant and maximally wide — they must contain every
// value the quantity can take on this arch. All narrowing, including from
// runtime-discovered config (CPUID phys-bits, VA_BITS, VMSPLIT), happens
// via constraints, never via a dependent or runtime top. This is the
// soundness invariant the rest of the engine relies on.
//
// x86_64 is fully treated. Other arches build via fallbacks and may carry
// looser (still sound, where the existing VAS/phys constants span honestly)
// tops until they receive the same per-arch treatment.
// ---
// <bcoles@gmail.com>

#include "include/kasld/estimate.h"
#include "include/kasld/quantity.h"

#include <limits.h>

/* ---- VA_BITS candidate table (finite-set lattice) --------------------- */
#if defined(VA_BITS_CANDIDATES)
static const unsigned long va_bits_candidates[] = VA_BITS_CANDIDATES;
#else
/* Fallback: single candidate so the lattice is well-formed on arches that
 * haven't declared a candidate set yet. */
static const unsigned long va_bits_candidates[] = {48ul};
#endif
#define N_VA_BITS                                                              \
  ((int)(sizeof(va_bits_candidates) / sizeof(va_bits_candidates[0])))

/* ---- honest tops ------------------------------------------------------ */

static void top_interval(struct estimate *e, unsigned long lo,
                         unsigned long hi) {
  e->kind = LK_INTERVAL;
  e->lo = lo;
  e->hi = hi;
  e->lo_binding = e->hi_binding = 0;
  e->stride = 0;
  e->stride_offset = 0;
  e->stride_binding = 0;
}

static void top_virt_text_base(struct estimate *e) {
  /* The virtual kernel-text base lives in the virtual KASLR window
   * [KASLR_VIRT_TEXT_MIN_WIDE, KASLR_VIRT_TEXT_MAX] — fixed per-arch by the
   * kernel's VA layout (unlike the physical base, this does not depend on DRAM
   * placement), so it is a sound and tighter honest top than the raw
   * mapping-region bounds KERNEL_VIRT_TEXT_MIN/MAX.
   *
   * The _WIDE floor is the conservative variant of KASLR_VIRT_TEXT_MIN — same
   * value where the arch's KASLR_VIRT_TEXT_MIN does not bake in a configurable
   * Kconfig knob; *wider* on arches like x86_64 where KASLR_VIRT_TEXT_MIN
   * embeds CONFIG_PHYSICAL_START at its compile-time default. The
   * physical_start_lower_bound rule restores the tight floor at the
   * appropriate confidence (CONF_PARSED from a learned SF_PHYSICAL_START,
   * CONF_HEURISTIC from the compile-time default — overridable by any
   * real evidence). */
  top_interval(e, (unsigned long)KASLR_VIRT_TEXT_MIN_WIDE,
               (unsigned long)KASLR_VIRT_TEXT_MAX);
}

static void top_phys_text_base(struct estimate *e) {
  /* Floor: the arch's minimum physical load address. Same widening
   * rationale as top_virt_text_base — KASLR_PHYS_MIN_WIDE is the
   * conservative variant of KASLR_PHYS_MIN. */
#if defined(KASLR_PHYS_MIN_WIDE)
  unsigned long lo = (unsigned long)KASLR_PHYS_MIN_WIDE;
#elif defined(KASLR_PHYS_MIN)
  unsigned long lo = (unsigned long)KASLR_PHYS_MIN;
#else
  unsigned long lo = 0ul;
#endif
#if defined(PHYS_ADDR_TOP)
  top_interval(e, lo, (unsigned long)PHYS_ADDR_TOP);
#elif defined(KERNEL_PHYS_MAX)
  /* Fallback: the heuristic ceiling, until this arch gets PHYS_ADDR_TOP.
   * Sound only insofar as KERNEL_PHYS_MAX is honest for the arch. */
  top_interval(e, lo, (unsigned long)KERNEL_PHYS_MAX);
#else
  /* Coupled arch with no independent physical KASLR: quantity inactive,
   * fully unknown. It simply never gets constrained. */
  top_interval(e, lo, ULONG_MAX);
#endif
}

static void top_page_offset(struct estimate *e) {
  /* Interval over the architectural kernel VAS window. Honest where
   * KERNEL_VIRT_VAS_START/END span every PAGE_OFFSET the arch admits (true on
   * x86_64: spans 4- and 5-level). Discrete-few arches (x86_32 VMSPLIT,
   * arm64/riscv64 paging) get the finite-set refinement in per-arch
   * follow-ups. */
  top_interval(e, (unsigned long)KERNEL_VIRT_VAS_START,
               (unsigned long)KERNEL_VIRT_VAS_END);
}

static void top_kernel_vas_window(struct estimate *e) {
  /* vmalloc/vmemmap bases (x86_64 RANDOMIZE_MEMORY) live somewhere in the
   * kernel VAS; inactive on other arches (never constrained). */
  top_interval(e, (unsigned long)KERNEL_VIRT_VAS_START,
               (unsigned long)KERNEL_VIRT_VAS_END);
}

static void top_maxalign(struct estimate *e) {
  /* Least information for an alignment lattice is "aligned to 1 byte";
   * meet (max) only raises it as evidence arrives. */
  e->kind = LK_MAXALIGN;
  e->lo = 1ul;
  e->hi = 0ul;
  e->lo_binding = e->hi_binding = 0;
  e->stride = e->stride_offset = e->stride_binding = 0;
}

static void top_va_bits(struct estimate *e) {
  e->kind = LK_FINSET;
  /* All candidates possible: low N_VA_BITS bits set. */
  e->lo = (N_VA_BITS >= (int)(sizeof(unsigned long) * 8))
              ? ~0ul
              : ((1ul << N_VA_BITS) - 1ul);
  e->hi = 0ul;
  e->lo_binding = e->hi_binding = 0;
  e->stride = e->stride_offset = e->stride_binding = 0;
}

/* ---- the table -------------------------------------------------------- */

/* X-macro list of every quantity the engine resolves. Used both to populate
 * the table below and to compile-time-verify (via the _Static_assert at the
 * bottom) that the list mentions exactly Q__COUNT entries — adding a new
 * Q_ enumerator without a list entry, or adding a list entry without a
 * matching enumerator, fails the build. Avoids the previous foot-gun where
 * a missing `[Q_NEW] = {...}` left the slot zero-initialised (NULL `name`,
 * NULL `init_top`, LK_INTERVAL by default) and surfaced as a NULL-deref on
 * the first access. */
#define KASLD_QUANTITY_LIST(X)                                                 \
  X(Q_VIRT_TEXT_BASE, "virt_text_base", LK_INTERVAL, top_virt_text_base, NULL, \
    0)                                                                         \
  X(Q_PHYS_TEXT_BASE, "phys_text_base", LK_INTERVAL, top_phys_text_base, NULL, \
    0)                                                                         \
  X(Q_PAGE_OFFSET, "virt_page_offset", LK_INTERVAL, top_page_offset, NULL, 0)  \
  X(Q_VMALLOC_BASE, "virt_vmalloc_base", LK_INTERVAL, top_kernel_vas_window,   \
    NULL, 0)                                                                   \
  X(Q_VMEMMAP_BASE, "virt_vmemmap_base", LK_INTERVAL, top_kernel_vas_window,   \
    NULL, 0)                                                                   \
  X(Q_VIRT_KASLR_ALIGN, "virt_kaslr_align", LK_MAXALIGN, top_maxalign, NULL,   \
    0)                                                                         \
  X(Q_PHYS_KASLR_ALIGN, "phys_kaslr_align", LK_MAXALIGN, top_maxalign, NULL,   \
    0)                                                                         \
  X(Q_VA_BITS, "va_bits", LK_FINSET, top_va_bits, va_bits_candidates, N_VA_BITS)

const struct quantity_def quantities[Q__COUNT] = {
#define X(qid, name, kind, top, cands, ncands)                                 \
  [qid] = {name, kind, top, cands, ncands},
    KASLD_QUANTITY_LIST(X)
#undef X
};

/* Compile-time completeness check: counts the X-macro entries and compares
 * to Q__COUNT. Drift in either direction (missing entry, extra entry)
 * fails the build. */
enum {
  kasld_quantity_list_count = 0
#define X(...) +1
  KASLD_QUANTITY_LIST(X)
#undef X
};
/* Cast both sides to int so the comparison is between integers, not between
 * two distinct anonymous enum types (gcc's -Wenum-compare otherwise warns).
 * __extension__ silences -Wpedantic on the -std=c99 build path:
 * _Static_assert is a C11 keyword that gcc has supported as an extension
 * since well before then, but pedantic flags any post-C99 keyword. */
__extension__ _Static_assert(
    (int)kasld_quantity_list_count == (int)Q__COUNT,
    "quantities[] X-macro must mention every Q_ enumerator "
    "(and nothing else)");
