// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Builds the report model from the engine's two resolutions.
//
// This is the only place that decides what a run reports. It reads estimates
// and the constraints behind them; it performs no I/O, consults no host fact,
// and reads nothing any format prints. Formats consume what it produces.
//
// ---
// <bcoles@gmail.com>

#include "include/kasld/report.h"

#include "include/kasld/api.h"

#include <string.h>

/* Human names, one per quantity, in one place.
 *
 * Indexed by the enum rather than listed in order, so a quantity added without
 * a name yields NULL instead of silently shifting every label onto the wrong
 * row. The machine name comes from the quantity table itself
 * (`quantities[q].name`), so the two cannot drift: there is one table of
 * quantities and one table of their labels, keyed the same way.
 *
 * The alignment quantities carry no label because they are not items. An
 * alignment is a parameter of the search rather than an unknown a reader hunts,
 * and it is already reported as the grain of every item it governs. */
static const char *const q_labels[Q__COUNT] = {
    [Q_VIRT_IMAGE_BASE] = "Virtual Image Base",
    [Q_PHYS_IMAGE_BASE] = "Physical Image Base",
    [Q_PAGE_OFFSET] = "Direct Map Base",
    [Q_VMALLOC_BASE] = "Vmalloc Base",
    [Q_VMEMMAP_BASE] = "Vmemmap Base",
    [Q_MODULE_BASE] = "Module Region Base",
    [Q_VA_BITS] = "Paging Level",
};

/* Whether this architecture has this unknown at all.
 *
 * Membership is a property of the machine: a target that does not randomize its
 * vmalloc base has no such unknown, and reporting one would state a non-fact.
 * Decided once here rather than per format, so no format can add or drop an
 * item.
 *
 * The alignment quantities are excluded because they are not items (see above).
 * Q_VA_BITS is a member only where more than one address-space size is
 * admissible; where the architecture admits one, nothing is unknown. */
static int q_is_member(enum kasld_quantity q) {
  switch (q) {
  case Q_VIRT_IMAGE_BASE:
  case Q_PHYS_IMAGE_BASE:
  case Q_PAGE_OFFSET:
  case Q_MODULE_BASE:
    return 1;
  case Q_VMALLOC_BASE:
  case Q_VMEMMAP_BASE:
    /* The memory-KASLR regions exist as unknowns only where the architecture
     * randomizes them. */
    return RANDOMIZE_MEMORY_ALIGN > 0;
  case Q_VA_BITS:
    return quantities[Q_VA_BITS].n_candidates > 1;
  default:
    return 0;
  }
}

/* The grain this quantity's candidates are counted on.
 *
 * Each quantity is counted at ITS OWN granularity. RANDOMIZE_MEMORY_ALIGN is
 * x86_64's memory-KASLR granule and is 0 elsewhere, so using it for every
 * target would count the memory regions at a pitch of zero on every other
 * architecture -- which yields no count at all rather than a coarse one. A
 * quantity that sits on no modelled grid returns 0, and has no candidate count
 * to state; that is a property of the quantity, not a judgement about whether
 * the count is worth showing. */
static unsigned long q_grain(enum kasld_quantity q,
                             const struct estimate *est) {
  switch (q) {
  /* The resolved alignment or the architecture's own, whichever is coarser.
   *
   * An alignment lattice starts at "aligned to 1 byte" -- least information --
   * and only rises as evidence arrives, so reading it directly would count a
   * window in BYTES whenever the rule that establishes the architectural floor
   * has not run. Taking the maximum makes the grain correct without depending
   * on any rule having fired, and is sound in the same direction the lattice
   * moves: the architectural value is the coarsest the kernel can be relied on
   * to use, and a resolved floor can only raise it. */
  case Q_VIRT_IMAGE_BASE: {
    unsigned long a = est[Q_VIRT_KASLR_ALIGN].lo;
    return a > (unsigned long)KASLR_VIRT_ALIGN
               ? a
               : (unsigned long)KASLR_VIRT_ALIGN;
  }
  case Q_PHYS_IMAGE_BASE: {
    unsigned long a = est[Q_PHYS_KASLR_ALIGN].lo;
    return a > (unsigned long)KASLR_PHYS_ALIGN
               ? a
               : (unsigned long)KASLR_PHYS_ALIGN;
  }
  case Q_PAGE_OFFSET:
  case Q_VMALLOC_BASE:
  case Q_VMEMMAP_BASE:
#if RANDOMIZE_MEMORY_ALIGN > 0
    return (unsigned long)RANDOMIZE_MEMORY_ALIGN;
#else
    /* Not randomized here, but still bounded, and a base is page-granular at
     * worst -- so there is a real pitch to count on. */
    return KASLD_LAYOUT_GRANULE;
#endif
  case Q_MODULE_BASE:
    return KASLD_LAYOUT_GRANULE;
  case Q_VA_BITS:
    return 0; /* a finite set of sizes sits on no grid */
  default:
    return 0;
  }
}

/* Bits of entropy from a candidate count: ceil(log2(v)) for v >= 1, 0 for 0.
 *
 * CEIL, not floor: the user-facing question is how much brute-force work
 * remains, and 13 candidates is ~4 bits of worst-case work rather than 3.
 * Power-of-two inputs are unaffected. */
static int report_bits(unsigned long v) {
  int r = 0;
  unsigned long n;
  if (v <= 1)
    return 0;
  n = v;
  while (n >>= 1)
    r++;
  if ((v & (v - 1)) != 0)
    r++;
  return r;
}

/* The window the kernel's own randomization draws from, in candidates.
 *
 * A static property of the architecture, so it is read from the arch header
 * rather than from the run -- it says what the kernel could have done, not what
 * this run learned. Zero where the architecture defines no randomization window
 * for the quantity: the memory-KASLR regions are bounded by a budget derived
 * from observed RAM rather than by a constant, so their denominator is resolved
 * rather than declared and does not belong here. A finite set is its own
 * denominator and needs none. */
static unsigned long q_entropy_top(enum kasld_quantity q, unsigned long grain) {
  unsigned long lo = 0, hi = 0;
  switch (q) {
  case Q_VIRT_IMAGE_BASE:
    lo = (unsigned long)KASLR_VIRT_TEXT_MIN;
    hi = (unsigned long)KASLR_VIRT_TEXT_MAX;
    break;
  case Q_PHYS_IMAGE_BASE:
    lo = (unsigned long)KASLR_PHYS_MIN;
    hi = (unsigned long)KASLR_PHYS_MAX;
    break;
  default:
    return 0;
  }
  return (grain && hi > lo) ? (hi - lo) / grain + 1 : 0;
}

/* Collect the excluded sub-ranges the engine carved out of this window's hull.
 *
 * The holes are NOT stored in the estimate -- it keeps only the convex hull --
 * so they are re-derived from the constraint list, exactly as the candidate
 * count is. A consumer handed only the estimate cannot recover them, which is
 * why they are lifted into the model here rather than left for a format to
 * rediscover.
 *
 * The floor gate matches the resolver's: a sub-floor exclusion never reached
 * this window's edges, so it must not be presented as carving its interior. */
static void collect_holes(struct kasld_report_window *w, enum kasld_quantity q,
                          enum kasld_confidence floor,
                          const struct constraint *cs, int n_cs) {
  w->n_excluded = 0;
  w->excluded_listed = 0;
  if (!cs || !w->present)
    return;
  for (int i = 0; i < n_cs; i++) {
    unsigned long a, b;
    if (cs[i].q != q || cs[i].op != C_EXCLUDE || (int)cs[i].conf < (int)floor)
      continue;
    a = cs[i].value;
    b = cs[i].value2;
    if (b < w->lo || a > w->hi)
      continue; /* entirely outside the hull */
    if (a < w->lo)
      a = w->lo;
    if (b > w->hi)
      b = w->hi;
    w->n_excluded++;
    if (w->excluded_listed < KASLD_REPORT_MAX_EXCLUDED) {
      w->excluded[w->excluded_listed].lo = a;
      w->excluded[w->excluded_listed].hi = b;
      w->excluded_listed++;
    }
  }
}

/* Project one resolution's estimate for one quantity into a reported window. */
static void build_window(struct kasld_report_window *w, enum kasld_quantity q,
                         struct kasld_resolution_view v, unsigned long grain) {
  const struct estimate *e;
  memset(w, 0, sizeof(*w));
  if (!v.est)
    return;
  e = &v.est[q];

  switch (e->kind) {
  case LK_INTERVAL:
    w->shape = RSHAPE_INTERVAL;
    w->lo = e->lo;
    w->hi = e->hi;
    w->has_lo = e->lo != 0;
    w->has_hi = e->hi != 0;
    w->stride = e->stride;
    w->stride_offset = e->stride_offset;
    break;
  case LK_FINSET: {
    /* Decode the live-candidate bitmask into the values it stands for. A set is
     * not an interval: it has no endpoints to report and no grid to count on,
     * so quantity_slots -- which needs a pitch -- cannot count it, and the
     * count is simply how many values remain admissible. */
    const struct quantity_def *qd = &quantities[q];
    w->shape = RSHAPE_SET;
    for (int i = 0; i < qd->n_candidates; i++)
      if (e->lo & (1ul << i))
        w->values[w->n_values++] = qd->candidates[i];
    w->present = w->n_values > 0;
    w->candidates = (unsigned long)w->n_values;
    w->bits = report_bits(w->candidates);
    return;
  }
  case LK_MAXALIGN:
    w->shape = RSHAPE_FLOOR;
    w->lo = e->lo;
    w->has_lo = e->lo != 0;
    w->has_hi = 0;
    break;
  }
  w->present = w->has_lo || w->has_hi;
  if (!w->present)
    return;

  /* A count needs both edges. A one-sided bound is real information -- "the
   * module base is at or below X" -- but it is UNBOUNDED, and counting it from
   * zero would state a number that contradicts the missing edge beside it. The
   * module base tops out at [0, VAS_END] precisely so an un-narrowed one reads
   * as unbounded rather than as a window, and a count would undo that. */
  if (w->has_lo && w->has_hi) {
    w->candidates = quantity_slots(q, e, v.floor, v.cs, v.n_cs, grain);
    w->bits = report_bits(w->candidates);
  }
  collect_holes(w, q, v.floor, v.cs, v.n_cs);
}

void kasld_report_build(struct kasld_resolution_view guaranteed,
                        struct kasld_resolution_view likely,
                        const struct kasld_report_point *points,
                        enum kasld_posture posture, struct kasld_report *out) {
  memset(out, 0, sizeof(*out));
  out->posture = posture;
  if (!guaranteed.est)
    return;

  for (int qi = 0; qi < Q__COUNT; qi++) {
    enum kasld_quantity q = (enum kasld_quantity)qi;
    struct kasld_report_quantity *it;
    unsigned long grain;
    struct estimate top;

    if (!q_is_member(q))
      continue;

    it = &out->quantities[out->n_quantities++];
    memset(it, 0, sizeof(*it));
    it->q = q;
    it->key = quantities[q].name;
    it->label = q_labels[q];

    grain = q_grain(q, guaranteed.est);
    it->align_min = grain;

    /* What the engine was willing to consider, counted the same way the
     * resolved window is so the two are directly comparable. */
    if (quantities[q].lattice == LK_FINSET) {
      it->search_top = (unsigned long)quantities[q].n_candidates;
    } else if (quantities[q].init_top) {
      quantities[q].init_top(&top);
      it->search_top =
          quantity_slots(q, &top, guaranteed.floor, NULL, 0, grain);
    }
    it->entropy_top = q_entropy_top(q, grain);

    build_window(&it->guaranteed, q, guaranteed, grain);
    build_window(&it->likely, q, likely, grain);

    if (points && points[q].present) {
      it->has_point = 1;
      it->point = points[q].value;
      it->anchor = points[q].anchor;
      it->slide = points[q].slide;
      it->has_slide = points[q].has_slide;
    }
  }
}

int kasld_report_likely_is_tighter(const struct kasld_report_quantity *it) {
  const struct kasld_report_window *l, *g;
  if (!it || !it->likely.present)
    return 0;
  l = &it->likely;
  g = &it->guaranteed;
  if (l->has_lo && (!g->has_lo || l->lo > g->lo))
    return 1;
  if (l->has_hi && (!g->has_hi || l->hi < g->hi))
    return 1;
  return 0;
}

const struct kasld_report_quantity *
kasld_report_find(const struct kasld_report *r, enum kasld_quantity q) {
  if (!r)
    return NULL;
  for (int i = 0; i < r->n_quantities; i++)
    if (r->quantities[i].q == q)
      return &r->quantities[i];
  return NULL;
}
