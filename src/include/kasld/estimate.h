// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Estimate: the resolved value of a quantity — a pure, conflict-aware fold
// of its confidence-ordered constraint set, starting from the quantity's
// honest top.
//
// The estimate stores the headline value plus, for interval quantities, the
// id of the binding constraint on each edge (so per-edge confidence and
// lineage are recoverable without duplicating state). The full
// confidence-stratified bound is a query, not stored: estimate_resolve()
// with a higher `floor` re-folds only the more-trusted constraints.
//
// Conflicts (constraints rejected because they contradict a stronger,
// already-accepted set) are resolution output, not estimate state — they
// are returned in a side list each round.
// ---
// <bcoles@gmail.com>

#ifndef KASLD_ESTIMATE_H
#define KASLD_ESTIMATE_H

#include "constraint.h"
#include "quantity.h"

#include <stdint.h>

/* One resolved quantity value. Representation per lattice:
 *  - LK_INTERVAL: [lo, hi]; lo_binding/hi_binding name the edge-setting
 *    constraints (0 = the top / no constraint bound this edge).
 *  - LK_MAXALIGN: lo holds the alignment; hi unused; lo_binding names the
 *    constraint that set it.
 *  - LK_FINSET:   lo holds the live-candidate bitmask; hi unused;
 *    lo_binding names the last constraint that narrowed it. */
struct estimate {
  enum lattice_kind kind;
  unsigned long lo, hi;
  uint32_t lo_binding, hi_binding;
  /* Optional stride annotation for LK_INTERVAL: when stride != 0, the live
   * value satisfies (q % stride) == stride_offset in addition to lying in
   * [lo, hi]. Multiple C_STRIDE constraints fold via CRT in estimate_meet;
   * unsolvable systems push the estimate to bottom. Always 0 on
   * LK_MAXALIGN / LK_FINSET (the stride concept doesn't apply there).
   * stride_binding names the most-recent C_STRIDE that touched the pair. */
  unsigned long stride;
  unsigned long stride_offset;
  uint32_t stride_binding;
};

/* Result of resolving one quantity: the estimate plus the ids of constraints
 * rejected as contradictory (lower priority than an already-accepted
 * constraint they conflict with). */
#ifndef ESTIMATE_MAX_CONFLICTS
#define ESTIMATE_MAX_CONFLICTS 32
#endif
/* Resolver per-quantity work cap. Bounds the gather buffer in
 * estimate_resolve and the hole / range buffers in quantity_ranges. None
 * of these bind on realistic deduped workloads (per-quantity constraint
 * counts stay in the dozens); the cap is a safety ceiling. */
#ifndef ESTIMATE_MAX_WORK
#define ESTIMATE_MAX_WORK 512
#endif

/* Saturation bits set by estimate_resolve when a fixed-size cap binds.
 * Engine carries these up into struct engine.saturation. */
enum estimate_saturation {
  ESTIMATE_SAT_WORK_FULL = 1u << 0, /* ESTIMATE_MAX_WORK gather truncated */
  ESTIMATE_SAT_CONFLICTS_FULL = 1u << 1, /* ESTIMATE_MAX_CONFLICTS overflowed */
};

struct resolve_result {
  struct estimate est;
  uint32_t conflicts[ESTIMATE_MAX_CONFLICTS];
  int n_conflicts;
  uint32_t saturation; /* enum estimate_saturation bits */
};

/* Meet a single constraint into an estimate (monotone narrowing). Updates
 * binding ids when an edge narrows. Caller checks estimate_is_bottom()
 * afterwards to decide whether to accept the meet. */
void estimate_meet(struct estimate *e, const struct quantity_def *qd,
                   const struct constraint *c);

/* True iff the estimate is lattice-bottom (unsatisfiable / empty). */
int estimate_is_bottom(const struct estimate *e, const struct quantity_def *qd);

/* If a finite-set (LK_FINSET) quantity's estimate has narrowed to exactly one
 * live candidate, write its value to *out and return 1. Returns 0 when the
 * quantity is not LK_FINSET, or zero / more than one candidate is still live.
 * Encapsulates the live-candidate bitmask so callers (e.g. rules reading a
 * resolved Q_VA_BITS) don't depend on the LK_FINSET representation. */
int estimate_finset_value(const struct quantity_def *qd,
                          const struct estimate *e, unsigned long *out);

/* Resolve quantity q over the constraints in cs[0..n_cs), considering only
 * those with conf >= floor. Greedy strongest-first (conf DESC, lineage_count
 * DESC, id ASC); a constraint that would force bottom is skipped and
 * recorded in out->conflicts. The result is always non-bottom and
 * deterministic. floor == CONF_BRUTE yields the headline (all real
 * constraints); a higher floor yields the trust-stratified bound. */
void estimate_resolve(enum kasld_quantity q, enum kasld_confidence floor,
                      const struct constraint *cs, int n_cs,
                      struct resolve_result *out);

/* Inclusive address sub-range. */
struct range {
  unsigned long lo, hi;
};

/* Consumer value-access seam (§0.7): yield the valid address sub-ranges of
 * quantity q's resolved estimate `e`, with interior `C_EXCLUDE` holes (from
 * cs) carved out. Writes up to out_max ranges, returns the count.
 *
 *  - LK_INTERVAL: one range [lo, hi], split by any interior excludes.
 *  - LK_FINSET:   one degenerate range [v, v] per live candidate.
 *  - LK_MAXALIGN: zero ranges (an alignment is not an address set).
 *
 * This is the set-ready interface every consumer (slot/entropy counter,
 * renderer, range-reading rules) uses, so a future LK_INTERVAL_SET changes
 * only how ranges are produced, not the consumers. The single-interval
 * lattice still narrows; holes are carved here at read time. */
int quantity_ranges(enum kasld_quantity q, const struct estimate *e,
                    const struct constraint *cs, int n_cs, struct range *out,
                    int out_max);

/* Hole-aware count of aligned candidate positions for q's resolved estimate:
 * the sum over quantity_ranges() of (span / align), span = hi - lo per range.
 * With no excludes this is (hi - lo) / align; each interior C_EXCLUDE hole
 * strictly reduces it. Returns 0 for align == 0 or a non-interval lattice. This
 * is the §0.7 terminal consumer over the set-ready range iterator — the basis
 * for hole-aware slot/entropy reporting, and the only place interior holes
 * affect a headline number. */
unsigned long quantity_slots(enum kasld_quantity q, const struct estimate *e,
                             const struct constraint *cs, int n_cs,
                             unsigned long align);

#endif /* KASLD_ESTIMATE_H */
