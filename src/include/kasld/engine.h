// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Inference engine: the fixpoint loop that turns evidence into estimates.
//
//   evidence_resolve (apply curation verdicts)
//   repeat:
//     regenerate constraints by running every rule over (evidence, estimates)
//     resolve each quantity's estimate from the full constraint set
//   until no estimate changes (or pass cap)
//
// A rule is a pure function (evidence, current estimates) -> constraints. It
// mutates nothing. Constraints are append-only across passes (deduplicated on
// content), so the constraint set only grows and estimates narrow
// monotonically — cross-pass termination is structural, not dependent on
// rule discipline, and within a pass the greedy resolver guarantees a
// non-bottom result.
// ---
// <bcoles@gmail.com>

#ifndef KASLD_ENGINE_H
#define KASLD_ENGINE_H

#include "estimate.h"
#include "evidence.h"
#include "quantity.h"

#ifndef ENGINE_MAX_CONSTRAINTS
#define ENGINE_MAX_CONSTRAINTS 1024
#endif
#ifndef ENGINE_MAX_PASSES
#define ENGINE_MAX_PASSES 8
#endif
#ifndef ENGINE_RULE_MAX_EMIT
#define ENGINE_RULE_MAX_EMIT 32
#endif

/* A rule reads evidence + current estimates, writes up to out_max
 * constraints to out[], returns the count. Pure: no mutation of inputs,
 * no global state. The engine assigns ids; rules leave constraint.id 0. */
typedef int (*rule_fn)(const struct evidence_set *ev,
                       const struct estimate *est, struct constraint *out,
                       int out_max);

/* A curation rule reads evidence and emits verdicts (V_INVALID) on
 * observations. It takes evidence only — NOT estimates — so curation is
 * fully determined by the immutable observations and fires before any
 * constraint rule consumes them; this is what keeps the append-only constraint
 * store from retaining a claim derived from a later-invalidated observation.
 * Pure: no mutation. The engine dedups verdicts and applies them via
 * evidence_resolve() before the constraint rules run each pass. */
typedef int (*verdict_fn)(const struct evidence_set *ev, struct verdict *out,
                          int out_max);

/* Saturation flags. Set by the engine when a fixed-size cap is hit. None of
 * the caps bind on realistic deduped workloads, but a hit would silently
 * drop information that could otherwise have flowed; surfacing the bit under
 * --verbose keeps the dropped-info case observable. Per-source bits so the
 * verbose output can name which cap fired. */
enum engine_saturation {
  ENGINE_SAT_CONSTRAINTS_FULL = 1u << 0, /* ENGINE_MAX_CONSTRAINTS reached */
  ENGINE_SAT_RULE_EMIT_OVERFLOW = 1u
                                  << 1, /* rule wanted > ENGINE_RULE_MAX_EMIT */
  ENGINE_SAT_VRULE_EMIT_OVERFLOW =
      1u << 2, /* verdict rule wanted > ENGINE_RULE_MAX_EMIT */
  ENGINE_SAT_ESTIMATE_WORK_FULL = 1u
                                  << 3, /* ESTIMATE_MAX_WORK gather truncated */
  ENGINE_SAT_CONFLICTS_FULL = 1u << 4,  /* ESTIMATE_MAX_CONFLICTS overflow */
};

struct engine {
  struct evidence_set ev;
  struct constraint constraints[ENGINE_MAX_CONSTRAINTS];
  int n_constraints;
  struct estimate est[Q__COUNT];
  int passes; /* diagnostic: passes taken to converge */
  /* Per-quantity ids of constraints the resolver rejected as contradictory
   * (each would force the estimate to bottom). Diagnostic only — surfaced under
   * --verbose for explainability; the resolved estimates above are unaffected.
   */
  uint32_t conflicts[Q__COUNT][ESTIMATE_MAX_CONFLICTS];
  int n_conflicts[Q__COUNT];
  /* Bitmap of engine_saturation flags. Diagnostic only; resolved estimates are
   * correct under truncation (the resolver sorts by confidence/lineage before
   * the greedy meet — see estimate.c). */
  uint32_t saturation;
};

/* Reset estimates to tops, clear the constraint store. Evidence is left
 * intact (populate it before engine_run, or reuse across runs). */
void engine_init(struct engine *e);

/* Run constraint rules + curation (verdict) rules to fixpoint. Each pass:
 * emit+dedup verdicts, evidence_resolve(), then emit+dedup constraints, then
 * resolve estimates. Populates e->est[], e->constraints[], and e->ev verdicts.
 */
void engine_run_full(struct engine *e, const rule_fn *rules, int n_rules,
                     const verdict_fn *vrules, int n_vrules);

/* Convenience: constraint rules only, no curation. */
void engine_run(struct engine *e, const rule_fn *rules, int n_rules);

#endif /* KASLD_ENGINE_H */
