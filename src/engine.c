// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Inference engine fixpoint loop. See engine.h for the model.
// Arch-independent.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine.h"

#include <string.h>

void engine_init(struct engine *e) {
  evidence_init(&e->ev);
  e->n_constraints = 0;
  e->passes = 0;
  e->saturation = 0;
  for (int q = 0; q < Q__COUNT; q++) {
    quantities[q].init_top(&e->est[q]);
    e->n_conflicts[q] = 0;
  }
}

/* Two constraints are duplicates if they make the same claim from the same
 * source (id and lineage ignored — the engine assigns fresh ids each pass,
 * and a re-emitted identical claim must not grow the store). */
static int same_claim(const struct constraint *a, const struct constraint *b) {
  return a->q == b->q && a->op == b->op && a->value == b->value &&
         a->value2 == b->value2 && a->conf == b->conf &&
         strncmp(a->origin, b->origin, ORIGIN_LEN) == 0;
}

static int already_have(const struct engine *e, const struct constraint *c) {
  for (int i = 0; i < e->n_constraints; i++)
    if (same_claim(&e->constraints[i], c))
      return 1;
  return 0;
}

static void resolve_all(struct engine *e, enum kasld_confidence floor) {
  for (int q = 0; q < Q__COUNT; q++) {
    struct resolve_result r;
    estimate_resolve((enum kasld_quantity)q, floor, e->constraints,
                     e->n_constraints, &r);
    e->est[q] = r.est;
    /* Retain the rejected-constraint ids for --verbose explainability. The
     * last (post-fixpoint) resolve's conflicts are the meaningful ones. */
    e->n_conflicts[q] = r.n_conflicts;
    for (int i = 0; i < r.n_conflicts; i++)
      e->conflicts[q][i] = r.conflicts[i];
    /* Carry per-quantity saturation up into engine-wide flags. */
    if (r.saturation & ESTIMATE_SAT_WORK_FULL)
      e->saturation |= ENGINE_SAT_ESTIMATE_WORK_FULL;
    if (r.saturation & ESTIMATE_SAT_CONFLICTS_FULL)
      e->saturation |= ENGINE_SAT_CONFLICTS_FULL;
  }
}

/* evidence_resolve() plus a confidence-floor gate on observations: an
 * observation is in scope for this run only if its confidence is at or above
 * `floor`. Marking a below-floor observation invalid (the same bit verdicts
 * use) makes the pure rules skip it with no rule changes; the next
 * evidence_resolve resets `valid`, so the gate is re-applied every pass.
 * floor == CONF_BRUTE gates nothing — identical to an unfiltered resolve. This
 * is the structural soundness mechanism for a floored run: a rule can only ever
 * read >= floor facts, so whatever it emits was derived purely from >= floor
 * inputs, regardless of how the rule labels its output. */
static void resolve_evidence(struct engine *e, enum kasld_confidence floor) {
  evidence_resolve(&e->ev);
  if (floor > CONF_BRUTE)
    for (int i = 0; i < e->ev.n_obs; i++)
      if ((int)e->ev.obs[i].conf < (int)floor)
        e->ev.obs[i].valid = 0;
}

/* Estimates compare by value only — binding ids change as constraints get
 * fresh ids each pass, so comparing them would prevent convergence. Includes
 * the stride annotation: a pass that tightened only the residue class
 * (without moving lo/hi) still narrowed the resolved value set, and
 * downstream consumers (quantity_slots) read stride/stride_offset directly,
 * so an unchanged interval with a changed stride is not converged. */
static int estimates_equal(const struct estimate *a, const struct estimate *b) {
  for (int q = 0; q < Q__COUNT; q++)
    if (a[q].kind != b[q].kind || a[q].lo != b[q].lo || a[q].hi != b[q].hi ||
        a[q].stride != b[q].stride || a[q].stride_offset != b[q].stride_offset)
      return 0;
  return 1;
}

/* Two verdicts are duplicates if they make the same ruling on the same
 * observation from the same source (lineage ignored). Verdicts carry no id;
 * dedup keeps the append-only verdict list from growing across passes. */
static int same_verdict(const struct verdict *a, const struct verdict *b) {
  return a->observation_id == b->observation_id && a->kind == b->kind &&
         strncmp(a->origin, b->origin, ORIGIN_LEN) == 0;
}

static int already_have_verdict(const struct evidence_set *ev,
                                const struct verdict *v) {
  for (int i = 0; i < ev->n_verdicts; i++)
    if (same_verdict(&ev->verdicts[i], v))
      return 1;
  return 0;
}

void engine_run_full_floored(struct engine *e, enum kasld_confidence floor,
                             const rule_fn *rules, int n_rules,
                             const verdict_fn *vrules, int n_vrules) {
  resolve_evidence(e, floor);
  e->n_constraints = 0;
  /* Reset diagnostic state. engine_init() also clears these, but callers may
   * re-drive an engine without re-init when only evidence has changed;
   * resetting here makes the saturation/conflict reports reflect *this* run
   * only. */
  e->saturation = 0;
  for (int q = 0; q < Q__COUNT; q++)
    e->n_conflicts[q] = 0;
  /* Re-resolve from cleared constraints. Redundant when the caller just
   * engine_init'd (est[] is already at tops), but load-bearing on re-use:
   * a second engine_run_full on the same engine would otherwise carry the
   * previous run's resolved estimates into the first pass's convergence
   * snapshot, breaking the estimates_equal early-exit. */
  resolve_all(e, floor);

  uint32_t next_id = 1;
  for (int pass = 0; pass < ENGINE_MAX_PASSES; pass++) {
    struct estimate snap[Q__COUNT];
    memcpy(snap, e->est, sizeof(snap));

    /* Curation first: emit + dedup verdicts, then recompute the effective
     * view so the constraint rules below see curated evidence. Verdict rules
     * read only (immutable) observations, so curation completes before any
     * constraint rule consumes an observation that would later be invalidated.
     */
    for (int v = 0; v < n_vrules; v++) {
      struct verdict vt[ENGINE_RULE_MAX_EMIT];
      int k = vrules[v](&e->ev, vt, ENGINE_RULE_MAX_EMIT);
      if (k > ENGINE_RULE_MAX_EMIT) {
        k = ENGINE_RULE_MAX_EMIT;
        e->saturation |= ENGINE_SAT_VRULE_EMIT_OVERFLOW;
      }
      for (int i = 0; i < k; i++)
        if (!already_have_verdict(&e->ev, &vt[i]))
          evidence_add_verdict(&e->ev, &vt[i]);
    }
    resolve_evidence(e, floor);

    for (int r = 0; r < n_rules; r++) {
      struct constraint tmp[ENGINE_RULE_MAX_EMIT];
      int k = rules[r](&e->ev, e->est, tmp, ENGINE_RULE_MAX_EMIT);
      if (k > ENGINE_RULE_MAX_EMIT) {
        k = ENGINE_RULE_MAX_EMIT;
        e->saturation |= ENGINE_SAT_RULE_EMIT_OVERFLOW;
      }
      for (int i = 0; i < k; i++) {
        if (e->n_constraints >= ENGINE_MAX_CONSTRAINTS) {
          e->saturation |= ENGINE_SAT_CONSTRAINTS_FULL;
          break; /* safety cap, far above realistic deduped counts */
        }
        if (already_have(e, &tmp[i]))
          continue; /* dedup keeps the store from growing across passes */
        tmp[i].id = next_id++;
        e->constraints[e->n_constraints++] = tmp[i];
      }
    }

    resolve_all(e, floor);
    e->passes = pass + 1;
    if (estimates_equal(snap, e->est))
      break;
  }
}

/* The unfiltered run (floor = CONF_BRUTE): every observation is in scope and
 * resolution admits every constraint — the engine's primary "likely" result.
 * A floored run (floor > CONF_BRUTE) is the sound-window computation; the
 * orchestrator owns the policy of which floors to run and what to call them. */
void engine_run_full(struct engine *e, const rule_fn *rules, int n_rules,
                     const verdict_fn *vrules, int n_vrules) {
  engine_run_full_floored(e, CONF_BRUTE, rules, n_rules, vrules, n_vrules);
}

void engine_run(struct engine *e, const rule_fn *rules, int n_rules) {
  engine_run_full(e, rules, n_rules, NULL, 0);
}
