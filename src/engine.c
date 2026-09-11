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
  if (floor > CONF_BRUTE) {
    for (int i = 0; i < e->ev.n_obs; i++)
      if ((int)e->ev.obs[i].conf < (int)floor)
        e->ev.obs[i].valid = 0;
    /* Coverings take the same gate. Without it a below-floor map reaches the
     * guaranteed window whenever a consuming rule forgets to carry the
     * covering's confidence into what it emits -- which the rule emitting
     * verdicts cannot do at all, verdicts having no floor gate to carry it
     * to. Gating the input makes that independent of each rule's diligence. */
    for (int i = 0; i < e->ev.n_coverings; i++)
      if ((int)e->ev.coverings[i].conf < (int)floor)
        e->ev.coverings[i].valid = 0;
  }
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

/* Run the curation rules to fixpoint, so the constraint rules below only ever
 * read fully-curated evidence.
 *
 * One round is not enough. A verdict rule reads the EFFECTIVE view — an
 * observation's `valid` bit and its effective region/type — so one ruling can
 * enable another: text_cluster_filter takes the median of the surviving
 * kernel-image observations, and dropping an outlier moves that median, which
 * can expose a second outlier (or flip its strict-majority guard from refusing
 * to acting). Running the constraint rules against a half-curated set would
 * leave the append-only constraint store holding a claim derived from an
 * observation the engine went on to reject, and nothing retracts a constraint.
 *
 * Terminates: verdicts are deduped and V_INVALID is a latch, so the valid set
 * shrinks monotonically and every round either adds a verdict or is the last.
 * The round cap is a backstop, not the mechanism.
 *
 * Both failure modes leave curation incomplete rather than merely truncated —
 * an observation the engine ruled invalid stays readable — so each raises its
 * own saturation bit. */
static void curate_to_fixpoint(struct engine *e, enum kasld_confidence floor,
                               const verdict_fn *vrules, int n_vrules) {
  for (int round = 0; round < ENGINE_MAX_CURATION_ROUNDS; round++) {
    int added = 0;
    for (int v = 0; v < n_vrules; v++) {
      struct verdict vt[ENGINE_RULE_MAX_EMIT];
      int k = vrules[v](&e->ev, vt, ENGINE_RULE_MAX_EMIT);
      if (k > ENGINE_RULE_MAX_EMIT) {
        k = ENGINE_RULE_MAX_EMIT;
        e->saturation |= ENGINE_SAT_VRULE_EMIT_OVERFLOW;
      }
      for (int i = 0; i < k; i++) {
        if (already_have_verdict(&e->ev, &vt[i]))
          continue;
        if (!evidence_add_verdict(&e->ev, &vt[i])) {
          e->saturation |= ENGINE_SAT_VERDICTS_FULL;
          continue;
        }
        added++;
      }
    }
    /* Recompute the effective view so the next round — and the constraint
     * rules after it — see this round's rulings. */
    resolve_evidence(e, floor);
    if (!added)
      return;
  }
  e->saturation |= ENGINE_SAT_CURATION_UNSETTLED;
}

/* Confidence of one lineage entry, or CONF_UNKNOWN when the id names nothing
 * this run holds. Lineage ids are drawn from two spaces (see constraint.h), so
 * the store to search is read off the id itself rather than guessed. */
static enum kasld_confidence lineage_entry_conf(const struct engine *e,
                                                uint32_t id) {
  if (id == 0)
    return CONF_UNKNOWN;
  if (kasld_id_is_constraint(id)) {
    for (int i = 0; i < e->n_constraints; i++)
      if (e->constraints[i].id == id)
        return e->constraints[i].conf;
    return CONF_UNKNOWN;
  }
  for (int i = 0; i < e->ev.n_obs; i++)
    if (e->ev.obs[i].id == id)
      return e->ev.obs[i].conf;
  for (int i = 0; i < e->ev.n_coverings; i++)
    if (e->ev.coverings[i].id == id)
      return e->ev.coverings[i].conf;
  return CONF_UNKNOWN;
}

/* Hold a constraint to the trust of what it rests on: its confidence is capped
 * at the least confident entry in its lineage.
 *
 * A rule grades what it emits by the provenance it reasoned about -- which
 * region tag a witness carried, which signal licensed a pin -- and that grading
 * is the rule's own judgement, kept. What a rule cannot state from where it
 * stands is the trust of the particular witness it happened to read: the same
 * REGION_DIRECTMAP tag arrives from a parsed map and from a timing probe, and a
 * bound derived from the second is worth what the second is worth. The two
 * factors are both real, so the emitted confidence is the lesser of them.
 *
 * Applied here rather than in each rule because reachability is not a property
 * a rule can see. Which observations can arrive weakly is a fact about the
 * component set, so a new timing technique reporting an existing region would
 * silently promote the output of rules that were correct the day before.
 *
 * The cap only ever lowers, which only ever removes constraints from a fold --
 * away from over-narrowing, never toward it. It cannot change what a floored
 * run admits: every observation a rule can read there is already at or above
 * the floor, so the minimum over any lineage is too. Where it does bite is a
 * rule that read an out-of-scope observation anyway; the claim then falls to
 * that observation's confidence and leaves the floored fold, which is the
 * repair a forgotten `valid` guard needs.
 *
 * Lineage is what the claim rests on, not merely what the rule looked at: an
 * emission carrying an architectural value alone records none (lineage_count
 * 0) and is not capped.
 *
 * An entry naming nothing this run holds is skipped rather than treated as
 * worthless, since capping to CONF_UNKNOWN would discard a claim over a stale
 * id. That is the permissive direction, so it is worth knowing what reaches it:
 * every lineage entry is an observation or covering id, both of which are in
 * the set before any rule runs, and no rule records a CONSTRAINT id. A rule
 * that began to do so could name one emitted later in the same pass, which is
 * not yet stored and so would not cap until the following pass -- by which time
 * the uncapped claim is already in an append-only store. Such a rule needs the
 * ordering settled here first. */
static void cap_conf_to_lineage(const struct engine *e, struct constraint *c) {
  enum kasld_confidence worst = c->conf;

  for (int i = 0; i < c->lineage_count && i < MAX_LINEAGE; i++) {
    enum kasld_confidence lc = lineage_entry_conf(e, c->derived_from[i]);
    if (lc != CONF_UNKNOWN && (int)lc < (int)worst)
      worst = lc;
  }
  c->conf = worst;
}

void engine_run_full_floored(struct engine *e, enum kasld_confidence floor,
                             const rule_fn *rules, int n_rules,
                             const verdict_fn *vrules, int n_vrules) {
  /* Discard any standing curation before the evidence is resolved. A verdict
   * is a conclusion a rule drew from the evidence that was in scope when it
   * ran, exactly as a constraint is, and it is retained in the evidence set
   * rather than in the per-run constraint store — so on a re-driven engine it
   * is the one conclusion that would outlive the run that reached it. The
   * damage is one-directional: a run at a higher floor re-derives its own
   * verdicts from its own in-scope evidence, but an inherited one was reached
   * from evidence this run excludes, and invalidating an in-scope observation
   * is enough to widen the resolved window. Clearing here makes each run's
   * curation a function of that run's floor, rather than of what the caller
   * remembered to reset. */
  e->ev.n_verdicts = 0;
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

  /* Curation settles once, before any constraint is emitted. Verdict rules
   * depend only on the evidence set, which nothing below mutates, so re-running
   * them per pass could not produce a ruling this has not already applied —
   * and running them alongside the constraint rules is precisely what would let
   * a retained constraint outlive the observation it came from. */
  curate_to_fixpoint(e, floor, vrules, n_vrules);

  uint32_t next_id = 1;
  for (int pass = 0; pass < ENGINE_MAX_PASSES; pass++) {
    struct estimate snap[Q__COUNT];
    memcpy(snap, e->est, sizeof(snap));

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
        /* Cap before the dedup test, not after: `same_claim` compares
         * confidence, so a claim stored capped and re-emitted uncapped would
         * read as new on every pass and grow the store. */
        cap_conf_to_lineage(e, &tmp[i]);
        if (already_have(e, &tmp[i]))
          continue; /* dedup keeps the store from growing across passes */
        tmp[i].id = KASLD_CONSTRAINT_ID(next_id++);
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
