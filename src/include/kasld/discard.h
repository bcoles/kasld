// This file is part of KASLD - https://github.com/bcoles/kasld
//
// The discard ledger: what left the pipeline, and why.
//
// Standalone: everything below rests on ORIGIN_LEN and nothing else, so a
// reader of the ledger need not take the orchestrator's internals with it.
// ---
// <bcoles@gmail.com>

#ifndef KASLD_DISCARD_H
#define KASLD_DISCARD_H

#include "api.h"

/* =========================================================================
 * Discard ledger — what this run threw away, and why.
 *
 * Evidence leaves the pipeline in several places: a wire line that fails
 * validation, an address outside its region's address space, a fixed-size
 * store that fills, a curation rule that invalidates an observation, the
 * resolver rejecting a conflicting constraint. Each arises in a different
 * layer with its own mechanism, so without one place to record them a loss
 * reaches no channel at all.
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
#define DSRC_META "component-meta"
#define DSRC_ESTIMATE_WORK "estimate-work"
#define DSRC_CONFLICT_STORE "conflict-store"
#define DSRC_CURATION_ROUNDS "curation-rounds"

#endif /* KASLD_DISCARD_H */
