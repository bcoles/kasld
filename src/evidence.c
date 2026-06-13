// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Evidence store + verdict application. See evidence.h for the model.
// Arch-independent.
// ---
// <bcoles@gmail.com>

#include "include/kasld/evidence.h"

#include <string.h>

void evidence_init(struct evidence_set *ev) {
  ev->n_obs = 0;
  ev->n_verdicts = 0;
  ev->n_coverings = 0;
  ev->next_id = 1; /* 0 is reserved as "no observation" */
}

uint32_t evidence_add(struct evidence_set *ev, const struct observation *src) {
  if (ev->n_obs >= MAX_OBSERVATIONS)
    return 0;
  struct observation *o = &ev->obs[ev->n_obs++];
  *o = *src;
  o->id = ev->next_id++;
  /* Effective view starts equal to source; valid until a verdict says
   * otherwise. evidence_resolve recomputes these from scratch each round,
   * so the initial values here only matter before the first resolve. */
  o->eff_type = o->type;
  o->eff_region = o->region;
  o->valid = 1;
  return o->id;
}

uint32_t evidence_add_covering(struct evidence_set *ev,
                               const struct covering *src) {
  /* Defensive: MAX_COVERINGS == MAX_OBSERVATIONS >= the result count coverings
   * are drawn from, so this never trips in practice. Kept so a covering is
   * dropped rather than overflowing the store if those bounds ever diverge. */
  if (ev->n_coverings >= MAX_COVERINGS)
    return 0;
  struct covering *c = &ev->coverings[ev->n_coverings++];
  *c = *src;
  c->id = ev->next_id++;
  return c->id;
}

int evidence_add_verdict(struct evidence_set *ev, const struct verdict *v) {
  if (ev->n_verdicts >= MAX_VERDICTS)
    return 0;
  ev->verdicts[ev->n_verdicts++] = *v;
  return 1;
}

static struct observation *find_obs(struct evidence_set *ev, uint32_t id) {
  for (int i = 0; i < ev->n_obs; i++)
    if (ev->obs[i].id == id)
      return &ev->obs[i];
  return NULL;
}

void evidence_resolve(struct evidence_set *ev) {
  /* Phase 1: reset every effective view to its immutable source. */
  for (int i = 0; i < ev->n_obs; i++) {
    struct observation *o = &ev->obs[i];
    o->eff_type = o->type;
    o->eff_region = o->region;
    o->valid = 1;
  }
  /* Phase 2: apply verdicts. Order-independent: V_INVALID is a latch (once
   * invalid, stays invalid). */
  for (int i = 0; i < ev->n_verdicts; i++) {
    const struct verdict *v = &ev->verdicts[i];
    if (v->kind != V_INVALID)
      continue;
    struct observation *o = find_obs(ev, v->observation_id);
    if (o)
      o->valid = 0; /* stale/unknown target (NULL) is ignored */
  }
}
