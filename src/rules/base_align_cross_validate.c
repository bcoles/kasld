// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: raise the KASLR alignment from observed base_align hints.
//
// A component may report a
// base_align (the largest power-of-two a leaked base is known to be aligned
// to); the greatest such hint is a sound lower bound on the KASLR slot
// granularity:
//
//   Q_VIRT_KASLR_ALIGN      >= max(base_align over VIRT observations)
//   Q_PHYS_KASLR_ALIGN >= max(base_align over PHYS observations)  (decoupled)
//
// C_AT_LEAST_ALIGN; dominated by the arch baseline / boot_params when those
// are coarser. Inert when no observation carries a base_align estimate.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"

#include <string.h>

static unsigned long max_base_align(const struct evidence_set *ev,
                                    enum kasld_addr_type type, uint32_t *src) {
  unsigned long best = 0;
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->value_kind != OBS_ADDRESS || o->eff_type != type)
      continue;
    if (!HAS_BASE_ALIGN(o))
      continue;
    if (o->base_align > best) {
      best = o->base_align;
      *src = o->id;
    }
  }
  return best;
}

int rule_base_align_cross_validate(const struct evidence_set *ev,
                                   const struct estimate *est,
                                   struct constraint *out, int out_max) {
  (void)est;
  int n = 0;
  uint32_t src = 0;
  unsigned long v = max_base_align(ev, KASLD_TYPE_VIRT, &src);
  if (v > 1 && n < out_max) {
    struct constraint *c = &out[n++];
    memset(c, 0, sizeof(*c));
    c->q = Q_VIRT_KASLR_ALIGN;
    c->op = C_AT_LEAST_ALIGN;
    c->value = v;
    c->conf = CONF_INFERRED;
    c->derived_from[0] = src;
    c->lineage_count = 1;
    snprintf(c->origin, ORIGIN_LEN, "base_align_cross_validate");
  }
#if !TEXT_TRACKS_DIRECTMAP
  src = 0;
  unsigned long p = max_base_align(ev, KASLD_TYPE_PHYS, &src);
  if (p > 1 && n < out_max) {
    struct constraint *c = &out[n++];
    memset(c, 0, sizeof(*c));
    c->q = Q_PHYS_KASLR_ALIGN;
    c->op = C_AT_LEAST_ALIGN;
    c->value = p;
    c->conf = CONF_INFERRED;
    c->derived_from[0] = src;
    c->lineage_count = 1;
    snprintf(c->origin, ORIGIN_LEN, "base_align_cross_validate");
  }
#endif
  return n;
}
