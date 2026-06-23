// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: arm64 VA_BITS discrimination from DIRECTMAP leak addresses.
//
// On arm64 PAGE_OFFSET is
// -(1UL << VA_BITS) and is not randomized, so a leaked DIRECTMAP virtual
// address falls in exactly one VA_BITS config's linear map — the disjoint,
// ordered ranges [PAGE_OFFSET(va), _PAGE_END(va)) — which pins the paging
// configuration:
//
//   addr in [arm64_page_offset_for(va), arm64_page_end_for(va))  -> VA_BITS=va,
//       PAGE_OFFSET = arm64_page_offset_for(va) (exact, not randomized)
//   addr in a gap (vmalloc/vmemmap/modules, not the linear map) -> ignored
//   addresses implying two different VA_BITS                     ->
//   contradictory no DIRECTMAP leaks -> nothing
//
// Emits a C_EQUALS on Q_VA_BITS (the resolved width) plus the exact
// virt_page_offset (lower+upper bound). Pure: reads DIRECTMAP observations
// only, emits no constraint when the evidence is absent or contradictory.
// Explicit window-inversion guards are unnecessary — the engine's monotone meet
// skips any bound that would empty the interval.
//
// arm64 only; inert elsewhere (Q_VA_BITS candidates differ per arch).
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"

#include <string.h>

int rule_arm64_va_bits_from_directmap(const struct evidence_set *ev,
                                      const struct estimate *est,
                                      struct constraint *out, int out_max) {
  (void)est;
#if defined(__aarch64__)
  if (out_max < 1)
    return 0;

  static const unsigned long cands[] = VA_BITS_CANDIDATES;
  const int ncands = (int)(sizeof(cands) / sizeof(cands[0]));

  unsigned long resolved_va = 0; /* 0 = none classified yet */
  int contradictory = 0;
  enum kasld_confidence conf = CONF_PARSED;
  uint32_t src = 0;
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->value_kind != OBS_ADDRESS)
      continue;
    if (o->eff_type != KASLD_TYPE_VIRT || o->eff_region != REGION_DIRECTMAP)
      continue;
    unsigned long a = obs_anchor(o);
    if (a == 0)
      continue;
    /* Classify a into the unique VA_BITS whose linear map contains it. */
    unsigned long va = 0;
    for (int k = 0; k < ncands; k++) {
      if (a >= arm64_page_offset_for(cands[k]) &&
          a < arm64_page_end_for(cands[k])) {
        va = cands[k];
        break;
      }
    }
    if (va == 0)
      continue; /* not in any linear map (a gap address) — ignore */
    if (resolved_va == 0)
      resolved_va = va;
    else if (resolved_va != va)
      contradictory = 1;
    if (o->conf < conf)
      conf = o->conf;
    if (!src)
      src = o->id;
  }

  if (resolved_va == 0 || contradictory)
    return 0;

  unsigned long po = arm64_page_offset_for(resolved_va);

  int n = 0;
  /* Q_VA_BITS = resolved width. */
  if (n < out_max) {
    struct constraint *c = &out[n++];
    memset(c, 0, sizeof(*c));
    c->q = Q_VA_BITS;
    c->op = C_EQUALS;
    c->value = resolved_va;
    c->conf = conf;
    c->derived_from[0] = src;
    c->lineage_count = src ? 1 : 0;
    snprintf(c->origin, ORIGIN_LEN, "arm64_va_bits_from_directmap");
  }
  /* virt_page_offset is exact (not randomized): pin both edges. The lower edge
   * is a no-op for VA52 (its PAGE_OFFSET is the architectural VAS floor). */
  for (int e = 0; e < 2 && n < out_max; e++) {
    struct constraint *c = &out[n++];
    memset(c, 0, sizeof(*c));
    c->q = Q_PAGE_OFFSET;
    c->op = e == 0 ? C_UPPER_BOUND : C_LOWER_BOUND;
    c->value = po;
    c->conf = conf;
    c->derived_from[0] = src;
    c->lineage_count = src ? 1 : 0;
    snprintf(c->origin, ORIGIN_LEN, "arm64_va_bits_from_directmap");
  }
  return n;
#else
  (void)ev;
  (void)out;
  (void)out_max;
  return 0;
#endif
}
