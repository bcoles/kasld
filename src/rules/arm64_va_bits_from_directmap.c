// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: arm64 VA_BITS discrimination from DIRECTMAP leak addresses.
//
// On arm64 PAGE_OFFSET is
// -(1UL << VA_BITS) and is not randomised, so the top bits of any leaked
// DIRECTMAP virtual address pin the paging configuration:
//
//   addr in [0xfff0000000000000, 0xffff000000000000)  -> VA_BITS=52,
//       PAGE_OFFSET = 0xfff0000000000000 (the window floor; pin the ceiling)
//   addr >= 0xffff000000000000 (none below)           -> VA_BITS=48,
//       PAGE_OFFSET = 0xffff000000000000 (pin both edges)
//   addresses from both ranges                         -> contradictory, skip
//   no DIRECTMAP leaks                                 -> nothing
//
// Emits a C_EQUALS on Q_VA_BITS (the resolved width) plus the virt_page_offset
// window bound(s). Pure: reads DIRECTMAP observations only,
// emits no constraint when the evidence is absent or contradictory. The
// Explicit window-inversion guards are unnecessary here — the engine's
// monotone meet skips any bound that would empty the interval.
//
// arm64 only; inert elsewhere (Q_VA_BITS candidates differ per arch).
// ---
// <bcoles@gmail.com>

#include "../include/kasld/engine_rules.h"

#include <string.h>

#define ARM64_VA48_PAGE_OFFSET 0xffff000000000000ul
#define ARM64_VA52_PAGE_OFFSET 0xfff0000000000000ul

int rule_arm64_va_bits_from_directmap(const struct evidence_set *ev,
                                      const struct estimate *est,
                                      struct constraint *out, int out_max) {
  (void)est;
#if defined(__aarch64__)
  if (out_max < 1)
    return 0;

  int have_va52 = 0, have_va48 = 0;
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
    if (a < ARM64_VA48_PAGE_OFFSET)
      have_va52 = 1;
    else
      have_va48 = 1;
    if (o->conf < conf)
      conf = o->conf;
    if (!src)
      src = o->id;
  }

  if (have_va52 == have_va48) /* none, or contradictory (both) */
    return 0;

  unsigned long va_bits, po;
  int pin_floor; /* VA48 pins both edges; VA52's floor is already the top */
  if (have_va52) {
    va_bits = 52;
    po = ARM64_VA52_PAGE_OFFSET;
    pin_floor = 0;
  } else {
    va_bits = 48;
    po = ARM64_VA48_PAGE_OFFSET;
    pin_floor = 1;
  }

  int n = 0;
  /* Q_VA_BITS = va_bits */
  if (n < out_max) {
    struct constraint *c = &out[n++];
    memset(c, 0, sizeof(*c));
    c->q = Q_VA_BITS;
    c->op = C_EQUALS;
    c->value = va_bits;
    c->conf = conf;
    c->derived_from[0] = src;
    c->lineage_count = src ? 1 : 0;
    snprintf(c->origin, ORIGIN_LEN, "arm64_va_bits_from_directmap");
  }
  /* virt_page_offset ceiling (both VA48 and VA52 pin the upper edge to
   * PAGE_OFFSET)
   */
  if (n < out_max) {
    struct constraint *c = &out[n++];
    memset(c, 0, sizeof(*c));
    c->q = Q_PAGE_OFFSET;
    c->op = C_UPPER_BOUND;
    c->value = po;
    c->conf = conf;
    c->derived_from[0] = src;
    c->lineage_count = src ? 1 : 0;
    snprintf(c->origin, ORIGIN_LEN, "arm64_va_bits_from_directmap");
  }
  /* virt_page_offset floor (VA48 only — VA52's floor is the architectural top)
   */
  if (pin_floor && n < out_max) {
    struct constraint *c = &out[n++];
    memset(c, 0, sizeof(*c));
    c->q = Q_PAGE_OFFSET;
    c->op = C_LOWER_BOUND;
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
