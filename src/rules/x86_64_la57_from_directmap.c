// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: x86_64 L4/L5 paging discrimination from DIRECTMAP leak addresses.
//
// The kernel VAS floor
// differs by paging mode, so the top bits of any leaked DIRECTMAP virtual
// address pin the mode:
//
//   addr < 0xffff800000000000 (the L4 VAS floor)  -> L5 paging (VA_BITS=57):
//       virt_page_offset in [0xff11000000000000, 0xffff7fffffffffff]
//       (floor = __PAGE_OFFSET_BASE_L5; ceiling = one below the L4 VAS floor)
//   addr >= 0xffff800000000000 (none below)       -> L4 paging (VA_BITS=48):
//       virt_page_offset floor raised to the L4 VAS start 0xffff800000000000
//   addresses from both ranges                    -> contradictory, skip
//   no DIRECTMAP leaks                            -> nothing
//
// Emits a C_EQUALS on Q_VA_BITS (48 for L4, 57 for L5) plus the
// virt_page_offset window bound(s). Confirmatory/backup path for LA57 when
// cpuinfo LA57 detection is unavailable; both write consistent virt_page_offset
// bounds and the engine's meet is idempotent.
//
// x86-64 only; inert elsewhere.
// ---
// <bcoles@gmail.com>

#include "../include/kasld/engine_rules.h"

#include <string.h>

#define X86_64_L4_VAS_START 0xffff800000000000ul
#define X86_64_L5_PO_BASE 0xff11000000000000ul

int rule_x86_64_la57_from_directmap(const struct evidence_set *ev,
                                    const struct estimate *est,
                                    struct constraint *out, int out_max) {
  (void)est;
#if defined(__x86_64__)
  if (out_max < 1)
    return 0;

  int have_l5 = 0, have_l4 = 0;
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
    if (a < X86_64_L4_VAS_START)
      have_l5 = 1;
    else
      have_l4 = 1;
    if (o->conf < conf)
      conf = o->conf;
    if (!src)
      src = o->id;
  }

  if (have_l5 == have_l4) /* none, or contradictory (both) */
    return 0;

  int n = 0;
  unsigned long va_bits = have_l5 ? 57 : 48;
  if (n < out_max) {
    struct constraint *c = &out[n++];
    memset(c, 0, sizeof(*c));
    c->q = Q_VA_BITS;
    c->op = C_EQUALS;
    c->value = va_bits;
    c->conf = conf;
    c->derived_from[0] = src;
    c->lineage_count = src ? 1 : 0;
    snprintf(c->origin, ORIGIN_LEN, "x86_64_la57_from_directmap");
  }

  if (have_l5) {
    /* L5: floor = L5 virt_page_offset base, ceiling = one below the L4 VAS
     * floor. */
    if (n < out_max) {
      struct constraint *c = &out[n++];
      memset(c, 0, sizeof(*c));
      c->q = Q_PAGE_OFFSET;
      c->op = C_LOWER_BOUND;
      c->value = X86_64_L5_PO_BASE;
      c->conf = conf;
      c->derived_from[0] = src;
      c->lineage_count = src ? 1 : 0;
      snprintf(c->origin, ORIGIN_LEN, "x86_64_la57_from_directmap");
    }
    if (n < out_max) {
      struct constraint *c = &out[n++];
      memset(c, 0, sizeof(*c));
      c->q = Q_PAGE_OFFSET;
      c->op = C_UPPER_BOUND;
      c->value = X86_64_L4_VAS_START - 1;
      c->conf = conf;
      c->derived_from[0] = src;
      c->lineage_count = src ? 1 : 0;
      snprintf(c->origin, ORIGIN_LEN, "x86_64_la57_from_directmap");
    }
  } else {
    /* L4: raise the virt_page_offset floor to the L4 VAS start. */
    if (n < out_max) {
      struct constraint *c = &out[n++];
      memset(c, 0, sizeof(*c));
      c->q = Q_PAGE_OFFSET;
      c->op = C_LOWER_BOUND;
      c->value = X86_64_L4_VAS_START;
      c->conf = conf;
      c->derived_from[0] = src;
      c->lineage_count = src ? 1 : 0;
      snprintf(c->origin, ORIGIN_LEN, "x86_64_la57_from_directmap");
    }
  }
  return n;
#else
  (void)ev;
  (void)out;
  (void)out_max;
  return 0;
#endif
}
