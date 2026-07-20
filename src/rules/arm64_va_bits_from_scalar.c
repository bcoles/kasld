// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: pin Q_VA_BITS on arm64 from SF_VIRT_ADDR_BITS.
//
// On arm64 SF_VIRT_ADDR_BITS is emitted only by mmap_arm64_va_bits, which
// probes the ACTIVE paging width (TASK_SIZE = 1<<VA_BITS) — there is no cpuinfo
// width on arm64, so the scalar is always a sound statement of the running
// level. Pinning Q_VA_BITS to it resolves the level leak-free;
// arm64_page_offset_from_va_bits then derives the exact PAGE_OFFSET =
// -(1<<VA_BITS).
//
// C_EQUALS on Q_VA_BITS when SF_VIRT_ADDR_BITS is one of the arm64 candidates.
// arm64 only; inert when the scalar is absent or out of range.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"

#include <string.h>

int rule_arm64_va_bits_from_scalar(const struct evidence_set *ev,
                                   const struct estimate *est,
                                   struct constraint *out, int out_max) {
  (void)est;
#if defined(__aarch64__)
  if (out_max < 1)
    return 0;

  static const unsigned long cands[] = VA_BITS_CANDIDATES;
  const int ncands = (int)(sizeof(cands) / sizeof(cands[0]));

  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->value_kind != OBS_SCALAR)
      continue;
    if (o->scalar_fact != SF_VIRT_ADDR_BITS)
      continue;
    unsigned long v = o->scalar_value;
    int ok = 0;
    for (int k = 0; k < ncands; k++)
      if (cands[k] == v) {
        ok = 1;
        break;
      }
    if (!ok)
      continue;

    struct constraint *c = &out[0];
    memset(c, 0, sizeof(*c));
    c->q = Q_VA_BITS;
    c->op = C_EQUALS;
    c->value = v;
    c->conf = o->conf;
    c->derived_from[0] = o->id;
    c->lineage_count = 1;
    snprintf(c->origin, ORIGIN_LEN, "arm64_va_bits_from_scalar");
    return 1;
  }
  return 0;
#else
  (void)ev;
  (void)out;
  (void)out_max;
  return 0;
#endif
}
