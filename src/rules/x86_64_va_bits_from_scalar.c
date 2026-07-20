// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: pin Q_VA_BITS on x86_64 from SF_VIRT_ADDR_BITS.
//
// On x86_64 SF_VIRT_ADDR_BITS is emitted only as a statement of the ACTIVE
// paging width, never the CPU capability:
//   - proc_cpuinfo publishes it only when the virtual width is 48 (a 48-bit CPU
//     cannot run 5-level, so 4-level is certain);
//   - mmap_x86_64_va_bits publishes the runtime-probed active level (48 or 57).
// So pinning Q_VA_BITS to the value is sound. This resolves the paging level
// for consumers that read it (the RANDOMIZE_MEMORY budget bounds, the
// KASLR-disabled directmap pin) on LA57-capable hardware that exposes no
// direct-map leak, where x86_64_la57_from_directmap cannot fire.
//
// C_EQUALS on Q_VA_BITS when SF_VIRT_ADDR_BITS is 48 or 57. x86_64 only; inert
// when the scalar is absent or out of range.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"

#include <string.h>

int rule_x86_64_va_bits_from_scalar(const struct evidence_set *ev,
                                    const struct estimate *est,
                                    struct constraint *out, int out_max) {
  (void)est;
#if defined(__x86_64__)
  if (out_max < 1)
    return 0;

  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->value_kind != OBS_SCALAR)
      continue;
    if (o->scalar_fact != SF_VIRT_ADDR_BITS)
      continue;
    unsigned long v = o->scalar_value;
    if (v != 48 && v != 57)
      continue;

    struct constraint *c = &out[0];
    memset(c, 0, sizeof(*c));
    c->q = Q_VA_BITS;
    c->op = C_EQUALS;
    c->value = v;
    c->conf = o->conf;
    c->derived_from[0] = o->id;
    c->lineage_count = 1;
    snprintf(c->origin, ORIGIN_LEN, "x86_64_va_bits_from_scalar");
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
