// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: pin Q_VA_BITS on riscv64 from SF_VIRT_ADDR_BITS.
//
// SF_VIRT_ADDR_BITS arrives from /proc/cpuinfo "mmu : svN" (proc_cpuinfo
// component), carrying the runtime paging width: 39, 48, or 57. Q_VA_BITS
// is a finite-set quantity (LK_FINSET) with three candidates on riscv64,
// so the scalar pins it via C_EQUALS at the observation's confidence.
//
// riscv64 only; inert elsewhere (the arch's VA_BITS_CANDIDATES drives this).
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"

#include <string.h>

#if defined(__riscv) && __riscv_xlen == 64

int rule_riscv64_va_bits_pin(const struct evidence_set *ev,
                             const struct estimate *est, struct constraint *out,
                             int out_max) {
  (void)est;
  if (out_max < 1)
    return 0;

  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->value_kind != OBS_SCALAR)
      continue;
    if (o->scalar_fact != SF_VIRT_ADDR_BITS)
      continue;
    unsigned long v = o->scalar_value;
    if (v != 39 && v != 48 && v != 57)
      continue;

    struct constraint *c = &out[0];
    memset(c, 0, sizeof(*c));
    c->q = Q_VA_BITS;
    c->op = C_EQUALS;
    c->value = v;
    c->conf = o->conf;
    c->derived_from[0] = o->id;
    c->lineage_count = 1;
    snprintf(c->origin, ORIGIN_LEN, "riscv64_va_bits_pin");
    return 1;
  }
  return 0;
}

#else /* !riscv64 */

int rule_riscv64_va_bits_pin(const struct evidence_set *ev,
                             const struct estimate *est, struct constraint *out,
                             int out_max) {
  (void)ev;
  (void)est;
  (void)out;
  (void)out_max;
  return 0;
}

#endif
