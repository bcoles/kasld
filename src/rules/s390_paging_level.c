// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: s390 text-base ceiling from the detected paging level.
//
// On s390x the KASLR vmax equals
// the user ASCE limit = 1 << VA_BITS (4 TiB for 3-level paging, 8 PiB for
// 4-level). The kernel text base lies below vmax, so:
//
//   virt_text_base < 1 << VA_BITS   (aligned down to the KASLR slot)
//
// VA_BITS arrives as SF_VIRT_ADDR_BITS from the in-process mmap boundary probe
// (kasld_s390_va_bits, emitted by the engine bridge). On 3-level paging this
// drops the ceiling from the 8 PiB default to 4 TiB — a 2048x reduction; on
// 4-level it equals the architectural top (a harmless no-op). Reads the
// resolved Q_KASLR_ALIGN for the slot granularity. s390 only; inert elsewhere.
// Under qemu the probe reports qemu's paging mode, not the captured kernel's.
// ---
// <bcoles@gmail.com>

#include "../include/kasld/engine_rules.h"

#include <string.h>

int rule_s390_paging_level(const struct evidence_set *ev,
                           const struct estimate *est, struct constraint *out,
                           int out_max) {
#if defined(__s390x__) || defined(__zarch__)
  if (out_max < 1)
    return 0;

  unsigned long va_bits = 0;
  uint32_t src = 0;
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (o->valid && o->value_kind == OBS_SCALAR &&
        o->scalar_fact == SF_VIRT_ADDR_BITS) {
      va_bits = o->scalar_value;
      src = o->id;
      break;
    }
  }
  if (va_bits == 0 || va_bits >= 64)
    return 0;

  unsigned long vmax = 1ul << va_bits; /* KASLR vmax = user ASCE limit */
  unsigned long align = est[Q_KASLR_ALIGN].lo;
  if (align < (unsigned long)KASLR_VIRT_ALIGN)
    align = (unsigned long)KASLR_VIRT_ALIGN;
  unsigned long ceiling = align ? (vmax & ~(align - 1)) : vmax;
  if (ceiling == 0)
    return 0;

  struct constraint *c = &out[0];
  memset(c, 0, sizeof(*c));
  c->q = Q_VIRT_TEXT_BASE;
  c->op = C_UPPER_BOUND;
  c->value = ceiling;
  c->conf = CONF_INFERRED;
  c->derived_from[0] = src;
  c->lineage_count = 1;
  snprintf(c->origin, ORIGIN_LEN, "s390_paging_level");
  return 1;
#else
  (void)ev;
  (void)est;
  (void)out;
  (void)out_max;
  return 0;
#endif
}
