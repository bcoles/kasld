// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: arm64 virt_page_offset from a resolved Q_VA_BITS.
//
// On arm64 the linear-map virtual base is PAGE_OFFSET = -(1 << VA_BITS), an
// exact function of the runtime paging width — it is NOT randomized (the boot
// seed shifts memstart_addr, the PHYSICAL anchor of the linear map, not its
// virtual base). So once Q_VA_BITS has resolved to a single width, the direct
// map's virtual base is pinned exactly.
//
// arm64_va_bits_from_directmap / arm64_va_bits_from_vmemmap already pin
// virt_page_offset as a side effect of a DIRECTMAP or VMEMMAP leak. This rule
// closes the gap when Q_VA_BITS is resolved by a leak-free path instead — e.g.
// mmap-probing (mmap_arm64_va_bits) on a hardened target with no linear-map
// leak — so the exact page_offset is recovered from the width alone.
//
// Reads only est[Q_VA_BITS] (cross-quantity, acyclic: Q_VA_BITS never derives
// from Q_PAGE_OFFSET) and emits a matching lower+upper bound. The lower edge is
// a no-op for VA_BITS=52, whose PAGE_OFFSET is the architectural VAS floor.
//
// arm64 only; inert when Q_VA_BITS has not narrowed to a single candidate.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"
#include "include/kasld/quantity.h"

#include <string.h>

int rule_arm64_page_offset_from_va_bits(const struct evidence_set *ev,
                                        const struct estimate *est,
                                        struct constraint *out, int out_max) {
  (void)ev;
#if defined(__aarch64__)
  if (out_max < 2)
    return 0;

  unsigned long va_bits = 0;
  if (!estimate_finset_value(&quantities[Q_VA_BITS], &est[Q_VA_BITS], &va_bits))
    return 0;
  if (va_bits == 0 || va_bits >= sizeof(unsigned long) * 8)
    return 0;

  unsigned long po = arm64_page_offset_for(va_bits);

  int n = 0;
  for (int e = 0; e < 2 && n < out_max; e++) {
    struct constraint *c = &out[n++];
    memset(c, 0, sizeof(*c));
    c->q = Q_PAGE_OFFSET;
    c->op = e == 0 ? C_LOWER_BOUND : C_UPPER_BOUND;
    c->value = po;
    /* Exact given the width, but no more trustworthy than the derivation that
     * resolved Q_VA_BITS; cap at the sound-band floor. */
    c->conf = CONF_INFERRED;
    c->lineage_count = 0;
    snprintf(c->origin, ORIGIN_LEN, "arm64_page_offset_from_va_bits");
  }
  return n;
#else
  (void)est;
  (void)out;
  (void)out_max;
  return 0;
#endif
}
