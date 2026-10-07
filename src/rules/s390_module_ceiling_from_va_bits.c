// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: s390 module-base ceiling from the resolved paging level.
//
// The module region is the top thing in the s390 kernel address space under
// every arrangement the architecture has carried, so its base is always a whole
// MODULES_LEN below the limit:
//
//     MODULES_END   <= vmax <= 1 << VA_BITS
//     MODULES_VADDR  = MODULES_END - MODULES_LEN
//     module_base   <= (1 << VA_BITS) - MODULES_LEN
//
// This is the one bound on Q_MODULE_BASE that needs no anchor established.
// Where the band is placed against the image, MODULES_END is round_down of a
// kernel_start that itself sits below vmax; where it is placed at the top of
// the address space, MODULES_END is vmax or the abs-lowcore mapping just under
// it. Both are at or below vmax, and the adjustments beside them -- the
// ultravisor secure-storage limit, the KASAN shadow -- only ever lower it
// further. So the ceiling holds without knowing which arrangement booted, which
// is what makes it worth having: on a vantage that cannot establish the anchor,
// module_base_from_text declines and this is all that is left.
//
// vmax is adjust_to_uv_max(asce_limit) and only ever LOWER than the width, so
// the width alone is sound whether or not the guest runs protected -- the same
// argument s390_text_ceiling_from_va_bits makes for the image. Both read the
// resolved Q_VA_BITS rather than re-deriving the level;
// s390_va_bits_from_config owns that derivation and reproducing it here would
// be a second statement of the kernel's own condition, free to drift from the
// first.
//
// MODULES_LEN is subtracted rather than left at the width for the reason the
// image ceiling subtracts the image size: a bound at the top admits a base the
// kernel cannot produce, and over a window that is a power-of-two multiple of
// the grid that one slot is a whole bit.
//
// The difference is the 3-level case, as it is for the image: _REGION2_SIZE is
// 2048 times smaller than _REGION1_SIZE, so a kernel proven 3-level has its
// module window cut from the 8 PiB architectural top to 4 TiB. On a kernel
// proven 4-level the bound is a near no-op, and where the level stays
// unresolved it emits nothing.
//
// Cross-quantity and acyclic: it reads est[Q_VA_BITS] and writes Q_MODULE_BASE,
// and nothing derives Q_VA_BITS from the module base.
//
// s390 only; inert elsewhere and while the level is unresolved.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"
#include "include/kasld/quantity.h"

#include <string.h>

int rule_s390_module_ceiling_from_va_bits(const struct evidence_set *ev,
                                          const struct estimate *est,
                                          struct constraint *out, int out_max) {
#if defined(__s390x__) || defined(__zarch__)
  (void)ev;
  if (out_max < 1)
    return 0;

  unsigned long va_bits = 0;
  if (!estimate_finset_value(&quantities[Q_VA_BITS], &est[Q_VA_BITS], &va_bits))
    return 0;
  if (va_bits == 0 || va_bits >= sizeof(unsigned long) * 8)
    return 0;

  /* MODULES_LEN, the 2 GiB the region always spans (asm/pgtable.h). Stated
   * here rather than read from the compile-time band, whose MODULES_END is the
   * architectural top and not a region length. */
  const unsigned long modules_len = 2ul * 1024 * 1024 * 1024;
  unsigned long top = 1ul << va_bits;
  if (top <= modules_len)
    return 0;

  struct constraint *c = &out[0];
  memset(c, 0, sizeof(*c));
  c->q = Q_MODULE_BASE;
  c->op = C_UPPER_BOUND;
  c->value = top - modules_len;
  /* No more trustworthy than the derivation that resolved the width. */
  c->conf = CONF_INFERRED;
  c->derived_from[0] = est[Q_VA_BITS].lo_binding;
  c->lineage_count = est[Q_VA_BITS].lo_binding ? 1 : 0;
  snprintf(c->origin, ORIGIN_LEN, "s390_module_ceiling_from_va_bits");
  return 1;
#else
  (void)ev;
  (void)est;
  (void)out;
  (void)out_max;
  return 0;
#endif
}
