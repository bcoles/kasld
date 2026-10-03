// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: s390 text-base ceiling from the resolved paging level.
//
// Every s390 kernel image sits below the ASCE limit, and the boot code places
// it deliberately close to that limit rather than anywhere beneath it:
// setup_kernel_memory_layout() computes kernel_end as vmax minus a multiple of
// THREAD_SIZE and then places the base a whole image below it,
//
//     kernel_end   = vmax - pos * THREAD_SIZE          (pos >= 0)
//     kernel_start = round_down(kernel_end - kernel_size, THREAD_SIZE)
//
// so
//
//     virt_image_base <= vmax - kernel_size < vmax <= 1 << VA_BITS
//
// The image size is subtracted for that reason. Bounding at vmax alone would
// publish `base <= vmax`, which the placement above never produces: the top
// kernel_size of the window holds no base. On a 3-level kernel that is the
// difference between 2^28 + 1 candidates and 2^28 -- a whole bit, because an
// inclusive window over a power-of-two span lands one slot above one.
//
// vmax is adjust_to_uv_max(asce_limit), and that adjustment only ever LOWERS
// the limit (it takes a min against the ultravisor's secure-storage ceiling),
// so the width alone is a sound upper bound whether or not the guest is
// running protected. The bound is floored onto the KASLR grid, since a base
// between grid positions is not a base.
//
// The level itself is not observed. It comes from the resolved Q_VA_BITS,
// which on s390 is reached by reproducing the boot code's own choice from
// parsed config facts -- see s390_va_bits_from_config. This rule reads the
// answer and does not re-derive it: a second derivation would be a second
// statement of the same kernel logic, free to drift from the first.
//
// The difference the bound makes is the whole 3-level case. _REGION2_SIZE is
// 2048 times smaller than _REGION1_SIZE, so a kernel proven 3-level has its
// window cut from the 8 PiB architectural top to 4 TiB. On a kernel proven
// 4-level the bound equals the honest top and the rule is a harmless no-op;
// where the level stays unresolved it emits nothing, and the window stands at
// the top that admits both.
//
// Cross-quantity and acyclic: it reads est[Q_VA_BITS] and writes
// Q_VIRT_IMAGE_BASE, and nothing derives Q_VA_BITS from the image base.
//
// s390 only; inert elsewhere and while the level is unresolved.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"
#include "include/kasld/quantity.h"

#include <string.h>

int rule_s390_text_ceiling_from_va_bits(const struct evidence_set *ev,
                                        const struct estimate *est,
                                        struct constraint *out, int out_max) {
#if defined(__s390x__) || defined(__zarch__)
  if (out_max < 1)
    return 0;

  unsigned long va_bits = 0;
  if (!estimate_finset_value(&quantities[Q_VA_BITS], &est[Q_VA_BITS], &va_bits))
    return 0;
  if (va_bits == 0 || va_bits >= sizeof(unsigned long) * 8)
    return 0;

  unsigned long align = est[Q_VIRT_KASLR_ALIGN].lo;
  if (align < (unsigned long)KASLR_VIRT_ALIGN)
    align = (unsigned long)KASLR_VIRT_ALIGN;

  /* The floored accessor, never the raw one: with no size fact observed this
   * still subtracts KASLD_MIN_IMAGE_SIZE, and any kernel image exceeds it, so
   * the bound holds at the hardened vantage where /boot may be unreadable. */
  unsigned long top = 1ul << va_bits;
  unsigned long min_image = evidence_image_size_min_or_floor(ev);
  if (min_image >= top)
    return 0;
  unsigned long ceiling = kasld_floor_virt_text_bound(top - min_image, align);
  if (ceiling == 0)
    return 0;

  struct constraint *c = &out[0];
  memset(c, 0, sizeof(*c));
  c->q = Q_VIRT_IMAGE_BASE;
  c->op = C_UPPER_BOUND;
  c->value = ceiling;
  /* No more trustworthy than the derivation that resolved the width, and that
   * derivation reaches the sound band on parsed config facts; cap here so a
   * weaker future resolver cannot promote its answer through this rule. */
  c->conf = CONF_INFERRED;
  c->derived_from[0] = est[Q_VA_BITS].lo_binding;
  c->lineage_count = est[Q_VA_BITS].lo_binding ? 1 : 0;
  snprintf(c->origin, ORIGIN_LEN, "s390_text_ceiling_from_va_bits");
  return 1;
#else
  (void)ev;
  (void)est;
  (void)out;
  (void)out_max;
  return 0;
#endif
}
