// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: CPU physical-address-width ceiling.
//
// The CPU's maximum physical
// address width (SF_PHYS_ADDR_BITS, from /proc/cpuinfo) caps the physical
// address space independent of installed RAM, so the kernel image must fit
// below it:
//
//   phys_base <= (1 << phys_bits) - min_image
//
// Decoupled arches (x86-64): a C_UPPER_BOUND on Q_PHYS_IMAGE_BASE.
// Coupled arches that expose the field (LoongArch, and x86-32 — /proc/cpuinfo
// carries `address sizes` on both): map through PAGE_OFFSET_MAX to a
// C_UPPER_BOUND on Q_VIRT_IMAGE_BASE. The extremal edge rather than a resolved
// value, so the bound needs no Q_PAGE_OFFSET dependency and still holds on a
// target whose split this binary cannot see.
//
// A hypervisor may restrict phys_bits below installed RAM, making this tighter
// than the MemTotal ceiling. Arches that don't expose the field, and 32-bit
// builds where 1 << phys_bits would overflow unsigned long, emit nothing.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"

#include <string.h>

int rule_phys_bits_ceiling(const struct evidence_set *ev,
                           const struct estimate *est, struct constraint *out,
                           int out_max) {
  (void)est;
  if (out_max < 1)
    return 0;
  const unsigned long min_image = evidence_image_size_min_or_floor(ev);

  int phys_bits = 0;
  enum kasld_confidence conf = CONF_UNKNOWN;
  uint32_t src = 0;
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->value_kind != OBS_SCALAR)
      continue;
    if (o->scalar_fact != SF_PHYS_ADDR_BITS)
      continue;
    phys_bits = (int)o->scalar_value;
    conf = o->conf;
    src = o->id;
    break;
  }

  /* 0 => field absent; >= word width => 1 << phys_bits is undefined (e.g.
   * 32-bit PAE reports 36). Either way, no sound bound. */
  if (phys_bits <= 0 || phys_bits >= (int)(sizeof(unsigned long) * 8))
    return 0;
  unsigned long phys_ceiling = 1UL << phys_bits;
  if (phys_ceiling <= min_image)
    return 0;

  struct constraint *c = &out[0];
  memset(c, 0, sizeof(*c));
  c->op = C_UPPER_BOUND;
  c->conf = conf;
  c->derived_from[0] = src;
  c->lineage_count = 1;
  snprintf(c->origin, ORIGIN_LEN, "phys_bits_ceiling");

#if !TEXT_TRACKS_DIRECTMAP
  unsigned long ceiling = phys_ceiling - min_image;
  if (KASLR_PHYS_ALIGN > 0)
    ceiling &= ~(KASLR_PHYS_ALIGN - 1);
  if (ceiling <= KASLR_PHYS_MIN)
    return 0;
  c->q = Q_PHYS_IMAGE_BASE;
  c->value = ceiling;
  return 1;
#else
  /* image_base = page_offset + (phys_base - PHYS_OFFSET) + IMAGE_BASE_OFFSET.
   *
   * PAGE_OFFSET_MAX, not the compile-time PAGE_OFFSET: an upper bound stays
   * sound when the base used to compute it is too HIGH, so the highest
   * admissible base is safe against every target, whereas this binary's own
   * value is safe only while it happens to be that highest one. On the arches
   * with a single admissible base the two are the same number, so nothing
   * changes where the base really is a hardware constant. Using the extremal
   * edge rather than the resolved Q_PAGE_OFFSET also keeps the rule firing
   * before anything has pinned the base. */
  unsigned long ceiling = (unsigned long)PAGE_OFFSET_MAX + IMAGE_BASE_OFFSET +
                          (phys_ceiling - min_image) - PHYS_OFFSET;
  ceiling =
      kasld_floor_virt_text_bound(ceiling, (unsigned long)KASLR_VIRT_ALIGN);
  if (ceiling <= KASLR_VIRT_TEXT_MIN)
    return 0;
  c->q = Q_VIRT_IMAGE_BASE;
  c->value = ceiling;
  return 1;
#endif
}
