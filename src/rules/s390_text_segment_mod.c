// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: s390 virt-phys segment-mod coupling.
//
// On s390 the kernel image is loaded at an absolute physical address aligned
// to _SEGMENT_SIZE (1 MiB) and mapped into the virtual address space at
// __kaslr_offset, which is also _SEGMENT_SIZE-aligned. Consequently the
// low 20 bits of (text_virt - PHYSICAL_START) are zero, which means
//
//     text_virt ≡ phys_anchor    (mod _SEGMENT_SIZE = 1 MiB)
//
// for any phys leak that points at a kernel-image byte at the SAME offset
// from the segment boundary as text_virt. A PHYS/KERNEL_IMAGE leak (e.g.
// the kernel image base parsed from a firmware reservation) gives that
// anchor directly; the rule emits one C_STRIDE on Q_VIRT_TEXT_BASE collapsing
// log2(_SEGMENT_SIZE / KASLR_VIRT_ALIGN) = log2(1 MiB / 16 KiB) = 6 bits of
// residual entropy.
//
// Soundness:
//   * Only fires on PHYS/KERNEL_IMAGE / KERNEL_TEXT observations (the
//     phys-side anchor must itself point at the image, not at unrelated
//     DRAM).
//   * The C_STRIDE residue is the phys anchor's low 20 bits; the modulus
//     is _SEGMENT_SIZE. estimate_meet's CRT handling caps moduli at 2^32,
//     so 0x100000 is well inside the safe range.
//   * Confidence inherits the lineage minimum (set to the observation's
//     confidence here — a single source).
//
// Inert when no s390 PHYS/KERNEL_IMAGE observation from a phys-side anchor
// (e.g. an unmasked /proc/iomem read) is present. s390 only; inert elsewhere.
// ---
// <bcoles@gmail.com>

#include "../include/kasld/engine_rules.h"
#include "../include/kasld/regions.h"

#include <string.h>

#define S390_SEGMENT_SIZE 0x100000ul /* 1 MiB */

int rule_s390_text_segment_mod(const struct evidence_set *ev,
                               const struct estimate *est,
                               struct constraint *out, int out_max) {
  (void)est;
#if defined(__s390__) || defined(__s390x__)
  if (out_max < 1)
    return 0;

  /* Lowest PHYS kernel-image anchor (any KERNEL_TEXT / KERNEL_IMAGE phys
   * leak qualifies; we take the lowest as the canonical witness). */
  unsigned long phys_anchor = 0;
  enum kasld_confidence conf = CONF_UNKNOWN;
  uint32_t src = 0;
  int found = 0;
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->value_kind != OBS_ADDRESS ||
        o->eff_type != KASLD_TYPE_PHYS)
      continue;
    if (o->eff_region != REGION_KERNEL_IMAGE &&
        o->eff_region != REGION_KERNEL_TEXT)
      continue;
    unsigned long a = obs_anchor(o);
    if (a == 0)
      continue;
    if (!found || a < phys_anchor) {
      phys_anchor = a;
      conf = o->conf;
      src = o->id;
      found = 1;
    }
  }
  if (!found)
    return 0;

  struct constraint *c = &out[0];
  memset(c, 0, sizeof(*c));
  c->q = Q_VIRT_TEXT_BASE;
  c->op = C_STRIDE;
  c->value = phys_anchor % S390_SEGMENT_SIZE; /* residue */
  c->value2 = S390_SEGMENT_SIZE;              /* modulus */
  c->conf = conf;
  c->derived_from[0] = src;
  c->lineage_count = 1;
  snprintf(c->origin, ORIGIN_LEN, "s390_text_segment_mod");
  return 1;
#else
  (void)ev;
  (void)out;
  (void)out_max;
  return 0;
#endif
}
