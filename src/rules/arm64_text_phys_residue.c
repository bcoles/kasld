// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: arm64 virt-phys text residue coupling.
//
// On arm64 the kernel image is mapped so that its virtual-to-physical offset
// (kimage_voffset = virt_text - phys_text) is aligned to MIN_KIMG_ALIGN (2
// MiB): the low log2(MIN_KIMG_ALIGN) bits of the virtual KASLR displacement are
// copied from the physical load address so kernel text can be mapped with 2 MiB
// blocks (arch/arm64/kernel/pi/map_kernel.c; head.S on pre-v6.9). Consequently
//
//     virt_text ≡ phys_text    (mod MIN_KIMG_ALIGN = 2 MiB)
//
// for every arm64 kernel (the graft makes the offset 2 MiB-aligned regardless
// of KASLR being on, and it holds trivially on 2 MiB-aligned loads). A PHYS
// kernel-image base leak (e.g. /proc/iomem "Kernel code", which starts at
// __pa_symbol(_text)) therefore pins Q_VIRT_IMAGE_BASE's residue mod 2 MiB.
// Because the virtual text base is only IMAGE_ALIGN (EFI_KIMG_ALIGN, 64 KiB /
// 128 KiB)-granular — not 2 MiB-aligned — this collapses
// log2(2 MiB / IMAGE_ALIGN) = up to 5 bits of residual entropy.
//
// Soundness:
//   * Fires only on a PHYS KERNEL_IMAGE / KERNEL_TEXT *base* observation
//     (POS_BASE): the residue is well defined only for the image base. An
//     interior sample sits at an unknown offset from _text, so its residue
//     would be wrong; those are skipped.
//   * The anchor is normalised to the image base (_text) with
//     kasld_image_base_from — a KERNEL_TEXT witness is _stext and is shifted
//     down by STEXT_OFFSET (64 KiB on arm64), which the 2 MiB modulus does NOT
//     absorb.
//   * A real phys _text is IMAGE_ALIGN-aligned, so its residue is too; a
//   residue
//     that is not IMAGE_ALIGN-aligned signals a bad anchor and is skipped
//     rather than emitted (an unaligned residue would leave no
//     IMAGE_ALIGN-aligned base in the class and force bottom).
//   * Confidence inherits the observation's (single source).
//
// Inert when no arm64 PHYS kernel-image base observation is present. arm64
// only.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"
#include "include/kasld/regions.h"

#include <string.h>

#define ARM64_KIMG_ALIGN                                                       \
  0x200000ul /* MIN_KIMG_ALIGN (2 MiB): the granule the */
             /* kernel-image virt-phys offset is aligned */
             /* to, so virt and phys _text share low bits */

int rule_arm64_text_phys_residue(const struct evidence_set *ev,
                                 const struct estimate *est,
                                 struct constraint *out, int out_max) {
  (void)est;
#if defined(__aarch64__)
  if (out_max < 1)
    return 0;

  /* Lowest PHYS kernel-image base, normalised to the image base (_text). */
  unsigned long img_base = 0;
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
    if (o->pos != POS_BASE || !HAS_LO(o))
      continue;
    unsigned long base = obs_anchor(o);
    if (base == 0)
      continue;
    unsigned long img =
        kasld_image_base_from(base, o->eff_region == REGION_KERNEL_TEXT);
    if (!found || img < img_base) {
      img_base = img;
      conf = o->conf;
      src = o->id;
      found = 1;
    }
  }
  if (!found)
    return 0;

  unsigned long residue = img_base % ARM64_KIMG_ALIGN;
  if (residue & ((unsigned long)IMAGE_ALIGN - 1))
    return 0; /* not on the image-alignment grid: bad anchor, skip */

  struct constraint *c = &out[0];
  memset(c, 0, sizeof(*c));
  c->q = Q_VIRT_IMAGE_BASE;
  c->op = C_STRIDE;
  c->value = residue;           /* virt_text ≡ residue ... */
  c->value2 = ARM64_KIMG_ALIGN; /* ... (mod 2 MiB) */
  c->conf = conf;
  c->derived_from[0] = src;
  c->lineage_count = 1;
  snprintf(c->origin, ORIGIN_LEN, "arm64_text_phys_residue");
  return 1;
#else
  (void)ev;
  (void)out;
  (void)out_max;
  return 0;
#endif
}
