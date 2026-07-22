// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: recover the arm64 VA47 image-base floor when an observation proves the
// modern (v5.4+ "flipped") VA layout, disambiguating the one PAGE_OFFSET value
// arm64_text_base cannot floor on its own.
//
// arm64_text_base withholds the image-base floor for exactly one resolved
// PAGE_OFFSET: arm64_page_offset_for(47) = 0xffff800000000000. That value is
// produced by BOTH a modern 16K/3-level (VA47) kernel — image high, at
// _PAGE_END(47)+module — AND the pre-v5.4 "unflipped" VA48 layout — image low,
// at VA_START(48)+module (e.g. v4.14 _text = 0xffff000008080000). From
// PAGE_OFFSET alone the two are indistinguishable, so the honest-top floor is
// kept. This rule supplies the missing tiebreaker.
//
// DISCRIMINATOR. On the pre-v5.4 unflipped layout the linear map occupies the
// top of the kernel half and EVERY other kernel region — image, modules,
// vmalloc, vmemmap — sits BELOW PAGE_OFFSET (v4.14 VA48: vmemmap
// [0xffff7e0000000000, 0xffff800000000000], all under the 0xffff800000000000
// linear-map base). The v5.4 flip inverted this: on modern kernels vmemmap is
// anchored near the top (VMEMMAP_END = 0xffffffffc0000000), far ABOVE the
// linear map. This holds for every pre-v5.4 VA_BITS (they share the unflipped
// geometry), so a VIRT/VMEMMAP observation strictly ABOVE the resolved
// PAGE_OFFSET is impossible before v5.4 and therefore proves the modern layout.
// For PAGE_OFFSET = 0xffff800000000000 that means VA47, whose minimum image
// base is _PAGE_END(47)+128M = 0xffffc00008000000 (smallest module region);
// emit that as a lower bound — it admits any real modern VA47 _text.
//
// WHY VMEMMAP ONLY. A text/image observation would also prove modern, but it is
// redundant: when one exists the base is already bounded directly (an interior
// sample gives base in [T-image_size, T]), and in the no-leak case where this
// floor matters there is no text observation. VMALLOC's position relative to
// the modern linear map is not established here, so it is not trusted. Only
// VMEMMAP — provably high on modern, low on old — is used as the witness.
//
// COMPOSITION. This rule only ADDS a lower bound (raised into the window by the
// engine's meet). It does NOT touch arm64_text_base's "no floor for va==47"
// invariant; that rule stays exactly as-is and this one narrows the floor
// further only when the witness is present. The emission is capped to the
// witness's confidence, so a low-confidence (guessed) vmemmap shapes only the
// likely window, never the guaranteed one.
//
// CURRENTLY DORMANT. The only source of a VIRT/VMEMMAP observation in the tree
// is the dmesg "Virtual kernel memory layout" parser (components/
// dmesg_mem_init_kernel_layout.c), and that block is no longer printed by
// modern arm64 kernels (and requires unrestricted dmesg regardless). So no
// current witness source fires on a modern arm64 target: this rule is correct
// and inert today, and activates automatically if a vmemmap-leaking source is
// ever added. It is retained because it is sound and cost-free when dormant,
// and closes the VA47 gap the moment such a source exists.
//
// arm64 only; inert elsewhere. Inert when PAGE_OFFSET is unresolved, resolves
// to any value other than the VA47 collision, or no qualifying VMEMMAP witness
// is present.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"

#include <string.h>

int rule_arm64_va47_modern_floor(const struct evidence_set *ev,
                                 const struct estimate *est,
                                 struct constraint *out, int out_max) {
#if defined(__aarch64__)
  if (out_max < 1)
    return 0;

  const struct estimate *po = &est[Q_PAGE_OFFSET];
  /* Act only on a fully resolved PAGE_OFFSET. */
  if (po->kind != LK_INTERVAL || po->lo != po->hi)
    return 0;
  /* Only the one ambiguous value: arm64_text_base already floors every other
   * resolved PAGE_OFFSET, so there is nothing to recover there. */
  if (po->lo != arm64_page_offset_for(47ul))
    return 0;

  /* Witness: a VIRT/VMEMMAP observation strictly above the linear-map base.
   * Impossible on any pre-v5.4 layout (everything but the linear map is below
   * PAGE_OFFSET there), so it proves the modern layout. */
  uint32_t witness_id = 0;
  enum kasld_confidence witness_conf = CONF_UNKNOWN;
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->value_kind != OBS_ADDRESS ||
        o->eff_type != KASLD_TYPE_VIRT || o->eff_region != REGION_VMEMMAP)
      continue;
    unsigned long a = obs_anchor(o);
    if (a > po->lo) {
      witness_id = o->id;
      witness_conf = o->conf;
      break;
    }
  }
  if (witness_id == 0)
    return 0; /* no modern witness — honest floor preserved */

  struct constraint *c = &out[0];
  memset(c, 0, sizeof(*c));
  c->q = Q_VIRT_IMAGE_BASE;
  c->op = C_LOWER_BOUND;
  /* Minimum modern VA47 KIMAGE_VADDR: _PAGE_END(47) + smallest module region.
   */
  c->value = arm64_page_end_for(47ul) + ARM64_MODULE_REGION_SIZE_MIN;
  c->conf = kasld_conf_min(CONF_INFERRED, witness_conf);
  c->lineage_count = 0;
  if (po->lo_binding)
    c->derived_from[c->lineage_count++] = po->lo_binding;
  c->derived_from[c->lineage_count++] = witness_id;
  snprintf(c->origin, ORIGIN_LEN, "arm64_va47_modern_floor");
  return 1;
#else
  (void)ev;
  (void)est;
  (void)out;
  (void)out_max;
  return 0;
#endif
}
