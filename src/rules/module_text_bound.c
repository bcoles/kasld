// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: bound the kernel text base from leaked module-region addresses.
//
// On arches where the module area is placed relative to kernel text
// (MODULES_RELATIVE_TO_TEXT: riscv64, s390) the band sits BELOW the image on
// both, so a leaked module virtual address bounds the text base from both
// sides.
//
// UPPER bound — arch-specific, set by which image symbol the band's LOW edge
// tracks:
//   Case A (riscv64): MODULES_VADDR = _end - 2 GiB, so
//     vmod_lo + MODULES_END_TO_TEXT_OFFSET ~= _end, and
//     image_base <= align_down(_end - MIN_KERNEL_IMAGE_SIZE, virt_kaslr_align).
//   Case B (s390): MODULES_END = round_down(_text), low edge = that - 2 GiB, so
//     image_base <= align_down(vmod_lo + MODULES_END_TO_TEXT_OFFSET,
//                              virt_kaslr_align).
//
// LOWER bound — common to both: the band ENDS at or below the image start, so
// every module sits below _text:
//     image_base >= align_down(vmod_hi, virt_kaslr_align) + virt_kaslr_align
//                   + IMAGE_BASE_OFFSET.
//
// That holds under each module-region layout riscv64 has carried, which matters
// because the older one is still in scope (see RISCV_LEGACY_PAGE_OFFSET and
// riscv64_text_base's legacy path):
//   dedicated band — MODULES_END = _start, so the region is carved to end
//     exactly where the image begins.
//   vmalloc-backed — no dedicated band at all; MODULES_VADDR/END are
//     VMALLOC_START/END, and VMALLOC_END is PAGE_OFFSET, while legacy text sits
//     ABOVE PAGE_OFFSET (RISCV_LEGACY_PAGE_OFFSET + the head gap). Modules are
//     below the linear-map base and the image is above it.
// The two reach the same conclusion by different routes, so the bound does not
// depend on which layout the target was built with — which is as well, since
// nothing here can tell them apart.
//
// Reads VIRT REGION_MODULE leaks ONLY -- never REGION_MODULE_BAND; see the
// provenance note at the filter below. Aligns to the resolved
// Q_VIRT_KASLR_ALIGN. Inert where MODULES_RELATIVE_TO_TEXT==0, and inert when
// no structurally-known module observation is present.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"
#include "include/kasld/regions.h"

#include <limits.h>
#include <string.h>

#define MTB_MIN_KERNEL_IMAGE_SIZE (4ul * 1024 * 1024)

int rule_module_text_bound(const struct evidence_set *ev,
                           const struct estimate *est, struct constraint *out,
                           int out_max) {
#if MODULES_RELATIVE_TO_TEXT
  if (out_max < 1)
    return 0;

  unsigned long valign = est[Q_VIRT_KASLR_ALIGN].lo;
  if (valign < (unsigned long)KASLR_VIRT_ALIGN)
    valign = (unsigned long)KASLR_VIRT_ALIGN;
  if (valign == 0)
    return 0;

  unsigned long vmod_lo = ULONG_MAX, vmod_hi = 0;
  uint32_t lo_src = 0, hi_src = 0;
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->value_kind != OBS_ADDRESS ||
        o->eff_type != KASLD_TYPE_VIRT)
      continue;
    /* REGION_MODULE only, never REGION_MODULE_BAND. This rule moves
     * Q_VIRT_IMAGE_BASE at the sound floor, so it may consume only addresses
     * whose source KNOWS they belong to a module -- not ones classified as
     * module because they fell inside the band. On both arches this rule runs
     * on, the band CONTAINS the whole kernel-text range (riscv64
     * [ffffffde.., ffffffffc0000000] over text [ffffffe0.., ffffffffc0000000];
     * s390 [0, 20000000000000] over text [100000, 20000000000000]), so a
     * range-classified kernel address is indistinguishable from a module one
     * and reaches here as a text-base bound. On s390 that is unsound in the
     * dangerous direction: modules sit BELOW the image, so a kernel .data
     * address raises the C_LOWER_BOUND above the true _text and carves truth
     * out of the guaranteed window. Requiring structural provenance removes
     * the whole class, rather than relying on every emitter to filter -- see
     * the region note in api.h. */
    if (o->eff_region != REGION_MODULE)
      continue;
    unsigned long a = obs_anchor(o);
    if (a < vmod_lo) {
      vmod_lo = a;
      lo_src = o->id;
    }
    if (a > vmod_hi) {
      vmod_hi = a;
      hi_src = o->id;
    }
  }
  if (vmod_lo == ULONG_MAX)
    return 0;

  int n = 0;

  /* UPPER bound: which image symbol the band's low edge tracks is arch-specific
   * (see the header). */
#if MODULES_BELOW_TEXT_START
  /* Case B (s390): low edge = round_down(_text) - 2 GiB, so lowest module +
   * offset bounds the text base directly. */
  unsigned long new_max = kasld_floor_virt_text_bound(
      vmod_lo + (unsigned long)MODULES_END_TO_TEXT_OFFSET, valign);
#else
  /* Case A (riscv64): low edge = _end - 2 GiB, so lowest module + offset bounds
   * _end; back off a minimum image size to reach the text base. The sanity
   * floor is the WIDE minimum (KASLR_VIRT_TEXT_MIN_WIDE), not
   * KASLR_VIRT_TEXT_MIN: on an arch with more than one text layout (riscv64
   * legacy linear-map vs modern KERNEL_LINK_ADDR) the narrow min is the modern
   * floor and would discard a legitimate legacy-region bound. */
  unsigned long new_max = 0;
  unsigned long end_est = vmod_lo + (unsigned long)MODULES_END_TO_TEXT_OFFSET;
  if (end_est > MTB_MIN_KERNEL_IMAGE_SIZE)
    new_max = kasld_floor_virt_text_bound(end_est - MTB_MIN_KERNEL_IMAGE_SIZE,
                                          valign);
#endif
  if (new_max > (unsigned long)KASLR_VIRT_TEXT_MIN_WIDE && n < out_max) {
    struct constraint *c = &out[n++];
    memset(c, 0, sizeof(*c));
    c->q = Q_VIRT_IMAGE_BASE;
    c->op = C_UPPER_BOUND;
    c->value = new_max;
    c->conf = CONF_INFERRED;
    c->derived_from[0] = lo_src;
    c->lineage_count = 1;
    snprintf(c->origin, ORIGIN_LEN, "module_text_bound");
  }

  /* LOWER bound (both arches -- the band ends at the image start, so every
   * module sits below _text): the slot above the highest module, plus the head.
   * Sound in the dangerous direction only because the REGION_MODULE provenance
   * filter above admits solely addresses KNOWN to be modules -- a misclassified
   * kernel .data address would raise this floor above the true _text. Flooring
   * vmod_hi down keeps it conservative; IMAGE_BASE_OFFSET (the _start->_stext
   * head) is re-added. */
  unsigned long mod_slot = vmod_hi & ~(valign - 1); /* virt-floor-ok */
  unsigned long new_min = mod_slot + valign + (unsigned long)IMAGE_BASE_OFFSET;
  if (new_min > (unsigned long)KASLR_VIRT_TEXT_MIN_WIDE && n < out_max) {
    struct constraint *c = &out[n++];
    memset(c, 0, sizeof(*c));
    c->q = Q_VIRT_IMAGE_BASE;
    c->op = C_LOWER_BOUND;
    c->value = new_min;
    c->conf = CONF_INFERRED;
    c->derived_from[0] = hi_src;
    c->lineage_count = 1;
    snprintf(c->origin, ORIGIN_LEN, "module_text_bound");
  }
  return n;
#else
  (void)ev;
  (void)est;
  (void)out;
  (void)out_max;
  return 0;
#endif
}
