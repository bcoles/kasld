// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: bound the kernel text base from leaked module-region addresses.
//
// On arches where the module area is
// placed relative to kernel text (MODULES_RELATIVE_TO_TEXT), a leaked module
// virtual address bounds the text base:
//
//   Case A (riscv64, MODULES_END ~= _end): module area sits just past the
//   image,
//     so _end ~= vmod_lo + MODULES_END_TO_TEXT_OFFSET and
//     image_base <= align_down(_end - MIN_KERNEL_IMAGE_SIZE, virt_kaslr_align).
//   Case B (s390, MODULES_END below __kaslr_offset):
//     image_base <= align_down(vmod_lo + MODULES_END_TO_TEXT_OFFSET,
//     virt_kaslr_align) image_base >= align_down(vmod_hi, virt_kaslr_align) +
//     virt_kaslr_align
//     + IMAGE_BASE_OFFSET
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
#if MODULES_BELOW_TEXT_START
  /* Case B (s390): upper + lower bound. */
  unsigned long new_max = kasld_floor_virt_text_bound(
      vmod_lo + (unsigned long)MODULES_END_TO_TEXT_OFFSET, valign);
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
  /* C_LOWER_BOUND: the slot above the highest module, plus the head. Flooring
   * vmod_hi down is sound for a lower bound; the head (IMAGE_BASE_OFFSET) is
   * re-added. */
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
#else
  /* Case A (riscv64): MODULES_END ~= _end. The sanity floor is the WIDE
   * minimum (KASLR_VIRT_TEXT_MIN_WIDE), not KASLR_VIRT_TEXT_MIN: on an arch
   * with more than one text layout (riscv64 legacy linear-map vs modern
   * KERNEL_LINK_ADDR) the narrow min is the modern floor and would discard a
   * legitimate legacy-region bound. */
  unsigned long end_est = vmod_lo + (unsigned long)MODULES_END_TO_TEXT_OFFSET;
  if (end_est > MTB_MIN_KERNEL_IMAGE_SIZE) {
    unsigned long new_max = kasld_floor_virt_text_bound(
        end_est - MTB_MIN_KERNEL_IMAGE_SIZE, valign);
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
  }
  (void)hi_src;
#endif
  return n;
#else
  (void)ev;
  (void)est;
  (void)out;
  (void)out_max;
  return 0;
#endif
}
