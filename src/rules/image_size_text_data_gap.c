// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: kernel-base ceiling from the leaked TEXT..DATA virtual gap.
//
// A leaked kernel TEXT
// address and a leaked DATA/BSS address bound the in-memory image size from
// below (gap = max_data - min_text); the base then cannot sit so high that
// base + gap overflows the KASLR window:
//
//   virt_image_base <= align_down(KASLR_VIRT_TEXT_MAX - gap, virt_kaslr_align)
//   phys_image_base <= align_down(KASLR_PHYS_MAX - gap, phys_align) (decoupled)
//
// Reads VIRT kernel TEXT/IMAGE (min) and DATA/BSS (max) leaks; aligns to the
// resolved Q_VIRT_KASLR_ALIGN / Q_PHYS_KASLR_ALIGN. Inert when no such
// observation is present.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"
#include "include/kasld/regions.h"

#include <limits.h>
#include <string.h>

int rule_image_size_text_data_gap(const struct evidence_set *ev,
                                  const struct estimate *est,
                                  struct constraint *out, int out_max) {
  unsigned long min_text = ULONG_MAX, max_data = 0;
  uint32_t tsrc = 0, dsrc = 0;
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->value_kind != OBS_ADDRESS ||
        o->eff_type != KASLD_TYPE_VIRT)
      continue;
    unsigned long a = obs_anchor(o);
    if (o->eff_region == REGION_KERNEL_TEXT ||
        o->eff_region == REGION_KERNEL_IMAGE) {
      if (a < min_text) {
        min_text = a;
        tsrc = o->id;
      }
    } else if (o->eff_region == REGION_KERNEL_DATA ||
               o->eff_region == REGION_KERNEL_BSS) {
      if (a > max_data) {
        max_data = a;
        dsrc = o->id;
      }
    }
  }
  if (min_text == ULONG_MAX || max_data == 0 || max_data <= min_text)
    return 0;
  unsigned long gap = max_data - min_text;

  int n = 0;
  unsigned long valign = est[Q_VIRT_KASLR_ALIGN].lo;
  if (valign < (unsigned long)KASLR_VIRT_ALIGN)
    valign = (unsigned long)KASLR_VIRT_ALIGN;
  if (gap < (unsigned long)KASLR_VIRT_TEXT_MAX -
                (unsigned long)KASLR_VIRT_TEXT_MIN &&
      n < out_max) {
    unsigned long vmax = (unsigned long)KASLR_VIRT_TEXT_MAX - gap;
    vmax = kasld_floor_virt_text_bound(vmax, valign);
    if (vmax > (unsigned long)KASLR_VIRT_TEXT_MIN) {
      struct constraint *c = &out[n++];
      memset(c, 0, sizeof(*c));
      c->q = Q_VIRT_IMAGE_BASE;
      c->op = C_UPPER_BOUND;
      c->value = vmax;
      c->conf = CONF_INFERRED;
      c->derived_from[0] = tsrc;
      c->derived_from[1] = dsrc;
      c->lineage_count = 2;
      snprintf(c->origin, ORIGIN_LEN, "image_size_text_data_gap");
    }
  }
#if !TEXT_TRACKS_DIRECTMAP
  unsigned long palign = est[Q_PHYS_KASLR_ALIGN].lo;
  if (palign < (unsigned long)KASLR_PHYS_ALIGN)
    palign = (unsigned long)KASLR_PHYS_ALIGN;
  if (gap < (unsigned long)KASLR_PHYS_MAX - (unsigned long)KASLR_PHYS_MIN &&
      n < out_max) {
    unsigned long pmax = (unsigned long)KASLR_PHYS_MAX - gap;
    if (palign > 0)
      pmax &= ~(palign - 1);
    if (pmax > (unsigned long)KASLR_PHYS_MIN) {
      struct constraint *c = &out[n++];
      memset(c, 0, sizeof(*c));
      c->q = Q_PHYS_IMAGE_BASE;
      c->op = C_UPPER_BOUND;
      c->value = pmax;
      c->conf = CONF_INFERRED;
      c->derived_from[0] = tsrc;
      c->derived_from[1] = dsrc;
      c->lineage_count = 2;
      snprintf(c->origin, ORIGIN_LEN, "image_size_text_data_gap");
    }
  }
#endif
  return n;
}
