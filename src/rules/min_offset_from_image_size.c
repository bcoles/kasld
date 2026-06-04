// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: minimum KASLR offset from the leaked TEXT..DATA gap (MIPS/LoongArch).
//
// On MIPS/LoongArch the
// kernel base is at least the image size above the window floor, because the
// placement code bumps the base past the image when the draw would overlap it:
//
//   virt_text_base >= KASLR_VIRT_TEXT_MIN + (max_data - min_text)
//
// Reads VIRT kernel TEXT/IMAGE (min) and DATA/BSS (max) leaks; emits a
// C_LOWER_BOUND on Q_VIRT_TEXT_BASE.
// MIPS/LoongArch only; dormant offline (no leaks) — LIVE-TEST list.
// ---
// <bcoles@gmail.com>

#include "../include/kasld/engine_rules.h"
#include "../include/kasld/regions.h"

#include <limits.h>
#include <string.h>

int rule_min_offset_from_image_size(const struct evidence_set *ev,
                                    const struct estimate *est,
                                    struct constraint *out, int out_max) {
  (void)est;
#if defined(__mips__) || defined(__loongarch__)
  if (out_max < 1)
    return 0;

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

  unsigned long new_min = (unsigned long)KASLR_VIRT_TEXT_MIN + gap;
  if (new_min <= (unsigned long)KASLR_VIRT_TEXT_MIN)
    return 0;

  struct constraint *c = &out[0];
  memset(c, 0, sizeof(*c));
  c->q = Q_VIRT_TEXT_BASE;
  c->op = C_LOWER_BOUND;
  c->value = new_min;
  c->conf = CONF_INFERRED;
  c->derived_from[0] = tsrc;
  c->derived_from[1] = dsrc;
  c->lineage_count = 2;
  snprintf(c->origin, ORIGIN_LEN, "min_offset_from_image_size");
  return 1;
#else
  (void)ev;
  (void)out;
  (void)out_max;
  return 0;
#endif
}
