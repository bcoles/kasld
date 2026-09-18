// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: kernel-base ceiling from the leaked TEXT..DATA virtual gap.
//
// A leaked kernel TEXT
// address and a leaked DATA/BSS address bound the in-memory image size from
// below (gap = max_data - min_text); the base then cannot sit so high that
// base + gap overflows the KASLR window:
//
//   virt_image_base <= align_down(VIRT_TEXT_MAX_ANY_CONFIG - gap,
//   virt_kaslr_align) phys_image_base <= align_down(PHYS_ADDR_TOP - gap,
//   phys_align) (decoupled)
//
// Both edges are the widest the architecture admits, never a default build's or
// a plausibility heuristic's: these bounds reach the guaranteed answer, so an
// edge that holds for most kernels rather than all of them would exclude the
// base on the rest.
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
  /* WIDE honest top/floor, not the raw 48-bit VIRT_TEXT_MAX_DEFAULT_CONFIG/MIN:
   * the raw MAX is below an arm64 sub-48 VA_BITS text base, so a raw-MAX
   * ceiling would exclude the true base. Equal to the raw values on arches
   * whose KASLR window already spans every layout (x86_64). Same fix as
   * ceiling_from_image_size.
   */
  if (gap < (unsigned long)VIRT_TEXT_MAX_ANY_CONFIG -
                (unsigned long)VIRT_TEXT_MIN_ANY_CONFIG &&
      n < out_max) {
    unsigned long vmax = (unsigned long)VIRT_TEXT_MAX_ANY_CONFIG - gap;
    vmax = kasld_floor_virt_text_bound(vmax, valign);
    if (vmax > (unsigned long)VIRT_TEXT_MIN_ANY_CONFIG) {
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
  /* PHYS_ADDR_TOP, not PHYS_PLAUSIBLE_MAX: the ceiling below is emitted at the
   * sound floor, and the plausibility constant is a heuristic about where
   * kernels are usually loaded rather than a limit on where they can be. See
   * ceiling_from_image_size, which bounds this same quantity the same way. */
  if (gap < (unsigned long)PHYS_ADDR_TOP - (unsigned long)KERNEL_PHYS_DEFAULT &&
      n < out_max) {
    unsigned long pmax = (unsigned long)PHYS_ADDR_TOP - gap;
    if (palign > 0)
      pmax &= ~(palign - 1);
    if (pmax > (unsigned long)KERNEL_PHYS_DEFAULT) {
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
