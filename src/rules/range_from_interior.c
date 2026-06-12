// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: tighten text-base ceilings from interior samples.
//
// Any address inside the kernel
// image satisfies sample = text_base + offset with offset >= 0, so
// text_base <= sample regardless of which symbol the offset belongs to.
// Because the base is itself slot-aligned, the bound tightens further to
// text_base <= floor(sample, align). Emits a C_UPPER_BOUND on Q_VIRT_TEXT_BASE
// (virt samples) / Q_PHYS_TEXT_BASE (phys samples) at the aligned minimum
// interior sample observed.
//
// Aligns down to the RESOLVED alignment quantity, never below the arch default
// (mirrors ceiling_from_image_size); the engine's fixpoint loop re-runs this
// after the alignment rules settle.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"
#include "include/kasld/regions.h"

#include <limits.h>
#include <string.h>

static int emit_min_sample(const struct evidence_set *ev,
                           enum kasld_addr_type type, enum kasld_quantity q,
                           unsigned long align, struct constraint *out,
                           int slot, int out_max) {
  unsigned long min_sample = ULONG_MAX;
  enum kasld_confidence conf = CONF_UNKNOWN;
  uint32_t src = 0;
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->eff_type != type)
      continue;
    if (!is_kernel_image_region(o->eff_region) || !HAS_SAMPLE(o))
      continue;
    if (o->sample < min_sample) {
      min_sample = o->sample;
      conf = o->conf;
      src = o->id;
    }
  }
  if (min_sample == ULONG_MAX || slot >= out_max)
    return 0;
  /* The base is slot-aligned, so floor the interior-sample ceiling to align. */
  if (align > 0)
    min_sample &= ~(align - 1);

  struct constraint *c = &out[slot];
  memset(c, 0, sizeof(*c));
  c->q = q;
  c->op = C_UPPER_BOUND;
  c->value = min_sample;
  c->conf = conf;
  c->derived_from[0] = src;
  c->lineage_count = 1;
  snprintf(c->origin, ORIGIN_LEN, "range_from_interior");
  return 1;
}

int rule_range_from_interior(const struct evidence_set *ev,
                             const struct estimate *est, struct constraint *out,
                             int out_max) {
  int n = 0;

  /* Align to the resolved alignment, never below the arch default
   * (Q_KASLR_ALIGN starts at its lattice top of 1 before the alignment rules
   * narrow it). */
  unsigned long valign = est[Q_KASLR_ALIGN].lo;
  if (valign < (unsigned long)KASLR_VIRT_ALIGN)
    valign = (unsigned long)KASLR_VIRT_ALIGN;
  n += emit_min_sample(ev, KASLD_TYPE_VIRT, Q_VIRT_TEXT_BASE, valign, out, n,
                       out_max);

  unsigned long palign = 0;
#if !TEXT_TRACKS_DIRECTMAP
  palign = est[Q_PHYS_KASLR_ALIGN].lo;
  if (palign < (unsigned long)KASLR_PHYS_ALIGN)
    palign = (unsigned long)KASLR_PHYS_ALIGN;
#endif
  n += emit_min_sample(ev, KASLD_TYPE_PHYS, Q_PHYS_TEXT_BASE, palign, out, n,
                       out_max);
  return n;
}
