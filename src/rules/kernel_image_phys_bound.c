// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: bound the kernel's PHYSICAL text base from leaked kernel-image PHYS
// witnesses.
//
// A leaked physical address in a kernel-image section (TEXT/DATA/BSS/whole-
// image) bounds the kernel's physical base from above:
//
//   phys_text_base <= align_down(min(witness), phys_align)
//
// A BSS-resident witness is tightened by the virtual TEXT..DATA gap (the
// in-image offset between text and data, which transfers 1:1 from virt to
// phys on every arch where the loader places the image contiguously). When
// the high witness is far enough above the low that it can only sit at the
// far end of a max-sized image, the spread also yields a LOWER bound:
//
//   phys_text_base >= hi - MAX_KERNEL_IMAGE_SIZE + 1
//
// A conflict guard rejects witnesses whose raw spread exceeds the max
// kernel image size (a misclassified observation would otherwise force
// bottom).
//
// All output is on Q_PHYS_TEXT_BASE regardless of arch — the symmetric
// text_base_coupling_synth rule projects these bounds onto Q_VIRT_TEXT_BASE
// on TEXT_TRACKS_DIRECTMAP arches when Q_PAGE_OFFSET is pinned. The
// phys↔virt coupling math lives in one rule so the projection formula
// (and its TEXT_OFFSET header-slack safety margin) is applied consistently;
// the TEXT_OFFSET headroom belongs to the upper bound only and is not added
// to the lower bound's direction.
//
// Reads leaked PHYS (kernel-locating) + VIRT (text/data, for the BSS-gap
// refinement) observations. Inert when no such observation is present.
// ---
// <bcoles@gmail.com>

#include "../include/kasld/engine_rules.h"
#include "../include/kasld/regions.h"

#include <limits.h>
#include <string.h>

#define MAX_KERNEL_IMAGE_SIZE (256ul * 1024 * 1024)
#define MIN_PLAUSIBLE_KERNEL_PHYS (1ul * 1024 * 1024)
#define MAX_PLAUSIBLE_KERNEL_PHYS                                              \
  (1ull << 50) /* ull: 1<<50 overflows 32-bit long */

static unsigned long kipb_virt_gap(const struct evidence_set *ev) {
  unsigned long min_text = ULONG_MAX, max_data = 0;
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->value_kind != OBS_ADDRESS ||
        o->eff_type != KASLD_TYPE_VIRT)
      continue;
    if (o->eff_region == REGION_KERNEL_TEXT ||
        o->eff_region == REGION_KERNEL_IMAGE) {
      unsigned long a = obs_anchor(o);
      if (a < min_text)
        min_text = a;
    } else if (o->eff_region == REGION_KERNEL_DATA) {
      unsigned long a = obs_anchor(o);
      if (a > max_data)
        max_data = a;
    }
  }
  if (min_text == ULONG_MAX || max_data <= min_text)
    return 0;
  return max_data - min_text;
}

int rule_kernel_image_phys_bound(const struct evidence_set *ev,
                                 const struct estimate *est,
                                 struct constraint *out, int out_max) {
  if (out_max < 1)
    return 0;

  unsigned long virt_gap = kipb_virt_gap(ev);
  unsigned long lo_raw = ULONG_MAX, lo_tight = ULONG_MAX, hi = 0;
  int count = 0;
  uint32_t src = 0;

  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->value_kind != OBS_ADDRESS ||
        o->eff_type != KASLD_TYPE_PHYS)
      continue;
    if (!is_kernel_locating_region(o->eff_region))
      continue;
    unsigned long a = obs_anchor(o);
    if (!kasld_addr_in_range(a, MIN_PLAUSIBLE_KERNEL_PHYS,
                             MAX_PLAUSIBLE_KERNEL_PHYS))
      continue;
    if (a < lo_raw)
      lo_raw = a;
    if (a > hi)
      hi = a;
    unsigned long contrib = a;
    if (virt_gap > 0 && o->eff_region == REGION_KERNEL_BSS && a > virt_gap)
      contrib = a - virt_gap;
    if (contrib < lo_tight) {
      lo_tight = contrib;
      src = o->id;
    }
    count++;
  }
  if (count == 0)
    return 0;
  /* Conflict guard on raw spread (the BSS refinement can't trigger it). */
  if (hi - lo_raw > MAX_KERNEL_IMAGE_SIZE)
    return 0;

  unsigned long palign = est[Q_PHYS_KASLR_ALIGN].lo;
  if (palign < (unsigned long)KASLR_PHYS_ALIGN)
    palign = (unsigned long)KASLR_PHYS_ALIGN;

  int n = 0;

  /* Upper bound (sound): phys_text_base ≤ lo_tight. Every kernel-image
   * witness sits at or above the text base, so the raw witness is always
   * a sound upper bound — independent of alignment assumptions. */
  if (lo_tight > (unsigned long)KASLR_PHYS_MIN && n < out_max) {
    struct constraint *c = &out[n++];
    memset(c, 0, sizeof(*c));
    c->q = Q_PHYS_TEXT_BASE;
    c->op = C_UPPER_BOUND;
    c->value = lo_tight;
    c->conf = CONF_INFERRED;
    c->derived_from[0] = src;
    c->lineage_count = src ? 1 : 0;
    snprintf(c->origin, ORIGIN_LEN, "kernel_image_phys_bound");
  }

  /* Tighter heuristic bound: phys_text_base ≤ align_down(lo_tight, palign).
   * Sound ONLY when text_base is palign-aligned. The arch's KASLR_PHYS_ALIGN
   * is a default assumption, not a hard invariant: a kernel built without
   * KASLR (or with a smaller-granularity loader) places text at finer
   * alignment than the constant suggests (e.g. riscv64 with text at a
   * 4 KiB-aligned, non-PMD-aligned phys address). When the assumption
   * fails, this tighter bound is below the real text base, so emit it at
   * CONF_HEURISTIC — any higher-confidence text-pin observation (e.g.
   * proc-iomem Kernel code, kallsyms-derived) overrides it cleanly, and
   * the sound CONF_INFERRED bound above still holds. Only emit when it
   * actually tightens (lo_tight isn't already palign-aligned). */
  if (palign > 0 && (lo_tight & (palign - 1)) != 0 && n < out_max) {
    unsigned long pmax = lo_tight & ~(palign - 1);
    if (pmax > (unsigned long)KASLR_PHYS_MIN) {
      struct constraint *c = &out[n++];
      memset(c, 0, sizeof(*c));
      c->q = Q_PHYS_TEXT_BASE;
      c->op = C_UPPER_BOUND;
      c->value = pmax;
      c->conf = CONF_HEURISTIC;
      c->derived_from[0] = src;
      c->lineage_count = src ? 1 : 0;
      snprintf(c->origin, ORIGIN_LEN, "kernel_image_phys_bound");
    }
  }

  /* Lower bound: when hi is high enough that even a max-sized image leaves
   * the base above zero, phys_text_base ≥ hi - MAX_KERNEL_IMAGE_SIZE + 1.
   * Independent of arch coupling — relies only on image-size bounding. */
  if (hi >= MAX_KERNEL_IMAGE_SIZE && n < out_max) {
    unsigned long pmin = hi - MAX_KERNEL_IMAGE_SIZE + 1;
    if (palign > 0)
      pmin = (pmin + palign - 1) & ~(palign - 1);
    if (pmin > (unsigned long)KASLR_PHYS_MIN) {
      struct constraint *c = &out[n++];
      memset(c, 0, sizeof(*c));
      c->q = Q_PHYS_TEXT_BASE;
      c->op = C_LOWER_BOUND;
      c->value = pmin;
      c->conf = CONF_INFERRED;
      c->derived_from[0] = src;
      c->lineage_count = src ? 1 : 0;
      snprintf(c->origin, ORIGIN_LEN, "kernel_image_phys_bound");
    }
  }
  return n;
}
