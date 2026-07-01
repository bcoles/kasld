// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: pin the text base from a POS_BASE kernel-image observation.
//
// A POS_BASE observation in a kernel-image region IS the kernel text base
// for that address type — the producing component (e.g. /proc/kallsyms
// _stext, /proc/iomem "Kernel code") already extracted it as a base, not
// as an interior sample.
//
// An at/above-sound-floor witness is exact -> C_EQUALS pin. A BELOW-floor
// witness is a floored dense-probe guess (perf, prefetch) carrying inherent
// +/-1-slot uncertainty (the base sits in the floored granule or one below it,
// where slot-0 head/.entry text was unobservable); on a large-page arch it is
// emitted as the [base - align, base] WINDOW instead, so the likely result
// brackets the truth rather than pinning one slot high. See the soundness note
// at the emission site. Emit at the observation's confidence:
//
//   VIRT  + KERNEL_TEXT / KERNEL_IMAGE  →  Q_VIRT_IMAGE_BASE  := lo
//   PHYS  + KERNEL_TEXT / KERNEL_IMAGE  →  Q_PHYS_IMAGE_BASE  := lo
//
// Multiple agreeing POS_BASE witnesses fold to one (dedup at the engine);
// disagreement is the engine's normal C_EQUALS-vs-C_EQUALS conflict
// resolution path (the higher-confidence pin wins; CONF_PARSED iomem +
// CONF_PARSED kallsyms agreeing on the same byte is the routine case).
//
// Soundness:
//   * Only POS_BASE observations participate. Interior samples (kallsyms
//     non-_stext, ksymtab fragments) are not the base and don't fire.
//   * Region gate to KERNEL_TEXT / KERNEL_IMAGE; KERNEL_DATA / KERNEL_BSS
//     iomem entries are excluded — their lo is the data-section start,
//     not the text base.
//   * Confidence inherits from the observation (set to its native
//     confidence; lineage is the witness id).
//
// Closes the gap on coupled arches (LoongArch/arm64) where the existing
// kernel_image_phys_bound only forwards PHYS witnesses to Q_VIRT_IMAGE_BASE
// via PAGE_OFFSET, leaving Q_PHYS_IMAGE_BASE at its honest top despite a
// known iomem witness — and surfaces as a misleading "Physical KASLR
// entropy: N bits" headline disagreeing with the displayed "Physical text
// base" witness. Arch-independent.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"
#include "include/kasld/regions.h"

#include <string.h>

static int emit_pin(const struct evidence_set *ev, enum kasld_addr_type type,
                    enum kasld_quantity q, unsigned long align,
                    struct constraint *out, int slot, int out_max) {
  if (slot >= out_max)
    return 0;

  unsigned long base = 0;
  enum kasld_confidence conf = CONF_UNKNOWN;
  uint32_t src = 0;
  int base_is_stext = 0;
  int found = 0;
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->value_kind != OBS_ADDRESS || o->eff_type != type)
      continue;
    if (o->eff_region != REGION_KERNEL_TEXT &&
        o->eff_region != REGION_KERNEL_IMAGE)
      continue;
    if (o->pos != POS_BASE || !HAS_LO(o))
      continue;
    /* Prefer the highest-confidence witness; on ties, prefer the lowest
     * address (the actual _stext start over any later text-region marker).
     * The engine's same_claim dedup folds agreeing emits across origins. */
    if (!found || o->conf > conf || (o->conf == conf && o->lo < base)) {
      base = o->lo;
      conf = o->conf;
      src = o->id;
      base_is_stext = (o->eff_region == REGION_KERNEL_TEXT);
      found = 1;
    }
  }
  if (!found)
    return 0;

  /* The engine's text quantity is the IMAGE BASE (_text). A KERNEL_TEXT witness
   * is _stext, so normalize it down by the head gap; a KERNEL_IMAGE witness is
   * already the image base. No-op where the head gap is 0 (every arch but
   * arm64). */
  base = kasld_image_base_from(base, base_is_stext);

  /* A base witness BELOW the sound floor is a floored dense-probe GUESS (perf's
   * lowest sampled IP, prefetch's latency scan), already aligned down to the
   * KASLR granule. Its true base sits either in that granule, or one granule
   * below it — the slot-0 head/.entry text the probe could not observe (e.g.
   * modern x86_64, whose first 2 MiB is un-sampleable .entry/.split_text). On a
   * large-page arch, model it as the [base - align, base] WINDOW, which
   * contains the true base in BOTH cases, rather than an exact pin that misses
   * by one slot whenever slot 0 is unobservable. The bounds keep the witness's
   * sub-floor confidence, so they shape the likely window only — the guaranteed
   * window never sees them. An at/above-floor witness (kallsyms _stext, iomem
   * "Kernel code") is exact and pins. Gated to align >= 2 MiB: on a fine
   * granule the lowest observed IP can sit many slots above the base, so a
   * one-slot window would not bound it (and the dense-probe emitters do not
   * fire there). */
  if ((int)conf < (int)CONF_INFERRED && align >= 2 * MB && base > align) {
    if (slot + 1 >= out_max)
      return 0;
    struct constraint *lo = &out[slot];
    memset(lo, 0, sizeof(*lo));
    lo->q = q;
    lo->op = C_LOWER_BOUND;
    lo->value = base - align;
    lo->conf = conf;
    lo->derived_from[0] = src;
    lo->lineage_count = 1;
    snprintf(lo->origin, ORIGIN_LEN, "text_pin_from_observation");

    struct constraint *hi = &out[slot + 1];
    memset(hi, 0, sizeof(*hi));
    hi->q = q;
    hi->op = C_UPPER_BOUND;
    hi->value = base;
    hi->conf = conf;
    hi->derived_from[0] = src;
    hi->lineage_count = 1;
    snprintf(hi->origin, ORIGIN_LEN, "text_pin_from_observation");
    return 2;
  }

  struct constraint *c = &out[slot];
  memset(c, 0, sizeof(*c));
  c->q = q;
  c->op = C_EQUALS;
  c->value = base;
  c->conf = conf;
  c->derived_from[0] = src;
  c->lineage_count = 1;
  snprintf(c->origin, ORIGIN_LEN, "text_pin_from_observation");
  return 1;
}

int rule_text_pin_from_observation(const struct evidence_set *ev,
                                   const struct estimate *est,
                                   struct constraint *out, int out_max) {
  (void)est;
  int n = 0;
  n += emit_pin(ev, KASLD_TYPE_VIRT, Q_VIRT_IMAGE_BASE,
                (unsigned long)KASLR_VIRT_ALIGN, out, n, out_max);
  n += emit_pin(ev, KASLD_TYPE_PHYS, Q_PHYS_IMAGE_BASE,
                (unsigned long)KASLR_PHYS_ALIGN, out, n, out_max);
  return n;
}
