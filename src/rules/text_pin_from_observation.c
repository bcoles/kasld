// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: pin the text base from a POS_BASE kernel-image observation.
//
// A POS_BASE observation in a kernel-image region IS the kernel text base
// for that address type — the producing component (e.g. /proc/kallsyms
// _stext, /proc/iomem "Kernel code") already extracted it as a base, not
// as an interior sample. Emit C_EQUALS at the observation's confidence:
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
                    enum kasld_quantity q, struct constraint *out, int slot,
                    int out_max) {
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
   * is _stext, so normalise it down by the head gap; a KERNEL_IMAGE witness is
   * already the image base. No-op where the head gap is 0 (every arch but
   * arm64). */
  base = kasld_image_base_from(base, base_is_stext);

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
  n += emit_pin(ev, KASLD_TYPE_VIRT, Q_VIRT_IMAGE_BASE, out, n, out_max);
  n += emit_pin(ev, KASLD_TYPE_PHYS, Q_PHYS_IMAGE_BASE, out, n, out_max);
  return n;
}
