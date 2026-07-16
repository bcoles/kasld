// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: pin virt_page_offset from a leaked exact linear-map base.
//
// Most direct-map evidence is a leaked directmap *address* — an upper bound on
// the base (see directmap_page_offset_bounds), because __va(lowest_RAM) sits
// above page_offset_base by however much physical RAM starts above PHYS_OFFSET.
// A few sources instead recover the base itself, exactly: /proc/kcore's RAM
// program headers carry both a direct-map VA (p_vaddr) and its physical base
// (p_paddr), and page_offset_base = p_vaddr - p_paddr + PHYS_OFFSET holds for
// every RAM segment. Such a source bridges the exact value as
// SF_VIRT_PAGE_OFFSET; this rule pins Q_PAGE_OFFSET to it.
//
// C_EQUALS at CONF_PARSED (a parsed, exact value). The engine's monotone meet
// drops it if it would fall outside the current window, so a stale or wrong
// value cannot widen a tighter sound bound — it collapses the direct-map base
// from the max_pfn-wide guaranteed span to a single value. Arch-agnostic: inert
// wherever no SF_VIRT_PAGE_OFFSET observation is present (the fact is emitted
// only where the offset is exactly recoverable — PHYS_OFFSET_EXACT).
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"

#include <string.h>

int rule_page_offset_from_leak(const struct evidence_set *ev,
                               const struct estimate *est,
                               struct constraint *out, int out_max) {
  (void)est;
  if (out_max < 1)
    return 0;

  unsigned long po = 0;
  uint32_t src = 0;
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (o->valid && o->value_kind == OBS_SCALAR &&
        o->scalar_fact == SF_VIRT_PAGE_OFFSET) {
      po = o->scalar_value;
      src = o->id;
      break;
    }
  }
  if (po == 0)
    return 0;

  struct constraint *c = &out[0];
  memset(c, 0, sizeof(*c));
  c->q = Q_PAGE_OFFSET;
  c->op = C_EQUALS;
  c->value = po;
  c->conf = CONF_PARSED;
  c->derived_from[0] = src;
  c->lineage_count = src ? 1 : 0;
  snprintf(c->origin, ORIGIN_LEN, "page_offset_from_leak");
  return 1;
}
