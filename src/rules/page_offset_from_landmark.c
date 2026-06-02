// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: PAGE_OFFSET from landmark observations.
//
// A REGION_PAGE_OFFSET observation
// is a component's assertion of the directmap base / VAS origin itself —
// CONFIG_PAGE_OFFSET from proc-config, the value derived by proc-cpuinfo, etc.
// Each such landmark pins the quantity exactly, so the rule emits a C_EQUALS
// on Q_PAGE_OFFSET per landmark.
//
// Conflict handling is structural, not bespoke: the greedy resolver applies
// the strongest-confidence C_EQUALS first (config `parsed` outranks a
// `heuristic` derivation); a contradicting landmark would invert the interval
// and is skipped and recorded as a conflict.
//
// Reproducible offline: these landmarks are file-derived (kernel config), so
// they replay from a captured sysroot. Reads only evidence.
// ---
// <bcoles@gmail.com>

#include "../include/kasld/engine_rules.h"

#include <string.h>

int rule_page_offset_from_landmark(const struct evidence_set *ev,
                                   const struct estimate *est,
                                   struct constraint *out, int out_max) {
  (void)est;
  int n = 0;
  for (int i = 0; i < ev->n_obs && n < out_max; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->value_kind != OBS_ADDRESS)
      continue;
    if (o->eff_type != KASLD_TYPE_VIRT || o->eff_region != REGION_PAGE_OFFSET)
      continue;
    unsigned long val = obs_anchor(o);
    if (val == 0)
      continue;

    /* A bounded range observation (both extents set and distinct) is a window,
     * not a pin — e.g. the riscv64 SV39 probe knows PAGE_OFFSET lies in
     * [LO, HI] but not which kernel-version value. Emit both bounds rather than
     * pinning C_EQUALS to the lower edge. */
    if (HAS_LO(o) && HAS_HI(o) && o->lo != o->hi && n + 1 < out_max) {
      struct constraint *lo_c = &out[n++];
      memset(lo_c, 0, sizeof(*lo_c));
      lo_c->q = Q_PAGE_OFFSET;
      lo_c->op = C_LOWER_BOUND;
      lo_c->value = o->lo;
      lo_c->conf = o->conf;
      lo_c->derived_from[0] = o->id;
      lo_c->lineage_count = 1;
      snprintf(lo_c->origin, ORIGIN_LEN, "page_offset_from_landmark");

      struct constraint *hi_c = &out[n++];
      memset(hi_c, 0, sizeof(*hi_c));
      hi_c->q = Q_PAGE_OFFSET;
      hi_c->op = C_UPPER_BOUND;
      hi_c->value = o->hi;
      hi_c->conf = o->conf;
      hi_c->derived_from[0] = o->id;
      hi_c->lineage_count = 1;
      snprintf(hi_c->origin, ORIGIN_LEN, "page_offset_from_landmark");
      continue;
    }

    enum constraint_op op = C_EQUALS;
#if defined(__x86_64__)
    /* On x86_64 the directmap base is randomised (RANDOMIZE_MEMORY) AT OR ABOVE
     * the canonical VAS floor, so a landmark at the L4 VAS floor or the L5
     * directmap base (what proc-cpuinfo derives from virt_bits) is a LOWER
     * bound, not the exact base. Pinning it would exclude the randomised base
     * above it; emit C_LOWER_BOUND so phys_virt_synth / directmap bounds can
     * reconstruct the real base within [floor, ...]. */
    if (val == 0xffff800000000000ul || val == 0xff11000000000000ul)
      op = C_LOWER_BOUND;
#endif

    struct constraint *c = &out[n++];
    memset(c, 0, sizeof(*c));
    c->q = Q_PAGE_OFFSET;
    c->op = op;
    c->value = val;
    c->conf = o->conf;
    c->derived_from[0] = o->id;
    c->lineage_count = 1;
    snprintf(c->origin, ORIGIN_LEN, "page_offset_from_landmark");
  }
  return n;
}
