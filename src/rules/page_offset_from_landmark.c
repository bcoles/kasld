// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: PAGE_OFFSET from landmark observations.
//
// A REGION_PAGE_OFFSET observation
// is a component's assertion of the directmap base / VAS origin itself —
// CONFIG_PAGE_OFFSET from proc_config, the EFI virt-minus-phys agreement from
// sysfs_efi_runtime_map, etc. Each such landmark pins the quantity exactly, so
// the rule emits a C_EQUALS on Q_PAGE_OFFSET per landmark.
//
// A component that has only a BOUND on the base states it on the constraint
// channel, which the anchor rules never read, so a floor does not reach this
// rule as a landmark in the first place. The x86_64 check below stays as a
// backstop for one that does: a floor pinned here would exclude the randomized
// base above it from the guaranteed window, and the cost of holding the net in
// place is nothing while nothing trips it.
//
// Conflict handling is structural, not bespoke: the greedy resolver applies
// the strongest-confidence C_EQUALS first (config `parsed` outranks a
// `heuristic` derivation); a contradicting landmark would invert the interval
// and is skipped and recorded as a conflict.
//
// A pure constraint over evidence: reads only the evidence set, no I/O.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"

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
    /* Backstop, not the primary defence. The canonical VAS floor is never an
     * exact directmap base on x86_64 -- RANDOMIZE_MEMORY places the base at or
     * above the compile-time value, itself above this floor -- so pinning a
     * landmark carrying it would exclude the truth however it arrived. The L5
     * base is admitted here too, conservatively: it can be exact when memory
     * randomization is off, and a bound merely gives up the pin. */
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
