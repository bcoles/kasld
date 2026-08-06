// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: bound Q_MODULE_BASE — the lowest address the module allocator can hand
// out — from module observations and from the architecture's module band.
//
// Two independent bounds, either of which may be absent:
//
//   UPPER, from evidence: the allocator cannot have returned an address below
//   its own region, so the lowest observed module address is an upper bound on
//   the base. Holds on every architecture, needs no band, and is the bound that
//   makes the quantity worth resolving.
//
//   LOWER + UPPER, from the band: the region lies inside
//   [MODULES_START, MODULES_END], so its base does too. The band is only usable
//   as a BOUND where its edges hold under every configuration the arch models —
//   a weaker claim than admission needs, which is why it is gated on
//   MODULES_BAND_EXACT (see api.h). Where the band follows PAGE_OFFSET it is
//   derived from the RESOLVED value instead: the compile-time macros describe
//   the compile-time split only, and on a moved VMSPLIT they name a place the
//   modules are not.
//
// PROVENANCE: reads VIRT REGION_MODULE only, never REGION_MODULE_REGION. A
// range-classified address is inside the band by construction, so bounding the
// base with it looks safe — but that safety is inherited from the band, and on
// an arch whose band spans most of the address space (arm64) it is worth
// nothing. Requiring structural provenance keeps the rule sound on its own
// terms rather than on a per-arch argument, and keeps it sound if the module
// base is ever coupled to another quantity. See the region note in api.h.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"
#include "include/kasld/regions.h"

#include <limits.h>
#include <string.h>

/* Emit one interval bound on Q_MODULE_BASE. */
static void mbb_emit(struct constraint *c, enum constraint_op op,
                     unsigned long value, uint32_t src) {
  memset(c, 0, sizeof(*c));
  c->q = Q_MODULE_BASE;
  c->op = op;
  c->value = value;
  c->conf = CONF_INFERRED;
  if (src) {
    c->derived_from[0] = src;
    c->lineage_count = 1;
  }
  snprintf(c->origin, ORIGIN_LEN, "module_base_bounds");
}

int rule_module_base_bounds(const struct evidence_set *ev,
                            const struct estimate *est, struct constraint *out,
                            int out_max) {
  int n = 0;
  if (out_max < 1)
    return 0;

  /* --- Upper bound from the lowest structurally-known module address ----- */
  unsigned long vmod_lo = ULONG_MAX;
  uint32_t lo_src = 0;
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->value_kind != OBS_ADDRESS ||
        o->eff_type != KASLD_TYPE_VIRT)
      continue;
    if (o->eff_region != REGION_MODULE)
      continue;
    unsigned long a = obs_anchor(o);
    if (a && a < vmod_lo) {
      vmod_lo = a;
      lo_src = o->id;
    }
  }
  if (vmod_lo != ULONG_MAX && n < out_max)
    mbb_emit(&out[n++], C_UPPER_BOUND, vmod_lo, lo_src);

  /* --- Bounds from the architecture's module band ------------------------ */
#if MODULES_RELATIVE_TO_PAGE_OFFSET
  {
    /* Derived from the resolved PAGE_OFFSET, and only from a two-sided
     * estimate: an unresolved split leaves the band unknown, and guessing it
     * from the compile-time macros is exactly the error this branch exists to
     * avoid. Both accessors are monotone in PAGE_OFFSET, so the widest sound
     * band pairs the lowest floor with the highest ceiling. */
    const struct estimate *po = &est[Q_PAGE_OFFSET];
    if (po->lo && po->hi && po->lo <= po->hi) {
      unsigned long band_lo = (unsigned long)MODULES_START_FOR(po->lo);
      unsigned long band_hi = (unsigned long)MODULES_END_FOR(po->hi);
      /* MODULES_START_FOR subtracts, so guard the wrap a low PAGE_OFFSET
       * would produce rather than emitting a floor near ULONG_MAX. */
      if (band_lo <= po->lo && n < out_max)
        mbb_emit(&out[n++], C_LOWER_BOUND, band_lo, 0);
      if (band_hi >= po->hi && n < out_max)
        mbb_emit(&out[n++], C_UPPER_BOUND, band_hi, 0);
    }
  }
#elif MODULES_BAND_EXACT
  if (n < out_max)
    mbb_emit(&out[n++], C_LOWER_BOUND, (unsigned long)MODULES_START, 0);
  if (n < out_max)
    mbb_emit(&out[n++], C_UPPER_BOUND, (unsigned long)MODULES_END, 0);
#else
  (void)est; /* band not usable as a bound on this arch */
#endif

  return n;
}
