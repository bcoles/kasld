// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: bound Q_MODULE_BASE — the lowest address the module allocator can hand
// out — from module observations and from the architecture's module band.
//
// Three independent sources, any of which may be absent:
//
//   PIN, from the kernel's own layout block: a POS_BASE observation of the
//   module region states where the region starts, so it fixes the quantity
//   outright rather than bounding it.
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
// PROVENANCE: module ADDRESSES are read as REGION_MODULE only, never
// REGION_MODULE_BAND. A range-classified address is inside the band by
// construction, so bounding the base with it looks safe — but that safety is
// inherited from the band, and on an arch whose band spans most of the address
// space (arm64) it is worth nothing. Requiring structural provenance keeps the
// rule sound on its own terms rather than on a per-arch argument.
//
// The one exception is a POS_BASE observation OF THE REGION, which is not an
// address that might be a module but the region's own start — see the pin
// below. See the region note in api.h.
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
  /* Only the MODULES_RELATIVE_TO_PAGE_OFFSET band below reads the estimates.
   * The cast sits outside that conditional so it covers every arch, including
   * those whose branch never touches est. */
  (void)est;
  if (out_max < 1)
    return 0;

  /* --- The region base, stated outright ---------------------------------
   * A POS_BASE observation of the module REGION is not a module address at
   * all: it is the region's own start, which the kernel prints in its
   * mem_init() layout block ("modules : 0x..."). That is the most direct
   * possible answer to this quantity, so it pins rather than bounds.
   *
   * This is the one place REGION_MODULE_BAND is the RIGHT tag to read.
   * Elsewhere the weak tag means "assumed to be a module because it fell in
   * the band"; combined with POS_BASE it means "this IS where the band
   * starts", and only the landmark parser emits that pair -- every other
   * band emitter reports interior samples. */
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->value_kind != OBS_ADDRESS ||
        o->eff_type != KASLD_TYPE_VIRT || o->pos != POS_BASE)
      continue;
    if (o->eff_region != REGION_MODULE_BAND)
      continue;
    unsigned long a = obs_anchor(o);
    if (!a)
      continue;
    if (n < out_max)
      mbb_emit(&out[n++], C_LOWER_BOUND, a, o->id);
    if (n < out_max)
      mbb_emit(&out[n++], C_UPPER_BOUND, a, o->id);
    break;
  }

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
#elif MODULES_BASE_IS_BAND_FLOOR
  /* The floor is not a bound here, it IS the base: a fixed segment address the
   * arch places the region at, with nothing randomized or runtime-derived in
   * between. Pin rather than bracket. */
  if (n < out_max)
    mbb_emit(&out[n++], C_EQUALS, (unsigned long)MODULES_START, 0);
#elif MODULES_BAND_EXACT
  if (n < out_max)
    mbb_emit(&out[n++], C_LOWER_BOUND, (unsigned long)MODULES_START, 0);
  if (n < out_max)
    mbb_emit(&out[n++], C_UPPER_BOUND, (unsigned long)MODULES_END, 0);
#else
  /* band not usable as a bound on this arch */
#endif

  return n;
}
