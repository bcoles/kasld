// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: initrd forbidden zone (physical base exclusion).
//
// The bootloader-supplied initrd occupies [initrd_start, initrd_end). The
// kernel placement code never selects a base whose image [base, base + size)
// overlaps it, so the physical base is forbidden in
//
//   (initrd_start - kernel_size, initrd_end)   i.e. the inclusive integer hole
//   [initrd_start - kernel_size + 1, initrd_end - 1]
//
// emitted as a C_EXCLUDE on Q_PHYS_TEXT_BASE. Rather than invalidating leaked
// results that land in the initrd, it removes the forbidden band from the
// candidate set itself. The hole shows up only in the
// hole-aware slot count, not the headline lo/hi (an interior C_EXCLUDE does not
// move the edges).
//
// Reads REGION_INITRD (emitted as a [lo,hi] range by boot_params_e820 /
// devicetree) + SF_IMAGE_SIZE; both already in evidence. Decoupled arches only
// (Q_PHYS_TEXT_BASE); emits nothing when either input is absent — sound.
// ---
// <bcoles@gmail.com>

#include "../include/kasld/engine_rules.h"
#include "../include/kasld/regions.h"

#include <string.h>

int rule_initrd_phys_exclude(const struct evidence_set *ev,
                             const struct estimate *est, struct constraint *out,
                             int out_max) {
  (void)est;
#if TEXT_TRACKS_DIRECTMAP
  (void)ev;
  (void)out;
  (void)out_max;
  return 0;
#else
  if (out_max < 1)
    return 0;

  unsigned long ksize = 0, istart = 0, iend = 0;
  enum kasld_confidence kconf = CONF_UNKNOWN, iconf = CONF_PARSED;
  uint32_t ksrc = 0, isrc = 0;
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid)
      continue;
    if (o->value_kind == OBS_SCALAR && o->scalar_fact == SF_IMAGE_SIZE) {
      ksize = o->scalar_value;
      kconf = o->conf;
      ksrc = o->id;
    } else if (o->value_kind == OBS_ADDRESS && o->eff_type == KASLD_TYPE_PHYS &&
               o->eff_region == REGION_INITRD && HAS_LO(o) && HAS_HI(o) &&
               o->hi > o->lo) {
      /* Lowest initrd interval seen (deterministic if several). */
      if (isrc == 0 || o->lo < istart) {
        istart = o->lo;
        iend = o->hi;
        iconf = o->conf;
        isrc = o->id;
      }
    }
  }

  if (ksize == 0 || isrc == 0)
    return 0;

  /* base forbidden in [istart - ksize + 1, iend - 1]; clamp the low end. */
  unsigned long hole_lo = (istart > ksize) ? (istart - ksize + 1) : 0;
  unsigned long hole_hi = iend - 1;
  if (hole_hi < hole_lo)
    return 0;

  struct constraint *c = &out[0];
  memset(c, 0, sizeof(*c));
  c->q = Q_PHYS_TEXT_BASE;
  c->op = C_EXCLUDE;
  c->value = hole_lo;
  c->value2 = hole_hi;
  c->conf = (kconf < iconf) ? kconf : iconf;
  c->derived_from[0] = isrc;
  c->derived_from[1] = ksrc;
  c->lineage_count = 2;
  snprintf(c->origin, ORIGIN_LEN, "initrd_phys_exclude");
  return 1;
#endif
}
