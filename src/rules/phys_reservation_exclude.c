// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: forbidden-zone physical-base exclusions from reserved / non-RAM
// regions.
//
// The kernel image loads only into E820 System RAM, and never into a region it
// structurally cannot occupy. Two disjointness sources (both verified against
// the kernel source — see is_phys_kernel_forbidden_region):
//   - never RAM: MMIO / PCI windows, persistent memory, ACPI tables / NVS are
//     not E820_TYPE_RAM, and KASLR places the image only in RAM;
//   - reserved from free RAM after the image is placed: crashkernel, SWIOTLB,
//     reserved-memory pools (memblock_phys_alloc over free memblock) cannot
//     overlap the already-loaded image.
//
// A leaked extent [lo, hi] of any such region therefore forbids the physical
// base from the band whose image would overlap it:
//
//   base forbidden in [lo - kernel_size + 1, hi - 1]
//
// the same shape as initrd_phys_exclude. One C_EXCLUDE per forbidden extent;
// interior holes compose into the hole-aware slot count without moving the
// headline lo/hi. Complements mmio_floor_phys_ceiling (which lowers the ceiling
// from the lowest MMIO window) by carving every forbidden extent, not just the
// lowest.
//
// Soundness:
//   * kernel_size is SF_IMAGE_SIZE, a deliberate UNDER-estimate, so the
//     low-edge widening can only under-exclude — never drop a valid base.
//   * hi - 1 is sound under both the inclusive and the half-open [lo,hi]
//     conventions (worst case one byte loose, immaterial under 2 MiB-class
//     KASLR alignment).
//   * each forbidden extent is disjoint from the image individually, so no
//     authoritative-whole-map precondition is needed (unlike the RAM-gap rule).
//
// Reads is_phys_kernel_forbidden_region PHYS observations + SF_IMAGE_SIZE; both
// already in evidence. Decoupled arches only (Q_PHYS_IMAGE_BASE); emits nothing
// without a size fact or a forbidden extent — sound.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"
#include "include/kasld/regions.h"

#include <string.h>

int rule_phys_reservation_exclude(const struct evidence_set *ev,
                                  const struct estimate *est,
                                  struct constraint *out, int out_max) {
  (void)est;
#if TEXT_TRACKS_DIRECTMAP
  (void)ev;
  (void)out;
  (void)out_max;
  return 0;
#else
  unsigned long ksize = 0;
  enum kasld_confidence kconf = CONF_UNKNOWN;
  uint32_t ksrc = 0;
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (o->valid && o->value_kind == OBS_SCALAR &&
        o->scalar_fact == SF_IMAGE_SIZE) {
      ksize = o->scalar_value;
      kconf = o->conf;
      ksrc = o->id;
      break;
    }
  }
  if (ksize == 0)
    return 0;

  int n = 0;
  for (int i = 0; i < ev->n_obs && n < out_max; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->value_kind != OBS_ADDRESS ||
        o->eff_type != KASLD_TYPE_PHYS || !HAS_LO(o) || !HAS_HI(o) ||
        o->hi <= o->lo)
      continue;
    if (!is_phys_kernel_forbidden_region(o->eff_region))
      continue;

    /* base forbidden in [lo - ksize + 1, hi - 1]; clamp the low end. */
    unsigned long hole_lo = (o->lo > ksize) ? (o->lo - ksize + 1) : 0;
    unsigned long hole_hi = o->hi - 1;
    if (hole_hi < hole_lo)
      continue;

    struct constraint *c = &out[n++];
    memset(c, 0, sizeof(*c));
    c->q = Q_PHYS_IMAGE_BASE;
    c->op = C_EXCLUDE;
    c->value = hole_lo;
    c->value2 = hole_hi;
    c->conf = (kconf < o->conf) ? kconf : o->conf;
    c->derived_from[0] = o->id;
    c->derived_from[1] = ksrc;
    c->lineage_count = 2;
    snprintf(c->origin, ORIGIN_LEN, "phys_reservation_exclude");
  }
  return n;
#endif
}
