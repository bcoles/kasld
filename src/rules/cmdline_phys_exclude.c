// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: cmdline forbidden zone (physical base exclusion).
//
// The bootloader-supplied kernel cmdline occupies
// [cmd_line_ptr, cmd_line_ptr + cmdline_size). The kernel placement code (x86
// MEM_AVOID_CMDLINE) refuses to select a base whose image [base, base + size)
// overlaps it, so the physical base is forbidden in
//
//   (cmd_line_ptr - kernel_size, cmd_line_ptr + cmdline_size)
//   i.e. the inclusive integer hole
//   [cmd_line_ptr - kernel_size + 1, cmd_line_ptr + cmdline_size - 1]
//
// emitted as a C_EXCLUDE on Q_PHYS_TEXT_BASE. The hole is interior to the
// [base, base+ksize) window, so it only shows up in the hole-aware slot count,
// not the headline lo/hi.
//
// Reads REGION_CMDLINE (emitted as a [lo,hi] range by cmdline_region) and
// SF_IMAGE_SIZE. Decoupled arches only (Q_PHYS_TEXT_BASE exists); emits nothing
// when either input is absent.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"
#include "include/kasld/regions.h"

#include <string.h>

int rule_cmdline_phys_exclude(const struct evidence_set *ev,
                              const struct estimate *est,
                              struct constraint *out, int out_max) {
  (void)est;
#if TEXT_TRACKS_DIRECTMAP
  (void)ev;
  (void)out;
  (void)out_max;
  return 0;
#else
  if (out_max < 1)
    return 0;

  unsigned long ksize = 0, cstart = 0, cend = 0;
  enum kasld_confidence kconf = CONF_UNKNOWN, cconf = CONF_PARSED;
  uint32_t ksrc = 0, csrc = 0;
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid)
      continue;
    if (o->value_kind == OBS_SCALAR && o->scalar_fact == SF_IMAGE_SIZE) {
      ksize = o->scalar_value;
      kconf = o->conf;
      ksrc = o->id;
    } else if (o->value_kind == OBS_ADDRESS && o->eff_type == KASLD_TYPE_PHYS &&
               o->eff_region == REGION_CMDLINE && HAS_LO(o) && HAS_HI(o) &&
               o->hi >= o->lo) {
      /* Lowest cmdline interval seen (deterministic if several). */
      if (csrc == 0 || o->lo < cstart) {
        cstart = o->lo;
        cend = o->hi;
        cconf = o->conf;
        csrc = o->id;
      }
    }
  }

  if (ksize == 0 || csrc == 0)
    return 0;

  /* base forbidden in [cstart - ksize + 1, cend]; clamp the low end. */
  unsigned long hole_lo = (cstart > ksize) ? (cstart - ksize + 1) : 0;
  unsigned long hole_hi = cend;
  if (hole_hi < hole_lo)
    return 0;

  struct constraint *c = &out[0];
  memset(c, 0, sizeof(*c));
  c->q = Q_PHYS_TEXT_BASE;
  c->op = C_EXCLUDE;
  c->value = hole_lo;
  c->value2 = hole_hi;
  c->conf = (kconf < cconf) ? kconf : cconf;
  c->derived_from[0] = csrc;
  c->derived_from[1] = ksrc;
  c->lineage_count = 2;
  snprintf(c->origin, ORIGIN_LEN, "cmdline_phys_exclude");
  return 1;
#endif
}
