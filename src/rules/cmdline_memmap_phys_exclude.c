// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: cmdline `memmap=` reservations as physical base exclusions.
//
// Each `memmap=size$start` / `size!start` / `size#start` reservation (emitted
// by cmdline_memmap as a PHYS REGION_CMDLINE_MEMMAP extent) marks an interval
// that the x86 KASLR placer refuses to overlap. The kernel image is therefore
// forbidden in
//
//   [start - image_size + 1, start + size - 1]
//
// the same inclusive integer hole shape as initrd_phys_exclude /
// cmdline_phys_exclude. Emitted as C_EXCLUDE on Q_PHYS_IMAGE_BASE — interior
// holes do not move the headline lo/hi; they show up in the hole-aware slot
// count.
//
// Unlike the single-interval exclusion rules (initrd / cmdline buffer), this
// rule iterates EVERY observed reservation: a cmdline may carry up to four
// `memmap=` entries with offset, and each is an independent forbidden zone.
// The output array is bounded by ENGINE_RULE_MAX_EMIT; we cap silently if a
// pathological cmdline produces more than the engine accepts.
//
// Reads PHYS REGION_CMDLINE_MEMMAP observations + SF_IMAGE_SIZE_MIN; emits
// nothing when either is absent. Decoupled arches only (x86_64).
//
// References:
// https://elixir.bootlin.com/linux/v6.12/source/arch/x86/boot/compressed/kaslr.c#L118
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"

#include <string.h>

int rule_cmdline_memmap_phys_exclude(const struct evidence_set *ev,
                                     const struct estimate *est,
                                     struct constraint *out, int out_max) {
  (void)est;
#if TEXT_TRACKS_DIRECTMAP
  (void)ev;
  (void)out;
  (void)out_max;
  return 0;
#else
  enum kasld_confidence kconf = CONF_UNKNOWN;
  uint32_t ksrc = 0;
  unsigned long ksize = evidence_image_size_min(ev, &kconf, &ksrc);
  if (ksize == 0)
    return 0;

  int n = 0;
  for (int i = 0; i < ev->n_obs && n < out_max; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->value_kind != OBS_ADDRESS ||
        o->eff_type != KASLD_TYPE_PHYS ||
        o->eff_region != REGION_CMDLINE_MEMMAP || !HAS_LO(o) || !HAS_HI(o) ||
        o->hi < o->lo)
      continue;

    unsigned long hole_lo = (o->lo > ksize) ? (o->lo - ksize + 1) : 0;
    unsigned long hole_hi = o->hi;
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
    snprintf(c->origin, ORIGIN_LEN, "cmdline_memmap_phys_exclude");
  }
  return n;
#endif
}
