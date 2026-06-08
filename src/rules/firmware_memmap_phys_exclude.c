// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: physical-base exclusions for the gaps in the authoritative System RAM
// map.
//
// /sys/firmware/memmap (origin "firmware_memmap") is the complete authoritative
// firmware RAM topology. The compressed-boot KASLR places the kernel image only
// in E820_TYPE_RAM and fits it wholly within ONE region (verified in
// arch/x86/boot/compressed/kaslr.c: `if (entry->type != E820_TYPE_RAM)
// continue;` and `if (region.size < image_size) ...`). So the physical base can
// neither sit in, nor place its image across, any non-RAM gap between RAM
// extents:
//
//   for each gap (prev_hi, next_lo):
//     base forbidden in [prev_hi + 1 - kernel_size + 1, next_lo - 1]
//
// One C_EXCLUDE per gap; the interior holes compose with the reservation
// excludes into a hole-aware slot count.
//
// Complements firmware_memmap_holes (a VERDICT that drops leaked candidates
// landing in a hole): this rule carves the quantity's range directly, so it
// tightens the slot count even when NO candidate was leaked into a hole — and,
// unlike the reservation rule, it catches firmware non-RAM holes (MMIO / ACPI /
// firmware-reserved) that were never individually leaked as observations.
//
// Soundness:
//   * Requires the COMPLETE authoritative map (origin "firmware_memmap", never
//   a
//     partial RAM leak): a "gap" between two PARTIAL leaks could be unobserved
//     RAM, and excluding it would drop the truth. If more RAM extents are
//     present than the local buffer holds, BAIL — a dropped middle extent would
//     synthesise a false gap.
//   * kernel_size is SF_IMAGE_SIZE, a deliberate UNDER-estimate, so the
//     low-edge widening can only under-exclude, never drop a valid base.
//   * Overlapping / adjacent extents are merged (running max), so only true
//     non-RAM gaps are carved. RAM extents are inclusive [lo, hi]
//     (matching firmware_memmap_holes' `last <= m->hi` fit test).
//
// Decoupled arches only (Q_PHYS_TEXT_BASE); inert without the map or a size
// fact. In practice x86 only (that is where /sys/firmware/memmap exists).
// ---
// <bcoles@gmail.com>

#include "../include/kasld/engine_rules.h"
#include "../include/kasld/regions.h"

#include <string.h>

#define FMPE_MAX_EXTENTS 64

struct fmpe_extent {
  unsigned long lo, hi;
  uint32_t id;
};

int rule_firmware_memmap_phys_exclude(const struct evidence_set *ev,
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

  /* Collect the authoritative RAM extents. */
  struct fmpe_extent ext[FMPE_MAX_EXTENTS];
  int ne = 0;
  enum kasld_confidence mconf = CONF_PARSED;
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->value_kind != OBS_ADDRESS || !HAS_LO(o) || !HAS_HI(o) ||
        o->hi < o->lo || strcmp(o->origin, "firmware_memmap") != 0)
      continue;
    if (ne >= FMPE_MAX_EXTENTS)
      return 0; /* map larger than the buffer — bail rather than fake a gap. */
    ext[ne].lo = o->lo;
    ext[ne].hi = o->hi;
    ext[ne].id = o->id;
    if (o->conf < mconf)
      mconf = o->conf;
    ne++;
  }
  if (ne < 2)
    return 0; /* need at least two extents for a gap between them. */

  /* Insertion-sort by low edge. */
  for (int i = 1; i < ne; i++) {
    struct fmpe_extent key = ext[i];
    int j = i - 1;
    while (j >= 0 && ext[j].lo > key.lo) {
      ext[j + 1] = ext[j];
      j--;
    }
    ext[j + 1] = key;
  }

  /* Sweep: carry the running max hi; a true gap is next.lo > cur_hi + 1. */
  int n = 0;
  unsigned long cur_hi = ext[0].hi;
  uint32_t cur_hi_id = ext[0].id;
  enum kasld_confidence econf = (kconf < mconf) ? kconf : mconf;
  for (int i = 1; i < ne && n < out_max; i++) {
    if (ext[i].lo > cur_hi + 1) {
      /* non-RAM gap [cur_hi + 1, ext[i].lo - 1] (both inclusive). */
      unsigned long gap_lo = cur_hi + 1;
      unsigned long gap_hi = ext[i].lo - 1;
      unsigned long hole_lo = (gap_lo > ksize) ? (gap_lo - ksize + 1) : 0;
      if (gap_hi >= hole_lo) {
        struct constraint *c = &out[n++];
        memset(c, 0, sizeof(*c));
        c->q = Q_PHYS_TEXT_BASE;
        c->op = C_EXCLUDE;
        c->value = hole_lo;
        c->value2 = gap_hi;
        c->conf = econf;
        c->derived_from[0] = cur_hi_id;
        c->derived_from[1] = ksrc;
        c->lineage_count = 2;
        snprintf(c->origin, ORIGIN_LEN, "firmware_memmap_phys_exclude");
      }
    }
    if (ext[i].hi > cur_hi) {
      cur_hi = ext[i].hi;
      cur_hi_id = ext[i].id;
    }
  }
  return n;
#endif
}
