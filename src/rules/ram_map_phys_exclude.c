// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: physical-base exclusions for the non-RAM gaps in an authoritative
// System RAM map.
//
// A component that reads the COMPLETE physical RAM map — not a partial leak —
// yields the full set of RAM extents; the gaps between them are places the
// kernel image cannot be, because the boot placement code loads the image only
// into RAM and fits it wholly within one region. Three such whole-map sources:
//   - x86 /sys/firmware/memmap (origin "firmware_memmap"): the E820 map.
//     arch/x86/boot/compressed/kaslr.c skips entries != E820_TYPE_RAM and bails
//     a region when `region.size < image_size`.
//   - device-tree /memory nodes (origin "sysfs_devicetree_memory"): each `reg`
//     (addr,size) is passed to memblock_add() (drivers/of/fdt.c
//     early_init_dt_scan_memory), i.e. the RAM the arm64 / riscv kernel places
//     into — gaps between nodes are non-RAM. Arch-general: the DT arches have
//     no /sys/firmware/memmap.
//   - hotplug memory blocks (origin "sysfs_memory_blocks"): merged runs of
//     online /sys/devices/system/memory blocks. Online = present RAM, and the
//     image is unmovable / never offlined, so the gaps are absent or runtime-
//     offlined blocks. Arch-general, block-coarse, and the only map that sees
//     runtime offlining (a block the boot E820 / static DT still call RAM).
//
// For each gap (prev_hi, next_lo) within ONE such map:
//   base forbidden in [prev_hi + 1 - kernel_size + 1, next_lo - 1]
//
// One C_EXCLUDE per gap, composing with the reservation excludes into a
// hole-aware slot count. Complements firmware_memmap_holes (a verdict that
// drops candidates landing in a hole): this carves the range even when no
// candidate was leaked into a hole.
//
// Soundness:
//   * Each map is processed SEPARATELY — never mix two maps' extents. They can
//     disagree (a runtime-offlined block is RAM in the boot E820 but a hole in
//     a hotplug view); unioning would lose one map's holes or, worse,
//     synthesise a false gap. Each map is independently complete for its own
//     substrate.
//   * Requires the COMPLETE map (the listed origins are whole-map readers,
//   never
//     partial leaks). If a map holds more extents than the buffer, BAIL — a
//     dropped middle extent would synthesise a false gap.
//   * kernel_size is SF_IMAGE_SIZE, a deliberate UNDER-estimate, so the
//   low-edge
//     widening can only under-exclude, never drop a valid base.
//   * Overlapping / adjacent extents are merged (running max); RAM extents are
//     inclusive [lo, hi].
//
// Decoupled arches only (Q_PHYS_TEXT_BASE); inert without a map or a size fact.
// ---
// <bcoles@gmail.com>

#include "../include/kasld/engine_rules.h"

#include <string.h>

#define RMPE_MAX_EXTENTS 64

struct rmpe_extent {
  unsigned long lo, hi;
  uint32_t id;
};

/* Authoritative COMPLETE RAM maps — whole-map readers, so the gaps between
 * their extents are genuinely non-RAM. (A partial leak — a single /proc/iomem
 * region, say — is deliberately NOT listed: a "gap" between two partial extents
 * could be unobserved RAM, and excluding it would drop the truth.) */
static const char *const rmpe_origins[] = {
    "firmware_memmap",         /* x86 /sys/firmware/memmap (E820)        */
    "sysfs_devicetree_memory", /* arm64/riscv DT /memory -> memblock RAM */
    "sysfs_memory_blocks",     /* /sys hotplug blocks: online = present  */
};

/* Carve the non-RAM gaps of ONE map (the extents tagged `origin`) into out[].
 * Returns the count of C_EXCLUDE constraints emitted. */
static int carve_map_gaps(const struct evidence_set *ev, const char *origin,
                          unsigned long ksize, uint32_t ksrc,
                          enum kasld_confidence kconf, struct constraint *out,
                          int out_max) {
  struct rmpe_extent ext[RMPE_MAX_EXTENTS];
  int ne = 0;
  enum kasld_confidence mconf = CONF_PARSED;
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->value_kind != OBS_ADDRESS ||
        o->eff_type != KASLD_TYPE_PHYS || !HAS_LO(o) || !HAS_HI(o) ||
        o->hi < o->lo || strcmp(o->origin, origin) != 0)
      continue;
    if (ne >= RMPE_MAX_EXTENTS)
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
    struct rmpe_extent key = ext[i];
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
        snprintf(c->origin, ORIGIN_LEN, "ram_map_phys_exclude");
      }
    }
    if (ext[i].hi > cur_hi) {
      cur_hi = ext[i].hi;
      cur_hi_id = ext[i].id;
    }
  }
  return n;
}

int rule_ram_map_phys_exclude(const struct evidence_set *ev,
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
  for (size_t m = 0; m < sizeof(rmpe_origins) / sizeof(rmpe_origins[0]); m++) {
    if (n >= out_max)
      break;
    n += carve_map_gaps(ev, rmpe_origins[m], ksize, ksrc, kconf, out + n,
                        out_max - n);
  }
  return n;
#endif
}
