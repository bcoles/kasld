// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: drop the physical text ceiling out of a DRAM hole.
//
// The kernel image loads in DRAM, so
// if the current physical ceiling lands in a gap between known RAM extents, it
// can be dropped to the top of the highest RAM extent strictly below it.
//
//   if phys_image_base hi lies in no RAM-coverage extent:
//     phys_image_base <= hi of the highest RAM-coverage extent below it
//
// Uses is_phys_ram_coverage_region() (System RAM / DMA / DMA32 / NUMA node),
// NOT is_phys_dram_region(): the hole test is only sound over extents that
// COVER RAM (whose absence means non-RAM). Interior reservations (initrd,
// crashkernel, reserved-mem, ...) sit within RAM without defining its
// boundaries — folding them in would treat the real RAM between two
// reservations as a hole and cap the ceiling below a true base there. When only
// reservations are present (a hardened host with a restricted /proc/iomem but a
// leaked dmesg crashkernel line), no coverage extent is collected and the rule
// stays inert.
//
// CROSS-QUANTITY: reads the resolved Q_PHYS_IMAGE_BASE upper edge and the
// leaked RAM-coverage extent observations (those with both lo and hi). Emits a
// C_UPPER_BOUND. Inert on coupled arches and when no coverage extent is
// present.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"
#include "include/kasld/regions.h"

#include <limits.h>
#include <string.h>

#define MAX_DRAM_EXTENTS 32

int rule_phys_hole_filter(const struct evidence_set *ev,
                          const struct estimate *est, struct constraint *out,
                          int out_max) {
#if !TEXT_TRACKS_DIRECTMAP
  if (out_max < 1)
    return 0;

  unsigned long lo[MAX_DRAM_EXTENTS], hi[MAX_DRAM_EXTENTS];
  int n = 0;
  for (int i = 0; i < ev->n_obs && n < MAX_DRAM_EXTENTS; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->value_kind != OBS_ADDRESS)
      continue;
    if (o->eff_type != KASLD_TYPE_PHYS ||
        !is_phys_ram_coverage_region(o->eff_region))
      continue;
    if (!HAS_LO(o) || !HAS_HI(o) || o->lo > o->hi)
      continue;
    lo[n] = o->lo;
    hi[n] = o->hi;
    n++;
  }
  if (n == 0)
    return 0;

  /* Insertion sort by lo, then merge overlapping/adjacent extents. */
  for (int i = 1; i < n; i++) {
    unsigned long kl = lo[i], kh = hi[i];
    int j = i - 1;
    while (j >= 0 && lo[j] > kl) {
      lo[j + 1] = lo[j];
      hi[j + 1] = hi[j];
      j--;
    }
    lo[j + 1] = kl;
    hi[j + 1] = kh;
  }
  int m = 0;
  for (int i = 0; i < n; i++) {
    /* Coalesce overlapping/adjacent extents. When the running extent already
     * spans to ULONG_MAX it contains everything above lo[i], so absorb it —
     * checking explicitly avoids the hi[m-1] + 1 wrap to 0 (crafted/corrupt
     * map), which would otherwise split it into a spurious separate extent. */
    if (m > 0 && (hi[m - 1] == ULONG_MAX || lo[i] <= hi[m - 1] + 1)) {
      if (hi[i] > hi[m - 1])
        hi[m - 1] = hi[i];
    } else {
      lo[m] = lo[i];
      hi[m] = hi[i];
      m++;
    }
  }

  unsigned long ceiling = est[Q_PHYS_IMAGE_BASE].hi;
  enum kasld_confidence ceiling_conf = est[Q_PHYS_IMAGE_BASE].hi_conf;

  /* If the ceiling already sits inside a DRAM extent, nothing to do. */
  for (int i = 0; i < m; i++)
    if (ceiling >= lo[i] && ceiling <= hi[i])
      return 0;

  /* Highest DRAM extent strictly below the ceiling. */
  unsigned long new_max = 0;
  int found = 0;
  for (int i = 0; i < m; i++)
    if (hi[i] < ceiling) {
      new_max = hi[i];
      found = 1;
    }
  if (!found || new_max <= KASLR_PHYS_MIN)
    return 0;

  struct constraint *c = &out[0];
  memset(c, 0, sizeof(*c));
  c->q = Q_PHYS_IMAGE_BASE;
  c->op = C_UPPER_BOUND;
  c->value = new_max;
  /* The snapped ceiling is only as trustworthy as the phys_image_base edge that
   * selected the DRAM extent (confidence propagation). */
  c->conf = kasld_conf_min(CONF_INFERRED, kasld_edge_conf(ceiling_conf));
  c->lineage_count = 0; /* derived from the merged DRAM topology */
  snprintf(c->origin, ORIGIN_LEN, "phys_hole_filter");
  return 1;
#else
  (void)ev;
  (void)est;
  (void)out;
  (void)out_max;
  return 0;
#endif
}
