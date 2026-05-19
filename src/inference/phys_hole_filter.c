// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Inference plugin: exclude phys text base from DRAM holes (POST_COLLECTION)
//
// On systems with a PCI hole (the classic x86 architecture: DRAM up to
// ~3 GiB, MMIO from 3-4 GiB, DRAM resumes above 4 GiB), the kernel
// image's physical base cannot sit in the hole — it must live in DRAM.
// The new model carries full DRAM extents (ram lo+hi, dma32 lo+hi,
// numa_node lo+hi, ...) which lets us compute hole boundaries
// geometrically and tighten phys_base_max when the current ceiling
// falls into a hole.
//
// Hole-aware tightening:
//
//   1. Collect all DRAM extents (records with HAS_LO && HAS_HI in a
//      DRAM-resident region).
//   2. Sort by lo, merge overlaps.
//   3. If phys_base_max falls in a gap between merged extents, drop it
//      to the inclusive hi of the highest DRAM extent strictly below
//      that gap.
//
// We do NOT tighten phys_base_min from below — the kernel image is
// almost always loaded in the bottom DRAM extent and lifting the floor
// requires arch-specific knowledge of which DRAM bank the kernel
// targeted (relocation, EFI handoff, etc.). The ceiling-only tightening
// is the safe and broadly-applicable case.
//
// Soundness:
// - Only fires on decoupled arches (phys KASLR is meaningful).
// - Requires at least one DRAM extent with both bounds known.
// - Tightens phys_base_max (only); never widens.
// - Merge step is N^2 in the number of DRAM extents (typically ≤ 8),
//   negligible cost.
// ---
// <bcoles@gmail.com>

#define _POSIX_C_SOURCE 200809L

#include "../include/kasld/inference.h"

#include <stdio.h>

#define MAX_DRAM_EXTENTS 32

struct extent {
  unsigned long lo, hi;
};

static int extent_cmp(const void *a, const void *b) {
  const struct extent *ea = a;
  const struct extent *eb = b;
  if (ea->lo < eb->lo) return -1;
  if (ea->lo > eb->lo) return 1;
  return 0;
}

/* Collect full-extent DRAM records into `out`; returns count. Records
 * without both bounds set are skipped — they can't define a hole boundary. */
static int collect_dram_extents(const struct kasld_analysis_ctx *ctx,
                                struct extent *out, int max) {
  int n = 0;
  for (size_t i = 0; i < ctx->result_count && n < max; i++) {
    const struct result *r = &ctx->results[i];
    if (r->type != KASLD_TYPE_PHYS)
      continue;
    if (!is_phys_dram_region(r->region))
      continue;
    if (!HAS_LO(r) || !HAS_HI(r))
      continue;
    if (!result_in_bounds(r, ctx->layout))
      continue;
    out[n].lo = r->lo;
    out[n].hi = r->hi;
    n++;
  }
  return n;
}

/* Merge sorted-by-lo extents in place; returns the new count. Adjacent
 * or overlapping extents collapse into one. After this call, the array
 * is strictly increasing in lo and has no overlaps. */
static int merge_extents(struct extent *e, int n) {
  if (n <= 1) return n;
  int w = 0;
  for (int r = 1; r < n; r++) {
    /* Touch or overlap: e[w].hi + 1 >= e[r].lo (use guarded arithmetic
     * to avoid overflow on hi == ULONG_MAX). */
    int touches = (e[w].hi == (unsigned long)-1)
                      ? 1
                      : (e[w].hi + 1 >= e[r].lo);
    if (touches) {
      if (e[r].hi > e[w].hi)
        e[w].hi = e[r].hi;
    } else {
      w++;
      e[w] = e[r];
    }
  }
  return w + 1;
}

static void phys_hole_filter_run(struct kasld_analysis_ctx *ctx) {
  if (!ctx->arch->phys_virt_decoupled)
    return;

  struct extent ext[MAX_DRAM_EXTENTS];
  int n = collect_dram_extents(ctx, ext, MAX_DRAM_EXTENTS);
  if (n == 0)
    return;

  /* Selection sort; small N (typically ≤ 8) makes this negligible.
   * extent_cmp compares by lo, which is what we need for merge_extents. */
  for (int i = 0; i < n - 1; i++) {
    int min = i;
    for (int j = i + 1; j < n; j++)
      if (extent_cmp(&ext[j], &ext[min]) < 0)
        min = j;
    if (min != i) {
      struct extent tmp = ext[i];
      ext[i] = ext[min];
      ext[min] = tmp;
    }
  }
  n = merge_extents(ext, n);

  /* Find the extent containing ctx->phys_base_max, if any. If
   * phys_base_max is INSIDE a DRAM extent, no tightening needed.
   * Otherwise drop it to the inclusive hi of the highest DRAM extent
   * strictly below it (no kernel image possible above that point
   * within the known DRAM topology). */
  for (int i = 0; i < n; i++) {
    if (ctx->phys_base_max >= ext[i].lo && ctx->phys_base_max <= ext[i].hi)
      return; /* in DRAM, no hole-tightening applies */
  }

  unsigned long new_max = 0;
  int found = 0;
  for (int i = 0; i < n; i++) {
    if (ext[i].hi < ctx->phys_base_max) {
      new_max = ext[i].hi;
      found = 1;
    }
  }
  if (!found)
    return; /* phys_base_max sits below all known DRAM — leave it alone */
  if (new_max >= ctx->phys_base_max)
    return;

  if (verbose && !quiet)
    fprintf(stdout,
            "[infer] phys_base_max tightened by phys_hole_filter:"
            " %#lx -> %#lx (current ceiling lay in DRAM hole)\n",
            ctx->phys_base_max, new_max);
  ctx->phys_base_max = new_max;
}

static const struct kasld_inference phys_hole_filter = {
    .name = "phys_hole_filter",
    .phase = KASLD_INFER_PHASE_POST_COLLECTION,
    .run = phys_hole_filter_run,
};

KASLD_REGISTER_INFERENCE(phys_hole_filter);
