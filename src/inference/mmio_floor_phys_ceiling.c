// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Inference plugin: phys kernel text base ≤ lowest MMIO floor
// (POST_COLLECTION)
//
// MMIO and DRAM occupy disjoint physical address ranges by hardware
// design. The kernel image must be loaded into DRAM, so its physical
// base address cannot sit in (or above) any MMIO mapping. The lowest
// MMIO `lo` that lies above the highest known DRAM `lo` is therefore
// a strict upper bound on the phys kernel text base.
//
// Why "above DRAM" matters: low MMIO (legacy VGA at 0xa0000, PIC at
// 0x000c0000) is BELOW DRAM and doesn't constrain the phys text base
// from above. We need MMIO entries that sit above DRAM — the lowest of
// THOSE forms the ceiling.
//
// Soundness:
// - Only tightens phys_base_max (decoupled arches only).
// - Only fires when at least one DRAM record gives a lower bound and at
//   least one MMIO record sits above that lower bound.
// - Uses HAS_LO on MMIO records (not anchor_addr) because we want the
//   actual MMIO base; a sample inside an MMIO range wouldn't give the
//   floor.
// - On coupled arches the phys text base isn't independently
//   randomised (it's tied to PAGE_OFFSET via phys_to_virt), so the
//   plugin is a no-op there.
// ---
// <bcoles@gmail.com>

#define _POSIX_C_SOURCE 200809L

#include "../include/kasld/inference.h"

#include <limits.h>
#include <stdio.h>

static int is_mmio_region(enum kasld_region region) {
  return region == REGION_MMIO || region == REGION_PCI_MMIO;
}

static void mmio_floor_phys_ceiling_run(struct kasld_analysis_ctx *ctx) {
  if (!ctx->arch->phys_virt_decoupled)
    return;

  /* Find the highest DRAM lo we know about. Anything above this is
   * candidate MMIO-above-DRAM territory. We use lo (not hi) because a
   * DRAM range's lo is the lowest address that's definitely DRAM, and
   * the MMIO floor must sit at least that high to be "above DRAM". */
  unsigned long dram_floor = 0;
  int have_dram = 0;
  for (size_t i = 0; i < ctx->result_count; i++) {
    const struct result *r = &ctx->results[i];
    if (r->type != KASLD_TYPE_PHYS)
      continue;
    if (!is_phys_dram_region(r->region))
      continue;
    if (!HAS_LO(r))
      continue;
    if (!result_in_bounds(r, ctx->layout))
      continue;
    if (!have_dram || r->lo > dram_floor) {
      dram_floor = r->lo;
      have_dram = 1;
    }
  }
  if (!have_dram)
    return;

  /* Lowest MMIO lo strictly above dram_floor. */
  unsigned long mmio_floor = ULONG_MAX;
  int have_mmio = 0;
  for (size_t i = 0; i < ctx->result_count; i++) {
    const struct result *r = &ctx->results[i];
    if (r->type != KASLD_TYPE_PHYS)
      continue;
    if (!is_mmio_region(r->region))
      continue;
    if (!HAS_LO(r))
      continue;
    if (!result_in_bounds(r, ctx->layout))
      continue;
    if (r->lo <= dram_floor)
      continue;
    if (!have_mmio || r->lo < mmio_floor) {
      mmio_floor = r->lo;
      have_mmio = 1;
    }
  }
  if (!have_mmio)
    return;

  /* The phys text base cannot equal or exceed the MMIO floor — text
   * must fit entirely in DRAM. Use mmio_floor - 1 as the inclusive
   * upper bound. Underflow is impossible: the filter `r->lo > dram_floor`
   * guarantees mmio_floor >= dram_floor + 1 >= 1 (even when dram_floor
   * is 0, i.e. DRAM starting at physical address 0). */
  unsigned long ceiling = mmio_floor - 1;
  if (ceiling >= ctx->phys_base_max)
    return;

  if (verbose && !quiet)
    fprintf(stdout,
            "[infer] phys_base_max tightened by mmio_floor_phys_ceiling:"
            " %#lx -> %#lx (lowest MMIO above DRAM at %#lx)\n",
            ctx->phys_base_max, ceiling, mmio_floor);
  ctx->phys_base_max = ceiling;
}

static const struct kasld_inference mmio_floor_phys_ceiling = {
    .name = "mmio_floor_phys_ceiling",
    .phase = KASLD_INFER_PHASE_POST_COLLECTION,
    .run = mmio_floor_phys_ceiling_run,
};

KASLD_REGISTER_INFERENCE(mmio_floor_phys_ceiling);
