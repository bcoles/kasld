// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Inference plugin: cross-origin min-DIRECTMAP / min-PHYS → page_offset_base
// (POST_COLLECTION)
//
// On x86-64 with CONFIG_RANDOMIZE_MEMORY, page_offset_base (the start of the
// directmap region) is independently randomised at 1 GiB (PUD_SIZE)
// granularity. For any directmap virtual address D mapping physical address P:
//   page_offset_base = D - P  (PHYS_OFFSET = 0 on x86-64)
//
// phys_virt_synth.c handles the same-origin case: a single component that
// emits both a DIRECTMAP virtual and a PHYS/DRAM physical for the same physical
// page. On decoupled architectures such as x86-64, components rarely emit both
// sides, so phys_virt_synth.c is a no-op. This plugin handles the cross-origin
// case: the global minimum DIRECTMAP virtual D_min and global minimum PHYS/DRAM
// physical P_min can come from different components.
//
// On a typical x86-64 system with DRAM starting at a 1 GiB-aligned boundary:
//   P_min ≈ DRAM base (from e.g. /proc/zoneinfo, /sys/devices/system/memory)
//   D_min ≈ page_offset_base + DRAM base
//   ⟹ D_min - P_min = page_offset_base
//
// Validity guards applied before tightening both bounds:
//   1. Candidate must be 1 GiB-aligned (PUD granularity of randomisation).
//   2. Candidate must fall within the current [page_offset_min,
//   page_offset_max]
//      window established by prior inference steps.
//
// A non-1 GiB-aligned result means D_min and P_min do not correspond to the
// same physical region; both guards together make false positives extremely
// unlikely.
//
// Phase: POST_COLLECTION — requires DIRECTMAP virtual and PHYS/DRAM results
//        from earlier components.
// Applicable: x86-64 only (page_offset_base is independently randomised;
//             on coupled-arch systems phys_virt_synth.c synthesises
//             PAGE_OFFSET).
// ---
// <bcoles@gmail.com>

#define _POSIX_C_SOURCE 200809L

#include "../include/kasld_inference.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>

static void randomize_memory_page_offset_run(struct kasld_analysis_ctx *ctx) {
#if defined(__x86_64__)

  /* Find the minimum valid DIRECTMAP virtual address across all results. */
  unsigned long vdmap_min = ULONG_MAX;

  for (size_t i = 0; i < ctx->result_count; i++) {
    const struct result *r = &ctx->results[i];
    if (!r->valid)
      continue;
    if (r->type != KASLD_ADDR_VIRT)
      continue;
    if (strcmp(r->section, KASLD_SECTION_DIRECTMAP) != 0)
      continue;
    if (r->raw < vdmap_min)
      vdmap_min = r->raw;
  }

  if (vdmap_min == ULONG_MAX)
    return;

  /* Find the minimum valid PHYS/DRAM physical address across all results. */
  unsigned long pdram_min = ULONG_MAX;

  for (size_t i = 0; i < ctx->result_count; i++) {
    const struct result *r = &ctx->results[i];
    if (!r->valid)
      continue;
    if (r->type != KASLD_ADDR_PHYS)
      continue;
    if (strcmp(r->section, KASLD_SECTION_DRAM) != 0)
      continue;
    if (r->raw < pdram_min)
      pdram_min = r->raw;
  }

  if (pdram_min == ULONG_MAX)
    return;

  /* Guard against unsigned underflow. */
  if (vdmap_min <= pdram_min)
    return;

  /* page_offset_base = D_min - P_min (PHYS_OFFSET = 0 on x86-64). */
  unsigned long candidate = vdmap_min - pdram_min;

  /* page_offset_base is randomised at 1 GiB (PUD_SIZE) granularity.
   * A non-aligned candidate indicates the two minimums do not map the same
   * physical region; reject to avoid a false pin. */
  const unsigned long pud_size = 1ul << 30;

  if (candidate & (pud_size - 1))
    return;

  /* Candidate must lie within the established page_offset window. */
  if (candidate < ctx->page_offset_min || candidate > ctx->page_offset_max)
    return;

  if (verbose && !quiet)
    fprintf(stdout,
            "[infer] page_offset_base pinned by"
            " randomize_memory_page_offset:"
            " [%#lx, %#lx] -> %#lx"
            " (D_min=%#lx P_min=%#lx)\n",
            ctx->page_offset_min, ctx->page_offset_max, candidate, vdmap_min,
            pdram_min);

  ctx->page_offset_min = candidate;
  ctx->page_offset_max = candidate;

#else
  (void)ctx;
#endif /* defined(__x86_64__) */
}

static const struct kasld_inference randomize_memory_page_offset = {
    .name = "randomize_memory_page_offset",
    .phase = KASLD_INFER_PHASE_POST_COLLECTION,
    .run = randomize_memory_page_offset_run,
};

KASLD_REGISTER_INFERENCE(randomize_memory_page_offset);
