// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Inference plugin: VA_BITS detection from directmap addresses
// (POST_COLLECTION) ARM64 only.
//
// On arm64, PAGE_OFFSET is -(1UL << VA_BITS):
//   VA_BITS=52: PAGE_OFFSET = 0xfff0000000000000
//   VA_BITS=48: PAGE_OFFSET = 0xffff000000000000
//
// The compile-time default assumes VA_BITS=52 (broadest safe assumption),
// so page_offset_min is initialised to 0xfff0000000000000. This plugin
// refines the page_offset window using the top bits of collected DIRECTMAP
// virtual addresses:
//
//   Any result in [0xfff0000000000000, 0xffff000000000000):
//     → VA_BITS=52 confirmed. PAGE_OFFSET is fixed at 0xfff0000000000000
//       (no randomisation on arm64). Pin page_offset_max to that value.
//
//   All results ≥ 0xffff000000000000 (none below):
//     → VA_BITS=48 confirmed. PAGE_OFFSET = 0xffff000000000000. Pin both
//       page_offset_min and page_offset_max — but only when 0xffff000000000000
//       lies within the current [page_offset_min, page_offset_max] window.
//       This guard prevents conflict with legacy layout detection in
//       layout_adjust.c, which raises page_offset_min to 0xffff800000000000
//       when old-layout kernel text is detected.
//
//   Mixed results (both ranges present): contradictory — no change.
//   No valid DIRECTMAP results: no-op.
//
// On VA_BITS=52, page_offset_max drops from KERNEL_VAS_END (0xffffffffffffffff)
// to 0xfff0000000000000, pinning PAGE_OFFSET exactly. This is stronger than
// directmap_page_offset_bounds, which only reaches V_min (≥ PAGE_OFFSET).
//
// Phase: POST_COLLECTION — requires collected DIRECTMAP results.
// ---
// <bcoles@gmail.com>

#define _POSIX_C_SOURCE 200809L

#include "../include/kasld_inference.h"

#include <stdio.h>
#include <string.h>

static void va_bits_from_results_run(struct kasld_analysis_ctx *ctx) {
#if defined(__aarch64__)
/* VA_BITS discriminator: addresses below this are in the VA_BITS=52 directmap
 * (PAGE_OFFSET = -(1UL<<52)); at or above are VA_BITS=48 or legacy. */
#define ARM64_VA48_PAGE_OFFSET 0xffff000000000000ul
#define ARM64_VA52_PAGE_OFFSET 0xfff0000000000000ul
  int have_va52 = 0; /* any valid result in [0xfff0..., 0xffff000000000000) */
  int have_va48 = 0; /* any valid result >= 0xffff000000000000 */

  for (size_t i = 0; i < ctx->result_count; i++) {
    const struct result *r = &ctx->results[i];
    if (r->type != KASLD_ADDR_VIRT || !r->valid ||
        strcmp(r->section, KASLD_SECTION_DIRECTMAP) != 0)
      continue;
    if (r->raw < ARM64_VA48_PAGE_OFFSET)
      have_va52 = 1;
    else
      have_va48 = 1;
  }

  if (!have_va52 && !have_va48)
    return; /* no DIRECTMAP results */

  if (have_va52 && have_va48) {
    /* Contradictory evidence — do not modify bounds. */
    if (verbose && !quiet)
      fprintf(stdout,
              "[infer] va_bits_from_results: contradictory DIRECTMAP addresses"
              " (VA_BITS=52 and VA_BITS=48 ranges both observed); skipping\n");
    return;
  }

  if (have_va52) {
    /* VA_BITS=52 confirmed. PAGE_OFFSET = 0xfff0000000000000 (no
     * randomisation). page_offset_min is already ARM64_VA52_PAGE_OFFSET
     * (compile-time default). Tighten page_offset_max to pin PAGE_OFFSET
     * exactly. */
    if (ARM64_VA52_PAGE_OFFSET >= ctx->page_offset_min &&
        ARM64_VA52_PAGE_OFFSET < ctx->page_offset_max) {
      if (verbose && !quiet)
        fprintf(stdout,
                "[infer] page_offset_max tightened by va_bits_from_results"
                " (VA_BITS=52): %#lx -> %#lx\n",
                ctx->page_offset_max, ARM64_VA52_PAGE_OFFSET);
      ctx->page_offset_max = ARM64_VA52_PAGE_OFFSET;
    }
    return;
  }

  /* have_va48: all DIRECTMAP results >= 0xffff000000000000. VA_BITS=48.
   * PAGE_OFFSET = 0xffff000000000000. Pin both bounds, but only if the
   * candidate value lies within the current window. If page_offset_min
   * was already raised above ARM64_VA48_PAGE_OFFSET (e.g. by layout_adjust
   * detecting the legacy arm64 layout where PAGE_OFFSET=0xffff800000000000),
   * the guard below prevents window inversion. */
  if (ARM64_VA48_PAGE_OFFSET < ctx->page_offset_min ||
      ARM64_VA48_PAGE_OFFSET > ctx->page_offset_max)
    return;

  if (ARM64_VA48_PAGE_OFFSET > ctx->page_offset_min) {
    if (verbose && !quiet)
      fprintf(stdout,
              "[infer] page_offset_min tightened by va_bits_from_results"
              " (VA_BITS=48): %#lx -> %#lx\n",
              ctx->page_offset_min, ARM64_VA48_PAGE_OFFSET);
    ctx->page_offset_min = ARM64_VA48_PAGE_OFFSET;
  }
  if (ARM64_VA48_PAGE_OFFSET < ctx->page_offset_max) {
    if (verbose && !quiet)
      fprintf(stdout,
              "[infer] page_offset_max tightened by va_bits_from_results"
              " (VA_BITS=48): %#lx -> %#lx\n",
              ctx->page_offset_max, ARM64_VA48_PAGE_OFFSET);
    ctx->page_offset_max = ARM64_VA48_PAGE_OFFSET;
  }
#else
  (void)ctx;
#endif /* __aarch64__ */
}

static const struct kasld_inference va_bits_from_results = {
    .name = "va_bits_from_results",
    .phase = KASLD_INFER_PHASE_POST_COLLECTION,
    .run = va_bits_from_results_run,
};

KASLD_REGISTER_INFERENCE(va_bits_from_results);
