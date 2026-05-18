// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Inference plugin: arm64 ARM64_MEMSTART_ALIGN → page_offset_max snap
// (POST_COLLECTION)
//
// On arm64, `memstart_addr` (the physical anchor of the linear map) is aligned
// to ARM64_MEMSTART_ALIGN:
//
//   4K/16K pages: ARM64_MEMSTART_ALIGN = 1 GiB  (PUD_SHIFT/CONT_PMD_SHIFT=30)
//   64K pages:    ARM64_MEMSTART_ALIGN = 512 MiB (PMD_SHIFT=29)
//
// The linear map formula is V = PAGE_OFFSET + (phys − memstart_addr) for all
// DRAM physical addresses phys ≥ memstart_addr. Therefore any DIRECTMAP virtual
// address V satisfies V ≥ PAGE_OFFSET.
//
// PAGE_OFFSET = _PAGE_OFFSET(vabits_actual) is always a multiple of
// ARM64_MEMSTART_ALIGN (it is a large power-of-two virtual address whose
// magnitude far exceeds ARM64_MEMSTART_ALIGN). For any DIRECTMAP result V:
//
//   PAGE_OFFSET ≤ round_down(V, ARM64_MEMSTART_ALIGN) ≤ V
//
// Proof: PAGE_OFFSET is align-aligned, so PAGE_OFFSET = round_down(PAGE_OFFSET,
// align). Since PAGE_OFFSET ≤ V, monotonicity of round_down gives
// round_down(PAGE_OFFSET, align) ≤ round_down(V, align), i.e. PAGE_OFFSET ≤
// round_down(V, align). The upper inequality is trivially true.
//
// The minimum DIRECTMAP result V_min therefore provides a tight upper bound:
//
//   page_offset_max = min(page_offset_max, round_down(V_min,
//   ARM64_MEMSTART_ALIGN))
//
// This is strictly tighter than the V_min bound already set by
// directmap_page_offset_bounds.c whenever the physical address corresponding
// to V_min is not at memstart_addr itself (i.e., whenever V_min > PAGE_OFFSET).
// The improvement is up to ARM64_MEMSTART_ALIGN − 1 (up to ~1 GiB for 4K/16K
// pages, ~512 MiB for 64K pages).
//
// Phase: POST_COLLECTION — requires VIRT/DIRECTMAP results.
// Applicable: arm64 only.
//
// References:
//   arch/arm64/include/asm/memory.h: ARM64_MEMSTART_ALIGN, _PAGE_OFFSET()
//   arch/arm64/mm/init.c: memstart_addr = round_down(PHYS_OFFSET, align)
// ---
// <bcoles@gmail.com>

#define _POSIX_C_SOURCE 200809L

#include "../include/kasld/inference.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void arm64_memstart_align_run(struct kasld_analysis_ctx *ctx) {
#if defined(__aarch64__)

  int pagesize = getpagesize();
  unsigned long align;

  /* Derive ARM64_MEMSTART_ALIGN from page size.
   * 64K pages: PMD_SHIFT=29 → MEMSTART_ALIGN = 1<<29 = 512 MiB.
   * 4K/16K:    PUD_SHIFT/CONT_PMD_SHIFT=30 → 1 GiB. */
  if (pagesize == 65536)
    align = 512ul * 1024 * 1024; /* 512 MiB */
  else if (pagesize == 4096 || pagesize == 16384)
    align = 1024ul * 1024 * 1024; /* 1 GiB */
  else
    return; /* unexpected page size */

  /* Find minimum valid VIRT/DIRECTMAP result. */
  unsigned long v_min = ULONG_MAX;

  for (size_t i = 0; i < ctx->result_count; i++) {
    const struct result *r = &ctx->results[i];
    if (r->type != KASLD_TYPE_VIRT || !result_in_bounds(r, ctx->layout))
      continue;
    if (r->region != REGION_DIRECTMAP)
      continue;
    if (anchor_addr(r) < v_min)
      v_min = anchor_addr(r);
  }

  if (v_min == ULONG_MAX)
    return; /* no valid DIRECTMAP results */

  /* Snap page_offset_max down to the nearest ARM64_MEMSTART_ALIGN boundary.
   * Sound: PAGE_OFFSET is align-aligned and PAGE_OFFSET ≤ v_min, therefore
   * PAGE_OFFSET ≤ round_down(v_min, align) ≤ v_min ≤ page_offset_max. */
  unsigned long new_max = v_min & ~(align - 1);

  if (new_max > ctx->page_offset_min && new_max < ctx->page_offset_max) {
    if (verbose && !quiet)
      fprintf(stdout,
              "[infer] page_offset_max tightened by arm64_memstart_align"
              " (align snap): %#lx -> %#lx"
              " (v_min_directmap=%#lx ARM64_MEMSTART_ALIGN=%#lx)\n",
              ctx->page_offset_max, new_max, v_min, align);
    ctx->page_offset_max = new_max;
  }

#else
  (void)ctx;
#endif /* __aarch64__ */
}

static const struct kasld_inference arm64_memstart_align = {
    .name = "arm64_memstart_align",
    .phase = KASLD_INFER_PHASE_POST_COLLECTION,
    .run = arm64_memstart_align_run,
};

KASLD_REGISTER_INFERENCE(arm64_memstart_align);
