// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Inference plugin: DRAM floor propagation (POST_COLLECTION)
//
// Raises kernel placement lower bounds from the minimum observed PHYS/DRAM
// address. Handles both coupling models:
//
// Coupled arches (PHYS_VIRT_DECOUPLED == 0, e.g. x86-32, MIPS, PPC32 BookE,
// LoongArch): physical and virtual KASLR are linked via phys_to_virt(). The
// minimum PHYS/DRAM address maps directly to a virtual text lower bound:
//
//   virt_lo = (pdram_lo - PHYS_OFFSET + PAGE_OFFSET + TEXT_OFFSET)
//                 aligned DOWN to kaslr_align
//   text_base_min = max(text_base_min, virt_lo)
//
// Align DOWN: the formula may place virt_lo above a slot boundary; rounding
// down gives the largest valid slot that is still a guaranteed lower bound.
//
// Decoupled arches (PHYS_VIRT_DECOUPLED == 1, e.g. x86-64, arm64, riscv64,
// s390): physical and virtual KASLR are independent. The minimum PHYS/DRAM
// address is a direct lower bound on phys_base:
//
//   phys_floor = align_up(pdram_lo, phys_kaslr_align)
//   phys_base_min = max(phys_base_min, phys_floor)
//
// Align UP: phys_base must be a slot-aligned address >= pdram_lo; rounding up
// gives the tightest sound floor. The largest benefit is on arm64, where
// KERNEL_PHYS_MIN = 0 while DRAM commonly starts at 1 GiB (QEMU virt) or
// 8 GiB (RK3588, Ampere Altra).
//
// Neither path touches the max bound — the minimum observed DRAM address only
// constrains the floor; the incomplete sample cannot safely rule out any
// upper slots.
// ---
// <bcoles@gmail.com>

#define _POSIX_C_SOURCE 200809L

#include "../include/kasld_inference.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>

static void dram_bound_run(struct kasld_analysis_ctx *ctx) {
  /* Find the minimum physical DRAM address across all results. */
  unsigned long pdram_lo = ULONG_MAX;
  for (size_t i = 0; i < ctx->result_count; i++) {
    const struct result *r = &ctx->results[i];
    if (r->type != KASLD_ADDR_PHYS)
      continue;
    if (strcmp(r->section, KASLD_SECTION_DRAM) != 0)
      continue;
    if (r->raw < pdram_lo)
      pdram_lo = r->raw;
  }

  if (pdram_lo == ULONG_MAX)
    return;

  if (ctx->arch->phys_virt_decoupled) {
    /* Decoupled arches: physical and virtual KASLR are independent. Raise
     * phys_base_min directly. Align UP — phys_base must be a slot-aligned
     * address >= pdram_lo; rounding up gives the tightest sound floor. */
    unsigned long phys_align = ctx->arch->phys_kaslr_align;
    unsigned long phys_arch_min = ctx->arch->phys_kaslr_base_min;

    if (phys_align > 0)
      pdram_lo = (pdram_lo + phys_align - 1) & ~(phys_align - 1);

    if (pdram_lo > phys_arch_min && pdram_lo > ctx->phys_base_min &&
        pdram_lo < ctx->phys_base_max) {
      if (verbose && !quiet)
        fprintf(stdout,
                "[infer] phys_base_min tightened by dram_bound:"
                " %#lx -> %#lx (min PHYS/DRAM=%#lx)\n",
                ctx->phys_base_min, pdram_lo, pdram_lo);
      ctx->phys_base_min = pdram_lo;
    }
  } else {
    /* Coupled arches: phys_to_virt() links physical DRAM to virtual text.
     * Derive a virtual text lower bound and align DOWN to stay conservative. */
    unsigned long phys_offset = ctx->arch->phys_offset;
    unsigned long page_offset = ctx->arch->page_offset;
    unsigned long text_offset = ctx->arch->text_offset;
    unsigned long kaslr_align = ctx->arch->kaslr_align;
    unsigned long kaslr_min = ctx->arch->kaslr_base_min;

    if (pdram_lo < phys_offset)
      return;

    /* Align down to the nearest slot boundary to stay conservative. */
    unsigned long virt_lo =
        (pdram_lo - phys_offset + page_offset + text_offset) &
        ~(kaslr_align - 1);

    if (virt_lo > kaslr_min && virt_lo > ctx->text_base_min &&
        virt_lo < ctx->text_base_max) {
      if (verbose && !quiet)
        fprintf(stdout,
                "[infer] text_base_min tightened by dram_bound:"
                " %#lx -> %#lx (min PHYS/DRAM=%#lx)\n",
                ctx->text_base_min, virt_lo, pdram_lo);
      ctx->text_base_min = virt_lo;
    }
  }
}

static const struct kasld_inference dram_bound = {
    .name = "dram_bound",
    .phase = KASLD_INFER_PHASE_POST_COLLECTION,
    .run = dram_bound_run,
};

KASLD_REGISTER_INFERENCE(dram_bound);
