// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Inference plugin: DRAM bound propagation (POST_COLLECTION)
//
// On coupled architectures (PHYS_VIRT_DECOUPLED == 0), physical and virtual
// KASLR are linked: virtual_text = phys_dram - PHYS_OFFSET + PAGE_OFFSET
// + TEXT_OFFSET.  When a component leaks a physical DRAM address, the minimum
// such address is a lower bound on the physical kernel placement, which maps
// directly to a virtual text lower bound.
//
// The plugin tightens ctx->text_base_min only — it never touches text_base_max.
// The minimum PHYS/DRAM result may not be the actual physical DRAM floor (we
// only see a subset of DRAM regions); lowering text_base_max based on an
// incomplete DRAM sample risks excluding the true kernel base.
//
// On decoupled architectures (x86_64, arm64, riscv64, s390) physical and
// virtual KASLR are independent; the plugin returns immediately.
// ---
// <bcoles@gmail.com>

#define _POSIX_C_SOURCE 200809L

#include "../include/kasld_inference.h"

#include <limits.h>
#include <string.h>

static void dram_bound_run(struct kasld_analysis_ctx *ctx) {
  if (ctx->arch->phys_virt_decoupled)
    return;

  unsigned long phys_offset = ctx->arch->phys_offset;
  unsigned long page_offset = ctx->arch->page_offset;
  unsigned long text_offset = ctx->arch->text_offset;
  unsigned long kaslr_align = ctx->arch->kaslr_align;
  unsigned long kaslr_min = ctx->arch->kaslr_base_min;

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

  if (pdram_lo == ULONG_MAX || pdram_lo < phys_offset)
    return;

  /* Derive virtual text lower bound from the minimum physical DRAM address.
   * Align down to the nearest slot boundary to stay conservative. */
  unsigned long virt_lo =
      (pdram_lo - phys_offset + page_offset + text_offset) & ~(kaslr_align - 1);

  if (virt_lo > kaslr_min && virt_lo > ctx->text_base_min &&
      virt_lo < ctx->text_base_max)
    ctx->text_base_min = virt_lo;
}

static const struct kasld_inference dram_bound = {
    .name = "dram_bound",
    .phase = KASLD_INFER_PHASE_POST_COLLECTION,
    .run = dram_bound_run,
};

KASLD_REGISTER_INFERENCE(dram_bound);
