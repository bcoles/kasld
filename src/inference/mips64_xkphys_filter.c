// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Inference plugin: MIPS64 XKPHYS result reclassification (LAYOUT_ADJUST)
//
// On MIPS64, the XKPHYS segment provides a hardware-wired direct physical
// mapping. Any 64-bit virtual address where bits [63:62] = 0b10 is an XKPHYS
// address:
//
//   (V >> 62) == 2  →  XKPHYS
//   phys = V & 0x07ffffffffffffff   (strip bits [63:59]: XKPHYS marker + CCA)
//
// Bits [61:59] are the Cache Coherency Attribute (CCA); bits [58:0] are the
// physical address (up to 2^59 = 512 PiB of physical address space).
//
// Components may emit XKPHYS addresses as VIRT/DIRECTMAP because they look
// like ordinary kernel virtual addresses. If phys_virt_synth then pairs an
// XKPHYS VIRT/DIRECTMAP result with a PHYS/DRAM result from the same
// component, it synthesises a bogus PAGE_OFFSET (e.g. 0x9000000000000000
// instead of 0xffffffff80000000) and permanently corrupts page_offset_min/max.
//
// This plugin reclassifies XKPHYS VIRT/DIRECTMAP results as PHYS/DRAM with
// the correct physical address before any POST_COLLECTION inference runs.
//
// Phase: LAYOUT_ADJUST — runs once before the POST_COLLECTION convergence
// loop, guaranteeing these results are correctly classified before
// phys_virt_synth sees them. POST_COLLECTION would be too late: if
// phys_virt_synth fired first in pass 1 it could irrecoverably tighten
// page_offset_max below the true PAGE_OFFSET.
//
// References:
//   arch/mips/include/asm/addrspace.h: XKPHYS definition
//   MIPS64 Architecture For Programmers Vol. III §4.3: address spaces
// ---
// <bcoles@gmail.com>

#define _POSIX_C_SOURCE 200809L

#include "../include/kasld/inference.h"

#include <stdio.h>
#include <string.h>

static void mips64_xkphys_filter_run(struct kasld_analysis_ctx *ctx) {
#if defined(__mips64) || defined(__mips64__)
  (void)ctx;
  int reclassified = 0;

  for (int i = 0; i < num_results; i++) {
    struct result *r = &results[i];
    if (r->type != KASLD_TYPE_VIRT)
      continue;
    if ((anchor_addr(r) >> 62) != 2)
      continue;

    /* Strip XKPHYS marker (bits 63:62) and CCA field (bits 61:59);
     * bits 58:0 are the physical address. */
    unsigned long phys = anchor_addr(r) & 0x07fffffffffffffful;

    if (verbose && !quiet)
      fprintf(stdout,
              "[infer] mips64_xkphys_filter: reclassifying XKPHYS"
              " %#lx -> PHYS/RAM %#lx\n",
              anchor_addr(r), phys);

    /* Reclassify: change type to PHYS, region to RAM, rewrite the
     * representative address. The result is mutated in place. */
    r->type = KASLD_TYPE_PHYS;
    r->region = REGION_RAM;
    if (HAS_SAMPLE(r))
      r->sample = phys;
    if (HAS_LO(r))
      r->lo = phys;
    if (HAS_HI(r))
      r->hi = phys;
    reclassified++;
  }
  (void)reclassified;
#else
  (void)ctx;
#endif /* __mips64 */
}

static const struct kasld_inference mips64_xkphys_filter = {
    .name = "mips64_xkphys_filter",
    .phase = KASLD_INFER_PHASE_LAYOUT_ADJUST,
    .run = mips64_xkphys_filter_run,
};

KASLD_REGISTER_INFERENCE(mips64_xkphys_filter);
