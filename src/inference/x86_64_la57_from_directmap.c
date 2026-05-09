// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Inference plugin: x86-64 L4/L5 paging detection from directmap addresses
// (POST_COLLECTION)
//
// On x86-64, two page-table modes are supported at runtime:
//   L4 (4-level): kernel VAS starts at 0xffff800000000000
//   L5 (5-level): kernel VAS starts at 0xff00000000000000
//
// The directmap (PAGE_OFFSET) linear-mapping base depends on the mode:
//   L4: __PAGE_OFFSET_BASE_L4 = 0xffff888000000000  (>= L4 VAS floor)
//   L5: __PAGE_OFFSET_BASE_L5 = 0xff11000000000000  (<  L4 VAS floor)
//
// The L4 VAS floor (0xffff800000000000) is the discriminator: any collected
// DIRECTMAP address below it is impossible in L4 mode, confirming L5.
//
// Classification:
//
//   Any result < 0xffff800000000000 (exclusively L5 range):
//     → L5 paging confirmed. Raise page_offset_min to __PAGE_OFFSET_BASE_L5
//       (0xff11000000000000) — the kernel directmap floor under L5; the
//       region [0xff10000000000000, 0xff11000000000000) is the LDT remap
//       and [0xff00000000000000, 0xff10000000000000) is a guard hole, so
//       page_offset can never live below 0xff11000000000000.
//       Lower page_offset_max to 0xffff7fffffffffff (one below the L4 VAS
//       floor) to exclude the L4-only region.
//
//   All results >= 0xffff800000000000, none below (L4-compatible range):
//     → L4 paging confirmed. Raise page_offset_min to X86_64_L4_VAS_START
//       (0xffff800000000000), the L4 kernel VAS floor.
//
//   Mixed (both ranges observed): contradictory — no change.
//   No valid DIRECTMAP results: no-op.
//
// This plugin provides a backup/confirmatory path for L4/L5 discrimination
// when proc-cpuinfo LA57 detection (H10) is unavailable or inconclusive.
// Both plugins write page_offset_min/max; they are consistent and idempotent.
//
// Phase: POST_COLLECTION — requires collected DIRECTMAP results.
// Applicable: x86-64 only.
// ---
// <bcoles@gmail.com>

#define _POSIX_C_SOURCE 200809L

#include "../include/kasld_inference.h"

#include <stdio.h>
#include <string.h>

static void x86_64_la57_from_directmap_run(struct kasld_analysis_ctx *ctx) {
#if defined(__x86_64__)
/* L4 kernel VAS floor: any DIRECTMAP below this is exclusively L5. */
#define X86_64_L4_VAS_START 0xffff800000000000ul
/* __PAGE_OFFSET_BASE_L5: directmap floor under L5 paging.
 * CONFIG_RANDOMIZE_MEMORY only randomises page_offset_base upward from this
 * base, and the regions below it ([0xff10..., 0xff11...) LDT remap, [0xff00...,
 * 0xff10...) guard hole) are never used as the directmap base. */
#define X86_64_L5_PO_BASE 0xff11000000000000ul

  int have_l5 = 0; /* any valid DIRECTMAP result below X86_64_L4_VAS_START */
  int have_l4 = 0; /* any valid DIRECTMAP result >= X86_64_L4_VAS_START */

  for (size_t i = 0; i < ctx->result_count; i++) {
    const struct result *r = &ctx->results[i];
    if (r->type != KASLD_ADDR_VIRT || !r->valid ||
        strcmp(r->section, KASLD_SECTION_DIRECTMAP) != 0)
      continue;
    if (r->raw < X86_64_L4_VAS_START)
      have_l5 = 1;
    else
      have_l4 = 1;
  }

  if (!have_l5 && !have_l4)
    return; /* no valid DIRECTMAP results */

  if (have_l5 && have_l4) {
    /* Addresses from both ranges present: contradictory evidence. */
    if (verbose && !quiet)
      fprintf(stdout,
              "[infer] x86_64_la57_from_directmap: contradictory DIRECTMAP"
              " addresses (L4 and L5 ranges both observed); skipping\n");
    return;
  }

  if (have_l5) {
    /* L5 paging confirmed: PAGE_OFFSET is in the L5 directmap region.
     * Raise page_offset_min; lower page_offset_max to exclude the L4 zone. */
    const unsigned long l5_max = X86_64_L4_VAS_START - 1;

    if (X86_64_L5_PO_BASE > ctx->page_offset_min &&
        X86_64_L5_PO_BASE <= ctx->page_offset_max) {
      if (verbose && !quiet)
        fprintf(stdout,
                "[infer] virt_page_offset_min tightened by "
                "x86_64_la57_from_directmap"
                " (L5): %#lx -> %#lx\n",
                ctx->page_offset_min, X86_64_L5_PO_BASE);
      ctx->page_offset_min = X86_64_L5_PO_BASE;
    }

    if (l5_max < ctx->page_offset_max && l5_max >= ctx->page_offset_min) {
      if (verbose && !quiet)
        fprintf(stdout,
                "[infer] virt_page_offset_max tightened by "
                "x86_64_la57_from_directmap"
                " (L5): %#lx -> %#lx\n",
                ctx->page_offset_max, l5_max);
      ctx->page_offset_max = l5_max;
    }
    return;
  }

  /* have_l4: all DIRECTMAP results >= X86_64_L4_VAS_START.
   * L4 paging confirmed. Raise page_offset_min to the L4 VAS floor. */
  if (X86_64_L4_VAS_START > ctx->page_offset_min &&
      X86_64_L4_VAS_START <= ctx->page_offset_max) {
    if (verbose && !quiet)
      fprintf(
          stdout,
          "[infer] virt_page_offset_min tightened by x86_64_la57_from_directmap"
          " (L4): %#lx -> %#lx\n",
          ctx->page_offset_min, X86_64_L4_VAS_START);
    ctx->page_offset_min = X86_64_L4_VAS_START;
  }
#else
  (void)ctx;
#endif /* __x86_64__ */
}

static const struct kasld_inference x86_64_la57_from_directmap = {
    .name = "x86_64_la57_from_directmap",
    .phase = KASLD_INFER_PHASE_POST_COLLECTION,
    .run = x86_64_la57_from_directmap_run,
};

KASLD_REGISTER_INFERENCE(x86_64_la57_from_directmap);
