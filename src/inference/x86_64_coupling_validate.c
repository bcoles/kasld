// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Inference plugin: x86-64 directmap/text region coupling validation
// (POST_COLLECTION)
//
// On x86-64, two kernel virtual regions are disjoint by design:
//
//   Directmap: starting at page_offset_base (≈ 0xffff888000000000 on L4,
//              lower on L5 with CONFIG_RANDOMIZE_MEMORY). Always below the
//              kernel text mapping area.
//
//   Text mapping: [__START_KERNEL_map, KERNEL_BASE_MAX)
//                = [0xffffffff80000000, 0xffffffffc0000000)
//
// Any VIRT/DIRECTMAP result V must satisfy V < KERNEL_BASE_MIN
// (0xffffffff80000000), because the directmap never reaches the kernel text
// mapping area. A DIRECTMAP result V ≥ KERNEL_BASE_MIN is in the text region
// and is misclassified.
//
// Any VIRT/TEXT result V must satisfy V ≥ KASLR_BASE_MIN
// (0xffffffff81000000 = KERNEL_BASE_MIN + PHYSICAL_START), the lowest possible
// KASLR text base. A TEXT result below KASLR_BASE_MIN cannot be a valid text
// base.
//
// This plugin invalidates such misclassified results and calls
// revalidate_results() so subsequent POST_COLLECTION inference uses a clean
// result set.
//
// Note: layout_adjust.c already revalidates all results against the active
// region windows at LAYOUT_ADJUST time. This plugin provides an additional
// check for results whose region membership can be determined from static
// architectural constants alone, independent of the computed window.
//
// Phase: POST_COLLECTION — runs in the convergence loop; invalidation in one
// pass is reflected in subsequent passes.
// Applicable: x86-64 only.
// ---
// <bcoles@gmail.com>

#define _POSIX_C_SOURCE 200809L

#include "../include/kasld/inference.h"

#include <stdio.h>
#include <string.h>

static void x86_64_coupling_validate_run(struct kasld_analysis_ctx *ctx) {
#if defined(__x86_64__)
  (void)ctx;
  int invalidated = 0;

  for (int i = 0; i < num_results; i++) {
    struct result *r = &results[i];
    if (!result_in_bounds(r, ctx->layout) || r->type != KASLD_TYPE_VIRT)
      continue;

    /* DIRECTMAP result in the kernel text mapping area: misclassified.
     * The directmap never reaches __START_KERNEL_map (KERNEL_BASE_MIN). */
    if (r->region == REGION_DIRECTMAP && anchor_addr(r) >= KERNEL_BASE_MIN) {
      if (verbose && !quiet)
        fprintf(stdout,
                "[infer] x86_64_coupling_validate: invalidating DIRECTMAP"
                " result %#lx (>= KERNEL_BASE_MIN %#lx); misclassified\n",
                anchor_addr(r), (unsigned long)KERNEL_BASE_MIN);
      r->region = REGION_UNKNOWN;
      invalidated++;
      continue;
    }

    /* TEXT result below the minimum KASLR text base: not a valid text base. */
    if ((r->region == REGION_KERNEL_TEXT || r->region == REGION_KERNEL_IMAGE) &&
        anchor_addr(r) < KASLR_BASE_MIN) {
      if (verbose && !quiet)
        fprintf(stdout,
                "[infer] x86_64_coupling_validate: invalidating TEXT"
                " result %#lx (< KASLR_BASE_MIN %#lx); not a valid text base\n",
                anchor_addr(r), (unsigned long)KASLR_BASE_MIN);
      r->region = REGION_UNKNOWN;
      invalidated++;
    }
  }
  (void)invalidated;
#else
  (void)ctx;
#endif /* __x86_64__ */
}

static const struct kasld_inference x86_64_coupling_validate = {
    .name = "x86_64_coupling_validate",
    .phase = KASLD_INFER_PHASE_POST_COLLECTION,
    .run = x86_64_coupling_validate_run,
};

KASLD_REGISTER_INFERENCE(x86_64_coupling_validate);
