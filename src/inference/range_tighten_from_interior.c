// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Inference plugin: tighten text-base ceilings from interior samples
// (POST_COLLECTION)
//
// Any address inside the kernel image satisfies:
//
//   sample = text_base + offset,   where 0 <= offset < image_size
//
// Even without knowing `offset` (the per-symbol displacement, which
// requires kallsyms or a build-ID-keyed offset table), the constraint
// `offset >= 0` gives us a strict upper bound:
//
//   text_base <= sample
//
// This applies to any interior sample in a kernel-image-family region
// (kernel_text / kernel_data / kernel_bss / kernel_image). The plugin
// scans for such samples and tightens text_base_max (virt) /
// phys_base_max (phys) to the minimum observed sample.
//
// We deliberately do NOT compute a lower bound here: that would require
// an upper bound on image_size, which lives in the kaslr_ceiling plugin
// chain (KCONFIG-derived or arch-default). Coupling this plugin to that
// derivation would create a circular dependency on the order of plugin
// execution within the convergence loop. Bounded image_size is handled
// separately.
//
// Soundness:
// - Only tighten *_max (never widen). Convergence-loop monotonicity.
// - Require result_in_bounds to drop garbage records before they affect
//   the ceiling.
// - Use r->sample directly (gated on HAS_SAMPLE), not anchor_addr().
//   anchor_addr() can fall back to lo, which is the base address —
//   using it here would tighten the base ceiling with a base address,
//   producing a trivially false constraint (base <= base). HAS_SAMPLE
//   ensures only genuine interior observations affect the ceiling.
// ---
// <bcoles@gmail.com>

#define _POSIX_C_SOURCE 200809L

#include "../include/kasld/inference.h"

#include <limits.h>
#include <stdio.h>

static void tighten_max(struct kasld_analysis_ctx *ctx, enum kasld_addr_type type,
                        unsigned long *ceiling, const char *bound_name) {
  unsigned long min_sample = ULONG_MAX;
  for (size_t i = 0; i < ctx->result_count; i++) {
    const struct result *r = &ctx->results[i];
    if (r->type != type)
      continue;
    if (!is_kernel_image_region(r->region))
      continue;
    if (!HAS_SAMPLE(r))
      continue;
    if (!result_in_bounds(r, ctx->layout))
      continue;
    if (r->sample < min_sample)
      min_sample = r->sample;
  }

  if (min_sample == ULONG_MAX)
    return;
  if (min_sample >= *ceiling)
    return;

  if (verbose && !quiet)
    fprintf(stdout,
            "[infer] %s tightened by range_tighten_from_interior:"
            " %#lx -> %#lx (min interior sample in kernel image)\n",
            bound_name, *ceiling, min_sample);
  *ceiling = min_sample;
}

static void range_tighten_from_interior_run(struct kasld_analysis_ctx *ctx) {
  tighten_max(ctx, KASLD_TYPE_VIRT, &ctx->text_base_max, "virt_text_base_max");
  if (ctx->arch->phys_virt_decoupled)
    tighten_max(ctx, KASLD_TYPE_PHYS, &ctx->phys_base_max,
                "phys_text_base_max");
}

static const struct kasld_inference range_tighten_from_interior = {
    .name = "range_tighten_from_interior",
    .phase = KASLD_INFER_PHASE_POST_COLLECTION,
    .run = range_tighten_from_interior_run,
};

KASLD_REGISTER_INFERENCE(range_tighten_from_interior);
