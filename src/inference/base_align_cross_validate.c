// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Inference plugin: tighten kaslr_align from observed base_align
// (LAYOUT_ADJUST)
//
// Components that know the alignment of a leaked base address (kallsyms
// parsers, ELF relocations, ...) may emit base_align on the wire. If the
// observed alignment across multiple independent BASE records is stricter
// than the arch's default kaslr_align (e.g. all leaks land on a 4 MiB
// boundary while the arch default is 2 MiB), the true KASLR step is the
// observed alignment — entropy is overcounted otherwise.
//
// Phase rationale: this plugin mutates layout.kaslr_align (and
// layout.phys_kaslr_align), which is only writable in LAYOUT_ADJUST.
// Reading merged results in LAYOUT_ADJUST is sound because merge_results
// runs immediately before this phase in run_post_collection_inference().
//
// Soundness:
// - Only raise alignment, never lower (tighten-only via min/max framing).
// - Require base_align to be a power of two — non-pow2 records should have
//   been rejected at the parser boundary, but we re-check defensively.
// - Skip if no eligible records found. Single-record observations are
//   accepted: a single high-confidence base_align is enough evidence,
//   since base_align is a property the emitting component asserts about
//   the leak source (not a statistical observation requiring N samples).
// ---
// <bcoles@gmail.com>

#define _POSIX_C_SOURCE 200809L

#include "../include/kasld/inference.h"

#include <stdio.h>

static int is_pow2_ul(unsigned long v) { return v && !(v & (v - 1)); }

/* Find the strictest (largest) base_align across BASE records of the given
 * type that target a kernel-image-family region. Returns 0 if no eligible
 * record carries HAS_BASE_ALIGN. */
static unsigned long max_base_align(const struct kasld_analysis_ctx *ctx,
                                    enum kasld_addr_type type) {
  unsigned long best = 0;
  for (size_t i = 0; i < ctx->result_count; i++) {
    const struct result *r = &ctx->results[i];
    if (r->type != type)
      continue;
    if (!is_kernel_image_region(r->region))
      continue;
    if (r->pos != POS_BASE || !HAS_BASE_ALIGN(r))
      continue;
    if (!is_pow2_ul(r->base_align))
      continue;
    if (r->base_align > best)
      best = r->base_align;
  }
  return best;
}

static void base_align_cross_validate_run(struct kasld_analysis_ctx *ctx) {
  unsigned long v = max_base_align(ctx, KASLD_TYPE_VIRT);
  if (v > ctx->layout->kaslr_align) {
    if (verbose && !quiet)
      fprintf(stdout,
              "[infer] kaslr_align tightened by base_align_cross_validate:"
              " %#lx -> %#lx (observed BASE alignment from leaks)\n",
              ctx->layout->kaslr_align, v);
    ctx->layout->kaslr_align = v;
  }

  if (ctx->arch->phys_virt_decoupled) {
    unsigned long p = max_base_align(ctx, KASLD_TYPE_PHYS);
    if (p > ctx->layout->phys_kaslr_align) {
      if (verbose && !quiet)
        fprintf(stdout,
                "[infer] phys_kaslr_align tightened by"
                " base_align_cross_validate: %#lx -> %#lx\n",
                ctx->layout->phys_kaslr_align, p);
      ctx->layout->phys_kaslr_align = p;
    }
  }
}

static const struct kasld_inference base_align_cross_validate = {
    .name = "base_align_cross_validate",
    .phase = KASLD_INFER_PHASE_LAYOUT_ADJUST,
    .run = base_align_cross_validate_run,
};

KASLD_REGISTER_INFERENCE(base_align_cross_validate);
