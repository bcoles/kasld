// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Inference plugin: module region → text bounds (POST_COLLECTION)
//
// Active only on architectures where the module region is anchored to the
// kernel image (MODULES_RELATIVE_TO_TEXT == 1). Two sub-cases:
//
// Case A — modules below _end (riscv64, MODULES_BELOW_TEXT_START undefined):
//   MODULES_END ≈ _end (image end). Module_lo ≥ _end - MODULES_LEN, so:
//
//     _end ≤ module_lo + MODULES_END_TO_TEXT_OFFSET
//     text_base ≤ _end - MIN_KERNEL_IMAGE_SIZE
//               ≤ module_lo + MODULES_END_TO_TEXT_OFFSET -
//               MIN_KERNEL_IMAGE_SIZE
//
//   Only text_base_max is tightened; text_base_min is not (a module far from
//   the top of the region gives no useful lower bound).
//
// Case B — modules below image start (s390, MODULES_BELOW_TEXT_START == 1):
//   MODULES_END = round_down(__kaslr_offset, _SEGMENT_SIZE) ≤ __kaslr_offset.
//   __kaslr_offset is KERNEL_ALIGN-aligned, so the gap between MODULES_END and
//   __kaslr_offset is at most _SEGMENT_SIZE - KERNEL_ALIGN. Any module address
//   vmod satisfies vmod < MODULES_END ≤ __kaslr_offset, giving constraints in
//   both directions:
//
//   Upper bound (minimum module address vmod_lo):
//     MODULES_END ≤ vmod_lo + MODULES_LEN
//     __kaslr_offset ≤ vmod_lo + MODULES_LEN + (_SEGMENT_SIZE - KERNEL_ALIGN)
//     _stext ≤ vmod_lo + MODULES_END_TO_TEXT_OFFSET
//              (= MODULES_LEN + (_SEGMENT_SIZE - KERNEL_ALIGN) + TEXT_OFFSET)
//
//   Lower bound (maximum module address vmod_hi):
//     __kaslr_offset > vmod_hi
//     __kaslr_offset ≥ align_down(vmod_hi, kaslr_align) + kaslr_align
//     _stext ≥ align_down(vmod_hi, kaslr_align) + kaslr_align + TEXT_OFFSET
//
//   Both text_base_max and text_base_min are tightened.
//
// MIN_KERNEL_IMAGE_SIZE (4 MiB, Case A only) matches the estimate used in
// compute_derived_addrs() for rendering; undershooting is safe.
// ---
// <bcoles@gmail.com>

#define _POSIX_C_SOURCE 200809L

#include "../include/kasld_inference.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>

/* Lower bound on kernel image size. Undershooting is safe: we compute a
 * higher (more permissive) text_base_max rather than risking excluding the
 * true kernel base. Matches the estimate in compute_derived_addrs(). */
#define MIN_KERNEL_IMAGE_SIZE (4UL * MB)

static void module_text_bound_run(struct kasld_analysis_ctx *ctx) {
#if MODULES_RELATIVE_TO_TEXT
  unsigned long kaslr_align = ctx->arch->kaslr_align;
  unsigned long kaslr_min = ctx->arch->kaslr_base_min;

  /* Find minimum and maximum valid aligned virtual module addresses. */
  unsigned long vmod_lo = ULONG_MAX;
  unsigned long vmod_hi = 0;
  for (size_t i = 0; i < ctx->result_count; i++) {
    const struct result *r = &ctx->results[i];
    if (r->type != KASLD_ADDR_VIRT || !r->valid ||
        strcmp(r->section, KASLD_SECTION_MODULE) != 0)
      continue;
    if (r->aligned < vmod_lo)
      vmod_lo = r->aligned;
    if (r->aligned > vmod_hi)
      vmod_hi = r->aligned;
  }

  if (vmod_lo == ULONG_MAX)
    return;

#if MODULES_BELOW_TEXT_START
  /* Case B: MODULES_END = round_down(__kaslr_offset, _SEGMENT_SIZE) (s390).
   * MODULES_END_TO_TEXT_OFFSET = MODULES_LEN + (_SEGMENT_SIZE - KERNEL_ALIGN)
   * + TEXT_OFFSET, accounting for the gap between MODULES_END and
   * __kaslr_offset. */
  unsigned long text_offset = ctx->arch->text_offset;

  /* Upper bound: _stext ≤ vmod_lo + MODULES_END_TO_TEXT_OFFSET. */
  unsigned long new_max =
      (vmod_lo + MODULES_END_TO_TEXT_OFFSET) & ~(kaslr_align - 1);

  if (new_max > kaslr_min && new_max > ctx->text_base_min &&
      new_max < ctx->text_base_max) {
    if (verbose && !quiet)
      fprintf(stdout,
              "[infer] text_base_max tightened by module_text_bound:"
              " %#lx -> %#lx (vmod_lo=%#lx)\n",
              ctx->text_base_max, new_max, vmod_lo);
    ctx->text_base_max = new_max;
  }

  /* Lower bound: any module must be strictly below __kaslr_offset.
   * __kaslr_offset ≥ align_down(vmod_hi, kaslr_align) + kaslr_align
   * _stext ≥ align_down(vmod_hi, kaslr_align) + kaslr_align + TEXT_OFFSET */
  unsigned long new_min =
      (vmod_hi & ~(kaslr_align - 1)) + kaslr_align + text_offset;

  if (new_min > ctx->text_base_min && new_min < ctx->text_base_max) {
    if (verbose && !quiet)
      fprintf(stdout,
              "[infer] text_base_min tightened by module_text_bound:"
              " %#lx -> %#lx (vmod_hi=%#lx)\n",
              ctx->text_base_min, new_min, vmod_hi);
    ctx->text_base_min = new_min;
  }

#else
  /* Case A: MODULES_END ≈ _end (riscv64).
   * _end ≈ vmod_lo + MODULES_END_TO_TEXT_OFFSET; text_base ≤ _end - MIN_size.
   */
  unsigned long end_est = vmod_lo + MODULES_END_TO_TEXT_OFFSET;
  unsigned long new_max =
      (end_est - MIN_KERNEL_IMAGE_SIZE) & ~(kaslr_align - 1);

  if (new_max > kaslr_min && new_max < ctx->text_base_max) {
    if (verbose && !quiet)
      fprintf(stdout,
              "[infer] text_base_max tightened by module_text_bound:"
              " %#lx -> %#lx (vmod_lo=%#lx)\n",
              ctx->text_base_max, new_max, vmod_lo);
    ctx->text_base_max = new_max;
  }
#endif /* MODULES_BELOW_TEXT_START */

#else
  (void)ctx;
#endif /* MODULES_RELATIVE_TO_TEXT */
}

static const struct kasld_inference module_text_bound = {
    .name = "module_text_bound",
    .phase = KASLD_INFER_PHASE_POST_COLLECTION,
    .run = module_text_bound_run,
};

KASLD_REGISTER_INFERENCE(module_text_bound);
