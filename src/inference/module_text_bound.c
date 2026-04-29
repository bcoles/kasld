// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Inference plugin: module region → text upper bound (POST_COLLECTION)
//
// Active only on architectures where the module region is anchored to the
// kernel image (MODULES_RELATIVE_TO_TEXT == 1; currently riscv64). On all
// other architectures the module range is fixed or PAGE_OFFSET-relative and
// carries no information about the text KASLR slot; the plugin is a no-op.
//
// On riscv64 the module region starts at PFN_ALIGN(_end) - 2 GiB, so:
//
//   _end ≈ module_lo + MODULES_END_TO_TEXT_OFFSET
//
// Since module_lo ≥ MODULES_VADDR and MODULES_VADDR = PFN_ALIGN(_end) - 2G,
// the estimate end_est = module_lo + 2G is always ≥ _end. Combined with the
// kernel-size lower bound (MIN_KERNEL_IMAGE_SIZE), this gives a safe upper
// bound on text_base:
//
//   text_base = _end - actual_size
//             ≤ end_est - MIN_KERNEL_IMAGE_SIZE
//
// The plugin therefore tightens ctx->text_base_max only. text_base_min is
// not tightened: the observed module_lo may be far above MODULES_VADDR (if
// few modules are loaded near the base of the region), which would make the
// derived lower bound unsafe.
//
// MIN_KERNEL_IMAGE_SIZE (4 MiB) matches the estimate used in
// compute_derived_addrs() for rendering; undershooting is safe — it gives
// a higher (less tight) upper bound rather than excluding the true text base.
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

  /* Find the minimum valid virtual module address. */
  unsigned long vmod_lo = ULONG_MAX;
  for (size_t i = 0; i < ctx->result_count; i++) {
    const struct result *r = &ctx->results[i];
    if (r->type == KASLD_ADDR_VIRT &&
        strcmp(r->section, KASLD_SECTION_MODULE) == 0 && r->valid &&
        r->aligned < vmod_lo)
      vmod_lo = r->aligned;
  }

  if (vmod_lo == ULONG_MAX)
    return;

  /* _end ≈ vmod_lo + MODULES_END_TO_TEXT_OFFSET (2 GiB on riscv64).
   * text_base ≤ end_est - MIN_KERNEL_IMAGE_SIZE is always safe (see header). */
  unsigned long end_est = vmod_lo + MODULES_END_TO_TEXT_OFFSET;
  unsigned long new_max =
      (end_est - MIN_KERNEL_IMAGE_SIZE) & ~(kaslr_align - 1);

  if (new_max > kaslr_min && new_max < ctx->text_base_max) {
    if (verbose && !quiet)
      fprintf(stderr,
              "[layout] text_base_max tightened by module_text_bound:"
              " %#lx -> %#lx (vmod_lo=%#lx)\n",
              ctx->text_base_max, new_max, vmod_lo);
    ctx->text_base_max = new_max;
  }
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
