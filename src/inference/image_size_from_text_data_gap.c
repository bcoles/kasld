// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Inference plugin: runtime image size lower bound from text/data gap
// (POST_COLLECTION)
//
// If the collected results contain at least one virtual TEXT address and at
// least one virtual DATA address, their gap is a lower bound on the kernel
// image size:
//
//   image_size >= max(DATA results) - min(TEXT results)
//
// Soundness argument:
//   Let B = _stext (true kernel text base, unknown).
//   Any TEXT result T satisfies T >= B (kernel text is above _stext).
//   Any DATA result D satisfies D <= B + image_size (_end >= D).
//   Therefore: D - T <= (B + image_size) - B = image_size.
//   Equivalently: image_size >= D - T for any valid (T, D) pair.
//   Using max(DATA) - min(TEXT) maximises the lower bound from collected data.
//
// The kernel image must fit within the KASLR randomisation window:
//   text_base + image_size <= KASLR_BASE_MAX
//   => text_base <= KASLR_BASE_MAX - image_size
//
// This extends kaslr_ceiling.c (which uses a compile-time compressed image
// size estimate) with a runtime-derived bound. When the runtime gap exceeds
// the compile-time estimate, this plugin provides a tighter ceiling.
//
// On PHYS_VIRT_DECOUPLED architectures (x86-64, arm64, riscv64, s390) the
// same logical image occupies the same number of bytes in physical memory, so
// the identical image size lower bound also tightens phys_base_max.
//
// Reliability notes:
// - TEXT and DATA results are emitted by different components (backtrace,
//   dmesg_mem_init_kernel_layout, sysfs_iscsi_transport_handle, etc.) and
//   are always from the running kernel image, so they come from the same
//   single KASLR slot. The gap is always a sound lower bound within one run.
// - If only TEXT or only DATA results are present, the plugin is a no-op.
// - Default ('D'-type) results are excluded implicitly: they carry type 'D',
//   not 'V', so they are skipped by the KASLD_ADDR_VIRT filter.
//
// Phase: POST_COLLECTION — requires both TEXT and DATA results to be collected.
// ---
// <bcoles@gmail.com>

#define _POSIX_C_SOURCE 200809L

#include "../include/kasld_inference.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>

static void image_size_from_text_data_gap_run(struct kasld_analysis_ctx *ctx) {
  unsigned long min_text = ULONG_MAX;
  unsigned long max_data = 0;

  for (size_t i = 0; i < ctx->result_count; i++) {
    const struct result *r = &ctx->results[i];
    /* Only virtual, valid results. KASLD_ADDR_DEFAULT ('D') results are
     * already excluded because they carry type 'D', not KASLD_ADDR_VIRT ('V').
     */
    if (r->type != KASLD_ADDR_VIRT || !r->valid)
      continue;

    if (strcmp(r->section, KASLD_SECTION_TEXT) == 0) {
      if (r->raw < min_text)
        min_text = r->raw;
    } else if (strcmp(r->section, KASLD_SECTION_DATA) == 0) {
      if (r->raw > max_data)
        max_data = r->raw;
    }
  }

  /* Need at least one of each. */
  if (min_text == ULONG_MAX || max_data == 0)
    return;

  /* Data must lie above text (which it always does in the Linux vmlinux
   * layout). If not, the pair is inconsistent — skip rather than underflow. */
  if (max_data <= min_text)
    return;

  unsigned long gap = max_data - min_text;

  /* Virtual ceiling: text_base <= KASLR_BASE_MAX - gap */
  unsigned long kaslr_max = ctx->arch->kaslr_base_max;
  unsigned long kaslr_min = ctx->arch->kaslr_base_min;
  unsigned long kaslr_align = ctx->arch->kaslr_align;

  if (gap < kaslr_max - kaslr_min) {
    unsigned long new_max = kaslr_max - gap;
    if (kaslr_align > 0)
      new_max &= ~(kaslr_align - 1);

    if (new_max > kaslr_min && new_max > ctx->text_base_min &&
        new_max < ctx->text_base_max) {
      if (verbose && !quiet)
        fprintf(
            stderr,
            "[layout] text_base_max tightened by image_size_from_text_data_gap:"
            " %#lx -> %#lx (gap=%#lx, min_text=%#lx, max_data=%#lx)\n",
            ctx->text_base_max, new_max, gap, min_text, max_data);
      ctx->text_base_max = new_max;
    }
  }

  /* Physical ceiling: same image size applies on decoupled arches. */
  if (ctx->arch->phys_virt_decoupled) {
    unsigned long phys_max = ctx->arch->phys_kaslr_base_max;
    unsigned long phys_min = ctx->arch->phys_kaslr_base_min;
    unsigned long phys_align = ctx->arch->phys_kaslr_align;

    if (phys_max > phys_min && gap < phys_max - phys_min) {
      unsigned long new_phys = phys_max - gap;
      if (phys_align > 0)
        new_phys &= ~(phys_align - 1);

      if (new_phys > phys_min && new_phys > ctx->phys_base_min &&
          new_phys < ctx->phys_base_max) {
        if (verbose && !quiet)
          fprintf(stderr,
                  "[layout] phys_base_max tightened by "
                  "image_size_from_text_data_gap:"
                  " %#lx -> %#lx (gap=%#lx)\n",
                  ctx->phys_base_max, new_phys, gap);
        ctx->phys_base_max = new_phys;
      }
    }
  }
}

static const struct kasld_inference image_size_from_text_data_gap = {
    .name = "image_size_from_text_data_gap",
    .phase = KASLD_INFER_PHASE_POST_COLLECTION,
    .run = image_size_from_text_data_gap_run,
};

KASLD_REGISTER_INFERENCE(image_size_from_text_data_gap);
