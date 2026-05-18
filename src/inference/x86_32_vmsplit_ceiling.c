// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Inference plugin: x86-32 vmsplit ceiling (POST_COLLECTION)
//
// On x86-32, KASLR places the kernel at a random physical address in
// [LOAD_PHYSICAL_ADDR=16 MiB, KERNEL_IMAGE_SIZE=512 MiB). Physical and
// virtual are coupled (PHYS_VIRT_DECOUPLED=0), so the virtual address is:
//
//   va = pa + PAGE_OFFSET
//   va ∈ [PAGE_OFFSET + 16 MiB, PAGE_OFFSET + 512 MiB)
//
// The kernel placement code enforces the upper bound:
//   arch/x86/boot/compressed/kaslr.c: mem_limit = KERNEL_IMAGE_SIZE (512 MiB)
//
// layout_adjust.c detects the vmsplit configuration from the PAGE_OFFSET
// result reported by mmap-brute-vmsplit.c and applies it to the layout before
// this plugin runs. Three possible configurations:
//
//   CONFIG_VMSPLIT_3G: PAGE_OFFSET = 0xc0000000 → ceiling = 0xe0000000
//   CONFIG_VMSPLIT_2G: PAGE_OFFSET = 0x80000000 → ceiling = 0xa0000000
//   CONFIG_VMSPLIT_1G: PAGE_OFFSET = 0x40000000 → ceiling = 0x60000000
//
// This plugin fires regardless of whether mmap-brute-vmsplit succeeded; if
// the vmsplit is undetected, the compile-time default PAGE_OFFSET (3G) gives
// the correct ceiling for the common case.
//
// Phase: POST_COLLECTION — fires after layout_adjust has applied the detected
// PAGE_OFFSET to ctx->layout.
//
// References:
//   arch/x86/boot/compressed/kaslr.c: KERNEL_IMAGE_SIZE ceiling
//   arch/x86/Kconfig: CONFIG_VMSPLIT_* options
// ---
// <bcoles@gmail.com>

#define _POSIX_C_SOURCE 200809L

#include "../include/kasld/inference.h"

#include <stdio.h>

static void x86_32_vmsplit_ceiling_run(struct kasld_analysis_ctx *ctx) {
#if defined(__i386__)

/* KERNEL_IMAGE_SIZE = 512 MiB: upper bound of the physical KASLR placement
 * window on x86-32. kaslr.c sets mem_limit to this when CONFIG_X86_32. */
#define X86_32_KERNEL_IMAGE_SIZE (512ul * MB)

  unsigned long ceiling = ctx->layout->page_offset + X86_32_KERNEL_IMAGE_SIZE;

  if (ceiling > ctx->text_base_min && ceiling < ctx->text_base_max) {
    if (verbose && !quiet)
      fprintf(stdout,
              "[infer] virt_text_base_max tightened by x86_32_vmsplit_ceiling:"
              " %#lx -> %#lx (PAGE_OFFSET + 512 MiB)\n",
              ctx->text_base_max, ceiling);
    ctx->text_base_max = ceiling;
  }

#undef X86_32_KERNEL_IMAGE_SIZE
#else
  (void)ctx;
#endif /* __i386__ */
}

static const struct kasld_inference x86_32_vmsplit_ceiling = {
    .name = "x86_32_vmsplit_ceiling",
    .phase = KASLD_INFER_PHASE_POST_COLLECTION,
    .run = x86_32_vmsplit_ceiling_run,
};

KASLD_REGISTER_INFERENCE(x86_32_vmsplit_ceiling);
