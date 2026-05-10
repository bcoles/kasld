// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Inference plugin: arm64 EFI_KIMG_ALIGN detection via getpagesize()
// (LAYOUT_ADJUST)
//
// On arm64, the physical KASLR slot granularity is EFI_KIMG_ALIGN:
//
//   EFI_KIMG_ALIGN = max(THREAD_ALIGN, SEGMENT_ALIGN)
//   SEGMENT_ALIGN  = 64 KiB (constant, arch/arm64/include/asm/memory.h)
//   THREAD_ALIGN   = 2 * THREAD_SIZE = 2 * (1 << max(PAGE_SHIFT, 14))
//
//   4K  pages (PAGE_SHIFT=12): THREAD_SHIFT=14, THREAD_ALIGN=32KiB
//                               → EFI_KIMG_ALIGN = 64 KiB
//   16K pages (PAGE_SHIFT=14): THREAD_SHIFT=14, THREAD_ALIGN=32KiB
//                               → EFI_KIMG_ALIGN = 64 KiB
//   64K pages (PAGE_SHIFT=16): THREAD_SHIFT=16, THREAD_ALIGN=128KiB
//                               → EFI_KIMG_ALIGN = 128 KiB
//
// The compile-time default KERNEL_ALIGN=64KiB covers 4K/16K pages correctly.
// On 64K-page EFI systems the actual granularity is 128KiB; this plugin
// detects and corrects that. Only phys_kaslr_align is updated; virtual
// KASLR_ALIGN (2 MiB) is independent of page size on arm64.
//
// getpagesize() returns the host page size (glibc reads AT_PAGESZ from the
// ELF auxiliary vector; always available, no syscall required).
//
// Phase: LAYOUT_ADJUST — no component results required; establishes correct
// physical slot granularity before POST_COLLECTION plugins run.
// Must be LAYOUT_ADJUST (not PRE_COLLECTION) because it writes ctx->layout.
//
// References:
//   arch/arm64/include/asm/efi.h: EFI_KIMG_ALIGN
//   arch/arm64/include/asm/memory.h: SEGMENT_ALIGN
//   arch/arm64/include/asm/thread_info.h: THREAD_ALIGN
// ---
// <bcoles@gmail.com>

#define _POSIX_C_SOURCE 200809L

#include "../include/kasld_inference.h"

#include <stdio.h>
#include <unistd.h>

static void arm64_phys_kaslr_align_run(struct kasld_analysis_ctx *ctx) {
#if defined(__aarch64__)

  int pagesize = getpagesize();
  unsigned long efi_kimg_align;

  /* Derive EFI_KIMG_ALIGN = max(THREAD_ALIGN, SEGMENT_ALIGN=64KiB).
   * 64K pages: THREAD_ALIGN = 2*(1<<16) = 128KiB → EFI_KIMG_ALIGN = 128KiB.
   * 4K/16K:    THREAD_ALIGN ≤ 32KiB → EFI_KIMG_ALIGN = 64KiB (SEGMENT_ALIGN).
   */
  if (pagesize == 65536)
    efi_kimg_align = 131072ul; /* 128 KiB */
  else if (pagesize == 4096 || pagesize == 16384)
    efi_kimg_align = 65536ul; /* 64 KiB */
  else
    return; /* unexpected page size — skip */

  if (ctx->layout->phys_kaslr_align == 0)
    return; /* physical KASLR absent — skip */

  if (efi_kimg_align > ctx->layout->phys_kaslr_align) {
    if (verbose && !quiet)
      fprintf(stdout,
              "[infer] phys_kaslr_align tightened by arm64_phys_kaslr_align:"
              " %#lx -> %#lx\n",
              ctx->layout->phys_kaslr_align, efi_kimg_align);
    ctx->layout->phys_kaslr_align = efi_kimg_align;
  }

  /* Alignment snap: re-snap phys_base_max to the slot boundary.
   * Removes any partial slot from the top of the physical window. */
  unsigned long phys_max = ctx->phys_base_max & ~(efi_kimg_align - 1);
  if (phys_max > ctx->phys_base_min && phys_max < ctx->phys_base_max) {
    if (verbose && !quiet)
      fprintf(stdout,
              "[infer] phys_base_max tightened by arm64_phys_kaslr_align"
              " (align snap): %#lx -> %#lx\n",
              ctx->phys_base_max, phys_max);
    ctx->phys_base_max = phys_max;
  }

#else
  (void)ctx;
#endif /* __aarch64__ */
}

static const struct kasld_inference arm64_phys_kaslr_align = {
    .name = "arm64_phys_kaslr_align",
    .phase = KASLD_INFER_PHASE_LAYOUT_ADJUST,
    .run = arm64_phys_kaslr_align_run,
};

KASLD_REGISTER_INFERENCE(arm64_phys_kaslr_align);
