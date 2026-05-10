// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Inference plugin: PPC64 RTAS base → text range ceiling (PRE_COLLECTION)
//
// RTAS (Run-Time Abstraction Services) occupies a physically contiguous
// region near the top of the first 2 GiB of physical memory. Its base
// address is stored in the device tree at:
//
//   /sys/firmware/devicetree/base/rtas/rtas-base
//
// as a big-endian 32-bit integer (world-readable, always present on
// POWER systems with RTAS firmware).
//
// The kernel image must fit entirely below RTAS in physical memory:
//
//   phys_text_end ≤ rtas_base
//   phys_text_start + kernel_image_size ≤ rtas_base
//   phys_text_start ≤ rtas_base - kernel_image_size
//
// On PPC64, PHYS_OFFSET = 0 and TEXT_OFFSET = 0, so
// phys_to_virt(x) = PAGE_OFFSET | x = PAGE_OFFSET + x. The virtual ceiling:
//
//   text_base_max = min(text_base_max,
//                       PAGE_OFFSET + rtas_base - kernel_image_size)
//
// PPC64 has no mainline KASLR; the kernel loads at PAGE_OFFSET + 0.
// This plugin constrains result validation rather than narrowing a KASLR
// slot window: any leaked virtual text address above the ceiling is invalid.
//
// Phase: PRE_COLLECTION — rtas-base is a static firmware property (set at
// boot); no component results are needed.
//
// Applicable: PPC64 only. Graceful no-op when RTAS is absent.
//
// References:
//   Documentation/devicetree/bindings/rtas/ibm,rtas.yaml
//   arch/powerpc/kernel/rtas.c: rtas_base
// ---
// <bcoles@gmail.com>

#define _POSIX_C_SOURCE 200809L

#include "../include/kasld_inference.h"

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#define RTAS_BASE_PATH "/sys/firmware/devicetree/base/rtas/rtas-base"

/* Conservative minimum kernel image size: never excludes a valid base.
 * PPC64 kernels are larger than most 32-bit arches; 16 MiB stays well
 * below the typical 50-100 MiB uncompressed size. */
#define PPC64_MIN_IMAGE_SIZE (16ul * 1024 * 1024)

#if defined(__powerpc64__)

static uint32_t read_rtas_base(void) {
  uint8_t buf[4];

  int fd = open(RTAS_BASE_PATH, O_RDONLY);
  if (fd < 0)
    return 0;

  ssize_t n = read(fd, buf, sizeof(buf));
  close(fd);

  if (n != (ssize_t)sizeof(buf))
    return 0;

  /* Device-tree properties are always big-endian. Assemble manually to
   * avoid a dependency on be32toh() which requires _BSD_SOURCE. */
  return ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16) |
         ((uint32_t)buf[2] << 8) | ((uint32_t)buf[3]);
}

#endif /* __powerpc64__ */

static void ppc64_rtas_bound_run(struct kasld_analysis_ctx *ctx) {
#if defined(__powerpc64__)

  uint32_t rtas_base = read_rtas_base();
  if (rtas_base == 0)
    return; /* RTAS absent or unreadable */

  if ((unsigned long)rtas_base <= PPC64_MIN_IMAGE_SIZE) {
    if (verbose && !quiet)
      fprintf(stdout,
              "[infer] ppc64_rtas_bound: rtas_base=%#x too small"
              " (≤ MIN_IMAGE_SIZE=%#lx); skipping\n",
              rtas_base, PPC64_MIN_IMAGE_SIZE);
    return;
  }

  if (verbose && !quiet)
    fprintf(stdout, "[infer] ppc64_rtas_bound: rtas_base=%#x\n", rtas_base);

  /* Physical ceiling: rtas_base - MIN_IMAGE_SIZE.
   * Virtual: PAGE_OFFSET + physical = kaslr_base_min + physical. */
  unsigned long kaslr_min = ctx->arch->kaslr_base_min;
  unsigned long kaslr_align = ctx->arch->kaslr_align;

  unsigned long virt_ceiling =
      kaslr_min + (unsigned long)rtas_base - PPC64_MIN_IMAGE_SIZE;

  if (kaslr_align > 0 && virt_ceiling > kaslr_min)
    virt_ceiling &= ~(kaslr_align - 1);

  if (virt_ceiling > ctx->text_base_min && virt_ceiling < ctx->text_base_max) {
    if (verbose && !quiet)
      fprintf(stdout,
              "[infer] virt_text_base_max tightened by ppc64_rtas_bound:"
              " %#lx -> %#lx (rtas_base=%#x)\n",
              ctx->text_base_max, virt_ceiling, rtas_base);
    ctx->text_base_max = virt_ceiling;
  }

#else
  (void)ctx;
#endif /* __powerpc64__ */
}

static const struct kasld_inference ppc64_rtas_bound = {
    .name = "ppc64_rtas_bound",
    .phase = KASLD_INFER_PHASE_PRE_COLLECTION,
    .run = ppc64_rtas_bound_run,
};

KASLD_REGISTER_INFERENCE(ppc64_rtas_bound);
