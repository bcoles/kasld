// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Inference plugin: PPC64 OPAL base → text range ceiling (PRE_COLLECTION)
//
// OPAL (OpenPOWER Abstraction Layer) occupies a physically contiguous region
// in the first few GiB of physical memory on POWER8/9/10 systems. Its base
// address is stored in the device tree at:
//
//   /sys/firmware/devicetree/base/ibm,opal/opal-base-address
//
// as a big-endian 64-bit integer (world-readable on OPAL systems).
//
// The kernel image must fit entirely below OPAL in physical memory:
//
//   phys_text_end ≤ opal_base
//   phys_text_start + kernel_image_size ≤ opal_base
//   phys_text_start ≤ opal_base - kernel_image_size
//
// On PPC64, PHYS_OFFSET = 0 and TEXT_OFFSET = 0, so
// phys_to_virt(x) = PAGE_OFFSET | x = PAGE_OFFSET + x. The virtual ceiling:
//
//   text_base_max = min(text_base_max,
//                       PAGE_OFFSET + opal_base - kernel_image_size)
//
// PPC64 has no mainline KASLR; the kernel loads at PAGE_OFFSET + 0.
// This plugin constrains result validation rather than narrowing a KASLR
// slot window: any leaked virtual text address above the ceiling is invalid.
//
// Phase: PRE_COLLECTION — opal-base-address is a static firmware property
// (set at boot); no component results are needed.
//
// Applicable: PPC64 only. Graceful no-op when OPAL node is absent.
//
// References:
//   Documentation/devicetree/bindings/opal/
//   arch/powerpc/platforms/powernv/opal.c: opal_base
// ---
// <bcoles@gmail.com>

#define _POSIX_C_SOURCE 200809L

#include "../include/kasld_inference.h"

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#define OPAL_BASE_PATH                                                         \
  "/sys/firmware/devicetree/base/ibm,opal/opal-base-address"

/* Conservative minimum kernel image size: never excludes a valid base.
 * PPC64 kernels are larger than most 32-bit arches; 16 MiB stays well
 * below the typical 50-100 MiB uncompressed size. */
#define PPC64_MIN_IMAGE_SIZE (16ul * 1024 * 1024)

#if defined(__powerpc64__)

static uint64_t read_opal_base(void) {
  uint8_t buf[8];

  int fd = open(OPAL_BASE_PATH, O_RDONLY);
  if (fd < 0)
    return 0;

  ssize_t n = read(fd, buf, sizeof(buf));
  close(fd);

  if (n != (ssize_t)sizeof(buf))
    return 0;

  /* Device-tree properties are always big-endian. Assemble manually to
   * avoid a dependency on be64toh() which requires _BSD_SOURCE. */
  return ((uint64_t)buf[0] << 56) | ((uint64_t)buf[1] << 48) |
         ((uint64_t)buf[2] << 40) | ((uint64_t)buf[3] << 32) |
         ((uint64_t)buf[4] << 24) | ((uint64_t)buf[5] << 16) |
         ((uint64_t)buf[6] << 8) | ((uint64_t)buf[7]);
}

#endif /* __powerpc64__ */

static void ppc64_opal_bound_run(struct kasld_analysis_ctx *ctx) {
#if defined(__powerpc64__)

  uint64_t opal_base = read_opal_base();
  if (opal_base == 0)
    return; /* OPAL absent or unreadable */

  /* Sanity: OPAL must be above the minimum image size and within the first
   * 4 GiB (constraint of current POWER hardware). Values outside this range
   * indicate a corrupt or absent node; skip rather than apply a wrong bound. */
  if (opal_base <= PPC64_MIN_IMAGE_SIZE || opal_base > 0xffffffff) {
    if (verbose && !quiet)
      fprintf(stdout,
              "[infer] ppc64_opal_bound: opal_base=%#lx"
              " failed sanity check; skipping\n",
              (unsigned long)opal_base);
    return;
  }

  if (verbose && !quiet)
    fprintf(stdout, "[infer] ppc64_opal_bound: opal_base=%#lx\n",
            (unsigned long)opal_base);

  /* Physical ceiling: opal_base - MIN_IMAGE_SIZE.
   * Virtual: PAGE_OFFSET + physical = kaslr_base_min + physical. */
  unsigned long kaslr_min = ctx->arch->kaslr_base_min;
  unsigned long kaslr_align = ctx->arch->kaslr_align;

  unsigned long virt_ceiling =
      kaslr_min + (unsigned long)opal_base - PPC64_MIN_IMAGE_SIZE;

  if (kaslr_align > 0 && virt_ceiling > kaslr_min)
    virt_ceiling &= ~(kaslr_align - 1);

  if (virt_ceiling > ctx->text_base_min && virt_ceiling < ctx->text_base_max) {
    if (verbose && !quiet)
      fprintf(stdout,
              "[infer] virt_text_base_max tightened by ppc64_opal_bound:"
              " %#lx -> %#lx (opal_base=%#lx)\n",
              ctx->text_base_max, virt_ceiling, (unsigned long)opal_base);
    ctx->text_base_max = virt_ceiling;
  }

#else
  (void)ctx;
#endif /* __powerpc64__ */
}

static const struct kasld_inference ppc64_opal_bound = {
    .name = "ppc64_opal_bound",
    .phase = KASLD_INFER_PHASE_PRE_COLLECTION,
    .run = ppc64_opal_bound_run,
};

KASLD_REGISTER_INFERENCE(ppc64_opal_bound);
