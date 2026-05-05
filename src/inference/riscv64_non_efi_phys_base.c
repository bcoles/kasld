// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Inference plugin: exact physical base on non-EFI riscv64 (POST_COLLECTION)
//
// On riscv64 systems without EFI firmware (OpenSBI + U-Boot), the kernel has
// no physical KASLR. OpenSBI loads the kernel at exactly:
//
//   phys_base = DRAM_BASE + TEXT_OFFSET
//
// where TEXT_OFFSET = 2 MiB is a hard-coded firmware constant (PMD-aligned
// kernel placement). When the DRAM base is observable from collected PHYS/DRAM
// results, this collapses the physical KASLR range to a single point:
//
//   phys_base_min = phys_base_max = min(PHYS/DRAM results) + TEXT_OFFSET
//
// This is a stronger result than the general dram_bound.c decoupled path,
// which only raises phys_base_min (align-up). Here we also pin phys_base_max
// because physical KASLR is absent and TEXT_OFFSET is exact.
//
// EFI detection:
//   /sys/firmware/efi exists → EFI boot: the EFI firmware allocates memory
//   for the kernel image; the physical load address is firmware-determined
//   and is not necessarily DRAM_BASE + TEXT_OFFSET. Skip pinning.
//
//   /sys/firmware/efi absent → no EFI: OpenSBI+U-Boot path; no physical
//   KASLR; load address is DRAM_BASE + TEXT_OFFSET exactly. Pin both bounds.
//
// Soundness:
//   The only assumption is that the minimum observed PHYS/DRAM result equals
//   the platform DRAM base. If components emit multiple DRAM ranges, the
//   minimum is the lowest physical memory address — exactly DRAM_BASE. Adding
//   TEXT_OFFSET gives the kernel load address.
//
//   Safety net: the `phys_exact >= phys_base_min && phys_exact <=
//   phys_base_max` guard prevents widening the bounds if DRAM results are
//   absent, malformed, or inconsistent with the arch constants.
//
// Note: the compile-time PHYS_OFFSET (0x80000000) is a QEMU virt default.
// On platforms with DRAM at a different physical base, PHYS/DRAM results give
// the true base and this plugin automatically adapts — provided the derived
// phys_exact falls within the established bounds.
//
// Phase: POST_COLLECTION — requires PHYS/DRAM results from components.
// ---
// <bcoles@gmail.com>

#define _POSIX_C_SOURCE 200809L

#include "../include/kasld_inference.h"

#include <limits.h>
#include <string.h>
#include <unistd.h>

static void riscv64_nonEFI_phys_base_run(struct kasld_analysis_ctx *ctx) {
#if (defined(__riscv) || defined(__riscv__)) && __riscv_xlen == 64
  /* On EFI-booted systems the load address is firmware-determined, not
   * necessarily DRAM_BASE + TEXT_OFFSET. Only pin on non-EFI (OpenSBI). */
  if (access("/sys/firmware/efi", F_OK) == 0)
    return;

  /* Find the minimum physical DRAM address across all results. */
  unsigned long pdram_lo = ULONG_MAX;
  for (size_t i = 0; i < ctx->result_count; i++) {
    const struct result *r = &ctx->results[i];
    if (r->type != KASLD_ADDR_PHYS)
      continue;
    if (strcmp(r->section, KASLD_SECTION_DRAM) != 0)
      continue;
    if (r->raw < pdram_lo)
      pdram_lo = r->raw;
  }

  if (pdram_lo == ULONG_MAX)
    return;

  /* Kernel is placed at DRAM_BASE + TEXT_OFFSET exactly. */
  unsigned long phys_exact = pdram_lo + TEXT_OFFSET;

  /* Guard: only apply if the derived value is within current bounds. */
  if (phys_exact < ctx->phys_base_min || phys_exact > ctx->phys_base_max)
    return;

  ctx->phys_base_min = phys_exact;
  ctx->phys_base_max = phys_exact;
#else
  (void)ctx;
#endif /* riscv64 */
}

static const struct kasld_inference riscv64_nonEFI_phys_base = {
    .name = "riscv64_nonEFI_phys_base",
    .phase = KASLD_INFER_PHASE_POST_COLLECTION,
    .run = riscv64_nonEFI_phys_base_run,
};

KASLD_REGISTER_INFERENCE(riscv64_nonEFI_phys_base);
