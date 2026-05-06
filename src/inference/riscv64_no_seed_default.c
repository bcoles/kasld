// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Inference plugin: riscv64 KASLR disabled when FDT kaslr-seed absent
// (PRE_COLLECTION)
//
// On riscv64, arch/riscv/mm/init.c setup_vm() randomises only when the seed
// is non-zero:
//
//   kaslr_seed = get_kaslr_seed_dt(dtb_va);
//   if (IS_ENABLED(CONFIG_EFI))
//       kaslr_seed ^= efi_kaslr_seed;
//   if (!kaslr_seed)
//       return;   // no KASLR; kernel loads at KERNEL_LINK_ADDR
//
// On a non-EFI system where the FDT has no /chosen/kaslr-seed property
// (U-Boot not configured to provide entropy, e.g. missing
// CONFIG_BOARD_RNG_SEED), get_kaslr_seed_dt() returns 0. With CONFIG_EFI
// not enabled (non-EFI build) there is no efi_kaslr_seed contribution,
// so kaslr_seed stays 0 and the kernel loads at the compile-time default
// KERNEL_LINK_ADDR = 0xffffffff80000000.
//
// Detection guards (in order):
//   1. access("/sys/firmware/efi", F_OK) == 0     → EFI present; skip.
//      On EFI systems kaslr_seed = fdt_seed ^ efi_seed; absence of the FDT
//      property alone does not disable KASLR.
//   2. access("/proc/device-tree", F_OK) != 0     → no FDT mounted; seed
//      state unknown; skip.
//   3. access("/proc/device-tree/chosen/kaslr-seed", F_OK) == 0 → property
//      present; KASLR may be active; fall back to riscv64_fdt_kaslr_seed.
//
// Trigger only on ENOENT (property absent), not on all-zero content.
// If the kernel zeroes the property after consuming it (seed-wiping, as
// noted in sysfs_devicetree_initrd.c), all-zero content is ambiguous
// ("active seed wiped" vs "no seed ever provided") and is unsafe for
// pinning without real-host confirmation.
//
// TODO: once seed-wiping behaviour is verified on a real riscv64 host, an
// additional trigger can be added for the all-zero case.
//
// Phase: PRE_COLLECTION — access() checks need no component results.
// Applicable: riscv64 only. See riscv64 H8.
// ---
// <bcoles@gmail.com>

#define _POSIX_C_SOURCE 200809L

#include "../include/kasld_inference.h"

#include <errno.h>
#include <stdio.h>
#include <unistd.h>

static void riscv64_no_seed_default_run(struct kasld_analysis_ctx *ctx) {
#if (defined(__riscv) || defined(__riscv__)) && __riscv_xlen == 64

  /* On EFI systems the combined seed (fdt ^ efi) can be non-zero even
   * when the FDT property is absent; pinning would be wrong. */
  if (access("/sys/firmware/efi", F_OK) == 0)
    return;

  /* FDT not mounted: seed state unknown. */
  if (access("/proc/device-tree", F_OK) != 0)
    return;

  /* Property present: KASLR may be active; fall back to riscv64_fdt_kaslr_seed.
   */
  if (access("/proc/device-tree/chosen/kaslr-seed", F_OK) == 0)
    return;

  /* access() failed: only pin on ENOENT (property definitively absent).
   * Any other error (EACCES, EIO) leaves seed state unknown. */
  if (errno != ENOENT)
    return;

  /* Property absent (ENOENT): get_kaslr_seed_dt() returned 0; KASLR disabled.
   */

  const unsigned long link_addr = (unsigned long)KERNEL_LINK_ADDR;

  /* Safety guard: only pin if KERNEL_LINK_ADDR is within the established
   * window. */
  if (link_addr < ctx->text_base_min || link_addr > ctx->text_base_max)
    return;

  if (verbose && !quiet)
    fprintf(stderr,
            "[layout] text_base pinned by riscv64_no_seed_default:"
            " [%#lx, %#lx] -> %#lx"
            " (non-EFI, FDT kaslr-seed absent -> KASLR disabled)\n",
            ctx->text_base_min, ctx->text_base_max, link_addr);

  ctx->text_base_min = link_addr;
  ctx->text_base_max = link_addr;

#else
  (void)ctx;
#endif /* riscv64 */
}

static const struct kasld_inference riscv64_no_seed_default = {
    .name = "riscv64_no_seed_default",
    .phase = KASLD_INFER_PHASE_PRE_COLLECTION,
    .run = riscv64_no_seed_default_run,
};

KASLD_REGISTER_INFERENCE(riscv64_no_seed_default);
