// This file is part of KASLD - https://github.com/bcoles/kasld
//
// In-process KASLR-disabled detection (no privileges, KASLD_SYSROOT-aware).
//
// Read in-process by the engine bridge (engine_build_evidence) so the
// riscv64_kaslr_disabled_pin rule works OFFLINE: component children do not
// execute under nested qemu-user (no binfmt) during replay, so a
// component-emitted "nokaslr" marker is unavailable — but these access() checks
// run in-process and replay from a captured sysroot.
//
// riscv64: arch/riscv/mm/init.c setup_vm() randomises only when kaslr_seed !=
// 0. On a non-EFI system whose FDT has no /chosen/kaslr-seed, the seed stays 0
// and the kernel loads at KERNEL_LINK_ADDR (== KERNEL_VIRT_TEXT_DEFAULT) with
// no KASLR. Guards mirror riscv64_no_seed_default precisely:
//   EFI present                         -> skip (seed may come from EFI)
//   no /proc/device-tree                -> skip (FDT state unknown)
//   /chosen/kaslr-seed present          -> skip (KASLR may be active)
// Only the property-absent + non-EFI + FDT-present case asserts KASLR off.
// ---
// <bcoles@gmail.com>

#ifndef KASLD_KASLR_DEFAULT_H
#define KASLD_KASLR_DEFAULT_H

#include "sysroot.h"

#include <stdint.h>
#include <unistd.h>

/* FDT /chosen/kaslr-seed as a big-endian u64, or 0 if absent/short/wiped.
 * Read via kasld_fopen (sysroot-redirected) so it replays. */
__attribute__((unused)) static uint64_t kasld_read_fdt_kaslr_seed(void) {
  FILE *fp = kasld_fopen("/proc/device-tree/chosen/kaslr-seed", "rb");
  if (!fp)
    return 0;
  uint8_t b[8] = {0};
  size_t n = fread(b, 1, sizeof(b), fp);
  fclose(fp);
  if (n != sizeof(b))
    return 0;
  return ((uint64_t)b[0] << 56) | ((uint64_t)b[1] << 48) |
         ((uint64_t)b[2] << 40) | ((uint64_t)b[3] << 32) |
         ((uint64_t)b[4] << 24) | ((uint64_t)b[5] << 16) |
         ((uint64_t)b[6] << 8) | (uint64_t)b[7];
}

/* Returns the default kernel-text virtual base when KASLR is detected disabled
 * for this arch, or 0 when KASLR may be active / detection is not applicable.
 */
__attribute__((unused)) static unsigned long
kasld_kaslr_disabled_text_default(void) {
#if defined(__riscv) && __riscv_xlen == 64
  if (kasld_access("/sys/firmware/efi", F_OK) == 0)
    return 0; /* EFI: seed may be efi_kaslr_seed; absence of FDT prop is moot */
  if (kasld_access("/proc/device-tree", F_OK) != 0)
    return 0; /* no FDT mounted: seed state unknown */
  if (kasld_access("/proc/device-tree/chosen/kaslr-seed", F_OK) == 0)
    return 0; /* property present: KASLR may be active */
  return (unsigned long)KERNEL_VIRT_TEXT_DEFAULT;
#else
  return 0;
#endif
}

#endif /* KASLD_KASLR_DEFAULT_H */
