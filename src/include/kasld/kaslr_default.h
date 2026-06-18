// This file is part of KASLD - https://github.com/bcoles/kasld
//
// In-process KASLR-disabled detection (no privileges, KASLD_SYSROOT-aware).
//
// Read in-process by the engine bridge (engine_build_evidence) so the checks
// honour KASLD_SYSROOT redirection. They run in-process rather than as a
// component because component children fork without access to in-process
// sysroot state. The resolved facts feed virt_kaslr_disabled_pin and
// phys_kaslr_disabled_pin.
//
// riscv64: arch/riscv/mm/init.c setup_vm() randomizes only when kaslr_seed !=
// 0. On a non-EFI system whose FDT has no /chosen/kaslr-seed, the seed stays 0
// and the kernel loads at KERNEL_LINK_ADDR (== KERNEL_VIRT_TEXT_DEFAULT) with
// no KASLR. Guards mirror riscv64_no_seed_default precisely:
//   EFI present                         -> skip (seed may come from EFI)
//   no /proc/device-tree                -> skip (FDT state unknown)
//   /chosen/kaslr-seed present          -> skip (KASLR may be active)
// Only the property-absent + non-EFI + FDT-present case asserts KASLR off.
//
// arm64: arch/arm64/kernel/pi/kaslr_early.c reads /chosen/kaslr-seed and zeroes
// it in place (property kept), so an absent property means no seed was supplied
// and map_kernel.c leaves kaslr_offset = 0 (virtual KASLR off). When the FDT
// seed is absent the kernel falls back to the RNDR instruction, so the same
// riscv64 guards apply PLUS a /proc/cpuinfo 'rng' (FEAT_RNG) check: only the
// property-absent + non-EFI + FDT-present + no-RNDR case asserts KASLR off, and
// only the virtual axis (arm64 physical placement is
// EFI/bootloader-determined).
// ---
// <bcoles@gmail.com>

#ifndef KASLD_KASLR_DEFAULT_H
#define KASLD_KASLR_DEFAULT_H

#include "sysroot.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* FDT /chosen/kaslr-seed as a big-endian u64, or 0 if absent/short/wiped.
 * Read via kasld_fopen so it honours KASLD_SYSROOT redirection. */
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

#if defined(__aarch64__)
/* arm64 only: 1 if the 'rng' hwcap (FEAT_RNG / RNDR) is present in
 * /proc/cpuinfo, OR if cpuinfo cannot be read (conservative — when in doubt,
 * assume RNDR could have seeded KASLR, so do not assert KASLR off).
 * Read via kasld_fopen so it honours KASLD_SYSROOT redirection. */
__attribute__((unused)) static int kasld_cpu_feature_rng_present(void) {
  FILE *fp = kasld_fopen("/proc/cpuinfo", "r");
  if (!fp)
    return 1; /* unknown -> assume present */
  char line[8192];
  int present = 0;
  while (fgets(line, sizeof(line), fp)) {
    if (strncmp(line, "Features", 8) != 0)
      continue;
    char *colon = strchr(line, ':');
    char *tok = strtok(colon ? colon + 1 : line, " \t\n");
    while (tok) {
      if (strcmp(tok, "rng") == 0) {
        present = 1;
        break;
      }
      tok = strtok(NULL, " \t\n");
    }
    break; /* only the Features line carries hwcaps */
  }
  fclose(fp);
  return present;
}
#endif

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
#elif defined(__aarch64__)
  if (kasld_access("/sys/firmware/efi", F_OK) == 0)
    return 0; /* EFI seed path not confirmed visible in FDT: skip (conservative)
               */
  if (kasld_access("/proc/device-tree", F_OK) != 0)
    return 0; /* ACPI boot: no FDT signal */
  if (kasld_access("/proc/device-tree/chosen/kaslr-seed", F_OK) == 0)
    return 0; /* property present: a seed existed, KASLR may be active */
  if (kasld_cpu_feature_rng_present())
    return 0; /* RNDR may have seeded KASLR despite the absent FDT seed */
  return (unsigned long)KERNEL_VIRT_TEXT_DEFAULT;
#else
  return 0;
#endif
}

#endif /* KASLD_KASLR_DEFAULT_H */
