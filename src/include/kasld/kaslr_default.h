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
// The FDT /chosen/kaslr-seed cell answers for an EFI boot as well as a
// device-tree one, which is why neither branch consults /sys/firmware/efi. The
// EFI stub is the writer: drivers/firmware/efi/libstub/fdt.c sets the property
// only under `IS_ENABLED(CONFIG_RANDOMIZE_BASE) && !efi_nokaslr` and only when
// efi_get_random_bytes() returned EFI_SUCCESS. So an absent cell on an EFI boot
// is evidence about the STUB, not about the vantage: no randomness reached the
// seed path. Presence of EFI itself says nothing either way, and testing for it
// cost the whole EFI case for no soundness gain.
//
// riscv64: arch/riscv/mm/init.c setup_vm() computes
// `virt_offset = (kaslr_seed % nr_pos) * PMD_SIZE` and then
// `virt_addr = KERNEL_LINK_ADDR + virt_offset`, so a zero seed puts the kernel
// at KERNEL_LINK_ADDR (== KERNEL_VIRT_TEXT_DEFAULT) EXACTLY. Nothing else feeds
// the virtual offset -- the physical placement is a separate field and does not
// reach it. Guards mirror riscv64_no_seed_default precisely:
//   no /proc/device-tree                -> skip (FDT state unknown)
//   /chosen/kaslr-seed present and zero -> skip (consumed, or a zero supplied)
//   'zkr' ISA extension present         -> skip (Zkr CSR may have seeded KASLR)
// setup_vm() seeds from the Zkr `seed` CSR first and only falls back to the FDT
// property when Zkr returns 0, so an absent FDT seed alone is not sufficient.
//
// arm64: arch/arm64/kernel/pi/kaslr_early.c reads /chosen/kaslr-seed and zeroes
// it in place (property kept), so the cell's VALUE carries the signal exactly
// as on riscv64: a non-zero cell was never consumed and the kernel did not
// slide, an absent cell means none was ever supplied, a zero cell is ambiguous
// and stays inert. The kernel falls back to RNDR when it
// consumes no FDT seed, so the same guards apply PLUS a /proc/cpuinfo 'rng'
// (FEAT_RNG) check, and only the virtual axis is asserted (arm64 physical
// placement is EFI/bootloader-determined).
//
// arm64 differs from riscv64 in one way that does NOT reach this file: a zero
// seed leaves the displacement's low bits set from the image's physical load
// address, so the base is KIMAGE_VADDR plus a residue below MIN_KIMG_ALIGN
// rather than KIMAGE_VADDR exactly. The residue is zero for every cause that
// makes the stub give up -- efi_nokaslr is set before the allocation, so
// efi_get_kimg_min_align() returns MIN_KIMG_ALIGN -- but not for a bootloader
// that ignores the 2 MiB boot protocol. The consuming rule carries the term;
// this file reports the signal, not the window.
// ---
// <bcoles@gmail.com>

#ifndef KASLD_KASLR_DEFAULT_H
#define KASLD_KASLR_DEFAULT_H

#include "sysroot.h"

#include <errno.h>
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

#if defined(__riscv) && __riscv_xlen == 64
/* riscv64 only: 1 if the 'zkr' ISA extension (Zkr entropy-source CSR) is
 * present in any /proc/cpuinfo 'isa' line, OR if cpuinfo cannot be read
 * (conservative — when in doubt, assume Zkr could have seeded KASLR, so do not
 * assert KASLR off). setup_vm() seeds KASLR from the Zkr `seed` CSR FIRST and
 * only falls back to the FDT /chosen/kaslr-seed when Zkr returns 0, so an
 * absent FDT seed alone does not mean KASLR is off on a Zkr-capable CPU.
 * Multi-letter RISC-V ISA extensions are underscore-delimited, so 'zkr' is its
 * own token. Read via kasld_fopen so it honours KASLD_SYSROOT redirection. */
__attribute__((unused)) static int kasld_cpu_feature_zkr_present(void) {
  FILE *fp = kasld_fopen("/proc/cpuinfo", "r");
  if (!fp)
    return 1; /* unknown -> assume present */
  char line[8192];
  int present = 0;
  while (fgets(line, sizeof(line), fp)) {
    if (strncmp(line, "isa", 3) != 0)
      continue;
    char *colon = strchr(line, ':');
    char *tok = strtok(colon ? colon + 1 : line, " \t\n_");
    while (tok) {
      if (strcmp(tok, "zkr") == 0) {
        present = 1;
        break;
      }
      tok = strtok(NULL, " \t\n_");
    }
    if (present)
      break;
  }
  fclose(fp);
  return present;
}
#endif

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
  if (kasld_access("/proc/device-tree", F_OK) != 0)
    return 0; /* no FDT mounted: seed state unknown */
  if (kasld_access("/proc/device-tree/chosen/kaslr-seed", F_OK) == 0) {
    /* Seed cell present. The kernel reads and zeroes the property in one step
       when it consumes it (arch/riscv/kernel/pi/fdt_early.c get_kaslr_seed),
       and that already-wiped blob is what setup_arch unflattens into
       /proc/device-tree. So a cell still holding a NON-ZERO value proves the
       kernel never consumed it: no FDT-seed randomization happened and the
       kernel sits at the compile-time default. A zero cell is ambiguous
       (consumed-then-wiped, or a zero seed supplied) and stays inert; an
       unreadable cell reads back as zero here, which likewise stays inert. */
    if (kasld_read_fdt_kaslr_seed() == 0)
      return 0;
  } else if (errno != ENOENT) {
    return 0; /* cell present but untraversable to this vantage (EACCES on an
                 unprivileged traversal): its presence can't be ruled out, so
                 skip. Only a genuine ENOENT is the no-seed signal — see the
                 arm64 branch below for why this must not depend on privilege.
               */
  }
  /* Reached iff the cell is genuinely absent (ENOENT) or present and non-zero:
     both mean the FDT seed did not place this kernel. The Zkr seed CSR takes
     priority and leaves the FDT cell untouched, so a Zkr-capable CPU may have
     randomized regardless — do not assert KASLR off there. */
  if (kasld_cpu_feature_zkr_present())
    return 0;
  return (unsigned long)KERNEL_VIRT_TEXT_DEFAULT;
#elif defined(__aarch64__)
  if (kasld_access("/proc/device-tree", F_OK) != 0)
    return 0; /* ACPI boot: no FDT signal */
  if (kasld_access("/proc/device-tree/chosen/kaslr-seed", F_OK) == 0) {
    /* Seed cell present. kaslr_early_init consumes it through get_kaslr_seed,
       which zeroes the cell in place, and that already-wiped blob is what
       setup_arch unflattens into /proc/device-tree. A cell still holding a
       NON-ZERO value therefore proves the kernel never consumed it -- it
       returns before get_kaslr_seed on a nokaslr command line, and is not
       called at all without CONFIG_RANDOMIZE_BASE -- so no FDT-seed
       randomization happened and the kernel did not slide. Not the same as
       sitting at the compile-time default: see the physical-residue note in
       the file header.
       A zero cell is ambiguous (consumed-then-wiped, or a zero seed supplied)
       and stays inert; an unreadable cell reads back as zero here, which
       likewise stays inert. */
    if (kasld_read_fdt_kaslr_seed() == 0)
      return 0;
  } else if (errno != ENOENT) {
    return 0; /* cell present but untraversable to this vantage: access()
                 returns EACCES when an unprivileged caller cannot traverse to
                 it (e.g. an SELinux-confined shell on Android), which is NOT
                 evidence of absence. Treating it as absent would make the
                 KASLR-disabled verdict depend on the caller's privilege. Only
                 a genuine ENOENT is the no-seed signal. */
  }
  if (kasld_cpu_feature_rng_present())
    return 0; /* RNDR may have seeded KASLR despite no FDT seed being consumed.
                 Kept on the visible-seed path too, though arm64 consults the
                 FDT ahead of RNDR so a non-zero cell rules the instruction out
                 as well: declining costs a narrowing, asserting wrongly costs
                 soundness. */
  return (unsigned long)KERNEL_VIRT_TEXT_DEFAULT;
#else
  return 0;
#endif
}

#endif /* KASLD_KASLR_DEFAULT_H */
