// This file is part of KASLD - https://github.com/bcoles/kasld
//
// arm64 KASLR-disabled detection: on a device-tree-booted arm64 system whose
// FDT carries no /chosen/kaslr-seed and whose CPU lacks FEAT_RNG (RNDR),
// virtual KASLR is off and the kernel sits at the un-slid image base.
//
// arch/arm64/kernel/pi/kaslr_early.c get_kaslr_seed() reads /chosen/kaslr-seed
// via fdt_getprop_w and zeroes it in place (`*prop = 0`), keeping the property
// — so an ABSENT property means no seed was ever supplied, and map_kernel.c
// leaves kaslr_offset = 0 (kaslr.c keeps __kaslr_is_enabled false). When the
// FDT seed is absent the kernel falls back to the RNDR instruction, so KASLR is
// only off when the CPU also lacks the 'rng' hwcap.
//
// Emits SF_VIRT_KASLR_DISABLED only — single axis. arm64 physical placement is
// EFI/bootloader-determined and independent of the virtual seed, so the phys
// axis is left unconstrained. The signal is consumed by arm64_text_base, not by
// virt_kaslr_disabled_pin (KASLR_DISABLED_PINS_VIRT_TEXT is 0 on arm64): the
// base is KIMAGE_VADDR exactly, but the module-region size that places it is
// unknown -- and the base carries the physical residue described below -- so
// the sound emission is an upper bound at the largest candidate plus that
// residue, rather than a C_EQUALS pin.
//
// The verdict covers an EFI boot as well as a bare device-tree one, because the
// seed cell answers for both. drivers/firmware/efi/libstub/fdt.c writes
// /chosen/kaslr-seed only under `IS_ENABLED(CONFIG_RANDOMIZE_BASE) &&
// !efi_nokaslr` and only when efi_get_random_bytes() returned EFI_SUCCESS, so
// an absent cell on an EFI boot proves the stub obtained no randomness for the
// seed path. EFI being present says nothing on its own.
//
// What the un-slid base is NOT is KIMAGE_VADDR exactly. A zero seed still
// leaves the displacement's low bits set from the image's physical load
// address, so the base carries a residue below MIN_KIMG_ALIGN. Every cause that
// makes the stub give up also sets efi_nokaslr before the allocation, which
// takes efi_get_kimg_min_align() back to MIN_KIMG_ALIGN and makes the residue
// zero -- but a bootloader that ignores the 2 MiB boot protocol is relocated
// rather than refused, so the consuming rule carries the term and this
// component asserts only the signal.
//
// Conservative: an ACPI boot (no /proc/device-tree), a present-and-zero seed
// property, a seed cell this vantage cannot traverse to, or an 'rng' hwcap each
// cause a skip.
//
// arm64 only — gated at compile time so non-arm64 builds skip via the
// Makefile's `cc-component` wrapper instead of shipping a no-op binary.
// ---
// <bcoles@gmail.com>
#if !defined(__aarch64__)
#error "Architecture is not supported"
#endif

#include "include/kasld/api.h"
#include "include/kasld/cli.h"
#include "include/kasld/kaslr_default.h"

KASLD_EXPLAIN(
    "On a device-tree arm64 system with no FDT /chosen/kaslr-seed and "
    "no FEAT_RNG (RNDR), virtual KASLR is off and the kernel sits at "
    "the un-slid image base; emits SF_VIRT_KASLR_DISABLED for the "
    "engine rule that caps the base. The EFI stub writes the seed "
    "cell only when it obtained randomness, so an absent cell "
    "answers for an EFI boot too. arm64 only.");
KASLD_META("method:parsed\n"
           "phase:inference\n"
           "discloses:facts\n"
           "source:files\n");

int main(void) {
  kasld_info("checking /proc/device-tree/chosen for a kaslr-seed and the CPU "
             "for FEAT_RNG ...");
  if (kasld_kaslr_disabled_text_default())
    kasld_emit_scalar(SF_VIRT_KASLR_DISABLED, 1, CONF_PARSED);
  return 0;
}
