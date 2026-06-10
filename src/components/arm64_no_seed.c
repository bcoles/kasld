// This file is part of KASLD - https://github.com/bcoles/kasld
//
// arm64 KASLR-disabled detection: on a non-EFI, device-tree-booted arm64 system
// whose FDT carries no /chosen/kaslr-seed and whose CPU lacks FEAT_RNG (RNDR),
// virtual KASLR is off and the kernel sits at KERNEL_VIRT_TEXT_DEFAULT
// (KIMAGE_VADDR + TEXT_OFFSET).
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
// axis is left unconstrained. virt_kaslr_disabled_pin pins Q_VIRT_TEXT_BASE
// (KASLR_DISABLED_PINS_VIRT_TEXT=1 on arm64).
//
// Conservative: EFI present, ACPI boot (no /proc/device-tree), a present seed
// property, or an 'rng' hwcap each cause a skip, so the assertion fires only on
// the sound non-EFI device-tree case. The EFI_RNG_PROTOCOL-unavailable collapse
// (which would surface via the FDT on EFI+DT boots) is deferred until the
// EFI-injected-seed visibility in /proc/device-tree is confirmed on hardware.
//
// arm64 only — gated at compile time so non-arm64 builds skip via the
// Makefile's `cc-component` wrapper instead of shipping a no-op binary.
// ---
// <bcoles@gmail.com>
#if !defined(__aarch64__)
#error "Architecture is not supported"
#endif

#include "include/kasld/api.h"
#include "include/kasld/kaslr_default.h"

KASLD_EXPLAIN("On non-EFI device-tree arm64 with no FDT /chosen/kaslr-seed and "
              "no FEAT_RNG (RNDR), virtual KASLR is off and the kernel sits at "
              "the compile-time default; emits SF_VIRT_KASLR_DISABLED for the "
              "engine pin rule. arm64 only.");
KASLD_META("method:parsed\n"
           "phase:inference\n");

int main(void) {
  if (kasld_kaslr_disabled_text_default())
    kasld_emit_scalar(SF_VIRT_KASLR_DISABLED, 1, CONF_PARSED);
  return 0;
}
