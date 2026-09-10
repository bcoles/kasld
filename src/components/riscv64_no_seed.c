// This file is part of KASLD - https://github.com/bcoles/kasld
//
// riscv64 KASLR-disabled detection: on a non-EFI riscv64 boot whose CPU lacks
// the 'zkr' ISA extension, the kernel sits at the compile-time default with no
// randomization when the FDT /chosen/kaslr-seed did not place it. Two runtime
// states show that: the seed cell is absent, or it is present but still holds a
// non-zero value. The kernel reads and zeroes the cell in one step when it
// consumes it (arch/riscv/kernel/pi/fdt_early.c), and the wiped blob is what is
// later unflattened into /proc/device-tree, so a visible non-zero cell proves
// the seed was never consumed and the kernel did not move. A present-but-zero
// cell is ambiguous (consumed then wiped, or a zero seed supplied) and is left
// inert. setup_vm() seeds KASLR from the Zkr `seed` CSR first and only falls
// back to the FDT property when Zkr returns 0, so the 'zkr' guard is required
// to avoid a false KASLR-off verdict on Zkr-capable hardware. On riscv64 the
// same seed feeds both virt and phys placement pre-EFI, so a non-placing seed
// disables both axes. Emits
// SF_VIRT_KASLR_DISABLED + SF_PHYS_KASLR_DISABLED. The virt pin is owned by
// riscv64_text_base, which pins Q_VIRT_IMAGE_BASE to arch_default_text_base()
// capped at CONF_INFERRED, not by virt_kaslr_disabled_pin
// (KASLR_DISABLED_PINS_VIRT_TEXT is 0 on riscv64); the phys pin is inert
// (KASLR_DISABLED_PINS_PHYS=0 — riscv64 phys placement is firmware-determined).
// riscv64 only — gated at compile time so non-riscv64 builds skip via the
// Makefile's `cc-component` wrapper instead of shipping a no-op binary.
// ---
// <bcoles@gmail.com>
#if !defined(__riscv) && !defined(__riscv__)
#error "Architecture is not supported"
#endif

#include "include/kasld/api.h"
#include "include/kasld/cli.h"
#include "include/kasld/kaslr_default.h"

KASLD_EXPLAIN(
    "On non-EFI riscv64 with no 'zkr' ISA extension, KASLR is off and "
    "the kernel sits at the compile-time default when the FDT "
    "/chosen/kaslr-seed did not place it: the cell is absent, or "
    "present but still non-zero (the kernel wipes it on consume, so a "
    "visible seed was never used). Emits SF_VIRT_KASLR_DISABLED + "
    "SF_PHYS_KASLR_DISABLED for the engine pin rules. The Zkr seed "
    "CSR takes priority over the FDT seed, so a Zkr-capable CPU is "
    "excluded from the verdict. riscv64 only.");
KASLD_META("method:parsed\n"
           "phase:inference\n"
           "discloses:facts\n"
           "source:files\n");

int main(void) {
  kasld_info("checking /proc/device-tree/chosen for a kaslr-seed ...");
  if (kasld_kaslr_disabled_text_default()) {
    kasld_emit_scalar(SF_VIRT_KASLR_DISABLED, 1, CONF_PARSED);
    kasld_emit_scalar(SF_PHYS_KASLR_DISABLED, 1, CONF_PARSED);
  }
  return 0;
}
