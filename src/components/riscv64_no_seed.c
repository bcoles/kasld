// This file is part of KASLD - https://github.com/bcoles/kasld
//
// riscv64 KASLR-disabled detection: on a non-EFI riscv64 boot whose FDT carries
// no /chosen/kaslr-seed AND whose CPU lacks the 'zkr' ISA extension, the kernel
// sits at the compile-time default with no randomization. setup_vm() seeds
// KASLR from the Zkr `seed` CSR first and only falls back to the FDT property
// when Zkr returns 0, so the 'zkr' guard is required to avoid a false KASLR-off
// verdict on Zkr-capable hardware. On riscv64 the same seed feeds both virt and
// phys placement pre-EFI, so absence of the seed disables both axes. Emits
// SF_VIRT_KASLR_DISABLED + SF_PHYS_KASLR_DISABLED; virt_kaslr_disabled_pin
// pins Q_VIRT_IMAGE_BASE (KASLR_DISABLED_PINS_VIRT_TEXT=1 on riscv64); the phys
// pin is inert (KASLR_DISABLED_PINS_PHYS=0 — riscv64 phys placement is
// firmware-determined).
// riscv64 only — gated at compile time so non-riscv64 builds skip via the
// Makefile's `cc-component` wrapper instead of shipping a no-op binary.
// ---
// <bcoles@gmail.com>
#if !defined(__riscv) && !defined(__riscv__)
#error "Architecture is not supported"
#endif

#include "include/kasld/api.h"
#include "include/kasld/kaslr_default.h"

KASLD_EXPLAIN("On non-EFI riscv64 with no FDT /chosen/kaslr-seed and no 'zkr' "
              "ISA extension, KASLR is off and the kernel sits at the "
              "compile-time default; emits SF_VIRT_KASLR_DISABLED + "
              "SF_PHYS_KASLR_DISABLED for the engine pin rules. The Zkr seed "
              "CSR takes priority over the FDT seed, so a Zkr-capable CPU is "
              "excluded from the verdict. riscv64 only.");
KASLD_META("method:parsed\n"
           "phase:inference\n");

int main(void) {
  if (kasld_kaslr_disabled_text_default()) {
    kasld_emit_scalar(SF_VIRT_KASLR_DISABLED, 1, CONF_PARSED);
    kasld_emit_scalar(SF_PHYS_KASLR_DISABLED, 1, CONF_PARSED);
  }
  return 0;
}
