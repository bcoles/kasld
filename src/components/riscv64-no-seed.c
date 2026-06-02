// This file is part of KASLD - https://github.com/bcoles/kasld
//
// riscv64 KASLR-disabled detection: on a non-EFI riscv64 boot whose FDT carries
// no /chosen/kaslr-seed, the kernel sits at the compile-time default with no
// randomisation. Emits SF_KASLR_DISABLED; the engine's kaslr_disabled_pin rule
// computes the per-arch default text base and pins Q_VIRT_TEXT_BASE.
// riscv64 only — gated at compile time so non-riscv64 builds skip via the
// Makefile's `cc-component` wrapper instead of shipping a no-op binary.
// ---
// <bcoles@gmail.com>
#if !defined(__riscv) && !defined(__riscv__)
#error "Architecture is not supported"
#endif

#include "include/kasld/api.h"
#include "include/kasld/kaslr_default.h"

KASLD_EXPLAIN("On non-EFI riscv64 with no FDT /chosen/kaslr-seed, KASLR is off "
              "and the kernel sits at the compile-time default; emits "
              "SF_KASLR_DISABLED for the engine pin rule. riscv64 only.");
KASLD_META("method:parsed\n"
           "phase:inference\n");

int main(void) {
  if (kasld_kaslr_disabled_text_default())
    kasld_emit_scalar(SF_KASLR_DISABLED, 1, CONF_PARSED);
  return 0;
}
