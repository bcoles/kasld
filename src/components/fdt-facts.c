// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Emit SF_FDT_KASLR_SEED: the FDT /chosen/kaslr-seed value (riscv64), which a
// rule turns into a deterministic text-base pin on non-EFI boots.
// ---
// <bcoles@gmail.com>
#include "include/kasld/api.h"
#include "include/kasld/kaslr_default.h"

KASLD_EXPLAIN("Reads the flattened device tree /chosen/kaslr-seed and emits it "
              "as a scalar fact. On non-EFI riscv64 the kernel derives its "
              "KASLR offset deterministically from this seed. No privileges.");
KASLD_META("method:parsed\n"
           "phase:inference\n");

int main(void) {
  unsigned long seed = (unsigned long)kasld_read_fdt_kaslr_seed();
  if (seed)
    kasld_emit_scalar(SF_FDT_KASLR_SEED, seed, CONF_PARSED);
  return 0;
}
