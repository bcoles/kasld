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
  if (!seed)
    return 0;

#if defined(__riscv) && __riscv_xlen == 64
  /* setup_vm() seeds KASLR from the Zkr `seed` CSR FIRST and only falls back to
   * the FDT /chosen/kaslr-seed when Zkr returns 0. On a Zkr-capable CPU the FDT
   * cell may therefore be present and non-zero yet have played NO part in the
   * slot selection, so the seed does not determine the base. The only consumer,
   * riscv64_fdt_kaslr_seed, turns this fact into a deterministic slot pin /
   * ceiling on Q_VIRT_IMAGE_BASE — feeding it a seed the kernel did not use
   * would place a guaranteed constraint that excludes the true base. Suppress
   * the fact unless the CPU lacks 'zkr' (the helper fails closed: an unreadable
   * /proc/cpuinfo counts as present). This mirrors riscv64_no_seed's guard. */
  if (kasld_cpu_feature_zkr_present())
    return 0;
#endif

  kasld_emit_scalar(SF_FDT_KASLR_SEED, seed, CONF_PARSED);
  return 0;
}
