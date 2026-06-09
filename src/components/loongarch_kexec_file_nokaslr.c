// This file is part of KASLD - https://github.com/bcoles/kasld
//
// LoongArch: detect the `kexec_file` cmdline token that disables KASLR.
//
// Detection component — does not leak an address.
//   Purpose: arch/loongarch/kernel/relocate.c kaslr_disabled() returns true
//   when the bare token "kexec_file" appears on the cmdline (word-boundary
//   match identical to the kernel's own strstr-based check). The kernel then
//   loads at the compile-time VMLINUX_LOAD_ADDRESS = KASLR_VIRT_TEXT_MIN. The
//   token is inserted by the predecessor kernel on the kexec_file_load(2)
//   path, so its presence reliably signals "this boot has KASLR off."
//
// Independent of the resume= / CONFIG_HIBERNATION path covered by
// hibernation_nokaslr.c, and of the nokaslr cmdline path covered by
// proc_cmdline.c — emits SF_VIRT_KASLR_DISABLED, the unified off-signal the
// engine's virt_/phys_kaslr_disabled_pin rule consumes.
//
// LoongArch only — gated at compile time so non-LoongArch builds skip via
// the Makefile's `cc-component` wrapper instead of shipping an empty
// main(). (MIPS, x86, PowerPC kaslr_disabled() do not check kexec_file.)
//
// References:
// https://elixir.bootlin.com/linux/v6.17/source/arch/loongarch/kernel/relocate.c#L176
// ---
// <bcoles@gmail.com>

#if !defined(__loongarch__)
#error "Architecture is not supported"
#endif

#include "include/cmdline.h"
#include "include/kasld/api.h"
#include "include/kasld/cli.h"
#include <stdio.h>

KASLD_EXPLAIN(
    "LoongArch only: arch/loongarch/kernel/relocate.c kaslr_disabled() "
    "returns true when the bare 'kexec_file' token is on /proc/cmdline, "
    "loading the kernel at VMLINUX_LOAD_ADDRESS with no KASLR. The token "
    "is inserted by the predecessor kernel on the kexec_file_load(2) path. "
    "Emits SF_VIRT_KASLR_DISABLED + SF_PHYS_KASLR_DISABLED for the "
    "engine's virt_kaslr_disabled_pin and phys_kaslr_disabled_pin rules. "
    "/proc/cmdline is world-readable (0444).");

KASLD_META("method:detection\n"
           "phase:inference\n"
           "addr:none\n");

int main(void) {
  if (!cmdline_has_word("kexec_file")) {
    kasld_err("no 'kexec_file' token on /proc/cmdline");
    return 1;
  }

  kasld_info("LoongArch 'kexec_file' cmdline token present — KASLR disabled "
             "by kaslr_disabled().");
  /* LoongArch kexec_file disables both axes via arch/loongarch's
   * relocate.c kaslr_disabled() short-circuit; the kernel lands at
   * VMLINUX_LOAD_ADDRESS (the compile-time virt + phys default). Both
   * KASLR_DISABLED_PINS_VIRT_TEXT and KASLR_DISABLED_PINS_PHYS are 1 on
   * loongarch64, so both pins fire. */
  kasld_emit_scalar(SF_VIRT_KASLR_DISABLED, 1, CONF_PARSED);
  kasld_emit_scalar(SF_PHYS_KASLR_DISABLED, 1, CONF_PARSED);
  return 0;
}
