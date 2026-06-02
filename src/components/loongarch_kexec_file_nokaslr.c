// This file is part of KASLD - https://github.com/bcoles/kasld
//
// LoongArch: detect the `kexec_file` cmdline token that disables KASLR.
//
// Detection component — does not leak an address.
//   Purpose: arch/loongarch/kernel/relocate.c kaslr_disabled() returns true
//   when the bare token "kexec_file" appears on the cmdline (word-boundary
//   match identical to the kernel's own strstr-based check). The kernel then
//   loads at the compile-time VMLINUX_LOAD_ADDRESS = KASLR_TEXT_MIN. The
//   token is inserted by the predecessor kernel on the kexec_file_load(2)
//   path, so its presence reliably signals "this boot has KASLR off."
//
// Independent of the resume= / CONFIG_HIBERNATION path covered by
// hibernation_nokaslr.c, and of the nokaslr cmdline path covered by
// proc-cmdline.c — emits SF_KASLR_DISABLED, the unified off-signal the
// engine's kaslr_disabled_pin rule consumes.
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
#include <stdio.h>

KASLD_EXPLAIN(
    "LoongArch only: arch/loongarch/kernel/relocate.c kaslr_disabled() "
    "returns true when the bare 'kexec_file' token is on /proc/cmdline, "
    "loading the kernel at VMLINUX_LOAD_ADDRESS with no KASLR. The token "
    "is inserted by the predecessor kernel on the kexec_file_load(2) path. "
    "Emits SF_KASLR_DISABLED for the engine's kaslr_disabled_pin rule. "
    "/proc/cmdline is world-readable (0444).");

KASLD_META("method:detection\n"
           "phase:inference\n"
           "addr:none\n");

int main(void) {
  if (!cmdline_has_word("kexec_file")) {
    fprintf(stderr, "[-] no 'kexec_file' token on /proc/cmdline\n");
    return 1;
  }

  printf("[.] LoongArch 'kexec_file' cmdline token present — KASLR disabled "
         "by kaslr_disabled().\n");
  kasld_emit_scalar(SF_KASLR_DISABLED, 1, CONF_PARSED);
  return 0;
}
