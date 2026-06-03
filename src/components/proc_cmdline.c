// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Check kernel command line /proc/cmdline for nokaslr flag.
//
// Detection component — does not leak an address.
//   Purpose: checks whether the kernel was booted with the nokaslr
//   flag, which disables KASLR. If set, the default text base is the
//   actual kernel base. /proc/cmdline is world-readable (0444).
//
// References:
// https://www.kernel.org/doc/html/v6.1/admin-guide/kernel-parameters.html
// ---
// <bcoles@gmail.com>

#include "include/cmdline.h"
#include "include/kasld/api.h"
#include <stdio.h>

KASLD_EXPLAIN(
    "Checks /proc/cmdline for the nokaslr boot flag. If present, KASLR "
    "was disabled at boot and the default text base is the actual "
    "kernel base. /proc/cmdline is world-readable (0444);.");

KASLD_META("method:detection\n"
           "phase:inference\n"
           "addr:none\n");

int main(void) {
  printf("[.] trying /proc/cmdline ...\n");

  if (!cmdline_has_word("nokaslr")) {
    fprintf(stderr, "[-] Kernel was not booted with nokaslr flag.\n");
    return 1;
  }

  printf("[.] Kernel booted with nokaslr flag.\n");

  /* Off-detection signal; the engine's kaslr_disabled_pin rule computes the
   * per-arch default text base and pins Q_VIRT_TEXT_BASE (gated by
   * KASLR_DISABLED_PINS_TEXT + window-containment). The renderer's baseline
   * is emitted independently by the `default` component. */
  kasld_emit_scalar(SF_KASLR_DISABLED, 1, CONF_PARSED);

  return 0;
}
