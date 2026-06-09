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
#include "include/kasld/cli.h"
#include <stdio.h>

KASLD_EXPLAIN(
    "Checks /proc/cmdline for the nokaslr boot flag. If present, KASLR "
    "was disabled at boot and the default text base is the actual "
    "kernel base. /proc/cmdline is world-readable (0444);.");

KASLD_META("method:detection\n"
           "phase:inference\n"
           "addr:none\n");

int main(void) {
  kasld_info("trying /proc/cmdline ...");

  if (!cmdline_has_word("nokaslr")) {
    kasld_err("Kernel was not booted with nokaslr flag.");
    return 1;
  }

  kasld_info("Kernel booted with nokaslr flag.");

  /* `nokaslr` disables both virtual and physical KASLR axes on every arch
   * that honours it (the kernel's boot stub treats the cmdline flag before
   * either axis randomises). Emit both facts; virt_kaslr_disabled_pin and
   * phys_kaslr_disabled_pin each gate by its arch macro
   * (KASLR_DISABLED_PINS_VIRT_TEXT / KASLR_DISABLED_PINS_PHYS) + window-
   * containment to decide whether to pin. */
  kasld_emit_scalar(SF_VIRT_KASLR_DISABLED, 1, CONF_PARSED);
  kasld_emit_scalar(SF_PHYS_KASLR_DISABLED, 1, CONF_PARSED);

  return 0;
}
