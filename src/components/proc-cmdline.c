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
#include "include/kasld.h"
#include <stdio.h>

KASLD_EXPLAIN(
    "Checks /proc/cmdline for the nokaslr boot flag. If present, KASLR "
    "was disabled at boot and the default text base is the actual "
    "kernel base. /proc/cmdline is world-readable (0444);.");

KASLD_META("method:detection\n"
           "addr:none\n");

int main(void) {
  printf("[.] trying /proc/cmdline ...\n");

  if (!cmdline_has_word("nokaslr")) {
    fprintf(stderr, "[-] Kernel was not booted with nokaslr flag.\n");
    return 1;
  }

  printf("[.] Kernel booted with nokaslr flag.\n");

  unsigned long addr = (unsigned long)KERNEL_TEXT_DEFAULT;
  printf("common default kernel text for arch: %lx\n", addr);
  kasld_result(KASLD_ADDR_DEFAULT, KASLD_SECTION_NONE, addr,
               "proc-cmdline:nokaslr");

  return 0;
}
