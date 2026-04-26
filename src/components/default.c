// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Print architecture default kernel base text virtual address
//
// Detection component — does not leak an address.
//   Purpose: reports the compile-time default kernel text base for the
//   current architecture. If KASLR is disabled or unsupported, this is
//   the actual kernel base. No access control applies.
// ---
// <bcoles@gmail.com>

#include "include/kasld.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

KASLD_EXPLAIN(
    "Reports the compile-time default kernel text base address for the "
    "current architecture. When KASLR is disabled or unsupported, this "
    "is the actual kernel load address. No access control applies.");

KASLD_META("method:detection\n"
           "addr:none\n");

unsigned long get_kernel_addr_default() {
  return (unsigned long)KERNEL_TEXT_DEFAULT;
}

int main(void) {
  unsigned long addr = get_kernel_addr_default();
  if (!addr)
    return 1;

  /* Always emit a DEFAULT-type fallback. The "text" name distinguishes
   * this informational fallback from the "nokaslr" / "unsupported"
   * markers that detect_kaslr_state() treats as KASLR-disabled
   * indicators. */
  printf("common default kernel text for arch: %lx\n", addr);
  kasld_result(KASLD_ADDR_DEFAULT, KASLD_SECTION_NONE, addr,
               KASLD_REGION_KERNEL_TEXT, "text");

#if !KASLR_SUPPORTED
  printf("[!] KASLR is not supported on this architecture\n");
  kasld_result(KASLD_ADDR_DEFAULT, KASLD_SECTION_NONE, addr,
               KASLD_REGION_KERNEL_TEXT, "unsupported");
#endif

  return 0;
}
