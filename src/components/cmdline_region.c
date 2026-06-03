// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Emit the bootloader-supplied kernel cmdline as a PHYS REGION_CMDLINE extent.
// The kernel placement code (arch/x86/boot/compressed/kaslr.c
// MEM_AVOID_CMDLINE) refuses to overlap this region, so cmdline_phys_exclude
// turns it into a C_EXCLUDE on the physical text base. x86 only — boot_params
// is x86-specific.
// ---
// <bcoles@gmail.com>
#define _POSIX_C_SOURCE 200809L /* pread() in boot_params.h */
#include "include/kasld/api.h"
#include "include/kasld/boot_params.h"

KASLD_EXPLAIN("Reads the physical address and length of the kernel cmdline "
              "from /sys/kernel/boot_params/data and emits the spanned region. "
              "The cmdline-phys-exclude rule treats it as a forbidden band for "
              "the kernel physical base. x86 only.");
KASLD_META("method:parsed\n"
           "phase:inference\n");

int main(void) {
  unsigned long ptr = kasld_read_boot_cmd_line_ptr();
  unsigned long size = kasld_read_boot_cmdline_size();
  if (ptr == 0 || size == 0)
    return 0;
  /* boot_params.hdr.cmdline_size is the bootloader-reported capacity; cap it
   * defensively at a sane upper bound to avoid a runaway exclude. */
  if (size > 0x10000ul) /* 64 KiB — far above any real cmdline */
    return 0;
  kasld_result_range(KASLD_TYPE_PHYS, REGION_CMDLINE, ptr, ptr + size - 1, NULL,
                     CONF_PARSED);
  return 0;
}
