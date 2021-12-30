// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Search kernel log for virtual kernel memory layout.
//
// The `mem_init()` function prints the layout of the kernel segments
// to the kernel debug log, including kernel vas start and .text start.
//
// x86:
// https://elixir.bootlin.com/linux/v5.6.19/source/arch/x86/mm/init_32.c
// Removed in kernel 5.7-rc1 on 2020-03-06:
// https://github.com/torvalds/linux/commit/681ff0181bbfb183e32bc6beb6ec076304470479#diff-3bfd62fd3cf596dbff9091b59a7168cdf8fb93ed342a633bd37fac9633e96025
//
// arm:
// https://elixir.bootlin.com/linux/v5.0.21/source/arch/arm/mm/init.c
// Removed in kernel 5.1-rc1 on 2019-03-16:
// https://github.com/torvalds/linux/commit/0be288630752e6358d02eba7b283c1783a5c7c38#diff-0ac47f754483fd3333a760d4285c7197ba5820b1ad1899f192270cd6a3a1e309
//
// arm64:
// https://elixir.bootlin.com/linux/v4.15.18/source/arch/arm64/mm/init.c
// Removed in kernel v4.16-rc1 on 2018-01-16:
// https://github.com/torvalds/linux/commit/071929dbdd865f779a89ba3f1e06ba8d17dd3743
//
// x86_64:
// This code was never present on x86_64.
//
// m68k:
// Due to a bug, this code always printed "ptrval", instead of segment
// addresses, and was later removed in kernel 4.17-rc1 on 2018-03-19:
// https://github.com/torvalds/linux/commit/31833332f79876366809ccb0614fee7df8afe9fe
//
// PA-RISC:
// https://elixir.bootlin.com/linux/v4.16-rc3/source/arch/parisc/mm/init.c
// Code was commented out in kernel 4.16-rc4 on 2018-03-02:
// https://github.com/torvalds/linux/commit/fd8d0ca2563151204f3fe555dc8ca4bcfe8677a3
//
// Requires:
// - kernel.dmesg_restrict = 0 (Default on Ubuntu systems);
//   or CAP_SYSLOG capabilities.
// ---
// <bcoles@gmail.com>

#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/klog.h>
#include <sys/mman.h>
#include <sys/types.h>
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

unsigned long search_dmesg_mem_init_kernel_text() {
  char *syslog;
  int size;
  unsigned long addr = 0;

  if (mmap_syslog(&syslog, &size))
    return 0;

  char * needle = " kernel memory layout:";
  printf("[.] searching dmesg for '%s' ...\n", needle);

  char *substr = (char *)memmem(&syslog[0], size, needle, strlen(needle));
  if (substr == NULL)
    return 0;

  char *text_buf = strstr(substr, "      .text : 0x");
  if (text_buf == NULL)
    return 0;

  char *addr_buf = strtok(text_buf, "\n");
  if (addr_buf == NULL)
    return 0;

  char delim[] = " ";

  char *ptr = strtok(addr_buf, delim);
  while ((ptr = strtok(NULL, delim)) != NULL) {
    char *endptr = &ptr[strlen(ptr)];
    addr = (unsigned long)strtoull(&ptr[0], &endptr, 16);

    if (addr >= KERNEL_BASE_MIN && addr <= KERNEL_BASE_MAX)
      break;

    addr = 0;
  }

  return addr;
}

int main(int argc, char **argv) {
  unsigned long addr = search_dmesg_mem_init_kernel_text();
  if (!addr)
    return 1;

  printf("kernel text start: %lx\n", addr);
  printf("possible kernel base: %lx\n", addr &~ KERNEL_BASE_MASK);

  return 0;
}
