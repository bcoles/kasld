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
// RISC-V:
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/riscv/mm/init.c#L127
// Kernel virtual memory layout is printed (excluding .text section),
// but requires kernel to be configured with CONFIG_DEBUG_VM.
//
// Xtensa:
// Code is still present as of 2023:
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/xtensa/mm/init.c#L134
//
// SuperH:
// Code is still present as of 2023:
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/sh/mm/init.c#L371
//
// Requires:
// - kernel.dmesg_restrict = 0; or CAP_SYSLOG capabilities.
// - CONFIG_DEBUG_VM on RISC-V systems
// ---
// <bcoles@gmail.com>

#define _DEFAULT_SOURCE
#include "kasld.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/klog.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

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
  char *addr_buf;
  char *substr;
  char *syslog;
  char *text_buf;
  char *ptr;
  char *endptr;
  int size;
  const char delim[] = " ";
  unsigned long addr = 0;
  const char *needle = " kernel memory layout:";

  if (mmap_syslog(&syslog, &size))
    return 0;

  printf("[.] searching dmesg for '%s' ...\n", needle);

  substr = strstr(syslog, needle);
  if (substr == NULL)
    return 0;

  text_buf = strstr(substr, "      .text : 0x");
  if (text_buf == NULL)
    return 0;

  addr_buf = strtok(text_buf, "\n");
  if (addr_buf == NULL)
    return 0;

  // printf("%s\n", addr_buf);

  ptr = strtok(addr_buf, delim);
  while ((ptr = strtok(NULL, delim)) != NULL) {
    addr = strtoul(&ptr[0], &endptr, 16);

    if (addr >= KERNEL_BASE_MIN && addr <= KERNEL_BASE_MAX)
      break;

    addr = 0;
  }

  return addr;
}

unsigned long search_dmesg_mem_init_lowmem() {
  char *addr_buf;
  char *substr;
  char *syslog;
  char *text_buf;
  char *ptr;
  char *endptr;
  int size;
  const char delim[] = " ";
  unsigned long addr = 0;
  const char *needle = " kernel memory layout:";

  if (mmap_syslog(&syslog, &size))
    return 0;

  printf("[.] searching dmesg for '%s' ...\n", needle);

  substr = strstr(syslog, needle);
  if (substr == NULL)
    return 0;

  text_buf = strstr(substr, "    lowmem ");
  if (text_buf == NULL)
    return 0;

  addr_buf = strtok(text_buf, "\n");
  if (addr_buf == NULL)
    return 0;

  // printf("%s\n", addr_buf);

  ptr = strtok(addr_buf, delim);
  while ((ptr = strtok(NULL, delim)) != NULL) {
    addr = strtoul(&ptr[0], &endptr, 16);

    if (addr && addr <= KERNEL_VAS_END)
      break;

    addr = 0;
  }

  return addr;
}

int main(int argc, char **argv) {
  unsigned long addr = search_dmesg_mem_init_kernel_text();
  if (addr) {
    printf("kernel text start: %lx\n", addr);
    printf("possible kernel base: %lx\n", addr & -KERNEL_ALIGN);
  }

  addr = search_dmesg_mem_init_lowmem();
  if (addr) {
    printf("kernel lowmem start: %lx\n", addr);
    if (addr < (unsigned long)KERNEL_VAS_START)
      printf("[!] warning: lowmem start %lx below configured KERNEL_VAS_START "
             "%lx\n",
             addr, (unsigned long)KERNEL_VAS_START);
  }

  return 0;
}
