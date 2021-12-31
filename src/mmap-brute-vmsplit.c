// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Find start of kernel virtual address space (CONFIG_PAGE_OFFSET)
// on 32-bit systems by mapping a page at 0x10000000 increments
// across the entire 32-bit address space (until failure).
//
// Usually vmsplit is located at 3GB (0xc0000000) on 32-bit systems;
// however, embedded systems may make use of a lower vmsplit.
//
// References:
// https://cateee.net/lkddb/web-lkddb/PAGE_OFFSET.html
// https://elixir.bootlin.com/linux/v5.10/source/arch/arm/Kconfig
// https://elixir.bootlin.com/linux/v5.10/source/arch/x86/Kconfig
// ---
// <bcoles@gmail.com>

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

unsigned long find_kernel_address_space_start(void) {
  unsigned long i;
  printf("[.] searching for kernel virtual address space start ...\n");

  for (i = 0x10000000; i < 0xf0000000; i += 0x10000000) {
    if (mmap((void *)i, 0x1000, PROT_READ,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0) == MAP_FAILED)
      return i;
    munmap((void *)i, 0x1000);
  }

  printf("[-] Could not locate kernel virtual address space\n");
  return 0;
}

int main(int argc, char **argv) {
  unsigned long addr = find_kernel_address_space_start();
  if (!addr)
    return 1;

  printf("kernel virtual address start: %lx\n", addr);

  return 0;
}
