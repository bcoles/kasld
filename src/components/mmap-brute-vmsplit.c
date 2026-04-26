// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Find start of kernel virtual address space (CONFIG_PAGE_OFFSET)
// on 32-bit systems by mapping a page at 0x10000000 increments
// across the entire 32-bit address space (until failure).
//
// Usually vmsplit is located at 3GB (0xc0000000) on 32-bit systems;
// however, embedded systems may make use of a lower vmsplit.
//
// Leak primitive:
//   Data leaked:      kernel/user address space split point
//   (CONFIG_PAGE_OFFSET) Kernel subsystem: mm — mmap syscall (virtual address
//   space probing) Data structure:   kernel virtual address space boundary
//   Address type:     virtual (kernel VAS start)
//   Method:           heuristic (mmap brute-force across 32-bit address space)
//   Status:           unfixed (fundamental to 32-bit VM split design)
//   Access check:     none (mmap syscall, unprivileged)
//   Source:           N/A (architectural inference — no specific kernel
//                     function)
//
// Mitigations:
//   None — 32-bit address space split is a fundamental architectural
//   property. No runtime sysctl can restrict access. Only applies to
//   32-bit systems.
//
// References:
// https://cateee.net/lkddb/web-lkddb/PAGE_OFFSET.html
// https://elixir.bootlin.com/linux/v5.10/source/arch/arm/Kconfig
// https://elixir.bootlin.com/linux/v5.10/source/arch/x86/Kconfig
// ---
// <bcoles@gmail.com>

#define _GNU_SOURCE
#include "include/kasld.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

KASLD_EXPLAIN("Probes the 32-bit address space by attempting mmap at 256 MiB "
              "increments until mapping fails. The first unmappable address is "
              "the kernel/user virtual address split (CONFIG_PAGE_OFFSET). "
              "32-bit only. No privilege or sysctl gate; the split is a "
              "fundamental architectural property.");

KASLD_META("method:heuristic\n"
           "addr:virtual\n");

unsigned long find_kernel_address_space_start(void) {
  unsigned long i;
  printf("[.] searching 32-bit address space for kernel virtual address space "
         "start ...\n");

  for (i = 0x10000000; i < 0xf0000000; i += 0x10000000) {
    if (mmap((void *)i, PAGE_SIZE, PROT_READ,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0) == MAP_FAILED)
      return i;
    munmap((void *)i, PAGE_SIZE);
  }

  fprintf(stderr, "[-] Could not locate kernel virtual address space\n");
  return 0;
}

int main(void) {
  unsigned long addr = find_kernel_address_space_start();
  if (!addr)
    return 0;

  printf("kernel virtual address start: %lx\n", addr);
  kasld_result(KASLD_ADDR_VIRT, KASLD_SECTION_PAGEOFFSET, addr,
               KASLD_REGION_PAGE_OFFSET, NULL);

  if (addr < (unsigned long)KERNEL_VAS_START)
    printf("[!] warning: virtual address start %lx below configured "
           "KERNEL_VAS_START %lx\n",
           addr, (unsigned long)KERNEL_VAS_START);

  return 0;
}
