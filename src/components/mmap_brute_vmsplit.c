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
//   Method:           brute (mmap sweep across the 32-bit address space)
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
#include "include/kasld/api.h"
#include "include/kasld/cli.h"
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

KASLD_META("method:brute\n"
           "phase:probing\n"
           "live:1\n"
           "addr:virtual\n");

static unsigned long find_kernel_address_space_start(void) {
  unsigned long i;
  kasld_info("searching 32-bit address space for kernel virtual address space "
             "start ...");

  for (i = 0x10000000; i < 0xf0000000; i += 0x10000000) {
    if (mmap((void *)i, PAGE_SIZE, PROT_READ,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0) == MAP_FAILED)
      return i;
    munmap((void *)i, PAGE_SIZE);
  }

  kasld_err("Could not locate kernel virtual address space");
  return 0;
}

int main(void) {
  if (kasld_skip_live_probe("VMSPLIT mmap"))
    return 0;
  /* Live mmap probe of the running VA space. */
  unsigned long addr = find_kernel_address_space_start();
  if (!addr)
    return 0;

  kasld_info("kernel virtual address start: %lx", addr);
  kasld_result_base(KASLD_TYPE_VIRT, REGION_PAGE_OFFSET, addr, NULL,
                    CONF_HEURISTIC);

#if KERNEL_VIRT_VAS_START /* vacuous where VAS_START is 0 (s390) */
  if (addr < (unsigned long)KERNEL_VIRT_VAS_START)
    kasld_err("warning: virtual address start %lx below configured "
              "KERNEL_VIRT_VAS_START %lx",
              addr, (unsigned long)KERNEL_VIRT_VAS_START);
#endif

  return 0;
}
