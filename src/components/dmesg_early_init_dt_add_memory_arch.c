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
// Leak primitive:
//   Data leaked:      physical DRAM base address (memblock range boundary)
//   Kernel subsystem: drivers/of/fdt — early_init_dt_add_memory_arch()
//   Data structure:   memblock range (physical base address)
//   Address type:     physical (DRAM)
//   Method:           parsed (dmesg string)
//   Status:           unfixed (printed unconditionally when range is truncated)
//
// Mitigations:
//   Access gated by dmesg_restrict (see dmesg.h for shared access gate
//   details). Only printed when FDT memory range extends below usable
//   DRAM start. On decoupled architectures, physical addresses cannot
//   derive the virtual text base.
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

KASLD_EXPLAIN(
    "Searches dmesg for 'Ignoring memory range' messages from the FDT "
    "(flattened device tree) memory setup. These messages print the "
    "physical address of memory ranges that exceed the kernel's "
    "addressable limit. Common on ARM/ARM64/RISC-V systems with more "
    "RAM than the virtual address space can map. Access is gated by "
    "dmesg_restrict.");

KASLD_META("method:parsed\n"
           "addr:physical\n"
           "sysctl:dmesg_restrict>=1\n"
           "bypass:CAP_SYSLOG\n"
           "fallback:/var/log/dmesg\n");

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
