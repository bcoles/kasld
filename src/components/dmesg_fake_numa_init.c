// This file is part of KASLD - https://github.com/bcoles/kasld
//
// fake_numa_init() / dummy_numa_init() prints memblock_start_of_DRAM()
// physical address of the first memblock to dmesg on systems which do not
// support Non-Uniform Memory Access (NUMA).
//
// On systems with a known phys->virt offset mapping, this may be used to
// identify the kernel virtual address region used for direct mapping.
//
// NUMA support may be disabled in BIOS or via Linux kernel command line with
// the `acpi=off` flag. Systems without Advanced Configuration and Power
// Interface (ACPI) do not support NUMA.
//
// Leak primitive:
//   Data leaked:      physical DRAM base address (memblock_start_of_DRAM)
//   Kernel subsystem: mm/numa, arch/x86/mm/numa — dummy_numa_init()
//   Data structure:   memblock_start_of_DRAM() return value (physical address)
//   Address type:     physical (DRAM)
//   Method:           parsed (dmesg string)
//   Status:           unfixed (printed unconditionally on non-NUMA systems)
//
// Mitigations:
//   Access gated by dmesg_restrict (see dmesg.h for shared access gate
//   details). Only printed on systems without NUMA support. On decoupled
//   architectures, physical addresses cannot derive the virtual text base.
//
// Requires:
// - kernel.dmesg_restrict = 0; or CAP_SYSLOG capabilities; or
//   readable /var/log/dmesg.
//
// References:
// https://cateee.net/lkddb/web-lkddb/NUMA.html
// https://elixir.bootlin.com/linux/v6.2-rc3/source/drivers/base/arch_numa.c#L429
// https://elixir.bootlin.com/linux/v6.2-rc3/source/arch/x86/mm/numa.c#L709
// https://elixir.bootlin.com/linux/v6.2-rc3/source/arch/loongarch/kernel/numa.c#L401
// https://elixir.bootlin.com/linux/v6.2-rc3/source/mm/memblock.c#L1663
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
    "Searches dmesg for fake_numa_init() or dummy_numa_init() messages "
    "that print memblock_start_of_DRAM() on non-NUMA systems. This "
    "reveals the physical base address of system RAM. Access is gated "
    "by dmesg_restrict.");

KASLD_META("method:parsed\n"
           "addr:physical\n"
           "sysctl:dmesg_restrict>=1\n"
           "bypass:CAP_SYSLOG\n"
           "fallback:/var/log/dmesg\n");

static int on_match(const char *line, void *ctx) {
  unsigned long *result = ctx;

  /* NUMA: Faking a node at [mem 0x0000000080200000-0x00000000bfffffff] */
  const char *p = strstr(line, " [mem ");
  if (!p)
    return 1;

  char *endptr;
  unsigned long addr = strtoul(p + 5, &endptr, 16);
  if (addr && addr < KERNEL_VAS_END) {
    *result = addr;
    return 0;
  }
  return 1;
}

int main(void) {
  unsigned long addr = 0;

  printf("[.] searching dmesg for fake_numa_init() info ...\n");
  int ds = dmesg_search("NUMA: Faking a node at", on_match, &addr);

  if (!addr) {
    if (ds < 0)
      return KASLD_EXIT_NOPERM;
    printf("[-] fake_numa_init info not found in dmesg\n");
    return 0;
  }

  printf("leaked faked NUMA NODE #0 physical address: 0x%016lx\n", addr);
  kasld_result(KASLD_ADDR_PHYS, KASLD_SECTION_DRAM, addr,
               "dmesg_fake_numa_init:dram");

#if !PHYS_VIRT_DECOUPLED
  unsigned long virt = phys_to_virt(addr);
  printf("possible direct-map virtual address: 0x%016lx\n", virt);
  kasld_result(KASLD_ADDR_VIRT, KASLD_SECTION_DIRECTMAP, virt,
               "dmesg_fake_numa_init:directmap");
#else
  printf("note: phys and virt KASLR are decoupled on this arch; "
         "cannot derive kernel text virtual address from physical leak\n");
#endif

  return 0;
}
