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
// - kernel.dmesg_restrict = 0; or CAP_SYSLOG capabilities.
//
// References:
// https://cateee.net/lkddb/web-lkddb/NUMA.html
// https://elixir.bootlin.com/linux/v6.2-rc3/source/drivers/base/arch_numa.c#L429
// https://elixir.bootlin.com/linux/v6.2-rc3/source/arch/x86/mm/numa.c#L709
// https://elixir.bootlin.com/linux/v6.2-rc3/source/arch/loongarch/kernel/numa.c#L401
// https://elixir.bootlin.com/linux/v6.2-rc3/source/mm/memblock.c#L1663
// ---
// <bcoles@gmail.com>

#define _DEFAULT_SOURCE
#include "kasld.h"
#include "include/syslog.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

unsigned long get_phys_addr_dmesg_fake_numa_init() {
  char *syslog;
  char *endptr;
  char *substr;
  char *line_buf;
  char *addr_buf;
  const char *needle = "NUMA: Faking a node at";
  int size;
  unsigned long addr = 0;

  printf("[.] searching for fake_numa_init() info ...\n");

  if (mmap_syslog(&syslog, &size))
    return 0;

  substr = strstr(syslog, needle);
  if (substr == NULL)
    return 0;

  line_buf = strtok(substr, "\n");
  if (line_buf == NULL)
    return 0;

  /* NUMA: Faking a node at [mem 0x0000000080200000-0x00000000bfffffff] */
  // printf("%s\n", line_buf);

  addr_buf = strstr(line_buf, " [mem ");
  if (addr_buf == NULL)
    return 0;

  addr = strtoul(&addr_buf[5], &endptr, 16);
  if (addr)
    return addr;

  return 0;
}

int main(int argc, char **argv) {
  unsigned long addr = get_phys_addr_dmesg_fake_numa_init();
  if (!addr)
    return 1;

  printf("leaked faked NUMA NODE #0 physical address: %#018lx\n", addr);

  return 0;
}
