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
#include "include/kasld.h"
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

  printf("[.] searching dmesg for fake_numa_init() info ...\n");

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

unsigned long get_phys_addr_dmesg_log_file_fake_numa_init() {
  FILE *f;
  char *endptr;
  char *substr;
  char *addr_buf;
  char *line_buf;
  const char *path = "/var/log/dmesg";
  const char *needle = "NUMA: Faking a node at";
  unsigned long addr = 0;
  char buff[BUFSIZ];

  printf("[.] searching %s for free_area_init_node() info ...\n", path);

  f = fopen(path, "rb");
  if (f == NULL) {
    perror("[-] fopen");
    return 0;
  }

  while ((fgets(buff, BUFSIZ, f)) != NULL) {
    substr = strstr(buff, needle);
    if (substr == NULL)
      continue;

    line_buf = strtok(substr, "\n");
    if (line_buf == NULL)
      break;

    /* NUMA: Faking a node at [mem 0x0000000080200000-0x00000000bfffffff] */
    // printf("%s\n", line_buf);

    addr_buf = strstr(line_buf, " [mem ");
    if (addr_buf == NULL)
      break;

    addr = strtoul(&addr_buf[5], &endptr, 16);
    if (addr)
      break;
  }

  fclose(f);

  return addr;
}

int main() {
  unsigned long addr = get_phys_addr_dmesg_fake_numa_init();
  if (!addr)
    addr = get_phys_addr_dmesg_log_file_fake_numa_init();

  if (!addr)
    return 1;

  printf("leaked faked NUMA NODE #0 physical address: %#018lx\n", addr);

  return 0;
}
