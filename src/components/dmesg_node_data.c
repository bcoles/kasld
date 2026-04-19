// This file is part of KASLD - https://github.com/bcoles/kasld
//
// alloc_node_data() prints the physical address of the NODE_DATA per-node
// NUMA metadata allocation to dmesg on NUMA-aware kernels:
//
//   NODE_DATA(0) allocated [mem 0x33ffd5000-0x33fffffff]
//
// The NODE_DATA structure is allocated at the top of each NUMA node's
// usable memory, so it reveals a physical address near the end of DRAM.
//
// Most x86_64 distribution kernels have NUMA enabled, so this message
// appears even on single-socket systems (using dummy_numa_init).
//
// Leak primitive:
//   Data leaked:      physical address of NODE_DATA allocation (top of DRAM)
//   Kernel subsystem: mm/numa, arch/x86/mm/numa — alloc_node_data()
//   Data structure:   NODE_DATA pgdat allocation (physical address range)
//   Address type:     physical (DRAM)
//   Method:           parsed (dmesg string)
//   Status:           unfixed (printed unconditionally on NUMA systems)
//
// Mitigations:
//   Access gated by dmesg_restrict (see dmesg.h for shared access gate
//   details). Printed unconditionally on NUMA-capable kernels. On
//   decoupled architectures, physical addresses cannot derive the
//   virtual text base.
//
// Requires:
// - kernel.dmesg_restrict = 0; or CAP_SYSLOG capabilities; or
//   readable /var/log/dmesg.
//
// References:
// https://elixir.bootlin.com/linux/v6.12/source/mm/numa.c#L27
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/x86/mm/numa.c#L185
// https://elixir.bootlin.com/linux/v6.1.1/source/drivers/base/arch_numa.c#L384
// ---
// <bcoles@gmail.com>

#define _GNU_SOURCE
#include "include/dmesg.h"
#include "include/kasld.h"
#include "include/kasld_internal.h"
#include "include/kasld_types.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define range_ctx addr_range

KASLD_EXPLAIN(
    "Searches dmesg for NODE_DATA() allocation messages that print the "
    "physical address of NUMA node data structures allocated at the top "
    "of each node's memory. This reveals the physical DRAM ceiling. "
    "Access is gated by dmesg_restrict.");

KASLD_META("method:parsed\n"
           "addr:physical\n"
           "sysctl:dmesg_restrict>=1\n"
           "bypass:CAP_SYSLOG\n"
           "fallback:/var/log/dmesg\n");

static int on_match(const char *line, void *ctx) {
  struct range_ctx *r = ctx;

  /* NODE_DATA(0) allocated [mem 0x33ffd5000-0x33fffffff] */
  const char *p = strstr(line, "[mem ");
  if (!p)
    return 1;

  char *endptr;
  unsigned long start = strtoul(p + 5, &endptr, 16);
  if (!start || *endptr != '-')
    return 1;

  unsigned long end = strtoul(endptr + 1, &endptr, 16);
  if (!end)
    return 1;

  if (!r->lo || start < r->lo)
    r->lo = start;
  if (end > r->hi)
    r->hi = end;

  return 1; /* continue — may be multiple NUMA nodes */
}

int main(void) {
  struct range_ctx r = {0, 0};

  printf("[.] searching dmesg for NODE_DATA allocations ...\n");
  int ds = dmesg_search("NODE_DATA(", on_match, &r);

  if (!r.hi) {
    printf("[-] no NODE_DATA allocation info found in dmesg\n");
    if (ds < 0)
      return KASLD_EXIT_NOPERM;
    return 0;
  }

  printf("lowest NODE_DATA physical address:  0x%016lx\n", r.lo);
  printf("highest NODE_DATA physical address: 0x%016lx\n", r.hi);

  kasld_result(KASLD_ADDR_PHYS, KASLD_SECTION_DRAM, r.hi,
               "dmesg_node_data:dram");

#if !PHYS_VIRT_DECOUPLED
  unsigned long virt = phys_to_virt(r.hi);
  printf("possible direct-map virtual address: 0x%016lx\n", virt);
  kasld_result(KASLD_ADDR_VIRT, KASLD_SECTION_DIRECTMAP, virt,
               "dmesg_node_data:directmap");
#else
  printf("note: phys and virt KASLR are decoupled on this arch; "
         "cannot derive kernel text virtual address from physical leak\n");
#endif

  return 0;
}
