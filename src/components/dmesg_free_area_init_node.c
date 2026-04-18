// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Extracts physical memory addresses from mm_init boot messages in dmesg.
// Three related message groups are scanned, all from mm/mm_init.c:
//
//   Zone ranges:
//     DMA      [mem 0x0000000000001000-0x0000000000ffffff]
//     Normal   [mem 0x0000000100000000-0x000000087fffffff]
//
//   Early memory node ranges
//     node   0: [mem 0x0000000000001000-0x000000000009ffff]
//     node   0: [mem 0x0000000000100000-0x000000087e7fffff]
//
//   Initmem setup node 0 [mem 0x0000000000001000-0x000000087fffffff]
//
// All three share the same [mem 0x...-0x...] format and provide
// physical DRAM range information.
//
// On systems with a known phys->virt offset mapping, the lowest
// address may be used to identify the kernel direct-map base.
//
// Requires:
// - kernel.dmesg_restrict = 0; or CAP_SYSLOG capabilities; or
//   readable /var/log/dmesg.
//
// References:
// https://elixir.bootlin.com/linux/v6.1.1/source/mm/page_alloc.c#L7927
// https://elixir.bootlin.com/linux/v6.1.1/source/mm/mm_init.c
// https://www.kernel.org/doc/html/v5.3/vm/memory-model.html
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

/* Parse "[mem 0x<start>-0x<end>]" and update lo/hi */
static int on_mem_range(const char *line, void *ctx) {
  struct range_ctx *r = ctx;

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

  return 1; /* continue searching */
}

int main(void) {
  struct range_ctx r = {0, 0};

  printf("[.] searching dmesg for mm_init physical memory info ...\n");

  /* All three needles hit lines with the same [mem 0x...-0x...] format */
  int ds = dmesg_search("Initmem setup node ", on_mem_range, &r);
  if (ds < 0)
    return KASLD_EXIT_NOPERM;

  dmesg_search("  node ", on_mem_range, &r);

  /* Zone lines: "  DMA ", "  DMA32 ", "  Normal ", "  HighMem " */
  dmesg_search("  DMA", on_mem_range, &r);
  dmesg_search("  Normal ", on_mem_range, &r);
  dmesg_search("  HighMem ", on_mem_range, &r);

  if (!r.lo) {
    printf("[-] no physical memory ranges found in dmesg\n");
    return 0;
  }

  printf("lowest physical address:  0x%016lx\n", r.lo);
  kasld_result(KASLD_ADDR_PHYS, KASLD_SECTION_DRAM, r.lo,
               "dmesg_free_area_init_node:dram");

  if (r.hi && r.hi != r.lo) {
    printf("highest physical address: 0x%016lx\n", r.hi);
    kasld_result(KASLD_ADDR_PHYS, KASLD_SECTION_DRAM, r.hi,
                 "dmesg_free_area_init_node:dram_hi");
  }

#if !PHYS_VIRT_DECOUPLED
  unsigned long virt = phys_to_virt(r.lo);
  printf("possible direct-map virtual address: 0x%016lx\n", virt);
  kasld_result(KASLD_ADDR_VIRT, KASLD_SECTION_DIRECTMAP, virt,
               "dmesg_free_area_init_node:directmap");
#else
  printf("note: phys and virt KASLR are decoupled on this arch; "
         "cannot derive kernel text virtual address from physical leak\n");
#endif

  return 0;
}
