// This file is part of KASLD - https://github.com/bcoles/kasld
//
// CMA/DMA reserved memory pool physical addresses from dmesg.
//
// The kernel prints physical addresses when creating CMA, DMA, and
// restricted DMA memory pools, and when finalizing CMA reservations:
//
//   Reserved memory: created CMA memory pool at 0x000000007a000000, size 96 MiB
//   Reserved memory: created DMA memory pool at 0x0000000070000000, size 32 MiB
//   Reserved memory: created restricted DMA pool at 0x0000000060000000, size 64
//   MiB cma: Reserved 256 MiB at 0x00000000f0000000 on node -1
//
// These are common on ARM/ARM64/embedded and on systems with DMA-constrained
// devices. Less common on x86 desktop but present on many x86 servers.
//
// Requires:
// - kernel.dmesg_restrict = 0; or CAP_SYSLOG capabilities; or
//   readable /var/log/dmesg.
//
// References:
// https://elixir.bootlin.com/linux/v6.6/source/kernel/dma/contiguous.c
// https://elixir.bootlin.com/linux/v6.6/source/kernel/dma/coherent.c
// https://elixir.bootlin.com/linux/v6.6/source/kernel/dma/swiotlb.c
// https://elixir.bootlin.com/linux/v6.6/source/mm/cma.c
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

static void update_range(struct range_ctx *r, unsigned long addr) {
  if (!addr)
    return;
  if (!r->lo || addr < r->lo)
    r->lo = addr;
  if (addr > r->hi)
    r->hi = addr;
}

/* "Reserved memory: created CMA memory pool at 0x..., size N MiB"
 * "Reserved memory: created DMA memory pool at 0x..., size N MiB"
 * "Reserved memory: created restricted DMA pool at 0x..., size N MiB" */
static int on_reserved_pool(const char *line, void *ctx) {
  struct range_ctx *r = ctx;

  const char *p = strstr(line, " at ");
  if (!p)
    return 1;

  unsigned long addr = strtoul(p + 4, NULL, 16);
  if (addr)
    printf("[.] Reserved memory pool at 0x%016lx\n", addr);

  update_range(r, addr);
  return 1; /* continue — may be multiple pools */
}

/* "cma: Reserved N MiB at 0x..."
 * v5.x:  "cma: Reserved 64 MiB at 0x00000000b4000000"
 * v6.x+: "cma: Reserved 256 MiB at 0x00000000f0000000 on node -1" */
static int on_cma_reserved(const char *line, void *ctx) {
  struct range_ctx *r = ctx;

  const char *p = strstr(line, " at ");
  if (!p)
    return 1;

  unsigned long addr = strtoul(p + 4, NULL, 16);
  if (!addr)
    return 1;

  printf("[.] CMA reservation at 0x%016lx\n", addr);

  update_range(r, addr);
  return 1; /* continue — may be multiple reservations */
}

int main(void) {
  struct range_ctx r = {0, 0};

  printf("[.] searching dmesg for CMA/DMA reserved memory pools ...\n");

  int ds = dmesg_search("Reserved memory: created", on_reserved_pool, &r);
  if (ds < 0)
    return KASLD_EXIT_NOPERM;

  dmesg_search("cma: Reserved", on_cma_reserved, &r);

  if (!r.lo) {
    printf("[-] No CMA/DMA reserved memory pools found in dmesg\n");
    return 0;
  }

  printf("lowest reserved pool:  0x%016lx\n", r.lo);
  kasld_result(KASLD_ADDR_PHYS, KASLD_SECTION_DRAM, r.lo,
               "dmesg_cma_reserved:lo");

  if (r.hi && r.hi != r.lo) {
    printf("highest reserved pool: 0x%016lx\n", r.hi);
    kasld_result(KASLD_ADDR_PHYS, KASLD_SECTION_DRAM, r.hi,
                 "dmesg_cma_reserved:hi");
  }

#if !PHYS_VIRT_DECOUPLED
  unsigned long virt = phys_to_virt(r.lo);
  printf("possible direct-map virtual address: 0x%016lx\n", virt);
  kasld_result(KASLD_ADDR_VIRT, KASLD_SECTION_DIRECTMAP, virt,
               "dmesg_cma_reserved:directmap");
#else
  printf("note: phys and virt KASLR are decoupled on this arch; "
         "cannot derive kernel text virtual address from physical leak\n");
#endif

  return 0;
}
