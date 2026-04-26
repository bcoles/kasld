// This file is part of KASLD - https://github.com/bcoles/kasld
//
// SWIOTLB (Software I/O TLB) prints the physical address range of the
// DMA bounce buffer pool during initialization. This is a large contiguous
// allocation within usable DRAM.
//
// Modern format (Linux ~4.17+):
//   software IO TLB: mapped [mem 0x00000000bbed0000-0x00000000bfed0000] (64MB)
//
// Older format (Linux <4.17):
//   Placing software IO TLB between 0xb7ed0000 and 0xbfed0000
//
// SWIOTLB is initialized on systems with IOMMU, VMs, or large-memory
// systems where some devices cannot address all physical memory.
//
// Leak primitive:
//   Data leaked:      physical address of SWIOTLB bounce buffer pool
//   Kernel subsystem: kernel/dma/swiotlb — swiotlb_init()
//   Data structure:   SWIOTLB buffer physical address range
//   Address type:     physical (DRAM)
//   Method:           parsed (dmesg string)
//   Status:           unfixed (printed unconditionally during boot)
//   Access check:     do_syslog() → check_syslog_permissions(); gated by
//                     dmesg_restrict
//   Source:
//   https://elixir.bootlin.com/linux/v6.1.1/source/kernel/dma/swiotlb.c
//
// Mitigations:
//   Access gated by dmesg_restrict (see dmesg.h for shared access gate
//   details). Only printed when SWIOTLB is initialized (common on VMs
//   and systems with IOMMU). On decoupled architectures, physical
//   addresses cannot derive the virtual text base.
//
// Requires:
// - kernel.dmesg_restrict = 0; or CAP_SYSLOG capabilities; or
//   readable /var/log/dmesg.
//
// References:
// https://elixir.bootlin.com/linux/v6.1.1/source/kernel/dma/swiotlb.c
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
    "Searches dmesg for SWIOTLB (Software I/O TLB) initialization "
    "messages that print the physical address of the bounce buffer "
    "pool. SWIOTLB is initialized on VMs and systems with IOMMU where "
    "some devices cannot address all physical memory. Access is gated "
    "by dmesg_restrict.");

KASLD_META("method:parsed\n"
           "addr:physical\n"
           "sysctl:dmesg_restrict>=1\n"
           "bypass:CAP_SYSLOG\n"
           "fallback:/var/log/dmesg\n");

/* Modern format: "mapped [mem 0x<start>-0x<end>]" */
static int on_mapped(const char *line, void *ctx) {
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

  return 0; /* stop after first match */
}

/* Older format: "Placing software IO TLB between 0x<start> and 0x<end>" */
static int on_placing(const char *line, void *ctx) {
  struct range_ctx *r = ctx;

  const char *p = strstr(line, "between ");
  if (!p)
    return 1;

  char *endptr;
  unsigned long start = strtoul(p + 8, &endptr, 16);
  if (!start)
    return 1;

  const char *q = strstr(endptr, "and ");
  if (!q)
    return 1;

  unsigned long end = strtoul(q + 4, &endptr, 16);
  if (!end)
    return 1;

  if (!r->lo || start < r->lo)
    r->lo = start;
  if (end > r->hi)
    r->hi = end;

  return 0; /* stop after first match */
}

int main(void) {
  struct range_ctx r = {0, 0};

  printf("[.] searching dmesg for SWIOTLB bounce buffer info ...\n");

  /* Try modern format first */
  int ds = dmesg_search("software IO TLB: mapped", on_mapped, &r);
  if (ds < 0)
    return KASLD_EXIT_NOPERM;

  /* Fall back to older format */
  if (!r.lo)
    dmesg_search("Placing software IO TLB between", on_placing, &r);

  if (!r.lo) {
    printf("[-] SWIOTLB not found in dmesg (may not be enabled)\n");
    return 0;
  }

  printf("SWIOTLB start: 0x%016lx\n", r.lo);
  kasld_result(KASLD_ADDR_PHYS, KASLD_SECTION_DRAM, r.lo, KASLD_REGION_SWIOTLB,
               NULL);

  if (r.hi && r.hi != r.lo) {
    printf("SWIOTLB end:   0x%016lx\n", r.hi);
    kasld_result(KASLD_ADDR_PHYS, KASLD_SECTION_DRAM, r.hi,
                 KASLD_REGION_SWIOTLB, NULL);
  }

#if !PHYS_VIRT_DECOUPLED
  unsigned long virt = phys_to_virt(r.lo);
  printf("possible direct-map virtual address: 0x%016lx\n", virt);
  kasld_result(KASLD_ADDR_VIRT, KASLD_SECTION_DIRECTMAP, virt,
               KASLD_REGION_SWIOTLB, NULL);
#else
  printf("note: phys and virt KASLR are decoupled on this arch; "
         "cannot derive kernel text virtual address from physical leak\n");
#endif

  return 0;
}
