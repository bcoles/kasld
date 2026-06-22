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
#include "include/kasld/api.h"
#include "include/kasld/cli.h"
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
           "phase:inference\n"
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

  kasld_info("searching dmesg for SWIOTLB bounce buffer info ...");

  /* Try modern format first */
  int ds = dmesg_search("software IO TLB: mapped", on_mapped, &r);
  if (ds < 0)
    return KASLD_EXIT_NOPERM;

  /* Fall back to older format */
  if (!r.lo)
    dmesg_search("Placing software IO TLB between", on_placing, &r);

  if (!r.lo) {
    kasld_err("SWIOTLB not found in dmesg (may not be enabled)");
    return 0;
  }

  kasld_info("SWIOTLB start: 0x%016lx", r.lo);

  /* The SWIOTLB pool is a single contiguous reservation (the search stops at
   * the first match), so emit [start, end] as one bounded range: the engine
   * excludes the whole forbidden band (phys_reservation_exclude), which a pair
   * of disconnected interior points cannot drive. Not a covering — this lone
   * reservation says nothing about the surrounding RAM, so range, not extent.
   */
  if (r.hi && r.hi > r.lo) {
    kasld_info("SWIOTLB end:   0x%016lx", r.hi);
    kasld_result_range(KASLD_TYPE_PHYS, REGION_SWIOTLB, r.lo, r.hi, NULL,
                       CONF_PARSED);
  } else {
    kasld_result_sample(KASLD_TYPE_PHYS, REGION_SWIOTLB, r.lo, NULL,
                        CONF_PARSED);
  }

#ifdef phys_to_directmap_virt
  unsigned long virt = phys_to_directmap_virt(r.lo);
  kasld_info("possible direct-map virtual address: 0x%016lx", virt);
  kasld_result_sample(KASLD_TYPE_VIRT, REGION_DIRECTMAP, virt, NULL,
                      CONF_PARSED);
#else
  kasld_info("note: phys and virt KASLR are decoupled on this arch; "
             "cannot derive kernel text virtual address from physical leak");
#endif

  return 0;
}
