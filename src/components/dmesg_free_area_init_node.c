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
// Leak primitive:
//   Data leaked:      physical DRAM address ranges (zone/node boundaries)
//   Kernel subsystem: mm/mm_init — zone/node initialization messages
//   Data structure:   zone ranges, node ranges, initmem setup (physical)
//   Address type:     physical (DRAM)
//   Method:           parsed (dmesg string)
//   Status:           unfixed (printed unconditionally during boot)
//   Access check:     do_syslog() → check_syslog_permissions(); gated by
//                     dmesg_restrict
//   Source:
//   https://elixir.bootlin.com/linux/v6.1.1/source/mm/mm_init.c
//
// Mitigations:
//   Access gated by dmesg_restrict (see dmesg.h for shared access gate
//   details). Messages printed unconditionally. On decoupled architectures,
//   physical addresses cannot derive the virtual text base.
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
#include "include/kasld/api.h"
#include "include/kasld/cli.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define range_ctx addr_range

KASLD_EXPLAIN(
    "Extracts physical DRAM address ranges from mm_init zone setup "
    "messages in dmesg. Messages like 'Zone ranges', 'early memory "
    "node ranges', and '[mem ...]' report physical address boundaries "
    "for each NUMA node. Access is gated by dmesg_restrict.");

KASLD_META("method:parsed\n"
           "phase:inference\n"
           "addr:physical\n"
           "sysctl:dmesg_restrict>=1\n"
           "bypass:CAP_SYSLOG\n"
           "fallback:/var/log/dmesg\n");

/* Parse "[mem 0x<start>-0x<end>]" and update lo/hi.
 *
 * Distinguishes parse failure from a real value of 0 via endptr: phys 0 is a
 * legitimate "Initmem setup node 0 [mem 0x0-...]" lower edge on systems where
 * RAM starts at the bottom of the address space. Rejecting it would drop the
 * node/initmem ranges and leave only the higher zone lines (e.g. HighMem on
 * ppc32 starting at 0x30000000), producing an unsound non-zero floor. */
static int on_mem_range(const char *line, void *ctx) {
  struct range_ctx *r = ctx;

  const char *p = strstr(line, "[mem ");
  if (!p)
    return 1;

  const char *sp = p + 5;
  char *endptr;
  unsigned long start = strtoul(sp, &endptr, 16);
  if (endptr == sp || *endptr != '-')
    return 1; /* genuine parse failure (no hex digits or missing '-') */

  const char *ep = endptr + 1;
  unsigned long end = strtoul(ep, &endptr, 16);
  if (endptr == ep || end <= start)
    return 1; /* genuine parse failure or zero-length range */

  /* r->hi is the uninitialized sentinel (a valid range always has end > 0);
   * r->lo doubles as a stored value, so checking r->lo == 0 would conflate
   * "no range seen yet" with "lowest range starts at phys 0". */
  if (r->hi == 0 || start < r->lo)
    r->lo = start;
  if (end > r->hi)
    r->hi = end;

  return 1; /* continue searching */
}

int main(void) {
  struct range_ctx r = {0, 0};

  kasld_info("searching dmesg for mm_init physical memory info ...");

  /* All three needles hit lines with the same [mem 0x...-0x...] format */
  int ds = dmesg_search("Initmem setup node ", on_mem_range, &r);
  if (ds < 0)
    return KASLD_EXIT_NOPERM;

  dmesg_search("  node ", on_mem_range, &r);

  /* Zone lines: "  DMA ", "  DMA32 ", "  Normal ", "  HighMem " */
  dmesg_search("  DMA", on_mem_range, &r);
  dmesg_search("  Normal ", on_mem_range, &r);
  dmesg_search("  HighMem ", on_mem_range, &r);

  if (r.hi == 0) {
    /* r.hi == 0 is the "no valid range seen" sentinel — see on_mem_range. */
    kasld_err("no physical memory ranges found in dmesg");
    return 0;
  }

  /* dmesg's zone/node ranges describe USER-ALLOCATABLE memory: the bottom
   * of the lowest published zone is NOT necessarily the bottom of physical
   * RAM. On systems where firmware reserves the low-phys range for the
   * kernel image (e.g. ppc32 PowerMac with the kernel at phys 0 and dmesg
   * zones starting at 0x30000000), treating r.lo as POS_BASE would feed
   * dram_floor_bound a bogus high floor and exclude the actual text base.
   * Emit as an interior SAMPLE — still a sound RAM witness, but not a
   * floor pin. Authoritative floors come from sysfs_devicetree_memory and
   * peer components that read the full memory map. r.hi IS sound as a TOP
   * bound (the highest published zone end ≤ true top of RAM). */
  printf("lowest physical address:  0x%016lx\n", r.lo);
  kasld_result_sample(KASLD_TYPE_PHYS, REGION_RAM, r.lo, NULL, CONF_PARSED);

  if (r.hi && r.hi != r.lo) {
    printf("highest physical address: 0x%016lx\n", r.hi);
    kasld_result_top(KASLD_TYPE_PHYS, REGION_RAM, r.hi, NULL, CONF_PARSED);
  }

#ifdef phys_to_directmap_virt
  /* Same soundness caveat: phys_to_directmap_virt(r.lo) is the BASE only
   * when r.lo == actual phys floor. When firmware reserves low phys for
   * the kernel image (RAM hole below r.lo), the projection lands INSIDE
   * the directmap, not at its base. Emit as a directmap SAMPLE so peer
   * rules treat it as a witness without pinning virt_page_offset's ceiling. */
  unsigned long virt = phys_to_directmap_virt(r.lo);
  printf("possible direct-map virtual address: 0x%016lx\n", virt);
  kasld_result_sample(KASLD_TYPE_VIRT, REGION_DIRECTMAP, virt, NULL,
                      CONF_PARSED);
#else
  printf("note: phys and virt KASLR are decoupled on this arch; "
         "cannot derive kernel text virtual address from physical leak\n");
#endif

  return 0;
}
