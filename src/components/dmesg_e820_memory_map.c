// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Search kernel log for e820 memory map physical addresses.
//
// On x86 systems, the BIOS/firmware provides the physical memory map via the
// e820 interface. The kernel prints these entries to dmesg during early boot.
//
// Two message formats may appear:
//
// pr_info (always printed):
//   BIOS-e820: [mem 0x0000000000000000-0x000000000009ffff] usable
//
// KERN_DEBUG (printed when reserving RAM alignment buffers):
//   e820: reserve RAM buffer [mem 0x0009fc00-0x0009ffff]
//
// Both formats leak physical memory addresses from the firmware memory map.
//
// Leak primitive:
//   Data leaked:      physical memory map (BIOS/firmware e820 table)
//   Kernel subsystem: arch/x86/kernel/e820 — e820__print_table()
//   Data structure:   e820_table entries (physical address ranges)
//   Address type:     physical (DRAM + reserved regions)
//   Method:           parsed (dmesg string)
//   Status:           unfixed (printed unconditionally during boot)
//   Access check:     do_syslog() → check_syslog_permissions(); gated by
//                     dmesg_restrict
//   Source:
//   https://elixir.bootlin.com/linux/v6.1.1/source/arch/x86/kernel/e820.c#L203
//
// Mitigations:
//   Access gated by dmesg_restrict (see dmesg.h for shared access gate
//   details). The e820 table is printed unconditionally. On x86_64
//   (decoupled), physical addresses cannot derive the virtual text base.
//
// Requires:
// - kernel.dmesg_restrict = 0; or CAP_SYSLOG capabilities; or
//   readable /var/log/dmesg.
//
// References:
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/x86/kernel/e820.c#L203
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/x86/kernel/e820.c#L1240
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

#if !defined(__i386__) && !defined(__x86_64__) && !defined(__amd64__)
#error "Architecture is not supported"
#endif

KASLD_EXPLAIN(
    "Parses the x86 BIOS-provided E820 physical memory map from dmesg. "
    "This boot-time table shows all usable RAM and reserved physical "
    "address ranges. The lowest and highest usable entries bound the "
    "physical DRAM base and top. x86 only. Access is gated by "
    "dmesg_restrict.");

KASLD_META("method:parsed\n"
           "phase:inference\n"
           "addr:physical\n"
           "sysctl:dmesg_restrict>=1\n"
           "bypass:CAP_SYSLOG\n"
           "fallback:/var/log/dmesg\n");

struct e820_ctx {
  unsigned long lo; /* lowest start address of usable RAM */
  unsigned long hi; /* highest end address of usable RAM */
};

static int on_match(const char *line, void *ctx) {
  struct e820_ctx *e = ctx;

  /*
   * Only two e820 line shapes denote usable DRAM:
   *   BIOS-e820:/modified:/user: [mem ...] usable  (type-tagged usable RAM)
   *   e820: reserve RAM buffer [mem ...]           (derived from an
   *                                                 E820_TYPE_RAM entry)
   * Every other e820 line names a NON-RAM range — e.g.
   *   e820: update [mem ...] usable ==> reserved
   *   e820: remove [mem ...]
   * and a type-tagged line whose type is not "usable" (reserved, ACPI, ...).
   * Folding any of those into REGION_RAM pollutes the map (a stray low range
   * lowers the RAM base; a stray high range raises the RAM top), so accept only
   * the two RAM shapes and reject everything else.
   */
  int is_tagged = strstr(line, "BIOS-e820:") != NULL ||
                  strstr(line, "modified:") != NULL ||
                  strstr(line, "user:") != NULL;
  int is_ram_buffer = strstr(line, "reserve RAM buffer") != NULL;
  if (is_tagged) {
    if (!strstr(line, "usable"))
      return 1;
  } else if (!is_ram_buffer) {
    return 1;
  }

  const char *p = strstr(line, "[mem ");
  if (!p)
    return 1;

  char *endptr;
  unsigned long start = strtoul(p + 5, &endptr, 16);

  /* Parse end address after the '-' separator */
  unsigned long end = 0;
  if (*endptr == '-')
    end = strtoul(endptr + 1, &endptr, 16);

  if (start && (!e->lo || start < e->lo))
    e->lo = start;
  if (end > e->hi)
    e->hi = end;

  return 1; /* continue scanning all entries */
}

int main(void) {
  struct e820_ctx e = {0, 0};

  kasld_info("searching dmesg for e820 physical memory map ...");
  int ds = dmesg_search("e820", on_match, &e);

  if (!e.lo && !e.hi) {
    if (ds < 0)
      return KASLD_EXIT_NOPERM;
    kasld_err("e820 memory map not found in dmesg");
    return 0;
  }

  if (e.lo) {
    kasld_found("leaked e820 DRAM low:  0x%016lx", e.lo);
    kasld_result_base(KASLD_TYPE_PHYS, REGION_RAM, e.lo, NULL, CONF_PARSED);
  }

  if (e.hi) {
    kasld_found("leaked e820 DRAM high: 0x%016lx", e.hi);
    kasld_result_top(KASLD_TYPE_PHYS, REGION_RAM, e.hi, NULL, CONF_PARSED);
  }

#ifdef phys_to_directmap_virt
  if (e.lo) {
    unsigned long virt = phys_to_directmap_virt(e.lo);
    kasld_info("possible direct-map virtual address (low):  0x%016lx", virt);
    kasld_result_base(KASLD_TYPE_VIRT, REGION_DIRECTMAP, virt, NULL,
                      CONF_PARSED);
  }
  if (e.hi) {
    unsigned long virt = phys_to_directmap_virt(e.hi);
    kasld_info("possible direct-map virtual address (high): 0x%016lx", virt);
    kasld_result_top(KASLD_TYPE_VIRT, REGION_DIRECTMAP, virt, NULL,
                     CONF_PARSED);
  }
#else
  kasld_info("note: phys and virt KASLR are decoupled on this arch; "
             "cannot derive kernel text virtual address from physical leak");
#endif

  return 0;
}
