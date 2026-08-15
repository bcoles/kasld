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
           "discloses:physical\n"
           "sysctl:dmesg_restrict>=1\n"
           "bypass:CAP_SYSLOG\n"
           "fallback:/var/log/dmesg\n");

struct e820_ctx {
  unsigned long lo; /* lowest start address of usable RAM */
  unsigned long hi; /* highest end address of usable RAM */
  int incomplete;   /* an entry could not be represented; see main() */
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

  /* An entry above 4 GiB is ordinary on a PAE kernel and wider than a 32-bit
   * build's word. Record that the map could not be read in full: lo and hi are
   * accumulated across every entry, so an unread one leaves hi below the real
   * top of RAM, and hi is published as a ceiling. */
  const char *endptr;
  unsigned long start;
  if (!kasld_addr_parse(p + 5, 16, &start, &endptr)) {
    if (kasld_addr_refused_wide(p + 5, endptr))
      e->incomplete = 1;
    return 1;
  }

  /* Parse end address after the '-' separator */
  unsigned long end = 0;
  if (*endptr == '-') {
    const char *ep = endptr + 1;
    if (!kasld_addr_parse(ep, 16, &end, &endptr)) {
      if (kasld_addr_refused_wide(ep, endptr))
        e->incomplete = 1;
      return 1;
    }
  }

  if (start && (!e->lo || start < e->lo))
    e->lo = start;
  if (end > e->hi)
    e->hi = end;

  return 1; /* continue scanning all entries */
}

int main(void) {
  struct e820_ctx e = {0, 0, 0};

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

  /* The ceiling is only sound when every entry was read. An entry this build
   * cannot represent is one whose top is above everything accumulated here, so
   * publishing hi anyway would assert that RAM ends lower than it does — the
   * ceiling rules take a REGION_RAM top as an upper bound. Suppress it, and
   * keep the base, which an unread high entry cannot lower. */
  if (e.hi && !e.incomplete) {
    kasld_found("leaked e820 DRAM high: 0x%016lx", e.hi);
    kasld_result_top(KASLD_TYPE_PHYS, REGION_RAM, e.hi, NULL, CONF_PARSED);
  } else if (e.incomplete) {
    kasld_err("e820 map has an entry wider than this build's word; "
              "DRAM ceiling suppressed");
  }

  return 0;
}
