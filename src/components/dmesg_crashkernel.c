// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Search kernel log for crashkernel reservation messages to extract the
// physical address range reserved for the kdump crash kernel.
//
// Modern format (generic, ~v6.7+; arm64 since at least v6.6):
//   crashkernel reserved: 0x0000000027e00000 - 0x000000003fe00000 (384 MB)
//
// Low memory variant (64-bit systems):
//   crashkernel low memory reserved: 0x27e00000 - 0x2fe00000 (128 MB)
//
// Older x86 format (pre-v6.7):
//   Reserving 384MB of memory at 632MB for crashkernel (System RAM: 13312MB)
//
// Older x86 low-memory format:
//   Reserving 256MB of low memory at 128MB for crashkernel (low RAM limit:
//   4095MB)
//
// Leak primitive:
//   Data leaked:      physical address range reserved for crash kernel
//   Kernel subsystem: kernel/crash_reserve — reserve_crashkernel()
//   Data structure:   crashk_res (struct resource, physical start/end)
//   Address type:     physical (DRAM)
//   Method:           parsed (dmesg string)
//   Status:           unfixed (printed unconditionally when crashkernel= is
//   set)
//   Access check:     do_syslog() → check_syslog_permissions(); gated by
//                     dmesg_restrict
//   Source:
//   https://elixir.bootlin.com/linux/v6.12/source/kernel/crash_reserve.c
//
// Mitigations:
//   No crashkernel= boot parameter means no message. Access gated by
//   dmesg_restrict (see dmesg.h for shared access gate details). On
//   decoupled architectures, physical addresses cannot derive the
//   virtual text base.
//
// Requires:
// - kernel.dmesg_restrict = 0; or CAP_SYSLOG capabilities; or
//   readable /var/log/dmesg.
// - crashkernel= boot parameter (common on servers/distros with kdump)
//
// References:
// https://elixir.bootlin.com/linux/v6.12/source/kernel/crash_reserve.c
// https://elixir.bootlin.com/linux/v6.6/source/arch/x86/kernel/setup.c
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
    "Searches dmesg for crashkernel (kdump) reservation messages that "
    "print the physical address range reserved for the crash kernel. "
    "Only present when the crashkernel= boot parameter is used. The "
    "reserved range reveals physical DRAM layout. Access is gated by "
    "dmesg_restrict.");

KASLD_META("method:parsed\n"
           "phase:inference\n"
           "addr:physical\n"
           "sysctl:dmesg_restrict>=1\n"
           "bypass:CAP_SYSLOG\n"
           "fallback:/var/log/dmesg\n");

/* Modern format: "crashkernel reserved: 0x<start> - 0x<end>" */
static int on_reserved(const char *line, void *ctx) {
  struct range_ctx *r = ctx;

  const char *p = strstr(line, "reserved:");
  if (!p)
    return 1;

  p += 9;
  while (*p == ' ')
    p++;

  char *endptr;
  unsigned long start = strtoul(p, &endptr, 16);

  /* Skip to end address after " - " */
  const char *q = strstr(endptr, " - ");
  if (!q)
    return 1;

  unsigned long end = strtoul(q + 3, &endptr, 16);

  if (start && (!r->lo || start < r->lo))
    r->lo = start;
  if (end > r->hi)
    r->hi = end;

  /* The high and low crashkernel reservations are TWO disjoint regions; emit
   * each line's [start, end] as its own bounded range rather than collapsing
   * to one [min, max] span (which would wrongly forbid the usable RAM in the
   * gap between them). Each band drives phys_reservation_exclude on its own. */
  if (start && end > start)
    kasld_result_range(KASLD_TYPE_PHYS, REGION_CRASHKERNEL, start, end, NULL,
                       CONF_PARSED);

  return 1; /* keep scanning for low-memory variant */
}

/* Older x86 format: "Reserving %ldMB of memory at %ldMB for crashkernel"
 * Also matches: "Reserving %ldMB of low memory at %ldMB for crashkernel" */
static int on_reserving(const char *line, void *ctx) {
  struct range_ctx *r = ctx;

  const char *p = strstr(line, "Reserving ");
  if (!p)
    return 1;

  p += 10;
  char *endptr;
  unsigned long size_mb = strtoul(p, &endptr, 10);
  if (!size_mb)
    return 1;

  /* Find "at %ldMB" */
  const char *q = strstr(endptr, " at ");
  if (!q)
    return 1;

  unsigned long base_mb = strtoul(q + 4, &endptr, 10);

  unsigned long start = base_mb * 1024 * 1024;
  unsigned long end = start + size_mb * 1024 * 1024;

  if (start && (!r->lo || start < r->lo))
    r->lo = start;
  if (end > r->hi)
    r->hi = end;

  /* Per-region band (memory + low-memory variants are disjoint); see
   * on_reserved() for why each line is emitted separately, not collapsed. */
  if (start && end > start)
    kasld_result_range(KASLD_TYPE_PHYS, REGION_CRASHKERNEL, start, end, NULL,
                       CONF_PARSED);

  return 1;
}

int main(void) {
  struct range_ctx r = {0, 0};

  kasld_info("searching dmesg for crashkernel reservation ...");

  /* Try modern hex format first */
  int ds = dmesg_search("crashkernel reserved:", on_reserved, &r);
  if (ds < 0)
    return KASLD_EXIT_NOPERM;

  dmesg_search("crashkernel low memory reserved:", on_reserved, &r);

  /* Fall back to older MB-only format */
  if (!r.lo)
    dmesg_search("for crashkernel", on_reserving, &r);

  if (!r.lo) {
    kasld_err("crashkernel reservation not found in dmesg");
    return 0;
  }

  kasld_info("crashkernel start: 0x%016lx", r.lo);
  if (r.hi && r.hi != r.lo)
    kasld_info("crashkernel end:   0x%016lx", r.hi);

  /* Per-region forbidden bands are emitted in the parse callbacks; the
   * directmap projection below derives one virtual landmark from the lowest. */

#ifdef phys_to_directmap_virt
  unsigned long virt = phys_to_directmap_virt(r.lo);
  kasld_info("possible direct-map virtual address: 0x%016lx", virt);
  kasld_result_sample(KASLD_TYPE_VIRT, REGION_DIRECTMAP, virt, NULL,
                      CONF_PARSED);
#else
  kasld_info("note: phys and virt KASLR are decoupled on this arch; "
             "cannot derive directmap virtual address from physical leak");
#endif

  return 0;
}
