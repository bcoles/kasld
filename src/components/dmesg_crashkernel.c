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

  return 1;
}

int main(void) {
  struct range_ctx r = {0, 0};

  printf("[.] searching dmesg for crashkernel reservation ...\n");

  /* Try modern hex format first */
  int ds = dmesg_search("crashkernel reserved:", on_reserved, &r);
  if (ds < 0)
    return KASLD_EXIT_NOPERM;

  dmesg_search("crashkernel low memory reserved:", on_reserved, &r);

  /* Fall back to older MB-only format */
  if (!r.lo)
    dmesg_search("for crashkernel", on_reserving, &r);

  if (!r.lo) {
    printf("[-] crashkernel reservation not found in dmesg\n");
    return 0;
  }

  printf("crashkernel start: 0x%016lx\n", r.lo);
  kasld_result(KASLD_ADDR_PHYS, KASLD_SECTION_DRAM, r.lo,
               KASLD_REGION_CRASHKERNEL, NULL);

  if (r.hi && r.hi != r.lo) {
    printf("crashkernel end:   0x%016lx\n", r.hi);
    kasld_result(KASLD_ADDR_PHYS, KASLD_SECTION_DRAM, r.hi,
                 KASLD_REGION_CRASHKERNEL, NULL);
  }

#if !PHYS_VIRT_DECOUPLED
  unsigned long virt = phys_to_virt(r.lo);
  printf("possible direct-map virtual address: 0x%016lx\n", virt);
  kasld_result(KASLD_ADDR_VIRT, KASLD_SECTION_DIRECTMAP, virt,
               KASLD_REGION_CRASHKERNEL, NULL);
#else
  printf("note: phys and virt KASLR are decoupled on this arch; "
         "cannot derive directmap virtual address from physical leak\n");
#endif

  return 0;
}
