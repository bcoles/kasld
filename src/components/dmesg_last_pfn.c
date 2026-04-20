// This file is part of KASLD - https://github.com/bcoles/kasld
//
// e820__end_of_ram_pfn() and e820__end_of_low_ram_pfn() print the last page
// frame number during boot on x86 / x86_64:
//
// last_pfn = 0x340000 max_arch_pfn = 0x400000000
// last_pfn = 0xc0000 max_arch_pfn = 0x400000000
//
// The first line is the overall RAM ceiling (e820__end_of_ram_pfn).
// The second is the ceiling below 4 GiB (e820__end_of_low_ram_pfn).
// Both are always printed on x86 / x86_64.
//
// Multiplying last_pfn by PAGE_SIZE (0x1000) gives the physical end of RAM:
//   0x340000 * 0x1000 = 0x340000000 (~13 GiB)
//
// Leak primitive:
//   Data leaked:      physical RAM ceiling (last page frame number)
//   Kernel subsystem: arch/x86/kernel/e820 — e820__end_of_ram_pfn()
//   Data structure:   last_pfn, max_arch_pfn (page frame numbers)
//   Address type:     physical (DRAM, as PFN × PAGE_SIZE)
//   Method:           parsed (dmesg string)
//   Status:           unfixed (printed unconditionally during boot)
//   Access check:     do_syslog() → check_syslog_permissions(); gated by
//                     dmesg_restrict
//   Source:
//   https://elixir.bootlin.com/linux/v6.8/source/arch/x86/kernel/e820.c
//
// Mitigations:
//   Access gated by dmesg_restrict (see dmesg.h for shared access gate
//   details). Always printed on x86/x86_64. On x86_64 (decoupled),
//   physical addresses cannot derive the virtual text base.
//
// Requires:
// - kernel.dmesg_restrict = 0; or CAP_SYSLOG capabilities; or
//   readable /var/log/dmesg.
//
// References:
// https://elixir.bootlin.com/linux/v6.8/source/arch/x86/kernel/e820.c
// ---
// <bcoles@gmail.com>

#define _GNU_SOURCE
#include "include/dmesg.h"
#include "include/kasld.h"
#include "include/kasld_internal.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if !defined(__i386__) && !defined(__x86_64__) && !defined(__amd64__)
#error "Architecture is not supported"
#endif

KASLD_EXPLAIN(
    "Searches dmesg for x86 last_pfn and max_arch_pfn values from "
    "e820__end_of_ram_pfn(). Multiplying the page frame number by "
    "PAGE_SIZE (4096) gives the physical RAM ceiling. x86 only. Access "
    "is gated by dmesg_restrict.");

KASLD_META("method:parsed\n"
           "addr:physical\n"
           "sysctl:dmesg_restrict>=1\n"
           "bypass:CAP_SYSLOG\n"
           "fallback:/var/log/dmesg\n");

static int match_count;

static int on_match(const char *line, void *ctx) {
  (void)ctx;

  /* Format: "last_pfn = 0x<hex> max_arch_pfn = 0x<hex>" */
  const char *p = strstr(line, "last_pfn = 0x");
  if (!p)
    return 1;

  char *endptr;
  unsigned long pfn = strtoul(p + strlen("last_pfn = "), &endptr, 16);
  if (endptr == p + strlen("last_pfn = ") || pfn == 0)
    return 1;

  /* last_pfn is the first invalid PFN (one past the end of RAM).
   * Emit the start of the last valid page so the address is within RAM. */
  unsigned long last_valid = (pfn - 1) * PAGE_SIZE;

  match_count++;
  const char *label =
      (match_count == 1) ? "dmesg_last_pfn:hi" : "dmesg_last_pfn:lo";

  printf("leaked last_pfn: %#lx (last valid page: 0x%016lx)\n", pfn,
         last_valid);
  kasld_result(KASLD_ADDR_PHYS, KASLD_SECTION_DRAM, last_valid, label);

  return 1; /* keep scanning for second line */
}

int main(void) {
  printf("[.] searching dmesg for last_pfn ...\n");
  match_count = 0;
  int found = dmesg_search("last_pfn = 0x", on_match, NULL);
  if (found < 0)
    return KASLD_EXIT_NOPERM;
  if (!found)
    printf("[-] last_pfn not found in dmesg\n");
  return 0;
}
