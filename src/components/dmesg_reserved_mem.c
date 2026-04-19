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
#include "include/kasld.h"
#include "include/kasld_internal.h"
#include "include/kasld_types.h"
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

  return 1; /* continue — multiple regions */
}

int main(void) {
  struct range_ctx r = {0, 0};

  printf("[.] searching dmesg for device tree reserved memory regions ...\n");
  int ds = dmesg_search("OF: reserved mem:", on_match, &r);

  if (!r.lo) {
    printf("[-] no device tree reserved memory regions found in dmesg\n");
    if (ds < 0)
      return KASLD_EXIT_NOPERM;
    return 0;
  }

  printf("lowest reserved mem physical address:  0x%016lx\n", r.lo);
  printf("highest reserved mem physical address: 0x%016lx\n", r.hi);

  kasld_result(KASLD_ADDR_PHYS, KASLD_SECTION_DRAM, r.lo,
               "dmesg_reserved_mem:lo");

  if (r.hi && r.hi != r.lo)
    kasld_result(KASLD_ADDR_PHYS, KASLD_SECTION_DRAM, r.hi,
                 "dmesg_reserved_mem:hi");

#if !PHYS_VIRT_DECOUPLED
  unsigned long virt = phys_to_virt(r.lo);
  printf("possible direct-map virtual address: 0x%016lx\n", virt);
  kasld_result(KASLD_ADDR_VIRT, KASLD_SECTION_DIRECTMAP, virt,
               "dmesg_reserved_mem:directmap");
#else
  printf("note: phys and virt KASLR are decoupled on this arch; "
         "cannot derive kernel text virtual address from physical leak\n");
#endif

  return 0;
}
