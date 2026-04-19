// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Read zone start_pfn and spanned page counts from /proc/zoneinfo.
// This file is world-readable (0444) and prints, for each populated
// memory zone, the start page frame number (PFN) and the number of
// spanned pages. The physical address of the zone start is:
// start_pfn * PAGE_SIZE. The zone end is: (start_pfn + spanned) * PAGE_SIZE.
//
// Using spanned pages to compute zone ends gives a more accurate DRAM
// upper bound than the highest zone start_pfn alone. For example, on
// a system with 4 GiB DRAM starting at 0x80000000:
//   Normal zone start_pfn = 262144    -> 0x100000000
//   Normal zone spanned   = 524288    -> zone end = 0x180000000
// Without spanned, the :hi result would report 0x100000000 (zone start),
// missing the top 2 GiB of DRAM.
//
// Example output (excerpt):
//   Node 0, zone      DMA
//     ...
//     spanned  4095
//     ...
//     start_pfn:           1
//   Node 0, zone    DMA32
//     ...
//     spanned  1044480
//     ...
//     start_pfn:           4096
//   Node 0, zone   Normal
//     ...
//     spanned  524288
//     ...
//     start_pfn:           1048576
//
// Leak primitive:
//   Data leaked:      physical DRAM base address (zone start PFN × PAGE_SIZE)
//   Kernel subsystem: mm/vmstat — /proc/zoneinfo (proc_zoneinfo_show)
//   Data structure:   struct zone → zone_start_pfn (unsigned long)
//   Address type:     physical (DRAM)
//   Method:           parsed (text file)
//   Status:           unfixed (information exposure by design)
//
// Mitigations:
//   None — /proc/zoneinfo is world-readable (0444); no runtime sysctl can
//   restrict access. The start_pfn field is part of core mm and cannot be
//   hidden without a kernel patch. On decoupled architectures (x86_64, ARM64,
//   RISC-V 64), the physical address cannot derive the virtual text base.
//
// Requires:
// - /proc filesystem
//
// References:
// https://elixir.bootlin.com/linux/v6.12/source/mm/vmstat.c#L1727
// ---
// <bcoles@gmail.com>

#include "include/kasld.h"
#include "include/kasld_internal.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

KASLD_EXPLAIN(
    "Reads /proc/zoneinfo to extract the start page frame number (PFN) "
    "of each memory zone. Multiplying the PFN by the page size (4096) "
    "yields the physical base address of system RAM. This file is "
    "world-readable (0444) and part of core mm; no sysctl or CONFIG "
    "option can hide the start_pfn field.");

KASLD_META("method:parsed\n"
           "addr:physical\n");

int main(void) {
  FILE *f;
  const char *path = "/proc/zoneinfo";
  char line[512];
  unsigned long lo_pfn = 0, hi_pfn = 0, hi_end_pfn = 0;
  unsigned long cur_spanned = 0;
  int count = 0;

  printf("[.] searching %s for zone start_pfn and spanned ...\n", path);

  f = fopen(path, "r");
  if (f == NULL) {
    perror("[-] fopen");
    return (errno == EACCES || errno == EPERM) ? KASLD_EXIT_NOPERM
                                               : KASLD_EXIT_UNAVAILABLE;
  }

  while (fgets(line, sizeof(line), f) != NULL) {
    unsigned long val;

    if (sscanf(line, " spanned %lu", &val) == 1) {
      cur_spanned = val;
      continue;
    }

    if (sscanf(line, "  start_pfn: %lu", &val) != 1)
      continue;

    if (!val)
      continue;

    if (!lo_pfn || val < lo_pfn)
      lo_pfn = val;
    if (val > hi_pfn)
      hi_pfn = val;

    unsigned long end_pfn = cur_spanned ? val + cur_spanned : val;
    if (end_pfn > hi_end_pfn)
      hi_end_pfn = end_pfn;

    cur_spanned = 0;
    count++;
  }
  fclose(f);

  if (!count || !lo_pfn) {
    printf("[-] no zone start_pfn entries found\n");
    return 0;
  }

  unsigned long lo = lo_pfn * PAGE_SIZE;
  unsigned long hi_use = hi_end_pfn > hi_pfn ? hi_end_pfn : hi_pfn;
  unsigned long hi = hi_use * PAGE_SIZE;

  printf("lowest zone start PFN:  %lu (phys 0x%016lx)\n", lo_pfn, lo);
  kasld_result(KASLD_ADDR_PHYS, KASLD_SECTION_DRAM, lo, "proc-zoneinfo:lo");

  if (hi_use != lo_pfn) {
    if (hi_end_pfn > hi_pfn)
      printf("highest zone end PFN:   %lu (phys 0x%016lx)\n", hi_use, hi);
    else
      printf("highest zone start PFN: %lu (phys 0x%016lx)\n", hi_use, hi);
    kasld_result(KASLD_ADDR_PHYS, KASLD_SECTION_DRAM, hi, "proc-zoneinfo:hi");
  }

#if !PHYS_VIRT_DECOUPLED
  unsigned long virt = phys_to_virt(lo);
  printf("possible direct-map virtual address: 0x%016lx\n", virt);
  kasld_result(KASLD_ADDR_VIRT, KASLD_SECTION_DIRECTMAP, virt,
               "proc-zoneinfo:directmap");
#else
  printf("note: phys and virt KASLR are decoupled on this arch; "
         "cannot derive directmap virtual address from physical leak\n");
#endif

  return 0;
}
