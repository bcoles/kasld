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
// Soundness: /proc/zoneinfo describes USER-ALLOCATABLE memory zones
// (buddy-allocator state), not the full physical-RAM extent. Firmware-
// and kernel-reserved regions (the kernel image, EFI runtime services,
// memblock reservations) live OUTSIDE the published zones. On systems
// where firmware reserves the low-phys range for the kernel image
// (e.g. ppc32 PowerMac with the kernel at phys 0 and the lowest zone
// starting at 0x30000000), treating the lowest zone start as POS_BASE
// would pin dram_floor_bound to a bogus high floor and exclude the
// actual text base. The lowest zone start is therefore emitted as an
// interior SAMPLE — a sound RAM witness, but not a floor pin.
// Authoritative phys floors come from sysfs_devicetree_memory,
// sysfs_firmware_memmap, boot_params_e820 and peers that read the full
// memory map. The HIGHEST zone end IS sound as a TOP bound (the largest
// published zone end ≤ true top of RAM).
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
//   Access check:     none (world-readable /proc/zoneinfo, 0444)
//   Source:           https://elixir.bootlin.com/linux/v6.12/source/mm/vmstat.c
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

#include "include/kasld/api.h"
#include "include/kasld/cli.h"
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

KASLD_EXPLAIN(
    "Reads /proc/zoneinfo to extract the start_pfn and spanned page "
    "count of each memory zone. Multiplying PFN by page size yields "
    "physical-RAM witnesses (interior samples) and a sound top edge of "
    "the published RAM extent. World-readable (0444); part of core mm; "
    "no sysctl or CONFIG option can hide the start_pfn field.");

KASLD_META("method:parsed\n"
           "phase:inference\n"
           "addr:physical\n");

int main(void) {
  FILE *f;
  const char *path = "/proc/zoneinfo";
  char line[512];
  unsigned long lo_pfn = 0, hi_pfn = 0, hi_end_pfn = 0;
  unsigned long cur_spanned = 0;
  int count = 0;

  kasld_info("searching %s for zone start_pfn and spanned ...", path);

  f = kasld_fopen(path, "r");
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

    /* `count` is the "no zones seen yet" sentinel — checking lo_pfn == 0
     * would conflate "first zone" with "zone genuinely starting at PFN 0"
     * (rare but admissible: some hot-plug / embedded boots place a zone at
     * PFN 0). The sscanf above already detected parse failure. */
    if (count == 0 || val < lo_pfn)
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

  if (!count) {
    kasld_err("no zone start_pfn entries found");
    return 0;
  }

  /* Clamp PFNs before the byte conversion: on a 32-bit (PAE) kernel a PFN
   * above ULONG_MAX / PAGE_SIZE wraps unsigned long and would yield a bogus
   * too-low RAM bound (and a wrapped direct-map projection below). */
  unsigned long hi_use = hi_end_pfn > hi_pfn ? hi_end_pfn : hi_pfn;
  if (lo_pfn > ULONG_MAX / PAGE_SIZE)
    lo_pfn = ULONG_MAX / PAGE_SIZE;
  if (hi_use > ULONG_MAX / PAGE_SIZE)
    hi_use = ULONG_MAX / PAGE_SIZE;
  unsigned long lo = lo_pfn * PAGE_SIZE;
  unsigned long hi = hi_use * PAGE_SIZE - 1;

  /* lo: the start of the lowest published zone — a sound RAM witness but
   * NOT a floor pin (reserved low memory below the lowest zone is
   * invisible to zoneinfo; see the file header). Emit as an interior
   * sample. hi: the end of the highest zone — a sound TOP bound (RAM
   * does not extend above the highest published zone end). The component
   * currently aggregates across zones rather than reporting per-zone
   * DMA_TOP / DMA32_TOP — finer-grained reporting is a future
   * enhancement. */
  kasld_info("lowest zone start PFN:  %lu (phys 0x%016lx)", lo_pfn, lo);
  kasld_result_sample(KASLD_TYPE_PHYS, REGION_RAM, lo, NULL, CONF_PARSED);

  if (hi_use != lo_pfn) {
    if (hi_end_pfn > hi_pfn)
      kasld_info("highest zone end PFN:   %lu (phys 0x%016lx)", hi_use, hi);
    else
      kasld_info("highest zone start PFN: %lu (phys 0x%016lx)", hi_use, hi);
    kasld_result_top(KASLD_TYPE_PHYS, REGION_RAM, hi, NULL, CONF_PARSED);
  }

#ifdef phys_to_directmap_virt
  /* Same caveat: phys_to_directmap_virt(lo) lands at the directmap base
   * ONLY when lo is the actual phys floor. When firmware reserves low
   * phys for the kernel image, lo is interior to the directmap, not its
   * base. Emit as a directmap sample. */
  unsigned long virt = phys_to_directmap_virt(lo);
  kasld_info("possible direct-map virtual address: 0x%016lx", virt);
  kasld_result_sample(KASLD_TYPE_VIRT, REGION_DIRECTMAP, virt, NULL,
                      CONF_PARSED);
#else
  kasld_info("note: phys and virt KASLR are decoupled on this arch; "
             "cannot derive directmap virtual address from physical leak");
#endif

  return 0;
}
