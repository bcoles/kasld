// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Read physical DRAM addresses from IOMMU group reserved regions.
//
// When an IOMMU is active (Intel VT-d or AMD-Vi), the kernel exposes
// the reserved memory regions for each IOMMU group at:
//
//   /sys/kernel/iommu_groups/N/reserved_regions   (0444 — world-readable)
//
// Each line describes a physical address range and its type:
//
//   0x<start_16hex> 0x<end_16hex> <type>
//
// Types are: "Direct", "Relaxed direct", "Reserved", "MSI", "softmap MSI"
//   (from iommu_group_resv_type_string[] in drivers/iommu/iommu.c).
//
// On Intel VT-d systems with Reserved Memory Region Reporting (RMRR),
// firmware (via the DMAR ACPI table) declares physical DRAM ranges that
// hardware — USB 2.0 controllers, integrated GPUs, Intel ME — require for
// DMA. The VT-d driver fetches these from the DMAR table
// (intel_iommu_get_resv_regions → iommu_alloc_resv_region) and registers
// them as IOMMU_RESV_RESERVED ("Reserved") entries. These are physical DRAM
// addresses, not MMIO: a DMA region must be in system RAM.
//
// "Direct" entries (IOMMU_RESV_DIRECT) mark regions that are identity-mapped
// through the IOMMU; they may also include pre-allocated DRAM buffers (e.g.
// display stolen memory).
//
// Both "Reserved" and "Direct" entries with addresses in plausible DRAM ranges
// are emitted as P/dram witnesses to bound the system's physical memory layout.
// "MSI" and "softmap MSI" entries are always MMIO (interrupt delivery ranges)
// and are skipped.
//
// The attribute is created with S_IRUGO (0444):
//
//   static IOMMU_GROUP_ATTR(reserved_regions, S_IRUGO, ...)
//
// No capability check. Not gated by kptr_restrict.
//
// Typical output on an Intel VT-d system with USB RMRR:
//
//   iommu_group 0: Reserved 0x000000007e300000 - 0x000000007e31ffff
//   P dram 0x000000007e300000 reserved_mem:0
//   P dram 0x000000007e31ffff reserved_mem:0
//
// Leak primitive:
//   Data leaked:      physical DRAM addresses (IOMMU group reserved / direct
//                     mapped regions — firmware RMRR + pre-allocated DMA)
//   Kernel subsystem: drivers/iommu —
//   /sys/kernel/iommu_groups/N/reserved_regions Data structure:   struct
//   iommu_resv_region → start / end Address type:     physical (DRAM) Method:
//   parsed (sysfs text attribute) Status:           unfixed (information
//   exposure by design) Access check:     none (world-readable via S_IRUGO /
//   IOMMU_GROUP_ATTR) Source:
//   https://elixir.bootlin.com/linux/v6.12/source/drivers/iommu/iommu.c#L3030
//
// Mitigations:
//   CONFIG_IOMMU_API=n removes IOMMU group sysfs entirely. On x86_64 with
//   CONFIG_RANDOMIZE_MEMORY enabled, physical addresses do not directly
//   reveal the virtual text base. Requires an active IOMMU with populated
//   reserved or direct-mapped regions.
//
// Requires:
// - CONFIG_IOMMU_API
// - An active IOMMU (Intel VT-d or AMD-Vi) with reserved/direct regions
// - At least one IOMMU group with a physical DRAM reserved region
//
// References:
// https://elixir.bootlin.com/linux/v6.12/source/drivers/iommu/iommu.c#L3030
// https://elixir.bootlin.com/linux/v6.12/source/include/linux/iommu.h#L168
// https://elixir.bootlin.com/linux/v6.12/source/drivers/iommu/intel/iommu.c
// https://www.kernel.org/doc/Documentation/ABI/testing/sysfs-kernel-iommu_groups
// ---
// <bcoles@gmail.com>

#include "include/kasld/api.h"
#include "include/kasld/internal.h"
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

KASLD_EXPLAIN(
    "Reads physical DRAM addresses from IOMMU group reserved regions at "
    "/sys/kernel/iommu_groups/N/reserved_regions. On Intel VT-d systems with "
    "Reserved Memory Region Reporting (RMRR), firmware declares physical DRAM "
    "ranges that USB controllers, integrated GPUs, and similar hardware "
    "require "
    "for DMA. These appear as 'Reserved' (RMRR) or 'Direct' (identity-mapped "
    "DMA) entries and bound the physical RAM layout. The attribute is "
    "world-readable (S_IRUGO, 0444) with no capability check. Requires "
    "CONFIG_IOMMU_API and an active IOMMU with populated reserved regions.");

// Untested: no hardware with an active IOMMU available for testing.
KASLD_META("method:parsed\n"
           "phase:inference\n"
           "addr:physical\n"
           "status:experimental\n"
           "config:CONFIG_IOMMU_API\n");

/* Physical DRAM range heuristic.
 *
 * Returns 1 if the address is plausibly in system DRAM rather than MMIO.
 * RMRR regions are definitionally DRAM (DMA into physical memory), but
 * "Direct" entries can include MMIO pass-through on some systems.
 *
 * Heuristic: accept addresses in [1 MB, 3 GB) — typical low DRAM — or
 * at or above 4 GB — typical high DRAM.  Reject the 3–4 GB PCI hole
 * and known MMIO hotspots (IOAPIC 0xfec00000, HPET 0xfed00000, LAPIC
 * 0xfee00000) regardless of type annotation.
 *
 * This is an approximation; on unusual systems the PCI hole may differ.
 * The KASLD inference layer discards results outside E820/firmware RAM
 * ranges anyway, so false positives here are harmless.
 */
static int is_likely_dram(unsigned long long addr) {
  if (addr < 0x100000ULL)
    return 0; /* below 1 MB: legacy BIOS area, VGA ROM, EBDA */
  if (addr >= 0xc0000000ULL && addr < 0x100000000ULL)
    return 0; /* 3 GB – 4 GB: PCI hole / MMIO (typical x86) */
  if (addr >= 0xfec00000ULL && addr < 0xff000000ULL)
    return 0; /* IOAPIC / HPET / LAPIC MMIO hot-spot */
  return 1;
}

int main(void) {
  const char *base = "/sys/kernel/iommu_groups";
  DIR *d;
  struct dirent *ent;
  char path[512];
  char line[256];
  int group_count = 0;
  int found = 0;

  printf("[.] searching %s for IOMMU group reserved region physical addresses "
         "...\n",
         base);

  d = opendir(base);
  if (!d) {
    if (errno == ENOENT) {
      printf("[-] %s: not present (no active IOMMU or CONFIG_IOMMU_API=n)\n",
             base);
      return KASLD_EXIT_UNAVAILABLE;
    }
    perror("[-] opendir");
    return (errno == EACCES || errno == EPERM) ? KASLD_EXIT_NOPERM
                                               : KASLD_EXIT_UNAVAILABLE;
  }

  while ((ent = readdir(d)) != NULL) {
    if (ent->d_name[0] == '.')
      continue;

    /* Only process numeric group directories (0, 1, 2, …). */
    char *endptr;
    strtoul(ent->d_name, &endptr, 10);
    if (*endptr != '\0')
      continue;

    snprintf(path, sizeof(path), "%s/%s/reserved_regions", base, ent->d_name);

    FILE *f = fopen(path, "r");
    if (!f)
      continue;

    group_count++;

    while (fgets(line, sizeof(line), f)) {
      unsigned long long start = 0, end_addr = 0;
      char type[64] = {0};

      if (sscanf(line, "0x%llx 0x%llx %63[^\n]", &start, &end_addr, type) != 3)
        continue;

      if (!start || !end_addr)
        continue;

      /* Skip MSI / softmap MSI entries — always interrupt-delivery MMIO. */
      if (strncmp(type, "MSI", 3) == 0 || strncmp(type, "softmap", 7) == 0)
        continue;

      /* Accept "Direct", "Relaxed direct", and "Reserved" entries that
       * pass the DRAM plausibility check. */
      if (!is_likely_dram(start))
        continue;

      found++;
      printf("iommu_group %s: %s 0x%016llx - 0x%016llx\n", ent->d_name, type,
             start, end_addr);

      kasld_result_sample(KASLD_TYPE_PHYS, REGION_RESERVED_MEM,
                          (unsigned long)start, ent->d_name, CONF_PARSED);

      if (end_addr != start) {
        kasld_result_sample(KASLD_TYPE_PHYS, REGION_RESERVED_MEM,
                            (unsigned long)end_addr, ent->d_name, CONF_PARSED);
      }
    }
    fclose(f);
  }
  closedir(d);

  if (!group_count) {
    printf("[-] no IOMMU groups found in %s (no active IOMMU or empty)\n",
           base);
    return KASLD_EXIT_UNAVAILABLE;
  }

  if (!found) {
    printf(
        "[-] no DRAM-range reserved regions found across %d IOMMU group(s)\n",
        group_count);
    return KASLD_EXIT_UNAVAILABLE;
  }

  return 0;
}
