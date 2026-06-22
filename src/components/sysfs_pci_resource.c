// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Read physical PCI BAR (Base Address Register) addresses from sysfs.
// The PCI subsystem exposes a world-readable "resource" text file for
// every PCI device:
//
//   /sys/bus/pci/devices/DDDD:BB:DD.F/resource
//
// Each line contains: start end flags (hex, space-separated).
// Lines with non-zero start/end represent allocated BARs whose
// addresses are physical MMIO or I/O port ranges.
//
// Knowing where PCI MMIO regions are placed constrains where physical
// DRAM can reside (they occupy disjoint regions). On x86 systems, the
// MMIO "PCI hole" is typically between ~3 GB and 4 GB, bounding the
// low DRAM region from above. This partially substitutes for
// /proc/iomem, which is gated by CAP_SYS_ADMIN.
//
// All attributes are world-readable (0444, DEVICE_ATTR_RO). No
// capability or kptr_restrict gate. The first 64 bytes of the PCI
// config space (including BARs at offsets 0x10-0x27) are also
// world-readable via the "config" binary attribute (0644), but the
// "resource" text file is easier to parse.
//
// Leak primitive:
//   Data leaked:      PCI BAR physical addresses (MMIO regions)
//   Kernel subsystem: drivers/pci — /sys/bus/pci/devices/*/resource
//   Data structure:   struct pci_dev → resource[] (PCI BARs)
//   Address type:     physical (MMIO)
//   Method:           parsed (sysfs text file)
//   Status:           unfixed (information exposure by design)
//   Access check:     none (world-readable sysfs attribute)
//   Source:
//   https://elixir.bootlin.com/linux/v6.12/source/drivers/pci/pci-sysfs.c#L163
//
// Mitigations:
//   CONFIG_PCI=n removes PCI subsystem entirely. The resource file is
//   world-readable (0444); no runtime sysctl or capability check
//   can restrict access. On decoupled architectures, MMIO addresses
//    cannot derive the virtual text base.
//
// Requires:
// - CONFIG_PCI
// - At least one PCI device with allocated BARs
//
// References:
// https://elixir.bootlin.com/linux/v6.12/source/drivers/pci/pci-sysfs.c#L163
// https://www.kernel.org/doc/Documentation/filesystems/sysfs-pci.txt
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
    "Reads PCI BAR (Base Address Register) physical addresses from "
    "/sys/bus/pci/devices/*/resource. These world-readable (0444) files "
    "expose MMIO physical address ranges assigned to PCI devices. On "
    "systems where MMIO is near DRAM, this constrains the physical "
    "memory layout. Requires CONFIG_PCI.");

KASLD_META("method:parsed\n"
           "phase:inference\n"
           "addr:physical\n"
           "config:CONFIG_PCI\n");

int main(void) {
  const char *base = "/sys/bus/pci/devices";
  DIR *d;
  struct dirent *ent;
  char path[512];
  char line[256];
  unsigned long lo_mmio = ~0ul, hi_mmio = 0;
  int device_count = 0;
  int bar_count = 0;

  kasld_info("searching %s for PCI device MMIO BAR addresses ...", base);

  d = kasld_opendir(base);
  if (!d) {
    perror("[-] opendir");
    return (errno == EACCES || errno == EPERM) ? KASLD_EXIT_NOPERM
                                               : KASLD_EXIT_UNAVAILABLE;
  }

  while ((ent = readdir(d)) != NULL) {
    if (ent->d_name[0] == '.')
      continue;

    snprintf(path, sizeof(path), "%s/%s/resource", base, ent->d_name);

    FILE *f = kasld_fopen(path, "r");
    if (!f)
      continue;

    device_count++;

    while (fgets(line, sizeof(line), f)) {
      unsigned long long start = 0, end = 0, flags = 0;

      if (sscanf(line, "%llx %llx %llx", &start, &end, &flags) != 3)
        continue;

      if (!start || !end)
        continue;

      /* Skip I/O port BARs (flag bit 0 set = IORESOURCE_IO).
       * We only care about memory-mapped BARs. */
      if (flags & 0x100)
        continue;

      bar_count++;

      if ((unsigned long)start < lo_mmio)
        lo_mmio = (unsigned long)start;
      if ((unsigned long)end > hi_mmio)
        hi_mmio = (unsigned long)end;

      /* Each BAR is one contiguous MMIO window [start, end]; emit it as its own
       * bounded range so the engine excludes every forbidden BAR band, not just
       * the lowest. BARs are scattered across the address space, so collapsing
       * them to one [min, max] span would wrongly forbid the DRAM between them
       * — range per BAR, never a covering extent. */
      if ((unsigned long)end > (unsigned long)start)
        kasld_result_range(KASLD_TYPE_PHYS, REGION_PCI_MMIO,
                           (unsigned long)start, (unsigned long)end,
                           ent->d_name, CONF_PARSED);
    }
    fclose(f);
  }
  closedir(d);

  if (!bar_count) {
    kasld_err("no PCI memory BARs found in %s", base);
    return 0;
  }

  kasld_info("PCI devices: %d, memory BARs: %d", device_count, bar_count);

  /* Per-BAR forbidden bands are emitted in the scan loop above. */
  kasld_info("lowest PCI MMIO start:  0x%016lx", lo_mmio);
  if (hi_mmio && hi_mmio != lo_mmio)
    kasld_info("highest PCI MMIO end:   0x%016lx", hi_mmio);

  return 0;
}
