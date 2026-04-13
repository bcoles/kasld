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
// Requires:
// - CONFIG_PCI
// - At least one PCI device with allocated BARs
//
// References:
// https://elixir.bootlin.com/linux/v6.12/source/drivers/pci/pci-sysfs.c#L163
// https://www.kernel.org/doc/Documentation/filesystems/sysfs-pci.txt
// ---
// <bcoles@gmail.com>

#include "include/kasld.h"
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
  const char *base = "/sys/bus/pci/devices";
  DIR *d;
  struct dirent *ent;
  char path[512];
  char line[256];
  unsigned long lo_mmio = ~0ul, hi_mmio = 0;
  int device_count = 0;
  int bar_count = 0;

  printf("[.] searching %s for PCI device MMIO BAR addresses ...\n", base);

  d = opendir(base);
  if (!d) {
    perror("[-] opendir");
    return 1;
  }

  while ((ent = readdir(d)) != NULL) {
    if (ent->d_name[0] == '.')
      continue;

    snprintf(path, sizeof(path), "%s/%s/resource", base, ent->d_name);

    FILE *f = fopen(path, "r");
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
    }
    fclose(f);
  }
  closedir(d);

  if (!bar_count) {
    printf("[-] no PCI memory BARs found in %s\n", base);
    return 1;
  }

  printf("PCI devices: %d, memory BARs: %d\n", device_count, bar_count);

  printf("lowest PCI MMIO start:  0x%016lx\n", lo_mmio);
  kasld_result(KASLD_ADDR_PHYS, KASLD_SECTION_MMIO, lo_mmio,
               "sysfs_pci_resource:lo");

  if (hi_mmio && hi_mmio != lo_mmio) {
    printf("highest PCI MMIO end:   0x%016lx\n", hi_mmio);
    kasld_result(KASLD_ADDR_PHYS, KASLD_SECTION_MMIO, hi_mmio,
                 "sysfs_pci_resource:hi");
  }

  return 0;
}
