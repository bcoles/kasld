// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Read physical start addresses of NVDIMM/PMem regions from the Linux
// libnvdimm sysfs interface.
//
// When a system has NVDIMM or Persistent Memory (PMem) hardware — such as
// Intel Optane DCPMM (Data Center Persistent Memory) or JEDEC NVDIMM-P —
// the libnvdimm driver registers nd_region devices under:
//
//   /sys/bus/nd/devices/ndregionN/
//
// Each nd_region's "resource" attribute exposes the physical start address
// of that PMem region:
//
//   /sys/bus/nd/devices/ndregionN/resource   (0444 — world-readable)
//
// Format: "%#llx\n"  (e.g. "0x2080000000\n")
//
// The attribute is created with DEVICE_ATTR_RO (mode 0444):
//
//   static DEVICE_ATTR_RO(resource);
//
// The value is nd_region->ndr_start, the physical byte offset of the first
// byte of this interleave set. On Intel Optane systems this is typically a
// persistent-memory range beyond the regular DRAM ceiling (e.g. starting at
// 0x40_0000_0000 / 256 GiB on a 256 GiB DRAM + 256 GiB PMem system).
//
// The attribute is hidden (mode 0) for degenerate regions with no interleave
// mappings (ndr_mappings == 0); it is visible and world-readable for all
// standard PMem regions.
//
// The resource attribute is only populated when the nd_region driver is
// bound to the device; if no driver is bound, read() returns ENXIO.
//
// Leak primitive:
//   Data leaked:      physical start address of NVDIMM/PMem interleave region
//   Kernel subsystem: drivers/nvdimm —
//                     /sys/bus/nd/devices/ndregionN/resource
//   Data structure:   struct nd_region → ndr_start
//   Address type:     physical (persistent memory / DRAM-like)
//   Method:           parsed (sysfs text attribute)
//   Status:           unfixed (information exposure by design)
//   Access check:     none (world-readable via DEVICE_ATTR_RO, 0444)
//   Source:
//   https://elixir.bootlin.com/linux/v6.12/source/drivers/nvdimm/region_devs.c
//
// Mitigations:
//   CONFIG_LIBNVDIMM=n removes the nd bus and all nd_region sysfs entries.
//   Requires physical NVDIMM/PMem hardware and the nd_region driver to be
//   bound. On x86_64 with CONFIG_RANDOMIZE_MEMORY, physical addresses do not
//   directly reveal the virtual text base. On ARM64/RISC-V without decoupled
//   KASLR, phys_to_virt() gives the directmap virtual address.
//
// Requires:
// - CONFIG_LIBNVDIMM
// - NVDIMM / Persistent Memory hardware (Intel Optane DCPMM, JEDEC NVDIMM-P)
// - nd_region driver bound to at least one ndregion device
//
// References:
// https://elixir.bootlin.com/linux/v6.12/source/drivers/nvdimm/region_devs.c
// https://www.kernel.org/doc/html/latest/driver-api/nvdimm/nvdimm.html
// https://www.kernel.org/doc/Documentation/ABI/testing/sysfs-bus-nd
// ---
// <bcoles@gmail.com>

#include "include/kasld/api.h"
#include "include/kasld/internal.h"
#include <dirent.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

KASLD_EXPLAIN(
    "Reads physical start addresses of NVDIMM/PMem regions from the libnvdimm "
    "sysfs interface (/sys/bus/nd/devices/ndregionN/resource). Each region's "
    "world-readable 'resource' attribute (0444, DEVICE_ATTR_RO) exposes "
    "nd_region->ndr_start — the physical byte address of the first byte of "
    "that interleave set. Only present on systems with NVDIMM or Persistent "
    "Memory hardware (Intel Optane DCPMM, JEDEC NVDIMM-P) and the nd_region "
    "driver bound.");

KASLD_META("method:parsed\n"
           "phase:inference\n"
           "addr:physical\n"
           "config:CONFIG_LIBNVDIMM\n");

static const char *nd_base = "/sys/bus/nd/devices";

int main(void) {
  DIR *d;
  struct dirent *ent;
  char path[512];
  char buf[64];
  int count = 0;

  printf("[.] trying %s/ndregionN/resource ...\n", nd_base);

  d = opendir(nd_base);
  if (!d) {
    int saved_errno = errno;
    if (saved_errno == ENOENT || saved_errno == ENODEV)
      printf("[-] %s not present (CONFIG_LIBNVDIMM=n or no nd bus)\n", nd_base);
    else
      perror("[-] opendir");
    return (saved_errno == EACCES || saved_errno == EPERM)
               ? KASLD_EXIT_NOPERM
               : KASLD_EXIT_UNAVAILABLE;
  }

  while ((ent = readdir(d)) != NULL) {
    /* Only process ndregionN devices (not namespace*, bregion*, dax*, etc.) */
    if (strncmp(ent->d_name, "ndregion", 8) != 0)
      continue;
    /* Name must be "ndregion" followed by one or more digits */
    const char *suffix = ent->d_name + 8;
    int all_digits = (*suffix != '\0');
    for (const char *p = suffix; *p; p++) {
      if (*p < '0' || *p > '9') {
        all_digits = 0;
        break;
      }
    }
    if (!all_digits)
      continue;

    snprintf(path, sizeof(path), "%s/%s/resource", nd_base, ent->d_name);

    FILE *f = fopen(path, "r");
    if (!f) {
      /* ENXIO = driver not bound; ENOENT = attribute hidden (no mappings) */
      if (errno != ENOENT && errno != ENXIO)
        fprintf(stderr, "[-] failed to open %s: %s\n", path, strerror(errno));
      continue;
    }

    if (!fgets(buf, sizeof(buf), f)) {
      fclose(f);
      continue;
    }
    fclose(f);

    /* Parse as hex (format: "0x%llx\n"); strtoul handles 0x prefix */
    char *end;
    unsigned long addr = strtoul(buf, &end, 0);
    if (end == buf || addr == 0)
      continue;

    printf("%s resource: 0x%016lx\n", ent->d_name, addr);
    kasld_result_sample(KASLD_TYPE_PHYS, REGION_PMEM, addr, ent->d_name,
                        CONF_PARSED);

#if !PHYS_VIRT_DECOUPLED
    unsigned long virt = phys_to_virt(addr);
    printf("possible direct-map virtual address: 0x%016lx\n", virt);
    kasld_result_sample(KASLD_TYPE_VIRT, REGION_PMEM, virt, ent->d_name,
                        CONF_PARSED);
#endif

    count++;
  }
  closedir(d);

  if (!count) {
    printf("[-] no readable ndregion resource attributes found "
           "(no NVDIMM hardware or driver not bound)\n");
    return KASLD_EXIT_UNAVAILABLE;
  }

  return 0;
}
