// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Read physical addresses from Device Tree reserved-memory nodes at
// /sys/firmware/devicetree/base/reserved-memory/*/reg.
//
// The reserved-memory node contains child nodes that describe firmware-
// reserved DRAM regions: CMA pools, secure-world buffers (OP-TEE, TrustZone
// shared memory), TEE carve-outs, GPU/display framebuffers, vendor-specific
// reservations, etc. Each child's "reg" property is a binary big-endian
// array of (address, size) cell pairs, identical in format to the memory@*
// nodes parsed by sysfs_devicetree_memory.
//
// The number of cells per field is read from #address-cells and #size-cells
// in the reserved-memory node itself; if absent, the root node's cell counts
// are used (the DT spec allows reserved-memory to define its own cells).
//
// All non-security sysfs properties are world-readable (0444); no
// capability check is required.
//
// Leak primitive:
//   Data leaked:      physical addresses of firmware-reserved DRAM regions
//   Kernel subsystem: drivers/of — /sys/firmware/devicetree/base/
//                     reserved-memory/*/reg
//   Data structure:   device tree reserved-memory child node reg properties
//   Address type:     physical (DRAM)
//   Method:           parsed (binary sysfs property)
//   Status:           unfixed (information exposure by design)
//   Access check:     none (world-readable sysfs attribute, 0444)
//   Source:
//   https://elixir.bootlin.com/linux/v6.12/source/drivers/of/kobj.c#L65
//
// Mitigations:
//   CONFIG_OF=n removes device tree sysfs entirely. The reg property is
//   world-readable (0444); no runtime sysctl can restrict access.
//
// Requires:
// - CONFIG_OF (device tree support — standard on ARM/RISC-V/MIPS/PPC)
// - CONFIG_SYSFS
// - A platform with a reserved-memory node in the device tree
//
// References:
// https://elixir.bootlin.com/linux/v6.12/source/drivers/of/kobj.c#L65
// https://www.kernel.org/doc/Documentation/devicetree/bindings/reserved-memory/reserved-memory.txt
// https://www.kernel.org/doc/Documentation/ABI/testing/sysfs-firmware-ofw
// ---
// <bcoles@gmail.com>

#include "include/kasld.h"
#include "include/kasld_internal.h"
#include <dirent.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

KASLD_EXPLAIN(
    "Reads physical addresses from Device Tree reserved-memory child "
    "nodes (/sys/firmware/devicetree/base/reserved-memory/*/reg). These "
    "world-readable binary reg properties describe firmware-reserved DRAM "
    "regions: CMA pools, OP-TEE / TrustZone buffers, display framebuffers, "
    "and vendor-specific carve-outs. Physical addresses bound the DRAM "
    "layout. Only present on device tree platforms (ARM, ARM64, RISC-V, "
    "MIPS, PowerPC); requires CONFIG_OF.");

KASLD_META("method:parsed\n"
           "phase:inference\n"
           "addr:physical\n"
           "config:CONFIG_OF\n");

/* Read raw binary content from a sysfs file. Returns bytes read, or -1. */
static int read_binary(const char *path, unsigned char *buf, size_t len) {
  FILE *f = fopen(path, "rb");
  if (!f)
    return -1;
  int n = (int)fread(buf, 1, len, f);
  fclose(f);
  return n;
}

/* Read a big-endian 32-bit cell from raw bytes. */
static uint32_t read_be32(const unsigned char *p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

/* Read a multi-cell big-endian value (1 or 2 cells). */
static unsigned long read_cells(const unsigned char *p, int ncells) {
  if (ncells == 2) {
    uint64_t hi = read_be32(p);
    uint64_t lo = read_be32(p + 4);
    return (unsigned long)((hi << 32) | lo);
  }
  return (unsigned long)read_be32(p);
}

int main(void) {
  const char *base = "/sys/firmware/devicetree/base";
  const char *alt = "/proc/device-tree";
  const char *root;
  DIR *d;
  struct dirent *ent;
  char path[512];
  unsigned char buf[256];
  int n;
  int count = 0;
  int addr_cells = 1, size_cells = 1;

  /* Try sysfs first, then /proc/device-tree symlink */
  d = opendir(base);
  if (d) {
    root = base;
    closedir(d);
  } else {
    d = opendir(alt);
    if (d) {
      root = alt;
      closedir(d);
    } else {
      printf("[-] device tree not available (not a DT platform?)\n");
      return KASLD_EXIT_UNAVAILABLE;
    }
  }

  /* Check that the reserved-memory node exists */
  snprintf(path, sizeof(path), "%s/reserved-memory", root);
  d = opendir(path);
  if (!d) {
    if (errno == EACCES || errno == EPERM)
      return KASLD_EXIT_NOPERM;
    printf("[-] reserved-memory node not found in device tree\n");
    return KASLD_EXIT_UNAVAILABLE;
  }
  closedir(d);

  printf("[.] searching %s/reserved-memory for physical addresses ...\n", root);

  /* Read root #address-cells and #size-cells as defaults */
  snprintf(path, sizeof(path), "%s/#address-cells", root);
  n = read_binary(path, buf, sizeof(buf));
  if (n == 4)
    addr_cells = (int)read_be32(buf);

  snprintf(path, sizeof(path), "%s/#size-cells", root);
  n = read_binary(path, buf, sizeof(buf));
  if (n == 4)
    size_cells = (int)read_be32(buf);

  /* The reserved-memory node often defines its own #address-cells and
   * #size-cells (commonly both 2 on 64-bit platforms); prefer those. */
  snprintf(path, sizeof(path), "%s/reserved-memory/#address-cells", root);
  n = read_binary(path, buf, sizeof(buf));
  if (n == 4)
    addr_cells = (int)read_be32(buf);

  snprintf(path, sizeof(path), "%s/reserved-memory/#size-cells", root);
  n = read_binary(path, buf, sizeof(buf));
  if (n == 4)
    size_cells = (int)read_be32(buf);

  if (addr_cells < 1 || addr_cells > 2 || size_cells < 1 || size_cells > 2) {
    fprintf(stderr,
            "[-] unexpected cell counts: #address-cells=%d, "
            "#size-cells=%d\n",
            addr_cells, size_cells);
    return 0;
  }

  int entry_bytes = (addr_cells + size_cells) * 4;

  printf("device tree: #address-cells=%d, #size-cells=%d\n", addr_cells,
         size_cells);

  /* Scan all children of reserved-memory/ for reg properties */
  snprintf(path, sizeof(path), "%s/reserved-memory", root);
  d = opendir(path);
  if (!d) {
    int e = errno;
    perror("[-] opendir");
    return (e == EACCES || e == EPERM) ? KASLD_EXIT_NOPERM
                                       : KASLD_EXIT_UNAVAILABLE;
  }

  while ((ent = readdir(d)) != NULL) {
    if (ent->d_name[0] == '.')
      continue;

    char reg_path[512];
    snprintf(reg_path, sizeof(reg_path), "%s/reserved-memory/%s/reg", root,
             ent->d_name);
    n = read_binary(reg_path, buf, sizeof(buf));
    if (n < entry_bytes)
      continue;

    /* Parse all (address, size) pairs in the reg property */
    int offset = 0;
    while (offset + entry_bytes <= n) {
      unsigned long base_addr = read_cells(buf + offset, addr_cells);
      unsigned long size =
          read_cells(buf + offset + addr_cells * 4, size_cells);

      if (!base_addr || !size) {
        offset += entry_bytes;
        continue;
      }

      printf("reserved-memory %s: base=0x%016lx size=0x%lx\n", ent->d_name,
             base_addr, size);

      /* Use the DT node name to identify the specific reservation
       * (e.g. "linux,cma", "optee@a0000000", "video_reserved@...") */
      kasld_result(KASLD_ADDR_PHYS, KASLD_SECTION_DRAM, base_addr,
                   KASLD_REGION_RESERVED_MEM, ent->d_name);

#if !PHYS_VIRT_DECOUPLED
      unsigned long virt = phys_to_virt(base_addr);
      printf("  possible direct-map virtual address: 0x%016lx\n", virt);
      kasld_result(KASLD_ADDR_VIRT, KASLD_SECTION_DIRECTMAP, virt,
                   KASLD_REGION_RESERVED_MEM, ent->d_name);
#endif

      count++;
      offset += entry_bytes;
    }
  }
  closedir(d);

  if (!count) {
    printf("[-] no reserved-memory regions with reg properties found\n");
    return 0;
  }

#if PHYS_VIRT_DECOUPLED
  printf("note: phys and virt KASLR are decoupled on this arch; "
         "cannot derive directmap virtual address from physical leak\n");
#endif

  return 0;
}
