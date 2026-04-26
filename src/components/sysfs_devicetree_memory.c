// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Read physical DRAM base address from device tree sysfs. On platforms
// that use device tree (ARM, ARM64, RISC-V, MIPS, PowerPC, LoongArch),
// the kernel exposes the flattened device tree as a sysfs hierarchy:
//
//   /sys/firmware/devicetree/base/
//   (also symlinked as /proc/device-tree/)
//
// The memory@<addr> node's "reg" property contains the physical DRAM
// base address and size as raw big-endian binary values. All non-
// "security-*" properties are world-readable (0444), so unprivileged
// users can read them.
//
// The number of 32-bit cells per address/size entry is defined by
// the root node's #address-cells and #size-cells properties (typically
// 2 and 2 on 64-bit platforms, 1 and 1 on 32-bit platforms).
//
// Not available on x86/x86_64 (uses ACPI instead of device tree).
// Use sysfs_firmware_memmap or sysfs_memory_blocks on x86.
//
// Leak primitive:
//   Data leaked:      physical DRAM base and size (device tree memory node)
//   Kernel subsystem: drivers/of — /sys/firmware/devicetree/base/memory*/reg
//   Data structure:   device tree memory node reg property (address + size
//   cells) Address type:     physical (DRAM) Method:           parsed (binary
//   sysfs property) Status:           unfixed (information exposure by design)
//   Access check:     none (world-readable sysfs attribute, 0444)
//   Source: https://elixir.bootlin.com/linux/v6.12/source/drivers/of/kobj.c#L65
//
// Mitigations:
//   CONFIG_OF=n removes device tree sysfs entirely (not applicable on
//   x86). The reg property is world-readable (0444); no runtime
//   sysctl can restrict access. On decoupled architectures, physical
//   addresses cannot derive the virtual text base.
//
// Requires:
// - CONFIG_OF (device tree support — standard on ARM/RISC-V/MIPS/PPC)
// - CONFIG_SYSFS
//
// References:
// https://elixir.bootlin.com/linux/v6.12/source/drivers/of/kobj.c#L65
// https://elixir.bootlin.com/linux/v6.12/source/drivers/of/base.c#L176
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
    "Reads the physical DRAM base address and size from the device tree "
    "sysfs memory node (/sys/firmware/devicetree/base/memory*/reg). "
    "This world-readable binary property contains the physical address "
    "ranges of system RAM. Only present on device tree platforms "
    "(ARM, ARM64, RISC-V, MIPS, PowerPC); requires CONFIG_OF.");

KASLD_META("method:parsed\n"
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
  unsigned char buf[128];
  int n;
  unsigned long lo = ~0ul, hi = 0;
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

  printf("[.] searching %s for memory node physical addresses ...\n", root);

  /* Read #address-cells from root node (default: 1) */
  snprintf(path, sizeof(path), "%s/#address-cells", root);
  n = read_binary(path, buf, sizeof(buf));
  if (n == 4) {
    addr_cells = (int)read_be32(buf);
  }

  /* Read #size-cells from root node (default: 1) */
  snprintf(path, sizeof(path), "%s/#size-cells", root);
  n = read_binary(path, buf, sizeof(buf));
  if (n == 4) {
    size_cells = (int)read_be32(buf);
  }

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

  /* Scan for memory@* directories */
  d = opendir(root);
  if (!d) {
    perror("[-] opendir");
    return (errno == EACCES || errno == EPERM) ? KASLD_EXIT_NOPERM
                                               : KASLD_EXIT_UNAVAILABLE;
  }

  while ((ent = readdir(d)) != NULL) {
    if (strncmp(ent->d_name, "memory", 6) != 0)
      continue;

    /* Accept "memory" and "memory@*" node names */
    if (ent->d_name[6] != '\0' && ent->d_name[6] != '@')
      continue;

    snprintf(path, sizeof(path), "%s/%s/reg", root, ent->d_name);
    n = read_binary(path, buf, sizeof(buf));
    if (n < entry_bytes)
      continue;

    /* Parse all (address, size) pairs in the reg property.
     * There may be multiple entries for multi-bank systems. */
    int offset = 0;
    while (offset + entry_bytes <= n) {
      unsigned long base_addr = read_cells(buf + offset, addr_cells);
      unsigned long size =
          read_cells(buf + offset + addr_cells * 4, size_cells);

      if (!size) {
        offset += entry_bytes;
        continue;
      }

      if (base_addr < lo)
        lo = base_addr;

      unsigned long end = base_addr + size;
      if (end > hi)
        hi = end;

      count++;
      offset += entry_bytes;
    }
  }
  closedir(d);

  if (!count) {
    printf("[-] no memory nodes found in device tree\n");
    return 0;
  }

  printf("device tree: %d memory region(s)\n", count);

  printf("lowest DRAM start:  0x%016lx\n", lo);
  kasld_result(KASLD_ADDR_PHYS, KASLD_SECTION_DRAM, lo, KASLD_REGION_RAM_BASE,
               NULL);

  if (hi && hi != lo) {
    printf("highest DRAM end:   0x%016lx\n", hi);
    kasld_result(KASLD_ADDR_PHYS, KASLD_SECTION_DRAM, hi, KASLD_REGION_RAM_TOP,
                 NULL);
  }

#if !PHYS_VIRT_DECOUPLED
  unsigned long virt = phys_to_virt(lo);
  printf("possible direct-map virtual address: 0x%016lx\n", virt);
  kasld_result(KASLD_ADDR_VIRT, KASLD_SECTION_DIRECTMAP, virt,
               KASLD_REGION_RAM_BASE, NULL);
#else
  printf("note: phys and virt KASLR are decoupled on this arch; "
         "cannot derive directmap virtual address from physical leak\n");
#endif

  return 0;
}
