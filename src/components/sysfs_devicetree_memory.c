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

#include "include/kasld/api.h"
#include "include/kasld/cli.h"
#include "include/kasld/devicetree.h"
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
           "phase:inference\n"
           "addr:physical\n"
           "config:CONFIG_OF\n");

int main(void) {
  const char *base = "/sys/firmware/devicetree/base";
  const char *alt = "/proc/device-tree";
  const char *root;
  DIR *d;
  struct dirent *ent;
  char path[512];
  unsigned char buf[1024];
  int n;
  unsigned long lo = ~0ul, hi = 0;
  int count = 0;
  int addr_cells = 1, size_cells = 1;
  /* Buffer the per-region extents and emit them only after the whole map has
   * been read and confirmed complete — a partial covering fabricates false
   * non-RAM gaps (see the emit site below). */
  enum { MAX_BANKS = 64 };
  unsigned long ext_lo[MAX_BANKS], ext_hi[MAX_BANKS];
  int n_ext = 0;
  int truncated = 0, overflow = 0;

  /* Try sysfs first, then /proc/device-tree symlink */
  d = kasld_opendir(base);
  if (d) {
    root = base;
    closedir(d);
  } else {
    d = kasld_opendir(alt);
    if (d) {
      root = alt;
      closedir(d);
    } else {
      kasld_err("device tree not available (not a DT platform?)");
      return KASLD_EXIT_UNAVAILABLE;
    }
  }

  kasld_info("searching %s for memory node physical addresses ...", root);

  /* Read #address-cells from root node (default: 1) */
  snprintf(path, sizeof(path), "%s/#address-cells", root);
  n = kasld_dt_read_blob(path, buf, sizeof(buf));
  if (n == 4) {
    addr_cells = (int)kasld_dt_be32(buf);
  }

  /* Read #size-cells from root node (default: 1) */
  snprintf(path, sizeof(path), "%s/#size-cells", root);
  n = kasld_dt_read_blob(path, buf, sizeof(buf));
  if (n == 4) {
    size_cells = (int)kasld_dt_be32(buf);
  }

  if (addr_cells < 1 || addr_cells > 2 || size_cells < 1 || size_cells > 2) {
    fprintf(stderr,
            "[-] unexpected cell counts: #address-cells=%d, "
            "#size-cells=%d\n",
            addr_cells, size_cells);
    return 0;
  }

  int entry_bytes = (addr_cells + size_cells) * 4;

  kasld_info("device tree: #address-cells=%d, #size-cells=%d", addr_cells,
             size_cells);

  /* Scan for memory@* directories */
  d = kasld_opendir(root);
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
    n = kasld_dt_read_blob(path, buf, sizeof(buf));
    if (n < entry_bytes)
      continue;

    /* A read that exactly fills buf may have been clipped mid-property: the reg
     * could hold more banks than we can see. The covering below is sound only
     * if the WHOLE map is emitted, so a possibly-truncated node poisons the
     * entire map — abandon it rather than fake gaps past the last bank seen. */
    if (n == (int)sizeof(buf)) {
      truncated = 1;
      break;
    }

    /* Parse all (address, size) pairs in the reg property.
     * There may be multiple entries for multi-bank systems. */
    int offset = 0;
    while (offset + entry_bytes <= n) {
      unsigned long base_addr = kasld_dt_cells(buf + offset, addr_cells);
      unsigned long size =
          kasld_dt_cells(buf + offset + addr_cells * 4, size_cells);

      if (!size) {
        offset += entry_bytes;
        continue;
      }

      if (base_addr < lo)
        lo = base_addr;

      unsigned long end = base_addr + size;
      if (end > hi)
        hi = end;

      /* Stash the extent; emitted after the map is confirmed complete. On
       * overflow the extent set is incomplete, but lo/hi stay exact (every
       * node was read in full), so keep tracking the hull. */
      if (n_ext < MAX_BANKS) {
        ext_lo[n_ext] = base_addr;
        ext_hi[n_ext] = end - 1;
        n_ext++;
      } else {
        overflow = 1;
      }

      count++;
      offset += entry_bytes;
    }
  }
  closedir(d);

  if (truncated) {
    kasld_err("device tree memory map may be truncated (a reg property exceeds "
              "the read buffer); withholding the RAM map to avoid a false "
              "covering");
    return 0;
  }

  if (!count) {
    kasld_err("no memory nodes found in device tree");
    return 0;
  }

  /* Per-region extents for ram_map_phys_exclude. The DT /memory nodes are the
   * complete RAM map (each reg is memblock_add'd), so the non-RAM gaps between
   * them forbid the physical kernel base. Positionless extents (not pos=base):
   * the authoritative floor/ceiling stay with the hull base/top below. Emit
   * only when the full set fit in the buffer — an overflowed (partial) set
   * would carve false gaps, so fall back to the hull bounds alone. */
  if (!overflow) {
    for (int i = 0; i < n_ext; i++)
      kasld_result_extent(KASLD_TYPE_PHYS, REGION_RAM, ext_lo[i], ext_hi[i],
                          NULL, CONF_PARSED);
  } else {
    kasld_info("device tree: more than %d memory regions; emitting hull bounds "
               "only (no gap covering)",
               (int)MAX_BANKS);
  }

  kasld_info("device tree: %d memory region(s)", count);

  kasld_info("lowest DRAM start:  0x%016lx", lo);
  kasld_result_base(KASLD_TYPE_PHYS, REGION_RAM, lo, NULL, CONF_PARSED);

  if (hi && hi != lo) {
    kasld_info("highest DRAM end:   0x%016lx", hi);
    kasld_result_top(KASLD_TYPE_PHYS, REGION_RAM, hi, NULL, CONF_PARSED);
  }

#ifdef phys_to_directmap_virt
  unsigned long virt = phys_to_directmap_virt(lo);
  kasld_info("possible direct-map virtual address: 0x%016lx", virt);
  kasld_result_base(KASLD_TYPE_VIRT, REGION_DIRECTMAP, virt, NULL, CONF_PARSED);
#else
  kasld_info("note: phys and virt KASLR are decoupled on this arch; "
             "cannot derive directmap virtual address from physical leak");
#endif

  return 0;
}
