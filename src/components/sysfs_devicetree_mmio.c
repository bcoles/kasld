// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Harvest physical MMIO register bases from every device node in the flattened
// device tree (/sys/firmware/devicetree/base, a.k.a. /proc/device-tree).
//
// On device-tree platforms (ARM, RISC-V, PowerPC, most embedded SoCs) each
// device node carries a "reg" property holding the physical base+size of its
// register block — collectively the MMIO half of what /proc/iomem reports. The
// device tree is world-readable (0444) and is NOT subject to kptr_restrict, so
// it survives on hardened systems where /proc/iomem is masked to zeroes (and on
// SoCs with no PCI, where /sys/bus/pci/.../resource is empty and
// ioctl_mmio_phys only covers serial/fb). This reconstructs the device MMIO map
// from a source the iomem mask does not touch.
//
// Only nodes whose "reg" is interpreted in the CPU physical address space are
// emitted: the root node's children, and descendants reached through buses with
// an empty "ranges" property (an identity 1:1 mapping). Buses with a non-empty
// "ranges" (a real translation) or no "ranges" (a separate child address space,
// e.g. i2c/spi device addresses) are not followed — so every emitted value is a
// true CPU physical address, never a mistranslated one. The DRAM nodes
// (memory*, reserved-memory) are skipped; they are covered by
// sysfs_devicetree_memory / _reserved_memory.
//
// Leak primitive:
//   Data leaked:      physical MMIO register-block bases (per device)
//   Kernel subsystem: drivers/of — the flattened device tree
//   Data structure:   each device node's "reg" property (address+size cells)
//   Address type:     physical (MMIO)
//   Method:           parsed (device tree read)
//   Status:           information exposure by design (DT is world-readable)
//   Access check:     none — DT is 0444, not gated by kptr_restrict
//
// Engine fit: emitted as REGION_MMIO PHYS windows. mmio_floor_phys_ceiling
// takes the lowest MMIO base strictly above the DRAM floor (from the memory
// node) to ceiling Q_PHYS_IMAGE_BASE — bracketing the physical kernel placement
// without /proc/iomem. On coupled arches that physical bound propagates to the
// virtual text base; on decoupled arches (x86_64, arm64, riscv64) it bounds the
// physical side only.
//
// Mitigations:
//   None practical — the device tree must be readable for the system to
//   function. Tightening DT node permissions is non-standard.
// ---
// <bcoles@gmail.com>

#include "include/kasld/api.h"
#include "include/kasld/cli.h"
#include "include/kasld/devicetree.h"
#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

KASLD_EXPLAIN(
    "Harvests physical MMIO register bases from every device node's reg "
    "property in the device tree (/sys/firmware/devicetree/base). The device "
    "tree is world-readable and not subject to kptr_restrict, so it supplies "
    "the device MMIO map even where /proc/iomem is masked (and on SoCs with no "
    "PCI). Only CPU-physical reg values are emitted (root children and "
    "identity-mapped buses); DRAM nodes are skipped. The lowest MMIO above the "
    "DRAM floor ceilings the physical kernel image base.");

KASLD_META("method:parsed\n"
           "phase:inference\n"
           "addr:physical\n"
           "config:CONFIG_OF\n");

#define MAX_EMIT 256
#define MAX_DEPTH 6

static int g_count;
/* DRAM extent (from the memory nodes). A device reg is real MMIO only if it is
 * disjoint from DRAM; a reg INSIDE DRAM is a carveout (reserved RAM, e.g. a
 * coprocessor/fast-boot region) mislabelled as MMIO — emitting it could wrongly
 * ceiling the physical image base if it sits below the kernel. */
static unsigned long g_dram_lo = ~0UL, g_dram_hi;

/* Read up to `cap` bytes of a node property; returns byte count, or -1. */
static int read_prop(const char *node, const char *prop, unsigned char *buf,
                     size_t cap) {
  char path[1024];
  snprintf(path, sizeof(path), "%s/%s", node, prop);
  FILE *f = kasld_fopen(path, "rb");
  if (!f)
    return -1;
  int n = (int)fread(buf, 1, cap, f);
  fclose(f);
  return n;
}

static int read_cell_prop(const char *node, const char *prop, int dflt) {
  unsigned char b[4];
  if (read_prop(node, prop, b, 4) == 4)
    return (int)kasld_dt_be32(b);
  return dflt;
}

/* A node passes CPU physical addresses through to its children iff it has an
 * EMPTY "ranges" (identity map). Present-but-non-empty = translation (skip);
 * absent = separate child address space (skip). */
static int has_empty_ranges(const char *node) {
  unsigned char b;
  int n = read_prop(node, "ranges", &b, 1);
  return n == 0; /* file exists and is empty */
}

static int is_memory_node(const char *name) {
  return strncmp(name, "memory", 6) == 0 ||
         strcmp(name, "reserved-memory") == 0;
}

/* Emit each (addr,size) tuple of this node's reg as a REGION_MMIO phys window.
 * addr_cells/size_cells come from the PARENT and describe this reg. */
static void emit_node_reg(const char *node, const char *name, int addr_cells,
                          int size_cells) {
  unsigned char reg[256];
  int n = read_prop(node, "reg", reg, sizeof(reg));
  int entry = (addr_cells + size_cells) * 4;
  if (n <= 0 || size_cells < 1 || entry <= 0)
    return;
  for (int off = 0; off + entry <= n && g_count < MAX_EMIT; off += entry) {
    unsigned long addr = kasld_dt_cells(reg + off, addr_cells);
    unsigned long size = kasld_dt_cells(reg + off + addr_cells * 4, size_cells);
    if (addr == 0 || size == 0)
      continue;
    unsigned long hi = addr + size - 1;
    if (hi < addr)
      continue; /* overflow */
    /* A reg that lands inside DRAM is a carveout (reserved RAM), not MMIO —
     * skip it so it cannot be taken for an MMIO floor below the kernel. */
    if (g_dram_hi > g_dram_lo && addr >= g_dram_lo && addr <= g_dram_hi)
      continue;
    kasld_info("device tree MMIO %s: 0x%lx-0x%lx", name, addr, hi);
    kasld_result_range(KASLD_TYPE_PHYS, REGION_MMIO, addr, hi, name,
                       CONF_PARSED);
    g_count++;
  }
}

/* Recursively walk the DT. addr_cells/size_cells describe THIS node's reg (the
 * parent's #address-cells/#size-cells); `addressable` is whether this node's
 * reg is in CPU physical space. */
static void walk(const char *node, const char *name, int addr_cells,
                 int size_cells, int addressable, int depth) {
  if (depth > MAX_DEPTH || g_count >= MAX_EMIT)
    return;
  if (depth > 0 && is_memory_node(name))
    return; /* DRAM — covered elsewhere */

  if (addressable && size_cells >= 1)
    emit_node_reg(node, name, addr_cells, size_cells);

  int my_ac = read_cell_prop(node, "#address-cells", 2);
  int my_sc = read_cell_prop(node, "#size-cells", 1);
  if (my_ac < 1 || my_ac > 2 || my_sc < 0 || my_sc > 2)
    return;

  /* Root's children are in CPU space; otherwise a child is addressable iff this
   * node passes addresses through (empty ranges). */
  int child_addr = (depth == 0) ? 1 : (addressable && has_empty_ranges(node));

  DIR *d = kasld_opendir(node);
  if (!d)
    return;
  struct dirent *ent;
  while ((ent = readdir(d)) != NULL && g_count < MAX_EMIT) {
    if (ent->d_name[0] == '.')
      continue;
    char child[1024];
    snprintf(child, sizeof(child), "%s/%s", node, ent->d_name);
    /* Child nodes are directories; properties are files. Test portably by
     * trying to open it as a directory (avoids the non-c99 d_type field). */
    DIR *cd = kasld_opendir(child);
    if (!cd)
      continue;
    closedir(cd);
    walk(child, ent->d_name, my_ac, my_sc, child_addr, depth + 1);
  }
  closedir(d);
}

/* Determine the DRAM extent from the root's memory nodes (device_type ==
 * "memory"), using the root's #address-cells/#size-cells. Sets g_dram_lo/hi to
 * the union so emit_node_reg can reject in-DRAM carveouts. */
static void find_dram(const char *root) {
  int ac = read_cell_prop(root, "#address-cells", 2);
  int sc = read_cell_prop(root, "#size-cells", 1);
  if (ac < 1 || ac > 2 || sc < 1 || sc > 2)
    return;
  DIR *d = kasld_opendir(root);
  if (!d)
    return;
  struct dirent *ent;
  while ((ent = readdir(d)) != NULL) {
    if (strncmp(ent->d_name, "memory", 6) != 0)
      continue;
    char node[1024];
    snprintf(node, sizeof(node), "%s/%s", root, ent->d_name);
    unsigned char dt[16];
    int dn = read_prop(node, "device_type", dt, sizeof(dt));
    if (dn < 6 || memcmp(dt, "memory", 6) != 0)
      continue; /* memory-controller etc. are real devices, not DRAM */
    unsigned char reg[256];
    int n = read_prop(node, "reg", reg, sizeof(reg));
    int entry = (ac + sc) * 4;
    for (int off = 0; off + entry <= n; off += entry) {
      unsigned long base = kasld_dt_cells(reg + off, ac);
      unsigned long size = kasld_dt_cells(reg + off + ac * 4, sc);
      if (!size)
        continue;
      unsigned long end = base + size - 1;
      if (end < base)
        continue;
      if (base < g_dram_lo)
        g_dram_lo = base;
      if (end > g_dram_hi)
        g_dram_hi = end;
    }
  }
  closedir(d);
}

int main(int argc, char **argv) {
  kasld_cli(argc, argv);

  const char *base = "/sys/firmware/devicetree/base";
  const char *alt = "/proc/device-tree";
  const char *root = NULL;
  DIR *d = kasld_opendir(base);
  if (d) {
    root = base;
    closedir(d);
  } else if ((d = kasld_opendir(alt)) != NULL) {
    root = alt;
    closedir(d);
  } else {
    kasld_err("device tree not available (not a DT platform?)");
    return KASLD_EXIT_UNAVAILABLE;
  }

  kasld_info("harvesting device-tree MMIO from %s "
             "(unmasked, kptr_restrict-independent)",
             root);
  find_dram(root);
  if (g_dram_hi > g_dram_lo)
    kasld_info("DRAM extent 0x%lx-0x%lx (in-DRAM reg excluded as carveouts)",
               g_dram_lo, g_dram_hi);
  walk(root, "", 0, 0, 0, 0);

  if (!g_count)
    kasld_info("no CPU-addressable MMIO reg nodes found in %s", root);
  return 0;
}
