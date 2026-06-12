// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Enumerate memory block physical addresses from sysfs. The memory
// hotplug subsystem exposes memory blocks at:
//
//   /sys/devices/system/memory/block_size_bytes  (hex, e.g. "8000000")
//   /sys/devices/system/memory/memoryN/phys_index (hex section number)
//   /sys/devices/system/memory/memoryN/state      ("online"/"offline")
//
// All attributes are world-readable (0444). The physical address of
// each block is: phys_index * block_size. By scanning all online memory
// blocks, we derive the lowest and highest physical DRAM addresses.
//
// Leak primitive:
//   Data leaked:      physical DRAM address range (memory block indices)
//   Kernel subsystem: drivers/base/memory —
//   /sys/devices/system/memory/memory*/phys_index Data structure:   struct
//   memory_block → phys_index (section number) Address type:     physical
//   (DRAM) Method:           parsed (sysfs text attribute) Status: unfixed
//   (information exposure by design)
//   Access check:     none (world-readable sysfs attribute, 0444)
//   Source:
//   https://elixir.bootlin.com/linux/v6.12/source/drivers/base/memory.c#L120
//
// Mitigations:
//   CONFIG_MEMORY_HOTPLUG=n removes the memory block sysfs entries.
//   The phys_index attribute is world-readable (0444); no runtime
//   sysctl can restrict access. On decoupled architectures, physical
//   addresses cannot derive the virtual text base.
//
// Requires:
// - CONFIG_MEMORY_HOTPLUG (common on distros)
//
// References:
// https://elixir.bootlin.com/linux/v6.12/source/drivers/base/memory.c#L120
// https://www.kernel.org/doc/Documentation/ABI/testing/sysfs-devices-memory
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
    "Reads physical memory block addresses from "
    "/sys/devices/system/memory/memory*/phys_index. Each world-readable "
    "(0444) entry reports the physical page frame number of a memory "
    "block (typically 128 MiB). Enumerating all blocks maps the "
    "physical DRAM layout. Requires CONFIG_MEMORY_HOTPLUG.");

KASLD_META("method:parsed\n"
           "phase:inference\n"
           "addr:physical\n"
           "config:CONFIG_MEMORY_HOTPLUG\n");

static int read_file_line(const char *path, char *buf, size_t len) {
  FILE *f = kasld_fopen(path, "r");
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

/* Per-run extent emission for ram_map_phys_exclude. Bounded so a huge or
 * heavily-fragmented map degrades to hull-only rather than flooding evidence or
 * emitting a partial (unsound) set. */
#define SMB_MAX_INDICES                                                        \
  4096                  /* online blocks we can collect to merge into runs */
#define SMB_MAX_RUNS 64 /* matches the exclude rule's per-map extent cap   */

int main(void) {
  const char *base = "/sys/devices/system/memory";
  char path[512];
  char buf[256];
  DIR *d;
  struct dirent *ent;
  unsigned long block_size;
  unsigned long lo = ~0ul, hi = 0;
  int count = 0;
  static unsigned long idxs[SMB_MAX_INDICES]; /* online block indices, merged */
  int n_idx = 0, idx_overflow = 0;

  kasld_info("searching %s for memory block info ...", base);

  /* read block size */
  snprintf(path, sizeof(path), "%s/block_size_bytes", base);
  if (read_file_line(path, buf, sizeof(buf)) < 0) {
    perror("[-] cannot read block_size_bytes");
    return (errno == EACCES || errno == EPERM) ? KASLD_EXIT_NOPERM
                                               : KASLD_EXIT_UNAVAILABLE;
  }

  block_size = strtoul(buf, NULL, 16);
  if (!block_size) {
    kasld_err("invalid block size");
    return 0;
  }

  kasld_info("memory block size: %#lx (%lu MB)", block_size,
             block_size / (1024 * 1024));

  d = opendir(base);
  if (!d) {
    perror("[-] opendir");
    return (errno == EACCES || errno == EPERM) ? KASLD_EXIT_NOPERM
                                               : KASLD_EXIT_UNAVAILABLE;
  }

  while ((ent = readdir(d)) != NULL) {
    /* memory block directories are named "memoryN" */
    if (strncmp(ent->d_name, "memory", 6) != 0)
      continue;
    /* skip non-numeric suffixes (e.g. "memory" without a number) */
    if (ent->d_name[6] < '0' || ent->d_name[6] > '9')
      continue;

    /* check state — only consider online blocks */
    snprintf(path, sizeof(path), "%s/%s/state", base, ent->d_name);
    if (read_file_line(path, buf, sizeof(buf)) < 0)
      continue;
    if (strcmp(buf, "online") != 0)
      continue;

    /* read phys_index */
    snprintf(path, sizeof(path), "%s/%s/phys_index", base, ent->d_name);
    if (read_file_line(path, buf, sizeof(buf)) < 0)
      continue;

    unsigned long idx = strtoul(buf, NULL, 16);
    unsigned long addr = idx * block_size;
    /* No `if (!addr) continue;` — block 0 at idx 0 is a legitimate value
     * (phys 0). lo = ~0ul above is the "no blocks seen" sentinel; the
     * comparison below handles addr == 0 cleanly. */

    if (addr < lo)
      lo = addr;

    unsigned long end = addr + block_size - 1;
    if (end > hi)
      hi = end;

    if (n_idx < SMB_MAX_INDICES)
      idxs[n_idx++] = idx;
    else
      idx_overflow = 1;

    count++;
  }
  closedir(d);

  if (!count) {
    kasld_err("no online memory blocks found");
    return 0;
  }

  kasld_info("memory blocks: %d online", count);

  /* `lo` is the start of the lowest ONLINE memory block. A block becomes
   * online once memory hotplug attaches it to a zone; reserved-during-boot
   * regions (the kernel image's hotplug block, EFI runtime, memblock
   * reservations) are typically offline or absent. On systems where
   * firmware reserves low phys for the kernel image (the same class as
   * dmesg_free_area_init_node / proc_zoneinfo), `lo` sits ABOVE the true
   * phys RAM floor. Emit the lowest block start as an interior SAMPLE —
   * a sound RAM witness, but not a floor pin. Authoritative phys floors
   * come from sysfs_devicetree_memory, sysfs_firmware_memmap,
   * boot_params_e820 and peers that read the full memory map. The
   * highest block end IS sound as a TOP bound. */
  kasld_info("lowest memory block start:  0x%016lx", lo);
  kasld_result_sample(KASLD_TYPE_PHYS, REGION_RAM, lo, NULL, CONF_PARSED);

  if (hi) {
    kasld_info("highest memory block end:   0x%016lx", hi);
    kasld_result_top(KASLD_TYPE_PHYS, REGION_RAM, hi, NULL, CONF_PARSED);
  }

  /* Per-region extents for ram_map_phys_exclude. Merge contiguous online blocks
   * into runs and emit one range each; the non-RAM gaps between runs (absent or
   * runtime-offlined blocks) then forbid the physical kernel base — online
   * blocks are present RAM, and the kernel image is unmovable and never
   * offlined, so a gap is not where the base is. Additive to the hull
   * SAMPLE/TOP above (which feed the floor/ceiling rules).
   *
   * Sound only over the COMPLETE online set: if a block could not be collected
   * (overflow) or the runs exceed what the exclude rule reads, emit nothing — a
   * partial set would synthesise a false gap. A single contiguous run has no
   * gap to carve, so >= 2 runs are required. */
  if (!idx_overflow && n_idx > 0) {
    for (int i = 1; i < n_idx; i++) { /* insertion-sort ascending */
      unsigned long key = idxs[i];
      int j = i - 1;
      while (j >= 0 && idxs[j] > key) {
        idxs[j + 1] = idxs[j];
        j--;
      }
      idxs[j + 1] = key;
    }
    int runs = 0;
    for (int i = 0; i < n_idx; i++)
      if (i == 0 || idxs[i] > idxs[i - 1] + 1)
        runs++;
    if (runs >= 2 && runs <= SMB_MAX_RUNS) {
      kasld_info("emitting %d online block run(s)", runs);
      unsigned long rlo_idx = idxs[0], rhi_idx = idxs[0];
      for (int i = 1; i <= n_idx; i++) {
        if (i == n_idx || idxs[i] > rhi_idx + 1) {
          kasld_result_extent(KASLD_TYPE_PHYS, REGION_RAM, rlo_idx * block_size,
                              (rhi_idx + 1) * block_size - 1, NULL,
                              CONF_PARSED);
          if (i < n_idx)
            rlo_idx = rhi_idx = idxs[i];
        } else {
          rhi_idx = idxs[i];
        }
      }
    }
  }

#ifdef phys_to_directmap_virt
  /* Same caveat: phys_to_directmap_virt(lo) lands at the directmap base
   * ONLY when lo is the actual phys floor. Emit as a directmap sample. */
  unsigned long virt = phys_to_directmap_virt(lo);
  kasld_info("possible direct-map virtual address: 0x%016lx", virt);
  kasld_result_sample(KASLD_TYPE_VIRT, REGION_DIRECTMAP, virt, NULL,
                      CONF_PARSED);
#else
  kasld_info("note: phys and virt KASLR are decoupled on this arch; "
             "cannot derive directmap virtual address from physical leak");
#endif

  return 0;
}
