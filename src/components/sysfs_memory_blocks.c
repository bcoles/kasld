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
// Requires:
// - CONFIG_MEMORY_HOTPLUG (common on distros)
//
// References:
// https://elixir.bootlin.com/linux/v6.12/source/drivers/base/memory.c#L120
// https://www.kernel.org/doc/Documentation/ABI/testing/sysfs-devices-memory
// ---
// <bcoles@gmail.com>

#include "include/kasld.h"
#include "include/kasld_internal.h"
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
  const char *base = "/sys/devices/system/memory";
  char path[512];
  char buf[256];
  DIR *d;
  struct dirent *ent;
  unsigned long block_size;
  unsigned long lo = ~0ul, hi = 0;
  int count = 0;

  printf("[.] searching %s for memory block info ...\n", base);

  /* read block size */
  snprintf(path, sizeof(path), "%s/block_size_bytes", base);
  if (read_file_line(path, buf, sizeof(buf)) < 0) {
    perror("[-] cannot read block_size_bytes");
    return (errno == EACCES || errno == EPERM) ? KASLD_EXIT_NOPERM
                                               : KASLD_EXIT_UNAVAILABLE;
  }

  block_size = strtoul(buf, NULL, 16);
  if (!block_size) {
    fprintf(stderr, "[-] invalid block size\n");
    return 0;
  }

  printf("memory block size: %#lx (%lu MB)\n", block_size,
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

    if (addr < lo)
      lo = addr;

    unsigned long end = addr + block_size;
    if (end > hi)
      hi = end;

    count++;
  }
  closedir(d);

  if (!count) {
    printf("[-] no online memory blocks found\n");
    return 0;
  }

  printf("memory blocks: %d online\n", count);

  printf("lowest memory block start:  0x%016lx\n", lo);
  kasld_result(KASLD_ADDR_PHYS, KASLD_SECTION_DRAM, lo,
               "sysfs_memory_blocks:lo");

  if (hi) {
    printf("highest memory block end:   0x%016lx\n", hi);
    kasld_result(KASLD_ADDR_PHYS, KASLD_SECTION_DRAM, hi,
                 "sysfs_memory_blocks:hi");
  }

#if !PHYS_VIRT_DECOUPLED
  unsigned long virt = phys_to_virt(lo);
  printf("possible direct-map virtual address: 0x%016lx\n", virt);
  kasld_result(KASLD_ADDR_VIRT, KASLD_SECTION_DIRECTMAP, virt,
               "sysfs_memory_blocks:directmap");
#else
  printf("note: phys and virt KASLR are decoupled on this arch; "
         "cannot derive directmap virtual address from physical leak\n");
#endif

  return 0;
}
