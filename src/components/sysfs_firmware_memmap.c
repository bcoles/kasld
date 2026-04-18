// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Read physical memory map from /sys/firmware/memmap/. Each entry has
// start, end, and type attributes. Entries of type "System RAM" give
// the physical DRAM ranges reported by the firmware (E820 on x86, EFI
// memory map on UEFI systems).
//
// All attributes are world-readable (0444). The lowest "System RAM"
// start address and highest end address are emitted as physical DRAM
// range hints.
//
// Layout:
//   /sys/firmware/memmap/0/start  -> "0x0"
//   /sys/firmware/memmap/0/end    -> "0x9e7ff"
//   /sys/firmware/memmap/0/type   -> "System RAM"
//
// Requires:
// - CONFIG_FIRMWARE_MEMMAP (common on x86 distros; not available on
//   ARM/RISC-V)
//
// References:
// https://elixir.bootlin.com/linux/v6.12/source/drivers/firmware/memmap.c
// https://www.kernel.org/doc/Documentation/ABI/testing/sysfs-firmware-memmap
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
  /* strip trailing newline */
  buf[strcspn(buf, "\n")] = '\0';
  return 0;
}

int main(void) {
  const char *base = "/sys/firmware/memmap";
  DIR *d;
  struct dirent *ent;
  char path[512];
  char buf[256];
  unsigned long lo = ~0ul, hi = 0;
  int count = 0;

  printf("[.] searching %s for System RAM entries ...\n", base);

  d = opendir(base);
  if (!d) {
    perror("[-] opendir");
    return (errno == EACCES || errno == EPERM) ? KASLD_EXIT_NOPERM
                                               : KASLD_EXIT_UNAVAILABLE;
  }

  while ((ent = readdir(d)) != NULL) {
    /* entries are numbered directories: 0, 1, 2, ... */
    if (ent->d_name[0] == '.')
      continue;

    /* read type */
    snprintf(path, sizeof(path), "%s/%s/type", base, ent->d_name);
    if (read_file_line(path, buf, sizeof(buf)) < 0)
      continue;

    if (strcmp(buf, "System RAM") != 0)
      continue;

    /* read start */
    snprintf(path, sizeof(path), "%s/%s/start", base, ent->d_name);
    if (read_file_line(path, buf, sizeof(buf)) < 0)
      continue;

    char *endptr;
    unsigned long start = strtoul(buf, &endptr, 16);

    /* read end */
    snprintf(path, sizeof(path), "%s/%s/end", base, ent->d_name);
    if (read_file_line(path, buf, sizeof(buf)) < 0)
      continue;

    unsigned long end = strtoul(buf, &endptr, 16);

    /* track lowest start and highest end across System RAM entries */
    if (start < lo)
      lo = start;
    if (end > hi)
      hi = end;

    count++;
  }
  closedir(d);

  if (!count) {
    printf("[-] no System RAM entries found in %s\n", base);
    return 0;
  }

  printf("firmware memmap: %d System RAM entries\n", count);

  printf("lowest System RAM start:  0x%016lx\n", lo);
  kasld_result(KASLD_ADDR_PHYS, KASLD_SECTION_DRAM, lo,
               "sysfs_firmware_memmap:lo");

  if (hi && hi != lo) {
    printf("highest System RAM end:   0x%016lx\n", hi);
    kasld_result(KASLD_ADDR_PHYS, KASLD_SECTION_DRAM, hi,
                 "sysfs_firmware_memmap:hi");
  }

#if !PHYS_VIRT_DECOUPLED
  unsigned long virt = phys_to_virt(lo);
  printf("possible direct-map virtual address: 0x%016lx\n", virt);
  kasld_result(KASLD_ADDR_VIRT, KASLD_SECTION_DIRECTMAP, virt,
               "sysfs_firmware_memmap:directmap");
#else
  printf("note: phys and virt KASLR are decoupled on this arch; "
         "cannot derive directmap virtual address from physical leak\n");
#endif

  return 0;
}
