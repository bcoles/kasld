// This file is part of KASLD - https://github.com/bcoles/kasld
//
// /sys/firmware/memmap "System RAM" interval reader (x86 E820 view), no privs.
//
// Each /sys/firmware/memmap/<n>/ has type/start/end files. We collect the
// "System RAM" entries as inclusive [start, end] physical extents. All reads go
// through the kasld_* sysroot wrappers (directory enumerated via kasld_opendir,
// fields via kasld_fopen), so they honour KASLD_SYSROOT redirection.
//
// Read by the engine bridge, which emits these as PHYS RAM extents that the
// firmware_memmap_holes verdict consumes.
// ---
// <bcoles@gmail.com>

#ifndef KASLD_FIRMWARE_MEMMAP_H
#define KASLD_FIRMWARE_MEMMAP_H

#include "sysroot.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define KASLD_MEMMAP_BASE "/sys/firmware/memmap"

struct kasld_ram_extent {
  unsigned long lo, hi; /* inclusive */
};

/* Read the first line of a sysroot fact file into buf (newline stripped). */
__attribute__((unused)) static int
kasld_memmap_first_line(const char *path, char *buf, size_t len) {
  FILE *f = kasld_fopen(path, "r");
  if (!f)
    return -1;
  if (!fgets(buf, (int)len, f)) {
    fclose(f);
    return -1;
  }
  fclose(f);
  buf[strcspn(buf, "\n")] = '\0';
  return 0;
}

/* Collect "System RAM" inclusive extents; returns count (0 if absent). */
__attribute__((unused)) static int
kasld_load_ram_extents(struct kasld_ram_extent *out, int max) {
  DIR *d = kasld_opendir(KASLD_MEMMAP_BASE);
  if (!d)
    return 0;
  int n = 0;
  struct dirent *ent;
  while ((ent = readdir(d)) != NULL && n < max) {
    if (ent->d_name[0] == '.')
      continue;
    char path[512], buf[256];
    snprintf(path, sizeof(path), "%s/%s/type", KASLD_MEMMAP_BASE, ent->d_name);
    if (kasld_memmap_first_line(path, buf, sizeof(buf)) != 0)
      continue;
    if (strcmp(buf, "System RAM") != 0)
      continue;
    snprintf(path, sizeof(path), "%s/%s/start", KASLD_MEMMAP_BASE, ent->d_name);
    if (kasld_memmap_first_line(path, buf, sizeof(buf)) != 0)
      continue;
    char *endp;
    unsigned long start = strtoul(buf, &endp, 16);
    if (endp == buf)
      continue;
    snprintf(path, sizeof(path), "%s/%s/end", KASLD_MEMMAP_BASE, ent->d_name);
    if (kasld_memmap_first_line(path, buf, sizeof(buf)) != 0)
      continue;
    unsigned long end = strtoul(buf, &endp, 16);
    if (endp == buf || end < start)
      continue;
    out[n].lo = start;
    out[n].hi = end;
    n++;
  }
  closedir(d);
  return n;
}

#endif /* KASLD_FIRMWARE_MEMMAP_H */
