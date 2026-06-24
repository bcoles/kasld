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
// firmware_memmap_holes verdict consumes. The loader is all-or-nothing: it
// returns -1 (caller emits nothing) if the map cannot be captured completely,
// because a partial covering would fabricate false gaps for gap-carving.
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

/* Collect "System RAM" inclusive extents into out[0..max).
 *
 * Returns the number of extents, or -1 if the firmware map cannot be
 * represented COMPLETELY and faithfully: more than `max` System RAM entries,
 * a numbered entry whose type/start/end could not be read or parsed, or an
 * extent value that does not fit unsigned long (i386/PAE >4 GiB truncation).
 * A covering MUST be complete — a truncated or partial map fabricates false
 * gaps that the gap-carving rules (firmware_memmap_holes, ram_map_phys_exclude)
 * turn into unsound C_EXCLUDEs — so callers MUST emit nothing on -1. Mirrors
 * the all-or-nothing covering_ok guard in boot_params_e820. */
__attribute__((unused)) static int
kasld_load_ram_extents(struct kasld_ram_extent *out, int max) {
  DIR *d = kasld_opendir(KASLD_MEMMAP_BASE);
  if (!d)
    return 0;
  int n = 0, incomplete = 0;
  struct dirent *ent;
  while ((ent = readdir(d)) != NULL) {
    if (ent->d_name[0] == '.')
      continue;
    char path[512], buf[256];
    snprintf(path, sizeof(path), "%s/%s/type", KASLD_MEMMAP_BASE, ent->d_name);
    if (kasld_memmap_first_line(path, buf, sizeof(buf)) != 0) {
      incomplete = 1; /* numbered entry with no type: map state unknown */
      break;
    }
    if (strcmp(buf, "System RAM") != 0)
      continue; /* a genuine non-RAM region: a real gap, correctly omitted */
    /* From here the entry IS System RAM; any failure makes the map partial. */
    if (n >= max) {
      incomplete = 1; /* more RAM entries than out[]: would truncate the map */
      break;
    }
    snprintf(path, sizeof(path), "%s/%s/start", KASLD_MEMMAP_BASE, ent->d_name);
    if (kasld_memmap_first_line(path, buf, sizeof(buf)) != 0) {
      incomplete = 1;
      break;
    }
    char *endp;
    unsigned long long start = strtoull(buf, &endp, 16);
    if (endp == buf) {
      incomplete = 1;
      break;
    }
    snprintf(path, sizeof(path), "%s/%s/end", KASLD_MEMMAP_BASE, ent->d_name);
    if (kasld_memmap_first_line(path, buf, sizeof(buf)) != 0) {
      incomplete = 1;
      break;
    }
    unsigned long long end = strtoull(buf, &endp, 16);
    if (endp == buf || end < start) {
      incomplete = 1;
      break;
    }
    /* On i386 unsigned long is 32-bit; a >4 GiB extent would truncate and
     * corrupt the covering. Suppress the whole map rather than store a wrong
     * extent. */
    if ((unsigned long long)(unsigned long)start != start ||
        (unsigned long long)(unsigned long)end != end) {
      incomplete = 1;
      break;
    }
    out[n].lo = (unsigned long)start;
    out[n].hi = (unsigned long)end;
    n++;
  }
  closedir(d);
  return incomplete ? -1 : n;
}

#endif /* KASLD_FIRMWARE_MEMMAP_H */
