// This file is part of KASLD - https://github.com/bcoles/kasld
//
// MemTotal reader (/proc/meminfo), without privileges.
//
// Read by the engine bridge. Reads route through the kasld_* wrappers, so it is
// KASLD_SYSROOT-aware (replayable).
// ---
// <bcoles@gmail.com>

#ifndef KASLD_MEMINFO_H
#define KASLD_MEMINFO_H

#include "sysroot.h"

#include <limits.h>
#include <stdio.h>

/* Total RAM in bytes from /proc/meminfo, or 0 on failure. Clamped to
 * ULONG_MAX so callers never see wraparound on 32-bit. */
__attribute__((unused)) static unsigned long kasld_read_memtotal_bytes(void) {
  FILE *f = kasld_fopen("/proc/meminfo", "r");
  if (!f)
    return 0;

  unsigned long long kb = 0;
  char line[128];
  /* /proc/meminfo format: "MemTotal:    16384000 kB\n" */
  while (fgets(line, sizeof(line), f)) {
    if (sscanf(line, "MemTotal: %llu kB", &kb) == 1)
      break;
  }
  fclose(f);

  unsigned long long bytes = kb * 1024ULL;
  return (bytes > (unsigned long long)ULONG_MAX) ? ULONG_MAX
                                                 : (unsigned long)bytes;
}

/* Lowmem bytes (LowTotal) on a 32-bit CONFIG_HIGHMEM system, or 0 when there
 * is no highmem (HighTotal == 0 or absent) — in which case LowTotal == MemTotal
 * and the MemTotal ceiling already suffices. The kernel image must reside in
 * lowmem, so LowTotal is the relevant ceiling when highmem is present. */
__attribute__((unused)) static unsigned long kasld_read_lowmem_bytes(void) {
  FILE *f = kasld_fopen("/proc/meminfo", "r");
  if (!f)
    return 0;

  unsigned long long low_kb = 0, high_kb = 0;
  char line[128];
  while (fgets(line, sizeof(line), f)) {
    if (sscanf(line, "LowTotal: %llu kB", &low_kb) == 1)
      continue;
    if (sscanf(line, "HighTotal: %llu kB", &high_kb) == 1)
      continue;
  }
  fclose(f);

  if (high_kb == 0 || low_kb == 0)
    return 0;
  unsigned long long bytes = low_kb * 1024ULL;
  return (bytes > (unsigned long long)ULONG_MAX) ? ULONG_MAX
                                                 : (unsigned long)bytes;
}

/* Highest spanned PFN from /proc/zoneinfo: max(start_pfn + spanned) across all
 * zones. Returns 0 on failure. /proc/zoneinfo is world-readable (0444) on all
 * kernel versions. Read by the engine bridge for SF_MAX_PFN. The zone block
 * lists "spanned N" before "start_pfn: N", so we latch spanned then pair it
 * with the following start_pfn. */
__attribute__((unused)) static unsigned long kasld_read_max_pfn(void) {
  FILE *f = kasld_fopen("/proc/zoneinfo", "r");
  if (!f)
    return 0;

  char line[256];
  unsigned long max_pfn = 0, cur_spanned = 0;
  while (fgets(line, sizeof(line), f)) {
    unsigned long val;
    if (sscanf(line, " spanned %lu", &val) == 1) {
      cur_spanned = val;
      continue;
    }
    if (sscanf(line, "  start_pfn: %lu", &val) != 1)
      continue;
    unsigned long end_pfn = cur_spanned ? val + cur_spanned : val;
    if (end_pfn > max_pfn)
      max_pfn = end_pfn;
    cur_spanned = 0;
  }
  fclose(f);
  return max_pfn;
}

#endif /* KASLD_MEMINFO_H */
