// This file is part of KASLD - https://github.com/bcoles/kasld
//
// MemTotal reader (/proc/meminfo), without privileges.
//
// Read by the engine bridge. Reads route through the kasld_* wrappers, so it is
// KASLD_SYSROOT-aware.
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

/* VmallocTotal bytes: VMALLOC_END - VMALLOC_START as the running kernel has
 * them. Printed unconditionally by fs/proc/meminfo.c, so its absence means the
 * file could not be read rather than that the kernel has no vmalloc area.
 *
 * Clamped like the others. On a 32-bit target the true figure can exceed
 * ULONG_MAX, and a clamped value matches no modelled layout, so a consumer
 * inverting it finds nothing and says nothing -- which is the right answer
 * there, since the layouts this feeds are 64-bit ones. */
__attribute__((unused)) static unsigned long
kasld_read_vmalloc_total_bytes(void) {
  FILE *f = kasld_fopen("/proc/meminfo", "r");
  if (!f)
    return 0;

  unsigned long long kb = 0;
  char line[128];
  while (fgets(line, sizeof(line), f)) {
    if (sscanf(line, "VmallocTotal: %llu kB", &kb) == 1)
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
 * kernel versions. Read by the engine bridge for SF_PHYS_MAX_PFN. The zone
 * block lists "spanned N" before "start_pfn: N", so spanned is latched, then
 * paired
 * it with the following start_pfn. */
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

/* Default huge page size in bytes from /proc/meminfo's `Hugepagesize:` line,
 * or 0 when the line is absent (a kernel built without hugetlb does not print
 * it). The value is reported in kB, as the kernel prints it.
 *
 * The caller is responsible for deciding whether the value means what the
 * architecture's HPAGE_SIZE would mean: the line reports the DEFAULT hstate,
 * which `default_hugepagesz=` on the command line can change. */
__attribute__((unused)) static unsigned long
kasld_read_hugepagesize_bytes(void) {
  FILE *f = kasld_fopen("/proc/meminfo", "r");
  if (!f)
    return 0;

  unsigned long long kb = 0;
  char line[256];
  int found = 0;
  while (fgets(line, sizeof line, f)) {
    if (sscanf(line, "Hugepagesize: %llu kB", &kb) == 1) {
      found = 1;
      break;
    }
  }
  fclose(f);
  if (!found || kb == 0 || kb > (ULONG_MAX >> 10))
    return 0;
  return (unsigned long)(kb << 10);
}

/* Total managed pages across every zone in /proc/zoneinfo, or 0 when the file
 * is unreadable or names no zone. This is the same counter MemTotal is
 * rendered from -- adjust_managed_page_count() adds to a zone's managed pages
 * and to totalram in one call -- so the two move together and their ratio is
 * the page size. */
__attribute__((unused)) static unsigned long kasld_read_zone_managed(void) {
  FILE *f = kasld_fopen("/proc/zoneinfo", "r");
  if (!f)
    return 0;

  char line[256];
  unsigned long total = 0;
  while (fgets(line, sizeof(line), f)) {
    unsigned long val;
    if (sscanf(line, " managed %lu", &val) != 1)
      continue;
    if (val > ULONG_MAX - total) { /* refuse to wrap */
      total = 0;
      break;
    }
    total += val;
  }
  fclose(f);
  return total;
}

/* The page size implied by a RAM total in bytes and the page count it was
 * rendered from, or 0 where the pair implies none.
 *
 * MemTotal is totalram << (PAGE_SHIFT - 10) and the managed pages of every
 * zone sum to that same totalram, so the quotient is the page size exactly --
 * no relation to invert and no architecture to know. It is the only route to a
 * page size that works on a REPLAYED capture whatever the architecture: the
 * direct reader describes whoever is replaying, and the huge-page tell needs
 * the huge page to be the PMD block.
 *
 * Refuses anything that does not divide exactly, is not a power of two, or
 * falls outside the sizes this architecture admits. A clamped RAM total cannot
 * slip through: the clamp is ULONG_MAX, which is odd, so any exact quotient of
 * it is odd too and no odd number above one is a page size.
 */
__attribute__((unused)) static unsigned long
kasld_page_size_from_ram_totals(unsigned long memtotal_bytes,
                                unsigned long managed_pages) {
  if (!memtotal_bytes || !managed_pages)
    return 0;
  if (memtotal_bytes % managed_pages)
    return 0;
  const unsigned long ps = memtotal_bytes / managed_pages;
  if (ps & (ps - 1))
    return 0;
  if (ps < (unsigned long)PAGE_SIZE_MIN || ps > (unsigned long)PAGE_SIZE_MAX)
    return 0;
  return ps;
}

/* Invert a default huge page size to the page size it implies on an
 * architecture whose huge page is the PMD block, or 0 where it implies none.
 *
 * The PMD block spans 2^(2*PAGE_SHIFT - 3) bytes, so the three granules give
 * three distinct sizes and the inverse is unambiguous. A value that is not an
 * exact power of two, does not invert to a whole shift, or lands on a granule
 * the architecture does not admit yields 0 -- a huge page configured to some
 * other supported size says nothing about the granule and must not be read as
 * though it did.
 *
 * The CALLER must also establish that the reported size is the architecture's
 * huge page rather than one chosen on the command line; this function sees
 * only the number. */
__attribute__((unused)) static unsigned long
kasld_page_size_from_pmd_hugepage(unsigned long huge) {
  if (!huge)
    return 0;
  unsigned long shift = 0;
  while (shift < 64 && (1ul << shift) < huge)
    shift++;
  if (shift >= 64 || (1ul << shift) != huge)
    return 0;
  if (shift < 3 || ((shift + 3) & 1))
    return 0;
  const unsigned long page_shift = (shift + 3) / 2;
  if (page_shift != 12 && page_shift != 14 && page_shift != 16)
    return 0;
  return 1ul << page_shift;
}

#endif /* KASLD_MEMINFO_H */
