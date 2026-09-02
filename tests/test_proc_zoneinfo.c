// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Tests for proc_zoneinfo. The component is #included with its main renamed,
// then driven over a staged KASLD_SYSROOT /proc/zoneinfo.
//
// The decision worth guarding is which POSITION each edge takes. /proc/zoneinfo
// describes user-allocatable buddy-allocator zones, not the full physical RAM
// extent: firmware and kernel reservations — including the kernel image itself
// — live outside the published zones. So the lowest zone start is a sound RAM
// WITNESS but not a floor, and it is emitted as an interior sample. Promoting
// it to a base would pin the DRAM floor above the real text base wherever
// firmware reserves the low range (ppc32 PowerMac places the kernel at physical
// 0 with the lowest zone starting at 0x30000000). The highest zone END is a
// sound top bound, and reaching it needs the spanned count: without it the top
// understates RAM by everything above the last zone's start.
//
// Addresses are derived from the architecture's own PAGE_SIZE_MIN. Where the
// page size is not a build constant the component declines under a captured
// tree rather than guessing, and the tests assert that decline instead — see
// the branch on PAGE_SIZE_KNOWN_AT_BUILD below.
// ---
// <bcoles@gmail.com>
#define _GNU_SOURCE

int proc_zoneinfo_main(void);
#define main proc_zoneinfo_main
#include "../src/components/proc_zoneinfo.c"
#undef main

#include "test_component.h"
#include "test_harness.h"
#include "test_sysroot.h"

#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* Two zones, in the shape /proc/zoneinfo prints them: the spanned count
 * precedes the start_pfn it belongs to. */
static const char *const ZONES_TWO = "Node 0, zone      DMA\n"
                                     "  pages free     3968\n"
                                     "        spanned  4095\n"
                                     "        present  3993\n"
                                     "  start_pfn:           1\n"
                                     "Node 0, zone   Normal\n"
                                     "  pages free     100000\n"
                                     "        spanned  1044480\n"
                                     "        present  1044480\n"
                                     "  start_pfn:           4096\n";

#if PAGE_SIZE_KNOWN_AT_BUILD
static unsigned long phys_of(unsigned long pfn) {
  return pfn * (unsigned long)PAGE_SIZE_MIN;
}
#endif

/* The lowest zone start reaches the wire as an interior SAMPLE. A base would
 * claim RAM starts there, and the reservations below the lowest zone are
 * exactly what zoneinfo cannot see. */
static void test_lowest_zone_start_is_a_sample_not_a_base(void) {
  th_sysroot_write("/proc/zoneinfo", ZONES_TWO);
  int rc;
  TH_RUN_COMPONENT(rc, proc_zoneinfo_main());
#if !PAGE_SIZE_KNOWN_AT_BUILD
  /* No build-constant page size and a captured tree: PFNs cannot be converted,
   * and the component says so rather than assuming one. */
  assert(rc == KASLD_EXIT_UNAVAILABLE);
  assert(th_cap[0] == '\0');
#else
  assert(rc == 0);
  assert(th_cap_field_is("sample", phys_of(1)));
  /* Never as a base: pos=base would carry lo= for this value. */
  assert(!th_cap_field_is("lo", phys_of(1)));
  assert(strstr(th_cap, "conf=parsed") != NULL);
#endif
}

/* The top bound uses start_pfn + spanned, not the highest start. Reporting the
 * start alone would place the top of RAM at the beginning of the last zone and
 * lose everything the zone spans. */
static void test_top_bound_uses_the_spanned_count(void) {
  th_sysroot_write("/proc/zoneinfo", ZONES_TWO);
  int rc;
  TH_RUN_COMPONENT(rc, proc_zoneinfo_main());
#if !PAGE_SIZE_KNOWN_AT_BUILD
  assert(rc == KASLD_EXIT_UNAVAILABLE);
#else
  assert(rc == 0);
  /* end_pfn = 4096 + 1044480; the emitted top is the last byte of that page. */
  assert(th_cap_field_is("hi", phys_of(4096UL + 1044480UL) - 1));
  /* And not the bare highest start. */
  assert(!th_cap_field_is("hi", phys_of(4096) - 1));
#endif
}

/* A spanned count belongs to the zone whose start_pfn follows it. Carrying one
 * into the next zone would inflate that zone's end. */
static void test_spanned_does_not_leak_into_the_next_zone(void) {
  th_sysroot_write("/proc/zoneinfo", "Node 0, zone      DMA\n"
                                     "        spanned  1000\n"
                                     "  start_pfn:           1\n"
                                     "Node 0, zone   Normal\n"
                                     "  start_pfn:           4096\n");
  int rc;
  TH_RUN_COMPONENT(rc, proc_zoneinfo_main());
#if !PAGE_SIZE_KNOWN_AT_BUILD
  assert(rc == KASLD_EXIT_UNAVAILABLE);
#else
  assert(rc == 0);
  /* The second zone has no spanned, so its end is its start; the highest end
   * across both zones is 1 + 1000. */
  assert(th_cap_field_is("hi", phys_of(4096) - 1));
#endif
}

/* A zone genuinely starting at PFN 0 is admissible on some hot-plug and
 * embedded boots. The "no zones yet" sentinel is a count, so PFN 0 is taken as
 * the lowest start rather than mistaken for the uninitialised value. */
static void test_zone_at_pfn_zero_is_the_lowest(void) {
  th_sysroot_write("/proc/zoneinfo", "Node 0, zone      DMA\n"
                                     "        spanned  16\n"
                                     "  start_pfn:           0\n"
                                     "Node 0, zone   Normal\n"
                                     "        spanned  4096\n"
                                     "  start_pfn:           4096\n");
  int rc;
  TH_RUN_COMPONENT(rc, proc_zoneinfo_main());
#if !PAGE_SIZE_KNOWN_AT_BUILD
  assert(rc == KASLD_EXIT_UNAVAILABLE);
#else
  assert(rc == 0);
  assert(th_cap_field_is("sample", 0));
#endif
}

/* A file carrying no start_pfn at all: the technique applied and found nothing,
 * so exit 0 with no result rather than a claim the source is absent. */
static void test_no_zones_emits_nothing(void) {
  th_sysroot_write("/proc/zoneinfo", "Node 0, zone      DMA\n"
                                     "  pages free     3968\n");
  int rc;
  TH_RUN_COMPONENT(rc, proc_zoneinfo_main());
  assert(rc == 0);
  assert(th_cap[0] == '\0');
}

/* No file is a source this kernel does not publish. */
static void test_absent_file_is_unavailable(void) {
  char full[TH_SYSROOT_MAX];
  th_sysroot_path("/proc/zoneinfo", full, sizeof(full));
  unlink(full);
  int rc;
  TH_RUN_COMPONENT(rc, proc_zoneinfo_main());
  assert(rc == KASLD_EXIT_UNAVAILABLE);
  assert(th_cap[0] == '\0');
}

int main(void) {
  th_sysroot_init("proc_zoneinfo");
  TEST_SUITE("proc_zoneinfo");

  BEGIN_CATEGORY("Zone extents");
  RUN(test_lowest_zone_start_is_a_sample_not_a_base);
  RUN(test_top_bound_uses_the_spanned_count);
  RUN(test_spanned_does_not_leak_into_the_next_zone);
  RUN(test_zone_at_pfn_zero_is_the_lowest);

  BEGIN_CATEGORY("Absence");
  RUN(test_no_zones_emits_nothing);
  RUN(test_absent_file_is_unavailable);

  return TEST_DONE();
}
