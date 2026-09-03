// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Tests for meminfo_facts. The component is nine lines over three parsers in
// include/kasld/meminfo.h, and those parsers are what this exercises: no other
// tested component reaches that header, so every line of it was unrun.
//
// The three carry one decision each, and all three feed the guaranteed window:
//
//   MemTotal   kB scaled to bytes. A kernel reports kB; a rule bounding
//              physical RAM needs bytes, and the factor is the whole parser.
//   LowTotal   emitted ONLY alongside HighTotal. LowTotal alone is what a
//              64-bit kernel prints for all of memory, where it says nothing
//              about a highmem split; treating it as a lowmem ceiling there
//              would cap the physical window at total RAM on every such host.
//   max_pfn    the highest zone END, which needs `spanned` as well as
//              `start_pfn`. Taking the largest start alone understates RAM by
//              the whole final zone.
//
// zoneinfo prints `spanned` before the `start_pfn` that closes a zone block, so
// the parser holds the count and applies it when the start arrives. The fixture
// below keeps that order, and puts the higher zone second so a parser that
// simply kept the last value it saw would still pass — the maximum has to be
// taken across zones, not read off the end.
// ---
// <bcoles@gmail.com>
#define _GNU_SOURCE

int meminfo_facts_main(void);
#define main meminfo_facts_main
#include "../src/components/meminfo_facts.c"
#undef main

#include "test_component.h"
#include "test_harness.h"
#include "test_sysroot.h"

#include <stdio.h>
#include <string.h>

/* Two zones in the shape /proc/zoneinfo prints them. The second spans further,
 * so the maximum is not the last start_pfn seen. */
static const char *const ZONEINFO = "Node 0, zone      DMA\n"
                                    "  pages free     3968\n"
                                    "        spanned  4095\n"
                                    "        present  3999\n"
                                    "        start_pfn:           1\n"
                                    "Node 0, zone    DMA32\n"
                                    "  pages free     100000\n"
                                    "        spanned  1044480\n"
                                    "        present  1044480\n"
                                    "        start_pfn:           4096\n";

static void run(int *rc) { TH_RUN_COMPONENT(*rc, meminfo_facts_main()); }

/* MemTotal is reported in kB and consumed in bytes. */
static void test_memtotal_scales_kb_to_bytes(void) {
  th_sysroot_clear();
  th_sysroot_write("/proc/meminfo", "MemTotal:       16384 kB\n");
  int rc;
  run(&rc);
  assert(th_cap_field_is("value", 16384ul * 1024ul));
  assert(strstr(th_cap, "phys_memtotal") != NULL);
}

/* LowTotal without HighTotal is not a highmem split: a 64-bit kernel prints it
 * for all of memory, so emitting it would cap the physical window at RAM. */
static void test_lowmem_needs_a_highmem_counterpart(void) {
  th_sysroot_clear();
  th_sysroot_write("/proc/meminfo", "MemTotal:       16384 kB\n"
                                    "LowTotal:       16384 kB\n");
  int rc;
  run(&rc);
  assert(strstr(th_cap, "phys_lowmem") == NULL);

  th_sysroot_clear();
  th_sysroot_write("/proc/meminfo", "MemTotal:       16384 kB\n"
                                    "LowTotal:        4096 kB\n"
                                    "HighTotal:      12288 kB\n");
  run(&rc);
  assert(strstr(th_cap, "phys_lowmem") != NULL);
  assert(th_cap_field_is("value", 4096ul * 1024ul));
}

/* The highest zone END, which is start_pfn + spanned — not the highest start.
 */
static void test_max_pfn_is_the_highest_zone_end(void) {
  th_sysroot_clear();
  th_sysroot_write("/proc/zoneinfo", ZONEINFO);
  int rc;
  run(&rc);
  assert(strstr(th_cap, "phys_max_pfn") != NULL);
  assert(th_cap_field_is("value", 4096ul + 1044480ul));
  /* The largest start alone would be 4096, and the first zone's end 4096 too;
   * either shortcut lands below the real top. */
  assert(!th_cap_field_is("value", 4096ul));
}

/* No files: nothing claimed. A component that reads nothing must say nothing
 * rather than emit a zero. */
static void test_absent_sources_emit_nothing(void) {
  th_sysroot_clear();
  int rc;
  run(&rc);
  assert(strstr(th_cap, "phys_memtotal") == NULL);
  assert(strstr(th_cap, "phys_lowmem") == NULL);
  assert(strstr(th_cap, "phys_max_pfn") == NULL);
}

int main(void) {
  th_sysroot_init("meminfo_facts");
  TEST_SUITE("meminfo_facts");

  BEGIN_CATEGORY("Scaling and gating");
  RUN(test_memtotal_scales_kb_to_bytes);
  RUN(test_lowmem_needs_a_highmem_counterpart);

  BEGIN_CATEGORY("Zone extents");
  RUN(test_max_pfn_is_the_highest_zone_end);

  BEGIN_CATEGORY("Absence");
  RUN(test_absent_sources_emit_nothing);

  return TEST_DONE();
}
