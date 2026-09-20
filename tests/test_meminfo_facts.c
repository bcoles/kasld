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
  TH_CHECK(th_cap_field_is("value", 16384ul * 1024ul));
  TH_CHECK(strstr(th_cap, "phys_memtotal") != NULL);
}

/* LowTotal without HighTotal is not a highmem split: a 64-bit kernel prints it
 * for all of memory, so emitting it would cap the physical window at RAM. */
static void test_lowmem_needs_a_highmem_counterpart(void) {
  th_sysroot_clear();
  th_sysroot_write("/proc/meminfo", "MemTotal:       16384 kB\n"
                                    "LowTotal:       16384 kB\n");
  int rc;
  run(&rc);
  TH_CHECK(strstr(th_cap, "phys_lowmem") == NULL);

  th_sysroot_clear();
  th_sysroot_write("/proc/meminfo", "MemTotal:       16384 kB\n"
                                    "LowTotal:        4096 kB\n"
                                    "HighTotal:      12288 kB\n");
  run(&rc);
  TH_CHECK(strstr(th_cap, "phys_lowmem") != NULL);
  TH_CHECK(th_cap_field_is("value", 4096ul * 1024ul));
}

/* The highest zone END, which is start_pfn + spanned — not the highest start.
 */
static void test_max_pfn_is_the_highest_zone_end(void) {
  th_sysroot_clear();
  th_sysroot_write("/proc/zoneinfo", ZONEINFO);
  int rc;
  run(&rc);
  TH_CHECK(strstr(th_cap, "phys_max_pfn") != NULL);
  TH_CHECK(th_cap_field_is("value", 4096ul + 1044480ul));
  /* The largest start alone would be 4096, and the first zone's end 4096 too;
   * either shortcut lands below the real top. */
  TH_CHECK(!th_cap_field_is("value", 4096ul));
}

/* No files: nothing claimed. A component that reads nothing must say nothing
 * rather than emit a zero. */
/* cmdline_lookup distinguishes three states where cmdline_has_prefix carries
 * two. The third -- the command line could not be read -- is the whole reason
 * it exists: a caller whose conclusion depends on a parameter being ABSENT
 * cannot infer absence from a file it never read, and a container is both
 * where that file goes missing and where the fact it guards is least
 * trustworthy.
 *
 * Asserted directly, because a three-way return collapsing back to a boolean
 * would leave every end-to-end result unchanged on a machine whose command
 * line happens to be readable. */
static void test_cmdline_lookup_is_three_valued(void) {
  th_sysroot_clear();
  th_sysroot_write("/proc/cmdline", "ro quiet default_hugepagesz=32M\n");
  TH_CHECK(cmdline_lookup("default_hugepagesz=") == 1);

  th_sysroot_clear();
  th_sysroot_write("/proc/cmdline", "ro quiet rootfstype=ext4\n");
  TH_CHECK(cmdline_lookup("default_hugepagesz=") == 0);

  /* No command line at all: neither present nor absent, and the caller must be
   * able to tell that apart from a clean one. */
  th_sysroot_clear();
  TH_CHECK(cmdline_lookup("default_hugepagesz=") == -1);

  /* An empty file reads as unreadable too -- nothing was learned from it. */
  th_sysroot_clear();
  th_sysroot_write("/proc/cmdline", "");
  TH_CHECK(cmdline_lookup("default_hugepagesz=") == -1);

  /* Left word boundary honoured: a parameter whose name merely ends with the
   * prefix is not that parameter. This scan has one implementation now, so
   * this is the only place it is covered. */
  th_sysroot_clear();
  th_sysroot_write("/proc/cmdline", "ro nodefault_hugepagesz=32M\n");
  TH_CHECK(cmdline_lookup("default_hugepagesz=") == 0);
}

/* The boolean form is a wrapper, and must agree with the tri-state on every
 * state -- including mapping "could not be read" to not-found, which is the
 * reading its three existing callers depend on. */
static void test_cmdline_has_prefix_agrees_with_lookup(void) {
  th_sysroot_clear();
  th_sysroot_write("/proc/cmdline", "ro quiet resume=/dev/sda2\n");
  TH_CHECK(cmdline_lookup("resume=") == 1);
  TH_CHECK(cmdline_has_prefix("resume=") == 1);

  th_sysroot_clear();
  th_sysroot_write("/proc/cmdline", "ro quiet\n");
  TH_CHECK(cmdline_lookup("resume=") == 0);
  TH_CHECK(cmdline_has_prefix("resume=") == 0);

  /* Unreadable: the tri-state says so, the boolean folds it into not-found. */
  th_sysroot_clear();
  TH_CHECK(cmdline_lookup("resume=") == -1);
  TH_CHECK(cmdline_has_prefix("resume=") == 0);
}

#if defined(__aarch64__)
/* The page-size derivation and its gate, end to end through the component.
 * The huge page is the PMD block here, so 2 MiB names a 4 KiB granule -- but
 * only where the command line can be read AND does not reassign the default
 * huge page, since that parameter makes the figure describe something else. */
static void test_page_size_from_hugepage_is_gated(void) {
  th_sysroot_clear();
  th_sysroot_write("/proc/meminfo", "MemTotal:       16384 kB\n"
                                    "Hugepagesize:    2048 kB\n");
  th_sysroot_write("/proc/cmdline", "ro quiet\n");
  int rc;
  run(&rc);
  TH_CHECK(strstr(th_cap, "page_size") != NULL);

  /* The parameter is present: the figure is some other huge page, so nothing
   * about the granule follows from it. */
  th_sysroot_clear();
  th_sysroot_write("/proc/meminfo", "MemTotal:       16384 kB\n"
                                    "Hugepagesize:    2048 kB\n");
  th_sysroot_write("/proc/cmdline", "ro quiet default_hugepagesz=1G\n");
  run(&rc);
  TH_CHECK(strstr(th_cap, "page_size") == NULL);

  /* No command line: absence of the parameter cannot be established, so the
   * derivation declines rather than assuming a clean boot. */
  th_sysroot_clear();
  th_sysroot_write("/proc/meminfo", "MemTotal:       16384 kB\n"
                                    "Hugepagesize:    2048 kB\n");
  run(&rc);
  TH_CHECK(strstr(th_cap, "page_size") == NULL);

  /* A huge page that is not the PMD block names no granule. */
  th_sysroot_clear();
  th_sysroot_write("/proc/meminfo", "MemTotal:       16384 kB\n"
                                    "Hugepagesize: 1048576 kB\n");
  th_sysroot_write("/proc/cmdline", "ro quiet\n");
  run(&rc);
  TH_CHECK(strstr(th_cap, "page_size") == NULL);
}
#endif

static void test_absent_sources_emit_nothing(void) {
  th_sysroot_clear();
  int rc;
  run(&rc);
  TH_CHECK(strstr(th_cap, "phys_memtotal") == NULL);
  TH_CHECK(strstr(th_cap, "phys_lowmem") == NULL);
  TH_CHECK(strstr(th_cap, "phys_max_pfn") == NULL);
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
  RUN(test_cmdline_lookup_is_three_valued);
  RUN(test_cmdline_has_prefix_agrees_with_lookup);
#if defined(__aarch64__)
  RUN(test_page_size_from_hugepage_is_gated);
#endif
  RUN(test_absent_sources_emit_nothing);

  return TEST_DONE();
}
