// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Tests for sysfs_firmware_memmap. The component is #included with its main
// renamed, then driven over a staged KASLD_SYSROOT /sys/firmware/memmap tree.
//
// The branch worth guarding is the width one. The component publishes the
// lowest System RAM start and the highest end as one range, and the range's TOP
// is consumed as an upper bound on physical memory. An entry whose address this
// build cannot represent lies above every entry it can, so a truncated or
// dropped high entry makes that top understate RAM — a bound that excludes the
// truth rather than a wide one. The component detects the refusal and publishes
// the base alone, which a dropped high entry cannot raise.
//
// The rest of the surface is the selection rules: only "System RAM" counts, a
// start of 0 carries no KASLR information and is skipped, and the lowest start
// and highest end are tracked across every qualifying entry rather than taken
// from the first.
// ---
// <bcoles@gmail.com>
#define _GNU_SOURCE

int sysfs_firmware_memmap_main(void);
#define main sysfs_firmware_memmap_main
#include "../src/components/sysfs_firmware_memmap.c"
#undef main

#include "test_component.h"
#include "test_harness.h"
#include "test_sysroot.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* Stage one numbered entry directory the way the kernel presents it. */
static void stage_entry(const char *n, const char *start, const char *end,
                        const char *type) {
  char p[256];
  snprintf(p, sizeof(p), "/sys/firmware/memmap/%s/start", n);
  th_sysroot_write(p, start);
  snprintf(p, sizeof(p), "/sys/firmware/memmap/%s/end", n);
  th_sysroot_write(p, end);
  snprintf(p, sizeof(p), "/sys/firmware/memmap/%s/type", n);
  th_sysroot_write(p, type);
}

/* Remove the whole tree between cases: readdir walks whatever is present, so a
 * leftover entry from an earlier test would join the next one's map. */
static void clear_entries(void) {
  char full[TH_SYSROOT_MAX];
  th_sysroot_path("/sys/firmware/memmap", full, sizeof(full));
  char cmd[TH_SYSROOT_MAX + 16];
  snprintf(cmd, sizeof(cmd), "rm -rf '%s'", full);
  assert(system(cmd) == 0);
}

/* Both edges known across several entries: the lowest start and the highest
 * end, not the first entry's pair. */
static void test_spans_lowest_start_to_highest_end(void) {
  clear_entries();
  stage_entry("0", "0x100000", "0x1fffff", "System RAM");
  stage_entry("1", "0x8000000", "0xbfffffff", "System RAM");
  stage_entry("2", "0x2000000", "0x2ffffff", "System RAM");
  int rc;
  TH_RUN_COMPONENT(rc, sysfs_firmware_memmap_main());
  assert(rc == 0);
  assert(strstr(th_cap, "lo=0x100000") != NULL);
  assert(strstr(th_cap, "hi=0xbfffffff") != NULL);
  assert(strstr(th_cap, "P ") != NULL);
  assert(strstr(th_cap, "conf=parsed") != NULL);
}

/* Only System RAM describes DRAM. A reserved or ACPI range sits inside the
 * physical map but is not memory the kernel places itself in, so admitting one
 * would widen the reported extent past the RAM it stands for. */
static void test_ignores_non_system_ram_types(void) {
  clear_entries();
  stage_entry("0", "0x100000", "0x1fffff", "System RAM");
  stage_entry("1", "0xf0000000", "0xffffffff", "reserved");
  stage_entry("2", "0xe0000000", "0xefffffff", "ACPI Non-volatile Storage");
  int rc;
  TH_RUN_COMPONENT(rc, sysfs_firmware_memmap_main());
  assert(rc == 0);
  assert(strstr(th_cap, "lo=0x100000") != NULL);
  assert(strstr(th_cap, "0xffffffff") == NULL);
  assert(strstr(th_cap, "0xefffffff") == NULL);
}

/* Physical zero is trivially known and carries no KASLR information, so the
 * entry starting there is skipped rather than becoming the lowest start. */
static void test_skips_the_zero_start_entry(void) {
  clear_entries();
  stage_entry("0", "0x0", "0x9e7ff", "System RAM");
  stage_entry("1", "0x100000", "0x7fffffff", "System RAM");
  int rc;
  TH_RUN_COMPONENT(rc, sysfs_firmware_memmap_main());
  assert(rc == 0);
  assert(strstr(th_cap, "lo=0x100000") != NULL);
  assert(strstr(th_cap, "lo=0x0 ") == NULL);
}

/* An entry wider than this build's word: the top of RAM is above anything the
 * range could state, so the component must publish the base alone. Emitting a
 * range here would hand the engine an upper bound below the real top of memory.
 *
 * Seventeen hex digits exceeds every supported word, so this reaches the
 * refusal on 64-bit and 32-bit targets alike rather than only where PAE makes
 * it reachable in the field. */
static void test_unrepresentable_entry_publishes_base_only(void) {
  clear_entries();
  stage_entry("0", "0x100000", "0x7fffffff", "System RAM");
  stage_entry("1", "0x10000000000000000", "0x1ffffffffffffffff", "System RAM");
  int rc;
  TH_RUN_COMPONENT(rc, sysfs_firmware_memmap_main());
  assert(rc == 0);
  /* The base, and no range: no hi= on the wire. */
  assert(strstr(th_cap, "lo=0x100000") != NULL);
  assert(strstr(th_cap, "hi=") == NULL);
}

/* A single entry gives one address, not a degenerate range whose two edges are
 * the same value. */
static void test_single_entry_publishes_base_only(void) {
  clear_entries();
  stage_entry("0", "0x100000", "0x100000", "System RAM");
  int rc;
  TH_RUN_COMPONENT(rc, sysfs_firmware_memmap_main());
  assert(rc == 0);
  assert(strstr(th_cap, "lo=0x100000") != NULL);
  assert(strstr(th_cap, "hi=") == NULL);
}

/* A map with no System RAM at all: the technique applied and found nothing, so
 * exit 0 with no result rather than a claim the source is absent. */
static void test_no_system_ram_emits_nothing(void) {
  clear_entries();
  stage_entry("0", "0xf0000000", "0xffffffff", "reserved");
  int rc;
  TH_RUN_COMPONENT(rc, sysfs_firmware_memmap_main());
  assert(rc == 0);
  assert(th_cap[0] == '\0');
}

/* No directory at all is firmware that publishes no map — provably
 * inapplicable rather than a miss. */
static void test_absent_tree_is_unavailable(void) {
  clear_entries();
  int rc;
  TH_RUN_COMPONENT(rc, sysfs_firmware_memmap_main());
  assert(rc == KASLD_EXIT_UNAVAILABLE);
  assert(th_cap[0] == '\0');
}

int main(void) {
  th_sysroot_init("sysfs_firmware_memmap");
  TEST_SUITE("sysfs_firmware_memmap");

  BEGIN_CATEGORY("Extent selection");
  RUN(test_spans_lowest_start_to_highest_end);
  RUN(test_ignores_non_system_ram_types);
  RUN(test_skips_the_zero_start_entry);
  RUN(test_single_entry_publishes_base_only);

  BEGIN_CATEGORY("Width and absence");
  RUN(test_unrepresentable_entry_publishes_base_only);
  RUN(test_no_system_ram_emits_nothing);
  RUN(test_absent_tree_is_unavailable);

  return TEST_DONE();
}
