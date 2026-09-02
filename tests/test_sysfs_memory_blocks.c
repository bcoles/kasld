// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Tests for sysfs_memory_blocks. The component is #included with its main
// renamed, then driven over a staged KASLD_SYSROOT
// /sys/devices/system/memory tree.
//
// Three decisions carry soundness, and none of them is visible from the values
// on the wire alone.
//
// The lowest online block start is an interior SAMPLE, not a floor. A block is
// online once hotplug attaches it to a zone, so boot-reserved regions — the
// kernel image's own block, EFI runtime, memblock reservations — are typically
// offline or absent, and the lowest ONLINE block can sit above the true
// physical RAM floor. Pinning there would put the floor above the kernel.
//
// The contiguous-run extents are sound only over the COMPLETE online set. They
// exist so the gaps BETWEEN runs forbid a physical kernel base, and a gap is
// only a real gap if every online block was seen: a partial set invents one.
// The component therefore emits no run at all when collection overflowed, and
// requires two or more runs, since one contiguous run has no gap to carve.
//
// Only "online" blocks count at all — an offline block is not present RAM.
//
// Block addresses are index * block_size, both read from the tree, so this file
// carries no architecture assumption and means the same thing on every target.
// ---
// <bcoles@gmail.com>
#define _GNU_SOURCE

int sysfs_memory_blocks_main(void);
#define main sysfs_memory_blocks_main
#include "../src/components/sysfs_memory_blocks.c"
#undef main

#include "test_component.h"
#include "test_harness.h"
#include "test_sysroot.h"

#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define BLK 0x8000000UL /* 128 MiB, the usual x86 block size */

static void clear_tree(void) {
  char full[TH_SYSROOT_MAX];
  th_sysroot_path("/sys/devices/system/memory", full, sizeof(full));
  char cmd[TH_SYSROOT_MAX + 16];
  snprintf(cmd, sizeof(cmd), "rm -rf '%s'", full);
  assert(system(cmd) == 0);
  th_sysroot_write("/sys/devices/system/memory/block_size_bytes", "8000000");
}

static void stage_block(unsigned long idx, const char *state) {
  char p[256], v[64];
  snprintf(p, sizeof(p), "/sys/devices/system/memory/memory%lu/state", idx);
  th_sysroot_write(p, state);
  snprintf(p, sizeof(p), "/sys/devices/system/memory/memory%lu/phys_index",
           idx);
  snprintf(v, sizeof(v), "%lx", idx);
  th_sysroot_write(p, v);
}

/* The hull: lowest start as a sample, highest end as a top. */
static void test_hull_is_sample_and_top(void) {
  clear_tree();
  stage_block(0, "online");
  stage_block(1, "online");
  stage_block(2, "online");
  int rc;
  TH_RUN_COMPONENT(rc, sysfs_memory_blocks_main());
  assert(rc == 0);
  assert(th_cap_field_is("sample", 0));
  assert(th_cap_field_is("hi", 3UL * BLK - 1));
  /* The lowest start is never a floor: reserved memory below the lowest
   * ONLINE block is invisible here. */
  assert(!th_cap_field_is("lo", 0) || th_cap_count("pos=base") == 0);
}

/* An offline block is not present RAM and must not widen the extent. */
static void test_offline_blocks_are_ignored(void) {
  clear_tree();
  stage_block(1, "online");
  stage_block(2, "online");
  stage_block(9, "offline");
  int rc;
  TH_RUN_COMPONENT(rc, sysfs_memory_blocks_main());
  assert(rc == 0);
  assert(th_cap_field_is("hi", 3UL * BLK - 1));
  assert(!th_cap_field_is("hi", 10UL * BLK - 1));
}

/* Two separated runs: each becomes an extent, and the gap between them is what
 * later forbids a physical kernel base. */
static void test_two_runs_emit_two_extents(void) {
  clear_tree();
  stage_block(0, "online");
  stage_block(1, "online");
  /* Block 2 absent: a gap of exactly ONE block. A boundary test that admits a
   * one-block hole would merge these into a single run and publish nothing,
   * so this is the width that separates "adjacent" from "separated". */
  stage_block(3, "online");
  stage_block(4, "online");
  int rc;
  TH_RUN_COMPONENT(rc, sysfs_memory_blocks_main());
  assert(rc == 0);
  assert(th_cap_count("pos=extent") == 2);
  assert(th_cap_field_is("lo", 0) && th_cap_field_is("hi", 2UL * BLK - 1));
  assert(th_cap_field_is("lo", 3UL * BLK) &&
         th_cap_field_is("hi", 5UL * BLK - 1));
}

/* One contiguous run has no gap to carve, so no extent is published — an
 * extent set of one would say "RAM is only here", which the online set does
 * not establish. */
static void test_single_run_emits_no_extent(void) {
  clear_tree();
  stage_block(0, "online");
  stage_block(1, "online");
  stage_block(2, "online");
  int rc;
  TH_RUN_COMPONENT(rc, sysfs_memory_blocks_main());
  assert(rc == 0);
  assert(th_cap_count("pos=extent") == 0);
  /* The hull is still published. */
  assert(th_cap_field_is("sample", 0));
}

/* More online blocks than can be collected. The run set would then describe
 * only part of the online map, and the gaps it implied would be invented — so
 * no extent may be published at all. The hull is still sound and still goes
 * out, because it does not depend on having seen every block. */
static void test_overflow_publishes_no_extents(void) {
  clear_tree();
  for (unsigned long i = 0; i < (unsigned long)SMB_MAX_INDICES; i++)
    stage_block(i, "online");
  stage_block(SMB_MAX_INDICES + 900UL, "online"); /* a second run */
  int rc;
  TH_RUN_COMPONENT(rc, sysfs_memory_blocks_main());
  assert(rc == 0);
  assert(th_cap_count("pos=extent") == 0);
  assert(th_cap_field_is("sample", 0));
}

/* No online blocks at all: the tree is present and the technique applied, so
 * exit 0 with no result rather than a claim the source is absent. */
static void test_all_offline_emits_nothing(void) {
  clear_tree();
  stage_block(0, "offline");
  stage_block(1, "offline");
  int rc;
  TH_RUN_COMPONENT(rc, sysfs_memory_blocks_main());
  assert(rc == 0);
  assert(th_cap[0] == '\0');
}

/* A block size of zero cannot convert an index to an address; the component
 * says so rather than publishing everything at address zero. */
static void test_zero_block_size_emits_nothing(void) {
  clear_tree();
  th_sysroot_write("/sys/devices/system/memory/block_size_bytes", "0");
  stage_block(0, "online");
  stage_block(1, "online");
  int rc;
  TH_RUN_COMPONENT(rc, sysfs_memory_blocks_main());
  assert(rc == 0);
  assert(th_cap[0] == '\0');
}

/* No block_size_bytes is a kernel without memory hotplug — provably
 * inapplicable rather than a miss. */
static void test_absent_tree_is_unavailable(void) {
  char full[TH_SYSROOT_MAX];
  th_sysroot_path("/sys/devices/system/memory", full, sizeof(full));
  char cmd[TH_SYSROOT_MAX + 16];
  snprintf(cmd, sizeof(cmd), "rm -rf '%s'", full);
  assert(system(cmd) == 0);
  int rc;
  TH_RUN_COMPONENT(rc, sysfs_memory_blocks_main());
  assert(rc == KASLD_EXIT_UNAVAILABLE);
  assert(th_cap[0] == '\0');
}

int main(void) {
  th_sysroot_init("sysfs_memory_blocks");
  TEST_SUITE("sysfs_memory_blocks");

  BEGIN_CATEGORY("Hull");
  RUN(test_hull_is_sample_and_top);
  RUN(test_offline_blocks_are_ignored);

  BEGIN_CATEGORY("Contiguous runs");
  RUN(test_two_runs_emit_two_extents);
  RUN(test_single_run_emits_no_extent);
  RUN(test_overflow_publishes_no_extents);

  BEGIN_CATEGORY("Absence");
  RUN(test_all_offline_emits_nothing);
  RUN(test_zero_block_size_emits_nothing);
  RUN(test_absent_tree_is_unavailable);

  return TEST_DONE();
}
