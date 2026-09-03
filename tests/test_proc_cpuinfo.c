// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Tests for proc_cpuinfo's x86_64 path. The component declares
// method:detection, so check-component-tests never asked for this file — but it
// reads /proc/cpuinfo, parses it, and emits at CONF_PARSED like any parser, and
// what it emits decides the paging level and therefore the floor under the
// direct map.
//
// The decision worth guarding is the ASYMMETRY between the two widths:
//
//   48 bits virtual is published as the active level, because a CPU that can
//   only address 48 bits cannot be running 5-level paging. The level follows
//   from the width with nothing left to assume.
//
//   57 bits virtual is NOT published. It is the CPU's capability, and an
//   LA57-capable part runs 4-level paging perfectly happily. Publishing it
//   would state an active level the machine may not be in, and the consumers
//   of that scalar treat it as the level in force. The active level comes from
//   a runtime probe instead.
//
// Both widths still yield a floor on the direct-map base, because a floor holds
// either way round: the 5-level base sits below the 4-level one, so reading 57
// on a machine running 4-level gives a sound-but-loose floor rather than a
// wrong one. That is why the floor is emitted on the constraint channel for
// both, while the level scalar is emitted for only one.
// ---
// <bcoles@gmail.com>
#define _GNU_SOURCE

int proc_cpuinfo_main(void);
#define main proc_cpuinfo_main
#include "../src/components/proc_cpuinfo.c"
#undef main

#include "test_component.h"
#include "test_harness.h"
#include "test_sysroot.h"

#include <stdio.h>
#include <string.h>

static void with_widths(const char *line) {
  th_sysroot_clear();
  char buf[256];
  snprintf(buf, sizeof(buf), "processor\t: 0\n%s", line);
  th_sysroot_write("/proc/cpuinfo", buf);
}

static void run(int *rc) { TH_RUN_COMPONENT(*rc, proc_cpuinfo_main()); }

#if defined(__x86_64__) || defined(__amd64__)
/* 48 bits virtual proves the level: the scalar is published. */
static void test_48_bits_publishes_the_active_level(void) {
  with_widths("address sizes\t: 46 bits physical, 48 bits virtual\n");
  int rc;
  run(&rc);
  assert(strstr(th_cap, "virt_addr_bits") != NULL);
  assert(th_cap_field_is("value", 48));
}

/* 57 bits is a capability, not a level, and must not be published as one. */
static void test_57_bits_does_not_publish_a_level(void) {
  with_widths("address sizes\t: 52 bits physical, 57 bits virtual\n");
  int rc;
  run(&rc);
  assert(strstr(th_cap, "virt_addr_bits") == NULL);
}

/* Either width still floors the direct-map base, on the constraint channel —
 * a bound, not a located address, so no anchor rule reads it as one. */
static void test_both_widths_floor_the_direct_map(void) {
  with_widths("address sizes\t: 46 bits physical, 48 bits virtual\n");
  int rc;
  run(&rc);
  assert(strstr(th_cap, "C virt_page_offset >=") != NULL);
  assert(th_cap_field_is("value", PAGE_OFFSET_BASE_MIN_L4));

  with_widths("address sizes\t: 52 bits physical, 57 bits virtual\n");
  run(&rc);
  assert(strstr(th_cap, "C virt_page_offset >=") != NULL);
  assert(th_cap_field_is("value", PAGE_OFFSET_BASE_MIN_L5));
  /* The 5-level floor is the lower of the two: reading a capability as a level
   * loosens the bound, it does not raise it past the truth. */
  assert(PAGE_OFFSET_BASE_MIN_L5 < PAGE_OFFSET_BASE_MIN_L4);
}

/* A line that cannot be parsed is not a width. */
static void test_unparsable_widths_claim_nothing(void) {
  with_widths("address sizes\t: unknown\n");
  int rc;
  run(&rc);
  assert(strstr(th_cap, "virt_addr_bits") == NULL);
  assert(strstr(th_cap, "virt_page_offset") == NULL);

  th_sysroot_clear();
  run(&rc);
  assert(th_cap[0] == '\0');
}
#endif

int main(void) {
  th_sysroot_init("proc_cpuinfo");
  TEST_SUITE("proc_cpuinfo");
#if defined(__x86_64__) || defined(__amd64__)
  BEGIN_CATEGORY("Paging level from the virtual width");
  RUN(test_48_bits_publishes_the_active_level);
  RUN(test_57_bits_does_not_publish_a_level);

  BEGIN_CATEGORY("Direct-map floor");
  RUN(test_both_widths_floor_the_direct_map);

  BEGIN_CATEGORY("Absence");
  RUN(test_unparsable_widths_claim_nothing);
#endif
  return TEST_DONE();
}
