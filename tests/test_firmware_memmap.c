// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Tests for firmware_memmap, and through it the extent loader in
// include/kasld/firmware_memmap.h — reached by no tested component, so unrun.
//
// What it emits is an EXTENT, and an extent is a claim about a COMPLETE
// covering: the gaps between the spans are asserted to be genuine non-RAM. That
// makes the interesting decision not how a span is parsed but when the whole
// map must be withheld. A "reserved" entry is a real gap and is correctly
// omitted; a numbered entry the reader could not understand is not a gap, it is
// an unknown, and publishing the rest would turn that unknown into asserted
// non-RAM. The loader answers the second case by returning -1 for the whole map
// rather than the spans it managed to read, and the component then emits
// nothing at all.
//
// So most of what follows is absence: a missing type file, an unparsable start,
// an end below its start. Each is a partial read, and each must yield silence
// rather than a smaller map — a map short by one span is not a smaller truth,
// it is a false statement about where RAM is not.
//
// Entry order is whatever readdir gives. That matters more than it looks: the
// loader stops at the first entry it cannot read, so how many spans it managed
// first depends on the order, and a component-level count cannot distinguish
// "withheld the map" from "the bad entry happened to come first". The
// withholding tests therefore assert the loader's own return value, which is -1
// for an incomplete map whatever order it was read in.
// ---
// <bcoles@gmail.com>
#define _GNU_SOURCE

int firmware_memmap_main(void);
#define main firmware_memmap_main
#include "../src/components/firmware_memmap.c"
#undef main

#include "test_component.h"
#include "test_harness.h"
#include "test_sysroot.h"

#include <stdio.h>
#include <string.h>

/* Stage one /sys/firmware/memmap/<n> entry. A NULL field is left absent. */
static void entry(const char *n, const char *type, const char *start,
                  const char *end) {
  char p[256];
  if (type) {
    snprintf(p, sizeof(p), "/sys/firmware/memmap/%s/type", n);
    th_sysroot_write(p, type);
  }
  if (start) {
    snprintf(p, sizeof(p), "/sys/firmware/memmap/%s/start", n);
    th_sysroot_write(p, start);
  }
  if (end) {
    snprintf(p, sizeof(p), "/sys/firmware/memmap/%s/end", n);
    th_sysroot_write(p, end);
  }
}

static void run(int *rc) { TH_RUN_COMPONENT(*rc, firmware_memmap_main()); }

/* Every System RAM span is published, and a non-RAM entry is a real gap. */
static void test_publishes_ram_spans_and_omits_other_types(void) {
  th_sysroot_clear();
  entry("0", "System RAM\n", "0x100000\n", "0xbfecffff\n");
  entry("1", "reserved\n", "0xbfed0000\n", "0xbfefffff\n");
  entry("2", "System RAM\n", "0x100000000\n", "0x33fffffff\n");
  int rc;
  run(&rc);
  assert(th_cap_count("pos=extent") == 2);
  assert(th_cap_field_is("lo", 0x100000ul) &&
         th_cap_field_is("hi", 0xbfecfffful));
  assert(th_cap_field_is("lo", 0x100000000ul) &&
         th_cap_field_is("hi", 0x33ffffffful));
  /* The reserved span is a gap, not an extent. */
  assert(!th_cap_field_is("lo", 0xbfed0000ul));
}

/* The loader's verdict on an incomplete map, asserted directly: -1 for the
 * whole map, never the count it reached before stopping. */
static int load_verdict(void) {
  struct kasld_ram_extent ext[8];
  return kasld_load_ram_extents(ext, 8);
}

/* An entry with no type is an unknown, not a gap: the whole map is withheld,
 * and the component emits nothing. */
static void test_a_typeless_entry_withholds_the_whole_map(void) {
  th_sysroot_clear();
  entry("0", "System RAM\n", "0x100000\n", "0xbfecffff\n");
  entry("1", NULL, "0xbfed0000\n", "0xbfefffff\n");
  assert(load_verdict() == -1);
  int rc;
  run(&rc);
  assert(th_cap_count("pos=extent") == 0);
}

/* An unparsable start, and an end below its start, are the same kind of
 * unknown. Neither may leave the spans that did read standing as a covering. */
static void test_an_unreadable_span_withholds_the_whole_map(void) {
  th_sysroot_clear();
  entry("0", "System RAM\n", "0x100000\n", "0xbfecffff\n");
  entry("1", "System RAM\n", "not-a-number\n", "0xbfefffff\n");
  assert(load_verdict() == -1);

  th_sysroot_clear();
  entry("0", "System RAM\n", "0x100000\n", "0xbfecffff\n");
  entry("1", "System RAM\n", "0xbff00000\n", "0xbfe00000\n");
  assert(load_verdict() == -1);
}

/* More RAM spans than the caller's array is the same unknown: the map that
 * would fit is not the map, so it is withheld rather than truncated. */
static void test_a_map_too_large_for_the_array_is_withheld(void) {
  th_sysroot_clear();
  entry("0", "System RAM\n", "0x100000\n", "0xbfecffff\n");
  entry("1", "System RAM\n", "0x100000000\n", "0x33fffffff\n");
  struct kasld_ram_extent one[1];
  assert(kasld_load_ram_extents(one, 1) == -1);
}

/* No map at all: nothing claimed, and no failure either. */
static void test_absent_map_emits_nothing(void) {
  th_sysroot_clear();
  int rc;
  run(&rc);
  assert(th_cap_count("pos=extent") == 0);
}

int main(void) {
  th_sysroot_init("firmware_memmap");
  TEST_SUITE("firmware_memmap");

  BEGIN_CATEGORY("Publishing the map");
  RUN(test_publishes_ram_spans_and_omits_other_types);

  BEGIN_CATEGORY("Withholding an incomplete map");
  RUN(test_a_typeless_entry_withholds_the_whole_map);
  RUN(test_an_unreadable_span_withholds_the_whole_map);
  RUN(test_a_map_too_large_for_the_array_is_withheld);

  BEGIN_CATEGORY("Absence");
  RUN(test_absent_map_emits_nothing);

  return TEST_DONE();
}
