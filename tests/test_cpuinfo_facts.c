// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Tests for cpuinfo_facts, and through it the sole parser in
// include/kasld/cpuinfo.h — a header no tested component reached, so none of it
// had ever run under test.
//
// It reads the CPU's physical address width, which bounds the physical window,
// and it carries three decisions worth pinning:
//
//   the key is matched in two spellings, because the line is "address sizes" on
//   x86 and "Address Sizes" elsewhere, and a reader that knew only one would
//   report nothing on the other rather than being wrong loudly;
//
//   the width is taken after the COLON, not by position in the line, so a
//   differing label width cannot shift which number is read;
//
//   a line that matches the key but not the format resets the value and keeps
//   scanning. That branch exists so a malformed line cannot end the search and
//   leave a later, well-formed one unread — and, equally, cannot leave the
//   half-parsed value from the bad line standing as the answer.
//
// Absence stays absence throughout: no file, or no such line, emits nothing at
// all rather than a zero width, which a rule would read as a real bound.
// ---
// <bcoles@gmail.com>
#define _GNU_SOURCE

int cpuinfo_facts_main(void);
#define main cpuinfo_facts_main
#include "../src/components/cpuinfo_facts.c"
#undef main

#include "test_component.h"
#include "test_harness.h"
#include "test_sysroot.h"

#include <stdio.h>
#include <string.h>

static void run(int *rc) { TH_RUN_COMPONENT(*rc, cpuinfo_facts_main()); }

/* The ordinary x86 line, and the width that follows the colon. */
static void test_reads_the_physical_width(void) {
  th_sysroot_clear();
  th_sysroot_write("/proc/cpuinfo",
                   "processor\t: 0\n"
                   "address sizes\t: 46 bits physical, 48 bits virtual\n");
  int rc;
  run(&rc);
  assert(strstr(th_cap, "phys_addr_bits") != NULL);
  assert(th_cap_field_is("value", 46));
  /* The virtual width sits on the same line and must not be the one taken. */
  assert(!th_cap_field_is("value", 48));
}

/* The capitalised spelling is the same fact. */
static void test_accepts_the_capitalised_spelling(void) {
  th_sysroot_clear();
  th_sysroot_write("/proc/cpuinfo",
                   "Address Sizes\t: 40 bits physical, 48 bits virtual\n");
  int rc;
  run(&rc);
  assert(th_cap_field_is("value", 40));
}

/* A malformed match neither ends the search nor supplies the answer. */
static void test_a_malformed_line_does_not_end_the_search(void) {
  th_sysroot_clear();
  th_sysroot_write("/proc/cpuinfo",
                   "address sizes\t: unknown\n"
                   "address sizes\t: 52 bits physical, 57 bits virtual\n");
  int rc;
  run(&rc);
  assert(th_cap_field_is("value", 52));
}

/* A key with no colon is not a claim. */
static void test_a_line_without_a_colon_is_skipped(void) {
  th_sysroot_clear();
  th_sysroot_write("/proc/cpuinfo", "address sizes 46 bits physical\n");
  int rc;
  run(&rc);
  assert(strstr(th_cap, "phys_addr_bits") == NULL);
}

/* No line, and no file: nothing claimed either way. A zero width would read as
 * a real bound on the physical window. */
static void test_absence_emits_nothing(void) {
  th_sysroot_clear();
  th_sysroot_write("/proc/cpuinfo", "processor\t: 0\nvendor_id\t: X\n");
  int rc;
  run(&rc);
  assert(strstr(th_cap, "phys_addr_bits") == NULL);

  th_sysroot_clear();
  run(&rc);
  assert(strstr(th_cap, "phys_addr_bits") == NULL);
}

int main(void) {
  th_sysroot_init("cpuinfo_facts");
  TEST_SUITE("cpuinfo_facts");

  BEGIN_CATEGORY("Reading the width");
  RUN(test_reads_the_physical_width);
  RUN(test_accepts_the_capitalised_spelling);

  BEGIN_CATEGORY("Malformed input");
  RUN(test_a_malformed_line_does_not_end_the_search);
  RUN(test_a_line_without_a_colon_is_skipped);

  BEGIN_CATEGORY("Absence");
  RUN(test_absence_emits_nothing);

  return TEST_DONE();
}
