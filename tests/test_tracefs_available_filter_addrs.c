// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Unit tests for tracefs_available_filter_addrs, driven end-to-end over a
// staged KASLD_SYSROOT available_filter_functions_addrs with the component's
// main renamed.
//
// Pins three behaviours:
//   1. Bounding. From an unsorted table only the lowest and highest kernel-text
//      witnesses are emitted (interior samples); an intermediate one is not.
//   2. Invalid-record skip. A "__ftrace_invalid_address___<n>" line (an ip that
//      did not resolve to a symbol) is skipped even when its address would
//      otherwise be the extreme witness.
//   3. Address width. A 64-bit address read by a narrower build is refused, not
//      truncated to its plausible-looking low half (runs for real under
//      tests/test-cross on the 32-bit arches).
// ---
// <bcoles@gmail.com>
#define _GNU_SOURCE

int tracefs_available_filter_addrs_main(int argc, char **argv);
#define main tracefs_available_filter_addrs_main
#include "../src/components/tracefs_available_filter_addrs.c"
#undef main

#include "test_harness.h"
#include "test_sysroot.h"

#include <assert.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

static char cap[8192];

static void stage(const char *text) {
  th_sysroot_write("/sys/kernel/tracing/available_filter_functions_addrs",
                   text);
}

static void run_capture(void) {
  fflush(stdout);
  char tmpl[] = "/tmp/kasld_aff_capXXXXXX";
  int fd = mkstemp(tmpl);
  assert(fd >= 0);
  int saved = dup(1);
  dup2(fd, 1);
  fflush(stderr);
  int saved_err = dup(2);
  int devnull = open("/dev/null", O_WRONLY);
  if (devnull >= 0)
    dup2(devnull, 2);

  static char a0[] = "test";
  static char *argv0[] = {a0, NULL};
  tracefs_available_filter_addrs_main(1, argv0);

  fflush(stdout);
  fflush(stderr);
  dup2(saved, 1);
  close(saved);
  dup2(saved_err, 2);
  close(saved_err);
  if (devnull >= 0)
    close(devnull);
  lseek(fd, 0, SEEK_SET);
  ssize_t r = read(fd, cap, sizeof(cap) - 1);
  cap[r > 0 ? r : 0] = '\0';
  close(fd);
  unlink(tmpl);
}

/* From an unsorted table, only the lowest and highest text witnesses are
 * emitted; an intermediate address is not. */
static void test_text_bounds_emitted(void) {
  unsigned long T = (unsigned long)KERNEL_VIRT_TEXT_DEFAULT;
  unsigned long lo = T, mid = T + 0x40000, hi = T + 0x80000;
  char fx[512];
  snprintf(fx, sizeof(fx), "%lx func_hi\n%lx func_lo\n%lx func_mid\n", hi, lo,
           mid);
  stage(fx);
  run_capture();
  char want[64];
  snprintf(want, sizeof(want), "sample=0x%lx", lo);
  assert(strstr(cap, want) != NULL);
  snprintf(want, sizeof(want), "sample=0x%lx", hi);
  assert(strstr(cap, want) != NULL);
  snprintf(want, sizeof(want), "sample=0x%lx", mid);
  assert(strstr(cap, want) == NULL);
}

/* A "__ftrace_invalid_address___<n>" record is skipped even when it is the
 * highest address in the table. */
static void test_invalid_address_skipped(void) {
  unsigned long T = (unsigned long)KERNEL_VIRT_TEXT_DEFAULT;
  unsigned long lo = T, hi = T + 0x80000, inv = T + 0xc0000; /* inv > hi */
  char fx[512];
  snprintf(fx, sizeof(fx),
           "%lx func_lo\n%lx func_hi\n%lx __ftrace_invalid_address___49152\n",
           lo, hi, inv);
  stage(fx);
  run_capture();
  char want[64];
  snprintf(want, sizeof(want), "sample=0x%lx", hi);
  assert(strstr(cap, want) != NULL); /* hi is the emitted high witness */
  snprintf(want, sizeof(want), "sample=0x%lx", inv);
  assert(strstr(cap, want) == NULL); /* invalid record skipped, not the max */
}

/* A bare hex with no name, a non-hex line, and a user-space address are all
 * ignored: none is a kernel-text or module witness. */
static void test_non_text_and_malformed_ignored(void) {
  stage("deadbeef\n"
        "garbage line here\n"
        "0000000000400000 user_func\n");
  run_capture();
  assert(strstr(cap, "sample=") == NULL);
}

/* A 64-bit-wide address read by a narrower build must be refused, not truncated
 * to its low half (which is itself a plausible kernel-text value). */
static void test_addr_width_refusal(void) {
  stage("ffffffff81a00000 some_func\n");
  run_capture();
  if (sizeof(kasld_addr_t) < 8)
    assert(strstr(cap, "81a00000") == NULL);
}

int main(void) {
  th_sysroot_init("tracefs_aff_addrs");

  TEST_SUITE("tracefs_available_filter_addrs");
  BEGIN_CATEGORY("text bounding + record skip");
  RUN(test_text_bounds_emitted);
  RUN(test_invalid_address_skipped);
  RUN(test_non_text_and_malformed_ignored);
  BEGIN_CATEGORY("address width");
  RUN(test_addr_width_refusal);
  return TEST_DONE();
}
