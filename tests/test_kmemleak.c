// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Tests for kmemleak. The component is #included with its main renamed, then
// driven end-to-end over a staged KASLD_SYSROOT /sys/kernel/debug/kmemleak.
//
// The behaviour under test: each "unreferenced object 0x<addr>" line is routed
// through kasld_addr_classify(); the lowest object that classifies as
// direct-map is emitted as an interior sample, and a vmalloc/percpu or
// text-band object is skipped. An empty report declines. Synthetic addresses
// are built from the arch's own direct-map window; where that window is empty
// (coupled/inverted arches) the positive case is skipped, matching the
// component, which finds no direct-map object there.
// ---
// <bcoles@gmail.com>
#define _GNU_SOURCE

int kmemleak_main(int argc, char **argv);
#define main kmemleak_main
#include "../src/components/kmemleak.c"
#undef main

#include "test_harness.h"
#include "test_sysroot.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static char cap[8192];

/* Run the component, capturing its stdout (the wire channel) into `cap`; stderr
 * diagnostics are silenced. */
static void run_capture(void) {
  fflush(stdout);
  char tmpl[] = "/tmp/kasld_kmemleak_capXXXXXX";
  int fd = mkstemp(tmpl);
  assert(fd >= 0);
  int saved = dup(1);
  dup2(fd, 1);
  fflush(stderr);
  int saved_err = dup(2);
  int devnull = open("/dev/null", O_WRONLY);
  if (devnull >= 0)
    dup2(devnull, 2);

  char arg0[] = "kmemleak";
  char *argv[] = {arg0, NULL};
  kmemleak_main(1, argv);

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

/* The lowest direct-map object is emitted; a text-band object (here behind a
 * "(percpu)" qualifier, to also exercise skipping past it to the address) is
 * not. Skipped on arches whose direct-map window is empty. */
static void test_lowest_directmap_object(void) {
  unsigned long lo = (unsigned long)PAGE_OFFSET + 0x2000;
  unsigned long hi = (unsigned long)PAGE_OFFSET + 0x100000;
  unsigned long nondm = (unsigned long)KERNEL_VIRT_TEXT_MIN + 0x1000;
  if (kasld_addr_classify(lo) != REGION_DIRECTMAP_BAND)
    return; /* empty direct-map window on this arch */
  char fx[512];
  snprintf(fx, sizeof(fx),
           "unreferenced object 0x%016lx (size 4096):\n"
           "  comm \"insmod\", pid 1, jiffies 1\n"
           "unreferenced object 0x%016lx (size 32):\n"
           "  comm \"insmod\", pid 1, jiffies 1\n"
           "unreferenced object (percpu) 0x%016lx (size 64):\n",
           hi, lo, nondm);
  th_sysroot_write("/sys/kernel/debug/kmemleak", fx);
  run_capture();
  char want[64];
  snprintf(want, sizeof(want), "sample=0x%lx", lo);
  assert(strstr(cap, "directmap_band") != NULL);
  assert(strstr(cap, want) != NULL);
}

/* An empty report declines: no direct-map witness emitted. */
static void test_empty_report_declines(void) {
  th_sysroot_write("/sys/kernel/debug/kmemleak", "");
  run_capture();
  assert(strstr(cap, "directmap") == NULL);
}

int main(void) {
  th_sysroot_init("kmemleak");

  TEST_SUITE("test_kmemleak");
  BEGIN_CATEGORY("leaked-object parse");
  RUN(test_lowest_directmap_object);
  RUN(test_empty_report_declines);
  return TEST_DONE();
}
