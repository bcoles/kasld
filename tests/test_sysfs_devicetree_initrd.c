// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Extent test for sysfs_devicetree_initrd. The component is #included with its
// main renamed and driven over a staged KASLD_SYSROOT chosen node (binary
// big-endian linux,initrd-start / linux,initrd-end properties).
//
// The behaviour under test is the convention boundary. The device tree names
// the byte AFTER the initrd — the kernel takes the size as end - start — while
// an emitted extent is the inclusive last address. A component publishing the
// property verbatim would overstate the region by one byte, and every consumer
// of the extent would inherit that byte. The staged sizes here are round
// (0x1000, 0x200000) so the emitted hi can only be read one way.
//
// Also covered: an absent or degenerate end property yields the start alone
// rather than a range, since a region whose end is not known is not an extent.
// ---
// <bcoles@gmail.com>
#define _GNU_SOURCE

int sysfs_devicetree_initrd_main(void);
#define main sysfs_devicetree_initrd_main
#include "../src/components/sysfs_devicetree_initrd.c"
#undef main

#include "test_harness.h"
#include "test_sysroot.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static char g_chosen[400]; /* <root>/sys/firmware/devicetree/base/chosen */
static char cap[8192];

/* Big-endian encode `v` into `cells` 4-byte words at p. */
static void wr_be(unsigned char *p, unsigned long long v, int cells) {
  int bytes = cells * 4;
  for (int i = 0; i < bytes; i++)
    p[bytes - 1 - i] = (unsigned char)((v >> (8 * i)) & 0xff);
}

static void write_prop(const char *name, unsigned long long v, int cells) {
  char path[600];
  unsigned char b[8];
  wr_be(b, v, cells);
  snprintf(path, sizeof(path), "%s/%s", g_chosen, name);
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  TH_CHECK(fd >= 0);
  TH_CHECK(write(fd, b, (size_t)cells * 4) == (ssize_t)cells * 4);
  close(fd);
}

static void rm_prop(const char *name) {
  char path[600];
  snprintf(path, sizeof(path), "%s/%s", g_chosen, name);
  unlink(path);
}

static void run_capture(void) {
  fflush(stdout);
  char tmpl[] = "/tmp/kasld_dti_capXXXXXX";
  int fd = mkstemp(tmpl);
  TH_CHECK(fd >= 0);
  int saved = dup(1);
  dup2(fd, 1);
  fflush(stderr);
  int saved_err = dup(2);
  int devnull = open("/dev/null", O_WRONLY);
  if (devnull >= 0)
    dup2(devnull, 2);

  sysfs_devicetree_initrd_main();

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

/* A 4 KiB initrd written as two 32-bit cells: the property pair spans
 * [0x30000000, 0x30001000), so the inclusive extent ends at 0x30000fff. */
static void test_end_property_is_exclusive(void) {
  write_prop("linux,initrd-start", 0x30000000ull, 1);
  write_prop("linux,initrd-end", 0x30001000ull, 1);
  run_capture();
  TH_CHECK(
      strstr(cap, "initrd pos=base conf=parsed lo=0x30000000 hi=0x30000fff") !=
      NULL);
}

/* The same boundary through the 64-bit (2-cell) property path, at a size no
 * plausible off-by-one could round away. */
static void test_two_cell_properties(void) {
  write_prop("linux,initrd-start", 0x0000000840000000ull, 2);
  write_prop("linux,initrd-end", 0x0000000840200000ull, 2);
  run_capture();
  if (sizeof(unsigned long) < 8) {
    printf("      (skipped: 64-bit properties exceed this build's word)\n");
    return;
  }
  TH_CHECK(strstr(cap, "initrd pos=base conf=parsed lo=0x840000000 "
                       "hi=0x8401fffff") != NULL);
}

/* No end property: the start is a located address but the region has no known
 * extent, so a base is published and no range. */
static void test_missing_end_yields_base_only(void) {
  write_prop("linux,initrd-start", 0x30000000ull, 1);
  rm_prop("linux,initrd-end");
  run_capture();
  TH_CHECK(strstr(cap, "initrd pos=base conf=parsed lo=0x30000000\n") != NULL);
  TH_CHECK(strstr(cap, "hi=") == NULL);
}

/* An end at or below the start describes no region; publishing it as an extent
 * would state a band whose top is under its bottom. */
static void test_degenerate_end_yields_base_only(void) {
  write_prop("linux,initrd-start", 0x30000000ull, 1);
  write_prop("linux,initrd-end", 0x30000000ull, 1);
  run_capture();
  TH_CHECK(strstr(cap, "initrd pos=base conf=parsed lo=0x30000000\n") != NULL);
  TH_CHECK(strstr(cap, "hi=") == NULL);
}

int main(void) {
  th_sysroot_init("sysfs_devicetree_initrd");
  th_sysroot_stage_path("/sys/firmware/devicetree/base/chosen", g_chosen,
                        sizeof(g_chosen));
  TH_CHECK(mkdir(g_chosen, 0755) == 0 || errno == EEXIST);

  TEST_SUITE("test_sysfs_devicetree_initrd");
  BEGIN_CATEGORY("device-tree initrd extent");
  RUN(test_end_property_is_exclusive);
  RUN(test_two_cell_properties);
  BEGIN_CATEGORY("absent and degenerate end");
  RUN(test_missing_end_yields_base_only);
  RUN(test_degenerate_end_yields_base_only);
  return TEST_DONE();
}
