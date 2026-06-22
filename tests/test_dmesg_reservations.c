// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Parser unit tests for the dmesg physical-reservation leak components. Each
// component is #included with its main() renamed, then driven over a staged
// KASLD_SYSROOT /var/log/dmesg fixture (mmap_syslog falls back to that file
// under a sysroot). The fixtures reproduce the exact boot-message format the
// kernel prints, and the tests assert the per-region forbidden-band wire
// records the parsers emit — locking in the per-region sample->range emission
// (collapsed interior points carried no [lo,hi] and never drove the engine's
// phys_reservation_exclude; a per-region range does):
//
//   dmesg_reserved_mem    "OF: reserved mem: 0x..0x.."  -> one range per line
//   dmesg_swiotlb         "software IO TLB: mapped [mem 0x..-0x..]" -> one
//   range dmesg_crashkernel     high + low reservations -> TWO disjoint bands
//   dmesg_cma_reserved    "created CMA ... at 0x.., size N MiB" -> per-pool
//   range
//
// The fixture addresses are fixed literals parsed from text (not derived from
// arch macros), so the parser logic is exercised identically regardless of the
// host the suite is built for.
// ---
// <bcoles@gmail.com>
#define _GNU_SOURCE

/* Pull in the public API once, then neutralise the two ELF-section macros so
 * the per-component KASLD_EXPLAIN/KASLD_META definitions do not collide when
 * several components are included into this single translation unit (same
 * approach as test_sysfs_parsers.c). */
#include "../src/include/kasld/api.h"
#undef KASLD_EXPLAIN
#undef KASLD_META
#define KASLD_CAT_(a, b) a##b
#define KASLD_CAT(a, b) KASLD_CAT_(a, b)
#define KASLD_EXPLAIN(t)                                                       \
  extern char KASLD_CAT(kasld_explain_unused_, __COUNTER__)[]
#define KASLD_META(t) extern char KASLD_CAT(kasld_meta_unused_, __COUNTER__)[]

/* Forward declarations for the renamed component entry points (avoids
 * -Wmissing-prototypes; the includes below define them). The parsers' static
 * callbacks (on_match / on_mapped / on_reserved / on_reserved_pool / ...) are
 * uniquely named across these four components, so they coexist in one TU. */
int resmem_main(void);
int swiotlb_main(void);
int crashkernel_main(void);
int cma_main(void);

#define main resmem_main
#include "../src/components/dmesg_reserved_mem.c"
#undef main

#define main swiotlb_main
#include "../src/components/dmesg_swiotlb.c"
#undef main

#define main crashkernel_main
#include "../src/components/dmesg_crashkernel.c"
#undef main

#define main cma_main
#include "../src/components/dmesg_cma_reserved.c"
#undef main

#include "test_harness.h"

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static char g_root[256];

static void mkparents(const char *path) {
  char buf[512];
  snprintf(buf, sizeof(buf), "%s", path);
  for (char *p = buf + 1; *p; p++) {
    if (*p == '/') {
      *p = '\0';
      mkdir(buf, 0755);
      *p = '/';
    }
  }
}

/* Overwrite the sysroot's /var/log/dmesg with `text` (the dmesg components fall
 * back to this file under KASLD_SYSROOT). */
static void stage_dmesg(const char *text) {
  char path[512];
  snprintf(path, sizeof(path), "%s/var/log/dmesg", g_root);
  mkparents(path);
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  assert(fd >= 0);
  size_t len = strlen(text);
  assert(write(fd, text, len) == (ssize_t)len);
  close(fd);
}

/* Run a renamed component main(), capturing its stdout (the wire channel) into
 * `cap`; stderr diagnostics are sent to /dev/null. */
static char cap[16384];
static void run_capture(int (*fn)(void)) {
  fflush(stdout);
  char tmpl[] = "/tmp/kasld_dmesg_capXXXXXX";
  int fd = mkstemp(tmpl);
  assert(fd >= 0);
  int saved = dup(1);
  dup2(fd, 1);
  fflush(stderr);
  int saved_err = dup(2);
  int devnull = open("/dev/null", O_WRONLY);
  if (devnull >= 0)
    dup2(devnull, 2);
  fn();
  fflush(stdout);
  fflush(stderr);
  dup2(saved, 1);
  close(saved);
  dup2(saved_err, 2);
  close(saved_err);
  if (devnull >= 0)
    close(devnull);
  lseek(fd, 0, SEEK_SET);
  ssize_t n = read(fd, cap, sizeof(cap) - 1);
  cap[n > 0 ? n : 0] = '\0';
  close(fd);
  unlink(tmpl);
}

/* --- dmesg_reserved_mem: one bounded range per "OF: reserved mem:" line.
 * Each line is one contiguous reservation [start, inclusive-end]; the two
 * sparse nodes must stay two ranges (the gap between them is usable RAM). ---
 */
static void test_reserved_mem_per_region(void) {
  stage_dmesg("OF: reserved mem: 0x0000000080000000..0x00000000801fffff (2048 "
              "KiB) nomap a@80000000\n"
              "OF: reserved mem: 0x0000000088000000..0x000000008bffffff (65536 "
              "KiB) map b@88000000\n");
  run_capture(resmem_main);
  assert(
      strstr(cap,
             "reserved_mem pos=base conf=parsed lo=0x80000000 hi=0x801fffff") !=
      NULL);
  assert(
      strstr(cap,
             "reserved_mem pos=base conf=parsed lo=0x88000000 hi=0x8bffffff") !=
      NULL);
}

/* --- dmesg_swiotlb: the pool is a single contiguous reservation -> one range.
 */
static void test_swiotlb_single_range(void) {
  stage_dmesg("software IO TLB: mapped [mem "
              "0x00000000bbed0000-0x00000000bfed0000] (64MB)\n");
  run_capture(swiotlb_main);
  assert(
      strstr(cap, "swiotlb pos=base conf=parsed lo=0xbbed0000 hi=0xbfed0000") !=
      NULL);
}

/* --- dmesg_crashkernel: the high and low reservations are TWO disjoint bands;
 * they must NOT collapse into one [min,max] span (that would forbid the usable
 * RAM in the gap between them). ---------------------------------------------
 */
static void test_crashkernel_two_disjoint_bands(void) {
  stage_dmesg(
      "crashkernel reserved: 0x0000000027e00000 - 0x000000003fe00000 (384 MB)\n"
      "crashkernel low memory reserved: 0x0000000004000000 - "
      "0x0000000008000000 "
      "(64 MB)\n");
  run_capture(crashkernel_main);
  assert(
      strstr(cap,
             "crashkernel pos=base conf=parsed lo=0x27e00000 hi=0x3fe00000") !=
      NULL);
  assert(strstr(cap,
                "crashkernel pos=base conf=parsed lo=0x4000000 hi=0x8000000") !=
         NULL);
  /* the collapsed span [low.lo, high.hi] must never be emitted */
  assert(strstr(cap, "lo=0x4000000 hi=0x3fe00000") == NULL);
}

/* --- dmesg_cma_reserved: per-pool range computed from the MiB size (both the
 * "created ... pool" and "cma: Reserved" formats). ------------------------- */
static void test_cma_size_to_range(void) {
  stage_dmesg(
      "Reserved memory: created CMA memory pool at 0x000000007a000000, size 96 "
      "MiB\n"
      "cma: Reserved 256 MiB at 0x00000000f0000000 on node -1\n");
  run_capture(cma_main);
  /* 96 MiB:  0x7a000000 + 0x6000000  - 1 = 0x7fffffff */
  assert(
      strstr(cap,
             "reserved_mem pos=base conf=parsed lo=0x7a000000 hi=0x7fffffff") !=
      NULL);
  /* 256 MiB: 0xf0000000 + 0x10000000 - 1 = 0xffffffff */
  assert(
      strstr(cap,
             "reserved_mem pos=base conf=parsed lo=0xf0000000 hi=0xffffffff") !=
      NULL);
}

/* --- dmesg_cma_reserved: with no parseable size, fall back to a base-only
 * sample rather than fabricating a bounded range. -------------------------- */
static void test_cma_size_absent_fallback(void) {
  stage_dmesg(
      "Reserved memory: created restricted DMA pool at 0x0000000060000000\n");
  run_capture(cma_main);
  assert(
      strstr(cap, "reserved_mem pos=interior conf=parsed sample=0x60000000") !=
      NULL);
  /* no size => no [lo,hi] band may be invented */
  assert(strstr(cap, "lo=0x60000000 hi=") == NULL);
}

int main(void) {
  /* One sysroot for the whole suite: kasld_sysroot() caches its value
   * process-wide, so the root must be set before any component runs. Each test
   * re-stages /var/log/dmesg (O_TRUNC) with only its own fixture lines. */
  char tmpl[] = "/tmp/kasld_dmesg_rootXXXXXX";
  char *r = mkdtemp(tmpl);
  assert(r != NULL);
  snprintf(g_root, sizeof(g_root), "%s", r);
  setenv("KASLD_SYSROOT", g_root, 1);

  TEST_SUITE("test_dmesg_reservations");
  BEGIN_CATEGORY("dmesg physical-reservation parsers");
  RUN(test_reserved_mem_per_region);
  RUN(test_swiotlb_single_range);
  RUN(test_crashkernel_two_disjoint_bands);
  RUN(test_cma_size_to_range);
  RUN(test_cma_size_absent_fallback);
  return TEST_DONE();
}
