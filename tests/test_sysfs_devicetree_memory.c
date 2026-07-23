// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Covering-completeness test for sysfs_devicetree_memory. The component is
// #included with its main renamed and driven over a staged KASLD_SYSROOT
// device tree (binary #address-cells / #size-cells / memory@*/reg blobs).
//
// The behaviour under test: the /memory nodes are treated as the COMPLETE RAM
// map, so a possibly-truncated read must not fabricate a covering.
//   - a complete small map emits the RAM hull (base + top) and per-region
//     extents for the gap carver;
//   - a reg that fills the read buffer may be clipped mid-property, so the
//     whole map is withheld (no base/top/extents) rather than fake a gap past
//     the last bank seen;
//   - more than 64 banks read in full is not truncation but exceeds the extent
//     buffer, so it falls back to the hull bounds alone (no gap covering).
// ---
// <bcoles@gmail.com>
#define _GNU_SOURCE

int sysfs_devicetree_memory_main(void);
#define main sysfs_devicetree_memory_main
#include "../src/components/sysfs_devicetree_memory.c"
#undef main

#include "test_harness.h"

#include <assert.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static char g_root[256];
static char g_base[400]; /* <root>/sys/firmware/devicetree/base */
static char cap[16384];

static void mkdirs(const char *path) {
  char tmp[512];
  snprintf(tmp, sizeof(tmp), "%s", path);
  for (char *p = tmp + 1; *p; p++) {
    if (*p == '/') {
      *p = '\0';
      mkdir(tmp, 0755);
      *p = '/';
    }
  }
  mkdir(tmp, 0755);
}

static void write_bytes(const char *path, const unsigned char *b, size_t n) {
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  assert(fd >= 0);
  assert(write(fd, b, n) == (ssize_t)n);
  close(fd);
}

/* Big-endian encode `v` into `cells` 4-byte words at p. */
static void wr_be(unsigned char *p, unsigned long long v, int cells) {
  int bytes = cells * 4;
  for (int i = 0; i < bytes; i++)
    p[bytes - 1 - i] = (unsigned char)((v >> (8 * i)) & 0xff);
}

static void write_cell(const char *rel, unsigned long v) {
  char path[512];
  unsigned char b[4];
  wr_be(b, v, 1);
  snprintf(path, sizeof(path), "%s/%s", g_base, rel);
  write_bytes(path, b, 4);
}

/* Create <base>/<node>/reg holding `nbanks` (base,size) pairs, each starting at
 * start + i*stride with the given size (2 address cells + 2 size cells). */
static void write_memory_node(const char *node, int nbanks,
                              unsigned long long start,
                              unsigned long long stride,
                              unsigned long long size) {
  char dir[512], path[600];
  snprintf(dir, sizeof(dir), "%s/%s", g_base, node);
  mkdirs(dir);
  size_t entry = 16; /* (2+2) cells * 4 */
  size_t n = (size_t)nbanks * entry;
  unsigned char *buf = malloc(n);
  assert(buf);
  for (int i = 0; i < nbanks; i++) {
    wr_be(buf + (size_t)i * entry, start + (unsigned long long)i * stride, 2);
    wr_be(buf + (size_t)i * entry + 8, size, 2);
  }
  snprintf(path, sizeof(path), "%s/reg", dir);
  write_bytes(path, buf, n);
  free(buf);
}

static void rm_memory_node(const char *node) {
  char path[600], dir[512];
  snprintf(path, sizeof(path), "%s/%s/reg", g_base, node);
  unlink(path);
  snprintf(dir, sizeof(dir), "%s/%s", g_base, node);
  rmdir(dir);
}

static void run_capture(void) {
  fflush(stdout);
  char tmpl[] = "/tmp/kasld_dtm_capXXXXXX";
  int fd = mkstemp(tmpl);
  assert(fd >= 0);
  int saved = dup(1);
  dup2(fd, 1);
  fflush(stderr);
  int saved_err = dup(2);
  int devnull = open("/dev/null", O_WRONLY);
  if (devnull >= 0)
    dup2(devnull, 2);

  sysfs_devicetree_memory_main();

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

/* A complete two-bank map: emits the RAM hull (base + top) and per-region
 * extents for the gap carver. */
static void test_complete_map_emits_hull_and_extents(void) {
  write_memory_node("memory@0", 1, 0x40000000ull, 0, 0x20000000ull);
  write_memory_node("memory@1", 1, 0x80000000ull, 0, 0x20000000ull);
  run_capture();
  rm_memory_node("memory@0");
  rm_memory_node("memory@1");

  assert(strstr(cap, "ram pos=base conf=parsed lo=0x40000000") != NULL);
  assert(strstr(cap, "ram pos=top conf=parsed hi=0xa0000000") != NULL);
  assert(strstr(cap, "ram pos=extent") != NULL);
}

/* A reg that fills the read buffer (>= 1024 bytes) may be clipped, so the whole
 * map is withheld — no hull, no extents. 65 banks * 16 = 1040 bytes. */
static void test_truncated_reg_withholds_map(void) {
  write_memory_node("memory@0", 65, 0x40000000ull, 0x100000ull, 0x80000ull);
  run_capture();
  rm_memory_node("memory@0");

  assert(strstr(cap, "ram pos=base") == NULL);
  assert(strstr(cap, "ram pos=top") == NULL);
  assert(strstr(cap, "ram pos=extent") == NULL);
}

/* More than 64 banks, each node read in full (no truncation): the extent buffer
 * overflows, so the covering is dropped but the hull stays (sound
 * floor/ceiling, since every node was read completely). Two nodes of 40 banks =
 * 80 total. */
static void test_overflow_emits_hull_only(void) {
  write_memory_node("memory@0", 40, 0x40000000ull, 0x100000ull, 0x80000ull);
  write_memory_node("memory@1", 40, 0x50000000ull, 0x100000ull, 0x80000ull);
  run_capture();
  rm_memory_node("memory@0");
  rm_memory_node("memory@1");

  assert(strstr(cap, "ram pos=base") != NULL);
  assert(strstr(cap, "ram pos=top") != NULL);
  assert(strstr(cap, "ram pos=extent") == NULL);
}

int main(void) {
  char tmpl[] = "/tmp/kasld_dtm_rootXXXXXX";
  char *r = mkdtemp(tmpl);
  assert(r != NULL);
  snprintf(g_root, sizeof(g_root), "%s", r);
  snprintf(g_base, sizeof(g_base), "%s/sys/firmware/devicetree/base", g_root);
  mkdirs(g_base);
  setenv("KASLD_SYSROOT", g_root, 1);

  /* 2 address cells + 2 size cells (typical 64-bit DT). */
  write_cell("#address-cells", 2);
  write_cell("#size-cells", 2);

  TEST_SUITE("test_sysfs_devicetree_memory");
  BEGIN_CATEGORY("device-tree RAM map covering completeness");
  RUN(test_complete_map_emits_hull_and_extents);
  RUN(test_truncated_reg_withholds_map);
  RUN(test_overflow_emits_hull_only);
  return TEST_DONE();
}
