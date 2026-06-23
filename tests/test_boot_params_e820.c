// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Parser unit test for boot_params_e820's RAM covering. The component is
// #included with its main() renamed and driven over a staged KASLD_SYSROOT
// /sys/kernel/boot_params/data — a 4096-byte zero-page whose E820 table is
// hand-built here. Asserts the covering contract: every E820 type-RAM entry
// (including one at address 0) is emitted as a pos=extent RAM record, non-RAM
// entries are not, and the base/top envelope is still emitted alongside.
//
// boot_params is x86-only (the component #errors elsewhere), so the body is
// gated to x86; on other hosts the suite is a trivial pass.
// ---
// <bcoles@gmail.com>
#define _GNU_SOURCE

#if defined(__x86_64__) || defined(__i386__) || defined(__amd64__)

/* Pull in the public API once, then neutralise the ELF-section macros so the
 * component's KASLD_EXPLAIN/KASLD_META do not emit colliding section arrays. */
#include "../src/include/kasld/api.h"
#undef KASLD_EXPLAIN
#undef KASLD_META
#define KASLD_EXPLAIN(t) extern char kasld_explain_unused[]
#define KASLD_META(t) extern char kasld_meta_unused[]

int bpe820_main(void);
#define main bpe820_main
#include "../src/components/boot_params_e820.c"
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
  for (char *p = buf + 1; *p; p++)
    if (*p == '/') {
      *p = '\0';
      mkdir(buf, 0755);
      *p = '/';
    }
}

static void put_le(unsigned char *p, unsigned long long v, int n) {
  for (int i = 0; i < n; i++)
    p[i] = (unsigned char)(v >> (8 * i));
}

/* The 4096-byte zero-page, built entry-by-entry. Offsets mirror the component:
 * OFF_E820_ENTRIES=0x1e8 (u8 count), OFF_E820_TABLE=0x2d0, 20 bytes/entry
 * { u64 addr; u64 size; u32 type } little-endian. */
static unsigned char zp[4096];
static void e820_set(int idx, unsigned long long addr, unsigned long long size,
                     unsigned int type) {
  unsigned char *e = zp + 0x2d0 + (size_t)idx * 20;
  put_le(e + 0, addr, 8);
  put_le(e + 8, size, 8);
  put_le(e + 16, type, 4);
}

static void stage_zeropage(int nent) {
  zp[0x1e8] = (unsigned char)nent;
  char path[512];
  snprintf(path, sizeof(path), "%s/sys/kernel/boot_params/data", g_root);
  mkparents(path);
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  assert(fd >= 0);
  assert(write(fd, zp, sizeof(zp)) == (ssize_t)sizeof(zp));
  close(fd);
}

static char cap[16384];
static void run_capture(int (*fn)(void)) {
  fflush(stdout);
  char tmpl[] = "/tmp/kasld_bpe820_capXXXXXX";
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

/* Three RAM regions (one at address 0) split by a PCI hole, with a reserved
 * entry in the hole. The covering must list every RAM extent — including the
 * one at address 0 — and must not list the reserved entry; the base/top
 * envelope skips address 0 for its low edge. */
static void test_boot_params_e820_covering(void) {
  memset(zp, 0, sizeof(zp));
  e820_set(0, 0x0, 0x100000, E820_TYPE_RAM);        /* [0, 0xfffff]        */
  e820_set(1, 0x100000, 0xbff00000, E820_TYPE_RAM); /* [0x100000,0xbfffffff]*/
  e820_set(2, 0xe0000000, 0x1000, 2u);              /* reserved, in the hole*/
  e820_set(3, 0x100000000ULL, 0x40000000,
           E820_TYPE_RAM); /* [4GiB,0x13fffffff]*/
  stage_zeropage(4);
  run_capture(bpe820_main);

  /* covering: each RAM entry as a pos=extent record; the addr-0 entry included
   * (a skipped extent would fabricate a false gap). */
  assert(strstr(cap, "ram pos=extent conf=parsed lo=0x0 hi=0xfffff") != NULL);
  assert(strstr(cap, "ram pos=extent conf=parsed lo=0x100000 hi=0xbfffffff") !=
         NULL);
  assert(strstr(cap, "ram pos=extent conf=parsed lo=0x100000000 "
                     "hi=0x13fffffff") != NULL);
  /* the reserved entry is not part of the RAM map */
  assert(strstr(cap, "0xe0000000") == NULL);
  /* envelope still emitted: lowest non-zero RAM start + highest RAM end */
  assert(strstr(cap, "ram pos=base conf=parsed lo=0x100000") != NULL);
  assert(strstr(cap, "ram pos=top conf=parsed hi=0x13fffffff") != NULL);
}

/* ACPI data (type 3) and ACPI NVS (type 4) entries are emitted as forbidden
 * bands (REGION_ACPI_TABLE / REGION_ACPI_NVS). A band entirely below
 * KASLR_PHYS_MIN is skipped: the image is never placed that low, so it would
 * exclude nothing and is the only band that could perturb a DRAM floor. */
static void test_boot_params_e820_acpi_bands(void) {
  memset(zp, 0, sizeof(zp));
  e820_set(0, 0x1000, 0xbffdf000, E820_TYPE_RAM);   /* RAM low             */
  e820_set(1, 0xbffe0000, 0x20000, E820_TYPE_ACPI); /* -> ACPI_TABLE       */
  e820_set(2, 0xbf000000, 0x10000, E820_TYPE_NVS);  /* -> ACPI_NVS         */
  e820_set(3, 0x1000, 0x1000, E820_TYPE_ACPI);      /* below floor: skipped*/
  stage_zeropage(4);
  run_capture(bpe820_main);

  assert(strstr(cap, "acpi_table pos=base conf=parsed lo=0xbffe0000 "
                     "hi=0xbfffffff") != NULL);
  assert(strstr(cap,
                "acpi_nvs pos=base conf=parsed lo=0xbf000000 hi=0xbf00ffff") !=
         NULL);
  /* the sub-KASLR_PHYS_MIN ACPI band is not emitted */
  assert(strstr(cap, "lo=0x1000 hi=0x1fff") == NULL);
}

int main(void) {
  char tmpl[] = "/tmp/kasld_bpe820_rootXXXXXX";
  char *r = mkdtemp(tmpl);
  assert(r != NULL);
  snprintf(g_root, sizeof(g_root), "%s", r);
  setenv("KASLD_SYSROOT", g_root, 1);

  TEST_SUITE("test_boot_params_e820");
  BEGIN_CATEGORY("boot_params E820 RAM covering");
  RUN(test_boot_params_e820_covering);
  RUN(test_boot_params_e820_acpi_bands);
  return TEST_DONE();
}

#else /* non-x86 host: boot_params_e820 is x86-only (the component #errors) */
#include "test_harness.h"
int main(void) {
  TEST_SUITE("test_boot_params_e820");
  return TEST_DONE();
}
#endif
