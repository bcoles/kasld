// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Unit tests for kernfs_ns_hash's salt recovery, driven directly over the
// component's pure functions (the live getdents64 path cannot be staged through
// a KASLD_SYSROOT, which stages file contents, not directory seek cookies).
//
// Pins four behaviours:
//   1. Unique recovery. Cookies synthesised from a known kernel-VA salt recover
//      exactly that salt from the surrounding window.
//   2. Offset-table pin. Walking the KASLR base grid with a build offset
//      recovers base + off, so the caller derives the true base.
//   3. Patched no-op. Cookies salted with a small ns_id (the post-fix salt)
//      have NO kernel-VA solution, so recovery emits nothing.
//   4. Discrimination. A wrong salt does not reproduce the cookies.
// ---
// <bcoles@gmail.com>
#define _GNU_SOURCE

int kernfs_ns_hash_main(int argc, char **argv);
#define main kernfs_ns_hash_main
#include "../src/components/kernfs_ns_hash.c"
#undef main

#include "test_harness.h"

#include <assert.h>
#include <stdint.h>
#include <string.h>

/* Build the (name, cookie) constraints a reader would harvest if every entry
 * were tagged with `salt`. */
static int build_pairs(unsigned long salt, const char *const *names, int n,
                       struct kernfs_pair *pr) {
  for (int i = 0; i < n; i++) {
    kernfs_affine(names[i], &pr[i].pow11, &pr[i].cname);
    pr[i].hash = kernfs_fold((uint64_t)salt * pr[i].pow11 + pr[i].cname);
  }
  return n;
}

static const char *const NAMES[] = {"lo", "ens33", "docker0", "virbr0"};

/* A word-aligned synthetic &init_net and a 2 MiB-aligned base, sized to the
 * target word width so the 32-bit builds (run under test-cross) exercise the
 * hash_32 fold and the 64-bit build exercises hash_64. The values are
 * arbitrary; only their recovery matters. */
#if __SIZEOF_LONG__ == 8
#define SALT_A 0xffffffff8e773d40UL
#define BASE_B 0xffffffff8c000000UL
#else
#define SALT_A 0x8e773d40UL
#define BASE_B 0x8c000000UL
#endif

/* Cookies from a known salt recover exactly that salt from its window. */
static void test_recovers_known_salt(void) {
  struct kernfs_pair pr[4];
  int n = build_pairs(SALT_A, NAMES, 3, pr);
  unsigned long got = 0;
  int ok = kernfs_scan(pr, n, SALT_A - 0x2000, SALT_A + 0x2000, sizeof(long), 0,
                       &got);
  assert(ok == 1);
  assert(got == SALT_A);
}

/* With a build offset, walking the aligned base grid recovers base + off. */
static void test_offset_table_pin(void) {
  unsigned long base = BASE_B; /* 2 MiB aligned */
  uint32_t off = 0x00773d40;   /* init_net - _text (word aligned) */
  unsigned long salt = base + off;
  struct kernfs_pair pr[4];
  int n = build_pairs(salt, NAMES, 3, pr);
  unsigned long align = 0x200000UL;
  unsigned long got = 0;
  int ok =
      kernfs_scan(pr, n, base - 4 * align, base + 4 * align, align, off, &got);
  assert(ok == 1);
  assert(got == salt);       /* == &init_net */
  assert(got - off == base); /* caller derives the true base */
}

/* Post-fix the salt is a small ns_id integer; no kernel-VA candidate reproduces
 * those cookies, so recovery finds nothing (a sound no-op). */
static void test_patched_is_noop(void) {
  unsigned long ns_id = 0x4002; /* small non-pointer salt */
  struct kernfs_pair pr[4];
  int n = build_pairs(ns_id, NAMES, 3, pr);
  unsigned long got = 0;
  int ok = kernfs_scan(pr, n, SALT_A - 0x4000, SALT_A + 0x4000, sizeof(long), 0,
                       &got);
  assert(ok == 0);
}

/* The true salt passes the cookie check; an adjacent one does not. */
static void test_wrong_salt_rejected(void) {
  struct kernfs_pair pr[4];
  int n = build_pairs(SALT_A, NAMES, 3, pr);
  assert(kernfs_salt_ok(SALT_A, pr, n) == 1);
  assert(kernfs_salt_ok(SALT_A + sizeof(long), pr, n) == 0);
  assert(kernfs_salt_ok(SALT_A - sizeof(long), pr, n) == 0);
}

int main(void) {
  TEST_SUITE("kernfs_ns_hash");
  BEGIN_CATEGORY("salt recovery");
  RUN(test_recovers_known_salt);
  RUN(test_offset_table_pin);
  BEGIN_CATEGORY("soundness");
  RUN(test_patched_is_noop);
  RUN(test_wrong_salt_rejected);
  return TEST_DONE();
}
