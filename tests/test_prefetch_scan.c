// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Unit tests for the prefetch scan left-edge finder (prefetch_scan.h).
//
// prefetch_scan_find_edge() locates the LEFT EDGE (base slot) of a contiguous
// mapped region in a per-slot timing array. These tests drive it with SYNTHETIC
// profiles — no real prefetch timing — so the pure edge-detection logic is
// checked deterministically on any host. They pin the property the live scan
// depends on: the base slot carries a weaker signal than the region body, and
// the edge walk must still recover it rather than reporting the base one slot
// high. prefetch_scan.h is x86_64-only, so the suite is inert elsewhere.
// ---
// <bcoles@gmail.com>

#if defined(__x86_64__) || defined(__amd64__)

#define _GNU_SOURCE /* cpu.h (via prefetch_scan.h) uses getline / sched        \
                       affinity */
#include "include/prefetch_scan.h"
#include "test_harness.h"

#include <assert.h>
#include <stddef.h>
#include <stdint.h>

#define N 256

/* Deterministic near-baseline fill (no rand: reproducible across runs/arches).
 */
static void fill_baseline(uint64_t *t, uint64_t base, uint64_t jitter) {
  size_t i;
  for (i = 0; i < N; i++)
    t[i] = base + (uint64_t)((i * 37) % (jitter ? jitter : 1));
}

/* AMD (sums, mapped reads HIGHER): a marginal base slot that still clears the
 * 1.5x-median threshold, a hot body, and two isolated outliers. The leftmost
 * confirmed cluster is the base; the outliers are rejected by K-of-M. */
static void test_amd_marginal_base(void) {
  uint64_t t[N];
  size_t B = 60, i;
  fill_baseline(t, 5000, 100); /* median ~5050, 1.5x ~7575, 1.25x ~6312 */
  t[B] = 7900;                 /* base slot: weaker than body, above strict */
  for (i = 1; i < 15; i++)
    t[B + i] = 8700; /* body */
  t[120] = 77000;    /* isolated scheduler outlier */
  t[200] = 25000;    /* isolated scheduler outlier */
  assert(prefetch_scan_find_edge(t, N, CPU_VENDOR_AMD, 5, 8) == (long)B);
}

/* AMD: the base slot sits BELOW the strict 1.5x threshold (a noisy pass) but
 * above the looser 1.25x edge bound. The strict cluster starts one slot high;
 * the left-edge walk must recover the base slot. This is the exact off-by-one
 * the edge walk fixes. */
static void test_amd_base_below_strict_walk_recovers(void) {
  uint64_t t[N];
  size_t B = 60, i;
  fill_baseline(t, 5000, 100);
  t[B] = 6800; /* below 1.5x (~7575), above 1.25x (~6312) */
  for (i = 1; i < 15; i++)
    t[B + i] = 8700;
  assert(prefetch_scan_find_edge(t, N, CPU_VENDOR_AMD, 5, 8) == (long)B);
}

/* AMD: baseline plus isolated outliers, no contiguous cluster -> -1. */
static void test_amd_no_cluster(void) {
  uint64_t t[N];
  fill_baseline(t, 5000, 100);
  t[50] = 60000;
  t[150] = 40000;
  assert(prefetch_scan_find_edge(t, N, CPU_VENDOR_AMD, 5, 8) == -1);
}

/* AMD: a cluster whose left edge is slot 0. */
static void test_amd_edge_at_zero(void) {
  uint64_t t[N];
  size_t i;
  fill_baseline(t, 5000, 100);
  t[0] = 7900;
  for (i = 1; i < 15; i++)
    t[i] = 8700;
  assert(prefetch_scan_find_edge(t, N, CPU_VENDOR_AMD, 5, 8) == 0);
}

/* Intel (mins, mapped reads FASTER): the global minimum seeds inside the hot
 * body; the walk to the baseline midpoint recovers the weaker base slot. */
static void test_intel_weaker_base_walk(void) {
  uint64_t t[N];
  size_t B = 60, i;
  fill_baseline(t, 300, 20); /* median ~310, min 200 -> midpoint ~255 */
  t[B] = 240;                /* base slot: below the midpoint (mapped) */
  for (i = 1; i < 15; i++)
    t[B + i] = 200; /* body (fastest) */
  assert(prefetch_scan_find_edge(t, N, CPU_VENDOR_INTEL, 5, 8) == (long)B);
}

/* Intel: a mapped run beginning at slot 0. */
static void test_intel_edge_at_zero(void) {
  uint64_t t[N];
  size_t i;
  fill_baseline(t, 300, 20);
  for (i = 0; i < 15; i++)
    t[i] = 200;
  assert(prefetch_scan_find_edge(t, N, CPU_VENDOR_INTEL, 5, 8) == 0);
}

int main(void) {
  TEST_SUITE("Prefetch scan edge detection");
  BEGIN_CATEGORY("AMD (sums, mapped higher)");
  RUN(test_amd_marginal_base);
  RUN(test_amd_base_below_strict_walk_recovers);
  RUN(test_amd_no_cluster);
  RUN(test_amd_edge_at_zero);
  BEGIN_CATEGORY("Intel (mins, mapped faster)");
  RUN(test_intel_weaker_base_walk);
  RUN(test_intel_edge_at_zero);
  return TEST_DONE();
}

#else /* prefetch_scan.h is x86_64-only */

#include "test_harness.h"

int main(void) {
  TEST_SUITE("Prefetch scan edge detection (x86_64 only - inert here)");
  return TEST_DONE();
}

#endif
