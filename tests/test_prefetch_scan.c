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

/* AMD low-amplitude fallback: a virtualized AMD guest can produce a mapped
 * plateau only a few percent above baseline — far below the strict 1.5x tier-1
 * threshold — yet spatially coherent across the whole kernel image. Tier 1
 * finds nothing; tier 2 (MAD-scaled threshold + minimum width) recovers the
 * plateau's left edge. A page-table boundary band is TALLER than the plateau
 * but only a few slots wide, so width — not amplitude — separates them. A dip
 * back to baseline and a steal-event spike inside the plateau are tolerated. */
static void test_amd_low_amplitude_wide_plateau(void) {
  uint64_t t[N];
  size_t B = 40, i;
  fill_baseline(t, 19800, 300); /* ~1.5x tier-1 threshold ~29900 */
  for (i = 0; i < 27; i++)
    t[B + i] = 21200; /* ~1.07x plateau: below tier-1, above median+4*MAD */
  t[B + 16] = 19850;  /* a baseline dip inside the plateau */
  t[B + 8] = 40000;   /* a vCPU steal-event spike inside the plateau */
  for (i = 0; i < 7; i++)
    t[100 + i] = 23800; /* boundary band: taller than the plateau, 7 wide */
  t[150] = 41000;       /* isolated spike */
  assert(prefetch_scan_find_edge(t, N, CPU_VENDOR_AMD, 5, 8) == (long)B);
}

/* AMD low-amplitude fallback: a boundary band and isolated spikes with NO wide
 * plateau must yield -1. The band clears the MAD-scaled threshold (it is taller
 * than baseline) but is narrower than PREFETCH_MIN_PLATEAU_SLOTS, so the width
 * requirement rejects it rather than reporting a false base. */
static void test_amd_low_amplitude_narrow_band_rejected(void) {
  uint64_t t[N];
  size_t i;
  fill_baseline(t, 19800, 300);
  for (i = 0; i < 7; i++)
    t[100 + i] = 23800;
  t[50] = 41000;
  t[200] = 39000;
  assert(prefetch_scan_find_edge(t, N, CPU_VENDOR_AMD, 5, 8) == -1);
}

/* AMD low-amplitude fallback boundary: a plateau exactly PREFETCH_MIN_PLATEAU_
 * SLOTS wide is accepted (its left edge is the base). Locks the width knob. */
static void test_amd_low_amplitude_min_width_accepted(void) {
  uint64_t t[N];
  size_t B = 40, i;
  fill_baseline(t, 19800, 300);
  for (i = 0; i < (size_t)PREFETCH_MIN_PLATEAU_SLOTS; i++)
    t[B + i] = 21200;
  assert(prefetch_scan_find_edge(t, N, CPU_VENDOR_AMD, 5, 8) == (long)B);
}

/* Batched finder: the batched collector amplifies the mapped/unmapped
 * differential to many-fold (an ~8x plateau) with a full-strength base slot.
 * The finder returns the leftmost slot of the plateau directly. A single
 * unmapped hole inside the image (a slot the kernel left unmapped) must not
 * split the cluster: K-of-M confirmation tolerates it. */
static void test_batched_plateau_with_hole(void) {
  uint64_t t[N];
  size_t B = 60, i;
  fill_baseline(t, 10000, 400); /* median ~10100, threshold 3x ~30300 */
  for (i = 0; i < 27; i++)
    t[B + i] = 80000; /* ~8x mapped plateau */
  t[B + 10] = 10200;  /* an unmapped hole mid-image, back at baseline */
  assert(prefetch_scan_find_edge_batched(t, N, 5, 8) == (long)B);
}

/* Batched finder robustness: under CPU contention a run of baseline slots can
 * be perturbed to ~1.5x the median — enough to form a false cluster that the
 * summed collector's 1.5x threshold would wrongly take as the leftmost edge.
 * The batched threshold sits many-fold above the median (in the empty gap below
 * the plateau), so the perturbed baseline cannot qualify and the true plateau —
 * even though it lies to the RIGHT of the noise — is the only cluster returned.
 */
static void test_batched_rejects_loaded_baseline_false_cluster(void) {
  uint64_t t[N];
  size_t B = 120, i;
  fill_baseline(t, 10000, 400);
  for (i = 0; i < 10; i++)
    t[30 + i] = 15500; /* perturbed baseline ~1.55x: a false 1.5x cluster */
  for (i = 0; i < 27; i++)
    t[B + i] = 150000; /* the real ~15x plateau, to the right of the noise */
  assert(prefetch_scan_find_edge_batched(t, N, 5, 8) == (long)B);
}

/* Batched finder: baseline plus a sub-threshold perturbation, no plateau -> -1
 * (reports no signal rather than guessing a base from noise). */
static void test_batched_no_plateau(void) {
  uint64_t t[N];
  size_t i;
  fill_baseline(t, 10000, 400);
  for (i = 0; i < 10; i++)
    t[30 + i] = 15500; /* ~1.55x: below the batched threshold */
  assert(prefetch_scan_find_edge_batched(t, N, 5, 8) == -1);
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
  RUN(test_amd_low_amplitude_wide_plateau);
  RUN(test_amd_low_amplitude_narrow_band_rejected);
  RUN(test_amd_low_amplitude_min_width_accepted);
  RUN(test_amd_no_cluster);
  RUN(test_amd_edge_at_zero);
  BEGIN_CATEGORY("Batched (strong bimodal, no walk)");
  RUN(test_batched_plateau_with_hole);
  RUN(test_batched_rejects_loaded_baseline_false_cluster);
  RUN(test_batched_no_plateau);
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
