// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Unit tests for the TASK_SIZE probe's pure logic: the binary search that
// converges on the user/kernel boundary and the two-scale check that a located
// boundary is the real top rather than the bottom of a gap. Both take the probe
// as a callback (kasld_ts_step_fn), so here they run against a SYNTHETIC
// address space -- no mmap, no kernel, deterministic. The live mmap-backed
// probe is 32-bit only and exercised by tests/vm boots; these cover the paths a
// boot cannot reach on a normal kernel (a porous layout, a probe that returns
// untrusted mid-search) and pin exact convergence rather than a containing
// window. Standalone -- task_size.h is header-only, so this links nothing.
// ---
// <bcoles@gmail.com>

#include "include/kasld/task_size.h"
#include "test_harness.h"

#include <assert.h>
#include <stdio.h>

/* A synthetic address space. Everything below g_ts maps (step -> 1), everything
 * at or above it refuses (step -> 0) -- EXCEPT an optional mappable band
 * [g_gap_lo, g_gap_hi) sitting above the boundary, modelling an architecture
 * with a hole the boundary search could mistake for the top. g_fail_at, when
 * nonzero, makes any probe at or above it return -1 (an untrusted answer, e.g.
 * a resource limit reached partway through the walk). g_probes counts calls so
 * a test can assert the search converges rather than thrashing. */
static unsigned long g_ts, g_gap_lo, g_gap_hi, g_fail_at;
static int g_probes;

static int mock_step(unsigned long addr, unsigned long len) {
  (void)len;
  g_probes++;
  if (g_fail_at && addr >= g_fail_at)
    return -1;
  if (g_gap_hi && addr >= g_gap_lo && addr < g_gap_hi)
    return 1; /* a mappable page above the boundary */
  return addr < g_ts ? 1 : 0;
}

static void reset(unsigned long ts) {
  g_ts = ts;
  g_gap_lo = g_gap_hi = g_fail_at = 0;
  g_probes = 0;
}

#define PAGE 0x1000ul
#define ANCHOR 0x40000000ul  /* known below every split tested */
#define CEILING 0xfffff000ul /* top page of the 32-bit space */

/* ========================================================================
 * Binary search converges EXACTLY on the boundary
 * ======================================================================== */
static void test_search_converges_exact(void) {
  /* Every 1 GiB VMSPLIT boundary plus a non-round one. */
  const unsigned long splits[] = {0x80000000ul, 0xb0000000ul, 0xbf000000ul,
                                  0xc0000000ul, 0x9a3c0000ul};
  for (unsigned i = 0; i < sizeof(splits) / sizeof(splits[0]); i++) {
    reset(splits[i]);
    unsigned long out = 0;
    enum kasld_ts_status st =
        kasld__ts_search(mock_step, ANCHOR, CEILING, PAGE, &out);
    assert(st == KASLD_TS_EXACT);
    assert(out == splits[i]); /* the exact boundary, not a containing window */
    /* A 32-bit space at page granularity is ~20 halvings; guard the loop. */
    assert(g_probes > 0 && g_probes < 40);
  }
}

/* An untrusted probe mid-search aborts to UNRELIABLE rather than reporting a
 * boundary dragged down by the failure. */
static void test_search_untrusted_aborts(void) {
  reset(0xc0000000ul);
  g_fail_at = 0x90000000ul; /* a limit reached once the walk climbs here */
  unsigned long out = 0xdeadbeef;
  enum kasld_ts_status st =
      kasld__ts_search(mock_step, ANCHOR, CEILING, PAGE, &out);
  assert(st == KASLD_TS_UNRELIABLE);
}

/* ========================================================================
 * "nothing maps above" tells a boundary from the bottom of a gap
 * ======================================================================== */
static void test_nothing_above_clean_boundary(void) {
  /* A real top: nothing maps above it. Every sample refuses -> 1. */
  reset(0xc0000000ul);
  assert(kasld__ts_nothing_above(mock_step, 0xc0000000ul, PAGE, CEILING) == 1);
}

static void test_nothing_above_detects_gap(void) {
  /* The located address is the bottom of a hole: a band above it still maps, so
   * it is at or BELOW the true boundary. This is the path a normal-kernel boot
   * never exercises -- there is no gap to find. */
  reset(0x80000000ul);
  g_gap_lo = 0x90000000ul;
  g_gap_hi = 0xa0000000ul; /* 256 MiB of mappable space above the candidate */
  assert(kasld__ts_nothing_above(mock_step, 0x80000000ul, PAGE, CEILING) == 0);
}

static void test_nothing_above_narrow_gap_found(void) {
  /* A few-page band, not a wide one: the near-scale sample (split + len<<k) is
   * what catches it, so both sampling scales earn their place. */
  reset(0x80000000ul);
  g_gap_lo = 0x80010000ul;
  g_gap_hi = 0x80014000ul; /* four pages, just above the candidate */
  assert(kasld__ts_nothing_above(mock_step, 0x80000000ul, PAGE, CEILING) == 0);
}

static void test_nothing_above_untrusted(void) {
  reset(0xc0000000ul);
  g_fail_at = 0xc0000000ul; /* every sample above the split is untrusted */
  assert(kasld__ts_nothing_above(mock_step, 0xc0000000ul, PAGE, CEILING) == -1);
}

int main(void) {
  TEST_SUITE("test_task_size");

  BEGIN_CATEGORY("Boundary search");
  RUN(test_search_converges_exact);
  RUN(test_search_untrusted_aborts);

  BEGIN_CATEGORY("Gap detection (nothing-maps-above)");
  RUN(test_nothing_above_clean_boundary);
  RUN(test_nothing_above_detects_gap);
  RUN(test_nothing_above_narrow_gap_found);
  RUN(test_nothing_above_untrusted);

  return TEST_DONE();
}
