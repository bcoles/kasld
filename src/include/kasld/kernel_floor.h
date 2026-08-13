// This file is part of KASLD - https://github.com/bcoles/kasld
//
// The lowest address that could belong to the kernel, measured rather than
// assumed.
//
// A component sorting leaked words into "kernel pointer" and "user value" needs
// the boundary between the two halves of the address space. That boundary is
// TASK_SIZE. Several components reached for the compile-time PAGE_OFFSET
// instead, because on x86_32 the two are equal (TASK_SIZE == __PAGE_OFFSET,
// no gap) and one of them was available at compile time — so the wrong quantity
// was used, hidden by an architectural coincidence on the arch it was written
// for.
//
// It is the wrong quantity twice over. PAGE_OFFSET describes the ANALYSING
// build, not the target: where the split is a VMSPLIT choice, or where the base
// is derived from a paging mode, the runtime value can sit BELOW the built one
// and every genuine kernel pointer in between is discarded. That failure is
// silent — a component that dropped everything looks exactly like a component
// that found nothing.
//
// TASK_SIZE, unlike PAGE_OFFSET, is measurable from an unprivileged process in
// microseconds: mmap refuses above it. `task_size.h` does the measuring; this
// header only decides what to do with each outcome.
//
// WHAT IS RETURNED is never above the true boundary. Rounding the other way
// would reintroduce the bug, so each outcome is used only in the safe
// direction: an exact boundary is TASK_SIZE itself, and no kernel pointer is
// below it; a coarse hint-path answer is the first 256 MiB step that would not
// map, which is at or ABOVE the boundary, so a stride is subtracted; a boundary
// with mappable space above it is already at or below the true one. Below the
// truth costs at most some user space admitted as a candidate, which the
// engine's own windows then reject. Above it discards real kernel pointers.
//
// This does NOT emit an observation, and callers must not emit one from it.
// The engine counts distinct origins as independent corroboration, so N
// components publishing one identical probe would manufacture agreement out of
// a single measurement. The dedicated probe components are the source of record
// for the split; everything here is a local decision.
// ---
// <bcoles@gmail.com>

#ifndef KASLD_KERNEL_FLOOR_H
#define KASLD_KERNEL_FLOOR_H

#include "include/kasld/api.h"
#include "include/kasld/task_size.h"

/* The boundary measurement itself, taken ONCE per process.
 *
 * Both accessors below need the same number for different purposes, and the
 * probe forks a child to get it. Caching inside each of them separately still
 * forked twice for one unchanging boundary — proc_pid_syscall calls both. The
 * measurement is shared here instead, so the second caller is a load.
 *
 * Not thread-safe, and does not need to be: components are single-threaded
 * processes. */
static inline enum kasld_ts_status kasld__ts_cached(unsigned long *out) {
  static unsigned long cached_split;
  static enum kasld_ts_status cached_status;
  static int done;
  if (!done) {
    cached_status = kasld_task_size_probe(&cached_split);
    done = 1;
  }
  *out = cached_split;
  return cached_status;
}

/* The lowest address that could be kernel, or 0 if it could not be measured.
 *
 * 32-bit only: kasld_task_size_probe() declines on 64-bit, where the two halves
 * of the address space are astronomically far apart and PAGE_OFFSET_MIN is
 * already a tight-enough floor. */
static inline unsigned long kasld_kernel_floor(void) {
  unsigned long split = 0;

  switch (kasld__ts_cached(&split)) {
  case KASLD_TS_EXACT:
    return split; /* the boundary itself */
  case KASLD_TS_POROUS:
    return split; /* the bottom of a gap: at or below the boundary */
  case KASLD_TS_APPROX:
    /* At or above the boundary, so step back one stride to the highest
     * address the sweep confirmed was user. */
    return (split > KASLD_VMSPLIT_STRIDE) ? split - KASLD_VMSPLIT_STRIDE : 0;
  case KASLD_TS_NOT_FOUND:
  case KASLD_TS_UNRELIABLE:
  default:
    return 0;
  }
}

/* The floor to sort leaked words with: measured where that is possible, and
 * otherwise the lowest base this architecture admits — which is sound (no real
 * kernel pointer is below it) but wide. Never the compile-time PAGE_OFFSET,
 * which is neither. */
/* Cached: the boundary cannot move while the process runs, and callers sort
 * leaked words in tight loops — a fork per candidate word would be absurd. The
 * first call measures; the rest are a load. Not thread-safe, and does not need
 * to be: components are single-threaded processes. */
static inline unsigned long kasld_kernel_pointer_floor(void) {
  static unsigned long cached;
  static int done;
  if (!done) {
    unsigned long measured = kasld_kernel_floor();
    cached = measured ? measured : (unsigned long)PAGE_OFFSET_MIN;
    done = 1;
  }
  return cached;
}

/* The measured linear-map base (PAGE_OFFSET) — the floor a REGION-tagged
 * emission needs, distinct from the user/kernel boundary above.
 *
 * A direct-map or kernel-text address is at or above PAGE_OFFSET, which sits a
 * module band ABOVE kasld_kernel_pointer_floor() (the boundary, TASK_SIZE). The
 * band [TASK_SIZE, PAGE_OFFSET) holds module text: a kernel pointer, but not a
 * direct-map or text one. A component emitting a REGION_DIRECTMAP or
 * REGION_KERNEL_TEXT bound floors at THIS value, not at the boundary, or a
 * leaked module address forms a bound its region does not support.
 *
 * Recovered from the boundary by snapping up to the nearest VMSPLIT base the
 * arch admits, so it tracks the target's split rather than this build's — among
 * the splits PAGE_OFFSET_CANDIDATES names. That qualifier is the whole caveat,
 * and it is a completeness assumption of the kind the engine deliberately
 * refuses to make: the list mirrors a Kconfig choice a vendor can extend, and
 * completeness cannot be established from inside this repo, which is why
 * Q_PAGE_OFFSET is a bracket and vmsplit_text_base emits bounds rather than an
 * equality.
 *
 * It is admissible HERE, where those are not, because the two failure modes are
 * not equivalent. On an unlisted split the snap lands on the next listed
 * boundary ABOVE the truth and the component drops a real address: lost
 * completeness, and the component simply reports nothing. Flooring at the
 * measured boundary instead would never over-floor, but the band
 * [TASK_SIZE, PAGE_OFFSET) is module text, so it would admit a module address
 * into a bound tagged as a direct-map or kernel-text region — an unsound
 * observation the engine then trusts. Over-flooring is the safe direction, so
 * the incomplete list is preferred to the complete-but-mistagging alternative.
 *
 * Trusted only from an EXACT measurement, since it gates a guaranteed-grade
 * bound. Where the arch admits a single base, or the boundary was not measured
 * exactly, the compile-time PAGE_OFFSET is the fallback: sound (never below a
 * real base), but blind to a moved split — the limitation the measurement
 * removes for every split the list does name. */
static inline unsigned long kasld_page_offset_floor(void) {
  static unsigned long cached;
  static int done;
  if (done)
    return cached;
  done = 1;
  cached = (unsigned long)PAGE_OFFSET;
#if (PAGE_OFFSET_MIN != PAGE_OFFSET_MAX) && defined(PAGE_OFFSET_CANDIDATES)
  {
    unsigned long ts = 0;
    if (kasld__ts_cached(&ts) == KASLD_TS_EXACT) {
      static const unsigned long cands[] = PAGE_OFFSET_CANDIDATES;
      unsigned long best = 0;
      int found = 0;
      unsigned int i;
      /* The lowest listed base at or above the boundary. */
      for (i = 0; i < sizeof(cands) / sizeof(cands[0]); i++)
        if (cands[i] >= ts && (!found || cands[i] < best)) {
          best = cands[i];
          found = 1;
        }
      /* No listed base is at or above the measured boundary, so the target is
       * not a kernel this list describes — a 32-bit process on a 64-bit kernel
       * reports a TASK_SIZE above every admissible split. Keep the compile-time
       * PAGE_OFFSET, which is never higher than PAGE_OFFSET_MAX and so never
       * the riskier answer. Stated rather than left to the loop's initial
       * value: a floor is the one quantity where silently choosing the highest
       * candidate is the unsafe direction. */
      if (found)
        cached = best;
    }
  }
#endif
  return cached;
}

#endif /* KASLD_KERNEL_FLOOR_H */
