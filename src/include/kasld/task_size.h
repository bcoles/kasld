// This file is part of KASLD - https://github.com/bcoles/kasld
//
// TASK_SIZE — the user/kernel address-space boundary — measured by mmap.
//
// mmap refuses any address at or above TASK_SIZE, so the boundary is
// measurable from an unprivileged process: binary-search between an address the
// kernel itself handed out (mappable, therefore below the boundary) and the top
// page of the address space, and the search converges on TASK_SIZE itself in
// about twenty probes.
//
// This header MEASURES and nothing else. It emits no observation, decides no
// confidence tier and names no region, because two callers want the same number
// for different purposes and only one of them may publish it: the engine counts
// distinct origins as independent corroboration, so a second publisher of one
// identical probe would manufacture agreement out of a single measurement.
// `mmap_brute_vmsplit` is the source of record; `kernel_floor.h` takes the same
// number for a local decision without emitting.
//
// TASK_SIZE is not PAGE_OFFSET. It equals it only where the architecture leaves
// no gap (x86_32); elsewhere the linear map starts above it, by 16 MiB on arm32
// and by the whole fixmap/PCI-IO/vmemmap stack on riscv32. Callers that want
// the linear-map base must apply their architecture's relation themselves.
//
// 32-bit only. On 64-bit the two halves of the address space are astronomically
// far apart, the top page of the address space is not past any boundary, and
// there is no search worth running.
// ---
// <bcoles@gmail.com>

#ifndef KASLD_TASK_SIZE_H
#define KASLD_TASK_SIZE_H

#include "include/kasld/api.h"

#include <errno.h>
#include <limits.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

/* The granularity every VMSPLIT boundary in mainline is a multiple of, and so
 * the step the coarse fallback sweeps in. */
#define KASLD_VMSPLIT_STRIDE 0x10000000ul

/* Steps of the check that nothing maps above the located boundary; each step
 * samples at two scales. */
#define KASLD_TS_ABOVE_SAMPLES 8

/* KASLD_TS_EXACT — the boundary is located to page granularity and nothing maps
 *   above it. This is TASK_SIZE.
 * KASLD_TS_APPROX — located by hint placement on a pre-v4.17 kernel, on the
 *   256 MiB stride. The value is the first stride that would not map, so it is
 *   at or ABOVE TASK_SIZE.
 * KASLD_TS_POROUS — located, but something above it still maps, so the address
 *   is the bottom of a gap rather than the boundary. At or BELOW TASK_SIZE.
 * The two directions matter: a value below the boundary is safe to treat as a
 * floor and unsound as an upper bound, and a value above it is the reverse. */
enum kasld_ts_status {
  KASLD_TS_EXACT = 0,
  KASLD_TS_APPROX = 1,
  KASLD_TS_POROUS = 2,
  KASLD_TS_NOT_FOUND = 3,
  KASLD_TS_UNRELIABLE = 4
};

/* One probe of a candidate address: 1 below the boundary, 0 at or above it, -1
 * when the answer cannot be trusted. The two functions below are the pure
 * search and gap-detection logic; they take the probe as a callback so the
 * algorithm is exercised on its own — the live probe (kasld__ts_step,
 * mmap-backed, 32-bit only) in production, a synthetic address space in tests.
 * Kept out of the !LP64 gate for that reason: the logic is width-agnostic, only
 * the mmap layer is 32-bit. */
typedef int (*kasld_ts_step_fn)(unsigned long addr, unsigned long len);

/* Binary-search the lowest address that will not map, between `lo` (known
 * below) and `hi` (known at or above). Both are page-aligned, so every midpoint
 * is too. Halving a 32-bit space at page granularity takes about twenty
 * probes. */
static inline enum kasld_ts_status
kasld__ts_search(kasld_ts_step_fn step, unsigned long lo, unsigned long hi,
                 unsigned long len, unsigned long *out) {
  while (hi - lo > len) {
    unsigned long mid = lo + (((hi - lo) / 2) & ~(len - 1));
    int r = step(mid, len);
    if (r < 0)
      return KASLD_TS_UNRELIABLE;
    if (r)
      lo = mid;
    else
      hi = mid;
  }
  *out = hi;
  return KASLD_TS_EXACT;
}

/* TASK_SIZE is the address above which NOTHING maps. One unmappable page is
 * weaker than that: an architecture with a gap below the boundary would present
 * the bottom of the gap, and a bound taken from there sits below the truth.
 *
 * A gap has mappable space above it and the boundary does not, so sampling
 * above the candidate tells them apart. Each step samples at two scales — a
 * fraction of the whole range above the candidate, and a small multiple of the
 * page size just above it — because a band of mappable space is only found by a
 * sample that lands in it, and the band could be either wide or a few pages.
 *
 * Returns 1 when every sample refuses, 0 when one maps, -1 when a sample is
 * uninformative. Refusal at every sample is evidence, not proof; it is the
 * check that catches an unmodelled layout, while what makes the boundary
 * trustworthy on the architectures in scope is that a page-aligned private
 * anonymous request has no other reason to fail below it. */
static inline int kasld__ts_nothing_above(kasld_ts_step_fn step,
                                          unsigned long split,
                                          unsigned long len,
                                          unsigned long ceiling) {
  unsigned long span = ceiling - split;
  int k, j;

  for (k = 0; k < KASLD_TS_ABOVE_SAMPLES; k++) {
    unsigned long at[2];
    at[0] = split + (span >> (k + 1));
    at[1] = ((len << k) <= span) ? split + (len << k) : split;

    for (j = 0; j < 2; j++) {
      unsigned long a = at[j] & ~(len - 1);
      int r;
      if (a <= split || a > ceiling)
        continue; /* the range is narrower than this sample's spacing */
      r = step(a, len);
      if (r < 0)
        return -1;
      if (r)
        return 0;
    }
  }
  return 1;
}

#if !defined(__LP64__) && !defined(_LP64)

/* The page size the KERNEL is enforcing, which is what decides whether a probe
 * address is aligned. The api.h constant is 4 KiB; arm32, mips and ppc32 build
 * kernels with 16 or 64 KiB pages, and a probe misaligned against the real page
 * size is refused with EINVAL — indistinguishable from being past the boundary,
 * and so an answer far below the truth. */
static inline unsigned long kasld__ts_probe_len(void) {
  long v = sysconf(_SC_PAGESIZE);
  return (v > 0) ? (unsigned long)v : KASLD_LAYOUT_GRANULE;
}

/* Probe one page, without ever displacing a live mapping.
 *
 * Returns 1 if `addr` lies below TASK_SIZE, 0 if it lies at or above it, and
 * -1 if the answer cannot be trusted.
 *
 * MAP_FIXED_NOREPLACE, not MAP_FIXED. The forcible flag does not fail on a
 * collision — it DESTROYS whatever is mapped there, silently, and the loss
 * surfaces later somewhere unrelated. The search walks the whole user address
 * space, including the range the kernel loads a PIE executable into, so the
 * process doing the probing is among the things it can unmap. NOREPLACE also
 * answers the question more precisely: EEXIST says the address is occupied and
 * therefore below TASK_SIZE, which a plain failure could not distinguish from
 * being past the boundary.
 *
 * What a page-aligned MAP_PRIVATE|MAP_ANONYMOUS request can fail on, and how
 * each outcome is handled here:
 *
 *   addr > TASK_SIZE - len     generic    ENOMEM   the boundary being measured
 *   TASK_SIZE - len < addr     mips       EINVAL   the same boundary, reported
 *                                                  with a different errno, so
 *                                                  EINVAL must also read as
 *                                                  "beyond"
 *   offset_in_page(addr)       generic    EINVAL   indistinguishable from the
 *                                                  two above; avoided by
 *                                                  aligning every probe to the
 *                                                  runtime page size
 *   MAP_SHARED cache aliasing  arm, mips  EINVAL   avoided: MAP_PRIVATE only
 *   addr < FIRST_USER_ADDRESS  arm        EINVAL   the bottom two pages, which
 *                                                  mmap_min_addr already blocks
 *                                                  and the search never visits
 *   security_mmap_addr()       generic    EPERM    vm.mmap_min_addr — declined
 *   RLIMIT_AS, max_map_count   generic    ENOMEM   address-independent, so the
 *                                                  anchor detects it
 *   occupied                   NOREPLACE  EEXIST   occupied, therefore BELOW
 *
 * Only ENOMEM and EINVAL mean "beyond". Every other errno is uninformative,
 * and a too-low answer would exclude the truth from the guaranteed window. */
static inline int kasld__ts_step(unsigned long addr, unsigned long len) {
  void *want = (void *)addr;
  void *p = mmap(want, len, PROT_NONE,
                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
  if (p == want) {
    munmap(p, len);
    return 1;
  }
  if (p != MAP_FAILED) {
    munmap(p, len);
    return -1; /* displaced: the flag was not honoured after all */
  }
  if (errno == EEXIST)
    return 1; /* occupied, so the address exists below TASK_SIZE */
  if (errno == ENOMEM || errno == EINVAL)
    return 0; /* at or above the boundary */
  return -1;  /* mmap_min_addr, seccomp, something unmodelled */
}

/* One step on a kernel that predates MAP_FIXED_NOREPLACE (< v4.17).
 *
 * There the flag is an unknown bit and mmap ignores it, so the request is a
 * plain hint — which is honoured exactly when the address is both free and
 * below TASK_SIZE, and otherwise satisfied somewhere else entirely. A plain
 * hint never displaces a live mapping, so this is safe; it is simply less
 * informative, because a displaced result means "occupied" OR "past the
 * boundary" and nothing says which. That ambiguity is why the hint path stays
 * on the 256 MiB stride: at page granularity every occupied page in the heap,
 * the libraries and the stack reads as a boundary.
 *
 * Measured on a 4.14 kernel with a 3G split: every 256 MiB boundary from
 * 0x10000000 to 0xb0000000 came back at the requested address and 0xc0000000
 * onwards was displaced, so the transition does land on the split. The
 * ambiguity is real but narrow — it needs a mapping to sit exactly on a 256 MiB
 * boundary — and it is resolved by probing the pages just above: an occupied
 * boundary has free neighbours below TASK_SIZE, whereas nothing above the
 * boundary can be mapped at all.
 *
 * Returns 1 for below TASK_SIZE, 0 for at or above it. */
static inline int kasld__ts_step_hint(unsigned long addr, unsigned long len) {
  int k;
  for (k = 0; k < 4; k++) {
    void *want = (void *)(addr + (unsigned long)k * len);
    void *p = mmap(want, len, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED)
      continue;
    munmap(p, len);
    if (p == want)
      return 1; /* honoured here, so the region is below TASK_SIZE */
  }
  return 0;
}

/* Does this kernel honour MAP_FIXED_NOREPLACE?
 *
 * Asked of an address that is certainly occupied — the page this object is on.
 * v4.17+ refuses with EEXIST; an older kernel has no such flag, treats the
 * request as a hint, finds the address taken and satisfies it elsewhere. The
 * probe cannot damage anything either way: NOREPLACE never displaces, and a
 * hint is not binding. */
static char kasld__ts_anchor_obj; /* a definitely-mapped page of our own */

static inline int kasld__ts_noreplace_honoured(unsigned long len) {
  unsigned long self = (unsigned long)&kasld__ts_anchor_obj & ~(len - 1);
  void *want = (void *)self;
  void *p = mmap(want, len, PROT_NONE,
                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
  if (p == MAP_FAILED)
    return errno == EEXIST;
  munmap(p, len);
  return 0;
}

/* An address the kernel chose itself, which is therefore below TASK_SIZE and
 * free to map again once released.
 *
 * Taking the anchor this way rather than guessing one settles the failure that
 * no single probe can: RLIMIT_AS and max_map_count refuse at EVERY address, so
 * a process against either limit reports a boundary wherever it starts looking.
 * A request the kernel satisfies proves neither is binding. Returns 0 if even
 * that fails. */
static inline unsigned long kasld__ts_anchor(unsigned long len) {
  void *p = mmap(NULL, len, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  unsigned long a;
  if (p == MAP_FAILED)
    return 0;
  a = (unsigned long)p;
  munmap(p, len);
  return a;
}

/* Sweep the low 32-bit address space in 256 MiB steps, for kernels that do not
 * honour MAP_FIXED_NOREPLACE. Sets *out to the first step that will not map. */
static inline enum kasld_ts_status kasld__ts_coarse(unsigned long len,
                                                    unsigned long *out) {
  unsigned long i;

  for (i = KASLD_VMSPLIT_STRIDE; i < 0xf0000000ul; i += KASLD_VMSPLIT_STRIDE) {
    if (!kasld__ts_step_hint(i, len)) {
      *out = i;
      return KASLD_TS_APPROX;
    }
  }
  return KASLD_TS_NOT_FOUND;
}

/* Locate the boundary. Pure: no output, no globals. It runs in a forked child
 * (see kasld_task_size_probe), so anything it printed would interleave with the
 * caller's own stream, which for a component is a format the orchestrator
 * parses. The caller reports. */
static inline enum kasld_ts_status kasld__ts_locate(unsigned long *out) {
  unsigned long len = kasld__ts_probe_len();
  unsigned long anchor, ceiling;
  enum kasld_ts_status st;

  if (!kasld__ts_noreplace_honoured(len))
    return kasld__ts_coarse(len, out);

  anchor = kasld__ts_anchor(len);
  if (!anchor)
    return KASLD_TS_UNRELIABLE;

  /* The highest page of the address space. TASK_SIZE is below 4 GiB on every
   * 32-bit kernel, so this page is always past it and always free. */
  ceiling = ULONG_MAX & ~(len - 1);
  if (anchor >= ceiling || kasld__ts_step(ceiling, len) != 0)
    return KASLD_TS_UNRELIABLE;

  st = kasld__ts_search(kasld__ts_step, anchor, ceiling, len, out);
  if (st != KASLD_TS_EXACT)
    return st;

  /* Re-take the anchor. A limit reached partway through the search would turn
   * every later probe into a refusal and drag the answer down with it; an
   * anchor that still maps afterwards proves the refusals were the boundary. */
  if (kasld__ts_step(anchor, len) != 1)
    return KASLD_TS_UNRELIABLE;

  switch (kasld__ts_nothing_above(kasld__ts_step, *out, len, ceiling)) {
  case 1:
    return KASLD_TS_EXACT;
  case 0:
    return KASLD_TS_POROUS;
  default:
    return KASLD_TS_UNRELIABLE;
  }
}

#endif /* 32-bit */

/* Measure the boundary, in a CHILD process.
 *
 * An address-space probe that can be wrong about where it may write is a hazard
 * to the process running it, and no caller can know which kernel it is on until
 * it has already probed. Doing the search in a child makes that irrelevant:
 * whatever becomes of the child's address space, the calling process still has
 * its own, and a child that dies is just a probe that declines. Cheap — one
 * fork, and about twenty mmap calls. */
static inline enum kasld_ts_status kasld_task_size_probe(unsigned long *out) {
#if defined(__LP64__) || defined(_LP64)
  (void)out;
  return KASLD_TS_UNRELIABLE;
#else
  unsigned long v[2] = {KASLD_TS_UNRELIABLE, 0};
  int fds[2];
  pid_t pid;
  ssize_t got;
  int status = 0;

  if (pipe(fds) != 0)
    return KASLD_TS_UNRELIABLE;
  pid = fork();
  if (pid < 0) {
    close(fds[0]);
    close(fds[1]);
    return KASLD_TS_UNRELIABLE;
  }
  if (pid == 0) {
    close(fds[0]);
    enum kasld_ts_status st = kasld__ts_locate(&v[1]);
    v[0] = (unsigned long)st;
    if (write(fds[1], v, sizeof(v)) != (ssize_t)sizeof(v))
      _exit(1);
    close(fds[1]);
    _exit(0);
  }

  close(fds[1]);
  got = read(fds[0], v, sizeof(v));
  close(fds[0]);
  while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
    ;
  if (got != (ssize_t)sizeof(v))
    return KASLD_TS_UNRELIABLE; /* child died before reporting */

  *out = v[1];
  return (enum kasld_ts_status)v[0];
#endif
}

#endif /* KASLD_TASK_SIZE_H */
