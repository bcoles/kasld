// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Inference plugin: arm64 VA_BITS detection via mmap boundary probe
// (PRE_COLLECTION)
//
// On arm64, TASK_SIZE = 1UL << VA_BITS, and the kernel rejects MAP_FIXED
// mappings at or above TASK_SIZE with ENOMEM. The probe address (1UL << 48)
// sits at exactly the VA_BITS=48 TASK_SIZE boundary:
//
//   Probe fails (ENOMEM):
//     TASK_SIZE ≤ 2^48  →  VA_BITS ≤ 48
//     PAGE_OFFSET = -(1UL << VA_BITS) ≥ -(1UL << 48) = 0xffff000000000000
//     → raise page_offset_min to 0xffff000000000000
//       (eliminates the compile-time default VA_BITS=52 assumption)
//
//   Probe succeeds:
//     TASK_SIZE > 2^48  →  VA_BITS ≥ 52
//     PAGE_OFFSET = 0xfff0000000000000 (exact; PAGE_OFFSET is not randomised)
//     → lower page_offset_max to 0xfff0000000000000, pinning PAGE_OFFSET
//
// This complements va_bits_from_results (POST_COLLECTION, requires directmap
// evidence): this plugin runs at PRE_COLLECTION and produces a result
// independent of whether any component leaks a directmap address.
//
// The LAYOUT_ADJUST plugin may subsequently raise page_offset_min to
// 0xffff800000000000 for old-layout arm64 kernels (PAGE_OFFSET there is
// 0xffff800000000000, not 0xffff000000000000). That is sound: both values
// are ≥ the floor established here.
//
// VA_BITS < 48 (e.g. VA_BITS=39, 4K pages, 3-level) also fail the probe.
// PAGE_OFFSET for VA_BITS=39 is 0xffffff8000000000, which lies above
// 0xffff000000000000, so raising page_offset_min to that floor is still
// conservative (sound).
//
// Caveat: RLIMIT_AS exhaustion also returns ENOMEM from mmap. This is
// unlikely at the start of a KASLD run and is the same risk accepted by
// mmap-brute-vmsplit.c.
//
// Phase: PRE_COLLECTION — runs before any component, establishes VA_BITS
// context for downstream inference.
// ---
// <bcoles@gmail.com>

#define _GNU_SOURCE

#include "../include/kasld_inference.h"

#include <errno.h>
#include <stdio.h>
#include <sys/mman.h>

static void arm64_va_bits_mmap_run(struct kasld_analysis_ctx *ctx) {
#if defined(__aarch64__)
/* PAGE_OFFSET values for the two supported VA_BITS configurations.
 * -(1UL << 48) = 0xffff000000000000
 * -(1UL << 52) = 0xfff0000000000000 */
#define ARM64_VA48_PAGE_OFFSET 0xffff000000000000ul
#define ARM64_VA52_PAGE_OFFSET 0xfff0000000000000ul

/* Probe address: first byte beyond the VA_BITS=48 user address space.
 * VA_BITS=48: TASK_SIZE = 1UL << 48; address is outside → ENOMEM.
 * VA_BITS=52: TASK_SIZE = 1UL << 52; address is inside → mmap may succeed. */
#define ARM64_VA_PROBE_ADDR ((void *)(1UL << 48))
#define ARM64_VA_PROBE_LEN 0x1000ul

  void *p = mmap(ARM64_VA_PROBE_ADDR, ARM64_VA_PROBE_LEN, PROT_READ,
                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);

  if (p == MAP_FAILED) {
    /* Any error other than ENOMEM indicates a different failure (permissions,
     * invalid flags, etc.). Skip rather than draw incorrect conclusions. */
    if (errno != ENOMEM)
      return;

    /* VA_BITS ≤ 48 confirmed. Raise page_offset_min to the VA_BITS=48
     * PAGE_OFFSET floor, guarding against window inversion. */
    if (ARM64_VA48_PAGE_OFFSET > ctx->page_offset_min &&
        ARM64_VA48_PAGE_OFFSET <= ctx->page_offset_max) {
      if (verbose && !quiet)
        fprintf(stderr,
                "[layout] page_offset_min tightened by arm64_va_bits_mmap"
                " (VA_BITS<=48 confirmed): %#lx -> %#lx\n",
                ctx->page_offset_min, ARM64_VA48_PAGE_OFFSET);
      ctx->page_offset_min = ARM64_VA48_PAGE_OFFSET;
    }
    return;
  }

  /* mmap succeeded: VA_BITS >= 52. PAGE_OFFSET = 0xfff0000000000000 exactly.
   * Unmap the probe mapping and pin page_offset_max. */
  munmap(p, ARM64_VA_PROBE_LEN);

  if (ARM64_VA52_PAGE_OFFSET >= ctx->page_offset_min &&
      ARM64_VA52_PAGE_OFFSET < ctx->page_offset_max) {
    if (verbose && !quiet)
      fprintf(stderr,
              "[layout] page_offset_max tightened by arm64_va_bits_mmap"
              " (VA_BITS>=52 confirmed): %#lx -> %#lx\n",
              ctx->page_offset_max, ARM64_VA52_PAGE_OFFSET);
    ctx->page_offset_max = ARM64_VA52_PAGE_OFFSET;
  }

#undef ARM64_VA48_PAGE_OFFSET
#undef ARM64_VA52_PAGE_OFFSET
#undef ARM64_VA_PROBE_ADDR
#undef ARM64_VA_PROBE_LEN
#else
  (void)ctx;
#endif /* __aarch64__ */
}

static const struct kasld_inference arm64_va_bits_mmap = {
    .name = "arm64_va_bits_mmap",
    .phase = KASLD_INFER_PHASE_PRE_COLLECTION,
    .run = arm64_va_bits_mmap_run,
};

KASLD_REGISTER_INFERENCE(arm64_va_bits_mmap);
