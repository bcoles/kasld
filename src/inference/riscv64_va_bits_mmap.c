// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Inference plugin: riscv64 SATP mode detection via mmap boundary probe
// (PRE_COLLECTION)
//
// On riscv64, TASK_SIZE = 1UL << (VA_BITS - 1), and the kernel rejects
// MAP_FIXED mappings at or above TASK_SIZE with ENOMEM. Two sequential probes
// distinguish all three supported SATP modes:
//
//   Probe 1 at 1UL << 38 (SV39 TASK_SIZE boundary):
//     ENOMEM → SV39 active
//     PAGE_OFFSET is one of two known values (kernel-version dependent):
//       v6.12+:    PAGE_OFFSET_L3 = 0xffffffd600000000
//       pre-v6.12: PAGE_OFFSET_L3 = 0xffffffd800000000
//     → narrow page_offset window to [0xffffffd600000000, 0xffffffd800000000]
//       (the exact value cannot be resolved from probe alone)
//     success → SV48 or SV57; continue to probe 2.
//
//   Probe 2 at 1UL << 47 (SV48 TASK_SIZE boundary):
//     ENOMEM → SV48 active
//     PAGE_OFFSET = PAGE_OFFSET_L4 = 0xffffaf8000000000 (single stable value)
//     → pin page_offset to 0xffffaf8000000000 exactly
//     success → SV57 active
//     PAGE_OFFSET = PAGE_OFFSET_L5 = 0xff60000000000000 (single stable value)
//     → pin page_offset to 0xff60000000000000 exactly
//
// This plugin provides an independent PRE_COLLECTION constraint before any
// component runs, complementing the proc-cpuinfo.c component which reads the
// "mmu : sv*" field from /proc/cpuinfo during collection. Both may fire; the
// POST_COLLECTION inference loop converges them.
//
// Note on the SV39 window: PAGE_OFFSET_L3 changed between kernel v6.10
// (0xffffffd800000000) and v6.12 (0xffffffd600000000) when the SV39 linear
// mapping was expanded from 160 GiB to 168 GiB. Without a kernel version
// check we narrow to the range containing both values. The range is tight
// enough to be useful: from the compile-time default [0xff60000000000000, max]
// down to a 512 MiB window.
//
// Phase: PRE_COLLECTION — runs before any component, establishes SATP mode
// context for downstream inference.
// ---
// <bcoles@gmail.com>

#define _GNU_SOURCE

#include "../include/kasld_inference.h"

#include <errno.h>
#include <stdio.h>
#include <sys/mman.h>

static void riscv64_va_bits_mmap_run(struct kasld_analysis_ctx *ctx) {
#if defined(__riscv) && __riscv_xlen == 64

/* PAGE_OFFSET values from arch/riscv/include/asm/page.h */
#define RISCV_PAGE_OFFSET_SV57                                                 \
  0xff60000000000000ul /* SV57, compile-time default */
#define RISCV_PAGE_OFFSET_SV48 0xffffaf8000000000ul /* SV48 */
/* SV39 has two known values depending on kernel version (see header comment) */
#define RISCV_PAGE_OFFSET_SV39_NEW 0xffffffd600000000ul /* v6.12+ */
#define RISCV_PAGE_OFFSET_SV39_OLD 0xffffffd800000000ul /* pre-v6.12 */

/* TASK_SIZE = 1UL << (VA_BITS - 1) for each mode */
#define RISCV_TASK_SIZE_SV39 ((void *)(1UL << 38))
#define RISCV_TASK_SIZE_SV48 ((void *)(1UL << 47))
#define RISCV_PROBE_LEN 0x1000ul

  /* --- Probe 1: SV39 boundary (1 << 38) --- */
  void *p1 = mmap(RISCV_TASK_SIZE_SV39, RISCV_PROBE_LEN, PROT_READ,
                  MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);

  if (p1 == MAP_FAILED) {
    if (errno != ENOMEM)
      return; /* unexpected error — skip */

    /* SV39: PAGE_OFFSET ∈ [RISCV_PAGE_OFFSET_SV39_NEW,
     * RISCV_PAGE_OFFSET_SV39_OLD]. */
    unsigned long new_min = RISCV_PAGE_OFFSET_SV39_NEW;
    unsigned long new_max = RISCV_PAGE_OFFSET_SV39_OLD;

    if (new_min > ctx->page_offset_min && new_min <= ctx->page_offset_max) {
      if (verbose && !quiet)
        fprintf(stderr,
                "[layout] page_offset_min tightened by riscv64_va_bits_mmap"
                " (SV39 confirmed): %#lx -> %#lx\n",
                ctx->page_offset_min, new_min);
      ctx->page_offset_min = new_min;
    }
    if (new_max < ctx->page_offset_max && new_max >= ctx->page_offset_min) {
      if (verbose && !quiet)
        fprintf(stderr,
                "[layout] page_offset_max tightened by riscv64_va_bits_mmap"
                " (SV39 confirmed): %#lx -> %#lx\n",
                ctx->page_offset_max, new_max);
      ctx->page_offset_max = new_max;
    }
    return;
  }

  munmap(p1, RISCV_PROBE_LEN);

  /* --- Probe 2: SV48 boundary (1 << 47) --- */
  void *p2 = mmap(RISCV_TASK_SIZE_SV48, RISCV_PROBE_LEN, PROT_READ,
                  MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);

  if (p2 == MAP_FAILED) {
    if (errno != ENOMEM)
      return;

    /* SV48: PAGE_OFFSET = 0xffffaf8000000000 exactly. Pin both bounds. */
    unsigned long po = RISCV_PAGE_OFFSET_SV48;

    if (po < ctx->page_offset_min || po > ctx->page_offset_max)
      return; /* out of current window — do not invert */

    if (po > ctx->page_offset_min) {
      if (verbose && !quiet)
        fprintf(stderr,
                "[layout] page_offset_min tightened by riscv64_va_bits_mmap"
                " (SV48 confirmed): %#lx -> %#lx\n",
                ctx->page_offset_min, po);
      ctx->page_offset_min = po;
    }
    if (po < ctx->page_offset_max) {
      if (verbose && !quiet)
        fprintf(stderr,
                "[layout] page_offset_max tightened by riscv64_va_bits_mmap"
                " (SV48 confirmed): %#lx -> %#lx\n",
                ctx->page_offset_max, po);
      ctx->page_offset_max = po;
    }
    return;
  }

  munmap(p2, RISCV_PROBE_LEN);

  /* SV57: PAGE_OFFSET = 0xff60000000000000 exactly. Pin both bounds. */
  unsigned long po57 = RISCV_PAGE_OFFSET_SV57;

  if (po57 < ctx->page_offset_min || po57 > ctx->page_offset_max)
    return; /* out of current window — do not invert */

  if (po57 > ctx->page_offset_min) {
    if (verbose && !quiet)
      fprintf(stderr,
              "[layout] page_offset_min tightened by riscv64_va_bits_mmap"
              " (SV57 confirmed): %#lx -> %#lx\n",
              ctx->page_offset_min, po57);
    ctx->page_offset_min = po57;
  }
  if (po57 < ctx->page_offset_max) {
    if (verbose && !quiet)
      fprintf(stderr,
              "[layout] page_offset_max tightened by riscv64_va_bits_mmap"
              " (SV57 confirmed): %#lx -> %#lx\n",
              ctx->page_offset_max, po57);
    ctx->page_offset_max = po57;
  }

#undef RISCV_PAGE_OFFSET_SV57
#undef RISCV_PAGE_OFFSET_SV48
#undef RISCV_PAGE_OFFSET_SV39_NEW
#undef RISCV_PAGE_OFFSET_SV39_OLD
#undef RISCV_TASK_SIZE_SV39
#undef RISCV_TASK_SIZE_SV48
#undef RISCV_PROBE_LEN
#else
  (void)ctx;
#endif /* riscv64 */
}

static const struct kasld_inference riscv64_va_bits_mmap = {
    .name = "riscv64_va_bits_mmap",
    .phase = KASLD_INFER_PHASE_PRE_COLLECTION,
    .run = riscv64_va_bits_mmap_run,
};

KASLD_REGISTER_INFERENCE(riscv64_va_bits_mmap);
