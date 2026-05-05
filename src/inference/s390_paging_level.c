// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Inference plugin: s390 paging level detection via mmap boundary probe
// (PRE_COLLECTION)
//
// On s390x the user ASCE (Address Space Control Element) limit equals the
// kernel's page-table level:
//
//   3-level paging: asce_limit = _REGION2_SIZE = 1 << 42 = 4 TiB
//   4-level paging: asce_limit = _REGION1_SIZE = 1 << 53 = 8 PiB
//
// The kernel KASLR range is [vmax - KASLR_LEN, vmax) where vmax = asce_limit.
// So text_base_max < vmax. Detecting the paging level with a single mmap
// probe constrains text_base_max:
//
//   Probe fails (ENOMEM):
//     3-level paging  →  vmax = 4 TiB
//     text_base_max = min(text_base_max, 4 TiB)
//     (eliminates the default 8 PiB assumption, a 2048× reduction)
//
//   Probe succeeds:
//     4-level paging  →  vmax = 8 PiB  (no change; KERNEL_BASE_MAX already 8
//     PiB)
//
// The probe address (1UL << 42) is the first byte at or above the 3-level
// ASCE limit. Mapping it fails on 3-level (address > asce_limit) and
// succeeds on 4-level (address within user range).
//
// Note: s390 does not use a traditional kernel/user address space split.
// Both kernel and user share the same virtual addresses via separate ASCEs.
// mmap() allocates in the user ASCE, so the ASCE limit governs the probe.
//
// References:
//   arch/s390/boot/startup.c: vmax = adjust_to_uv_max(asce_limit)
//   arch/s390/include/asm/pgtable.h: _REGION1_SIZE, _REGION2_SIZE
//   arch/s390/mm/init.c: TASK_SIZE determination
//
// Phase: PRE_COLLECTION — runs before any component, establishes vmax context
// for downstream inference.
// ---
// <bcoles@gmail.com>

#define _GNU_SOURCE

#include "../include/kasld_inference.h"

#include <errno.h>
#include <stdio.h>
#include <sys/mman.h>

static void s390_paging_level_run(struct kasld_analysis_ctx *ctx) {
#if defined(__s390x__)
/* _REGION2_SIZE = 1 << 42 (4 TiB): the 3-level ASCE limit and KASLR vmax. */
#define S390_3LEVEL_VMAX (1UL << 42)

/* Probe address: first byte at the 3-level ASCE limit.
 * 3-level: asce_limit = 1 << 42; this address is outside → ENOMEM.
 * 4-level: asce_limit = 1 << 53; this address is inside → mmap succeeds. */
#define S390_PROBE_ADDR ((void *)(1UL << 42))
#define S390_PROBE_LEN 0x1000ul

  void *p = mmap(S390_PROBE_ADDR, S390_PROBE_LEN, PROT_READ,
                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);

  if (p == MAP_FAILED) {
    /* Any error other than ENOMEM indicates a different failure. Skip. */
    if (errno != ENOMEM)
      return;

    /* 3-level paging: vmax = 4 TiB. Tighten text_base_max. */
    unsigned long ceiling = S390_3LEVEL_VMAX;
    unsigned long kaslr_align = ctx->arch->kaslr_align;
    if (kaslr_align > 0)
      ceiling &= ~(kaslr_align - 1);

    if (ceiling > ctx->text_base_min && ceiling < ctx->text_base_max) {
      if (verbose && !quiet)
        fprintf(stderr,
                "[layout] text_base_max tightened by s390_paging_level"
                " (3-level paging, vmax=4TiB): %#lx -> %#lx\n",
                ctx->text_base_max, ceiling);
      ctx->text_base_max = ceiling;
    }
    return;
  }

  /* mmap succeeded: 4-level paging. vmax = 8 PiB = current KERNEL_BASE_MAX.
   * No bound change needed; unmap the probe mapping. */
  munmap(p, S390_PROBE_LEN);

#undef S390_3LEVEL_VMAX
#undef S390_PROBE_ADDR
#undef S390_PROBE_LEN
#else
  (void)ctx;
#endif /* __s390x__ */
}

static const struct kasld_inference s390_paging_level = {
    .name = "s390_paging_level",
    .phase = KASLD_INFER_PHASE_PRE_COLLECTION,
    .run = s390_paging_level_run,
};

KASLD_REGISTER_INFERENCE(s390_paging_level);
