// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Inference plugin: PPC32 BookE physical KASLR ceiling (PRE_COLLECTION)
//
// On PPC32 BookE (Freescale e500/e500mc), arch/powerpc/mm/nohash/kaslr_booke.c
// restricts physical slot selection to:
//
//   linear_sz = min(MemTotal, 512 MiB)
//   nr_pos    = linear_sz / SZ_64M
//
// Regardless of installed RAM, no slot is selected at or above 512 MiB
// physical. PPC32 has PHYS_OFFSET = 0 and TEXT_OFFSET = 0, so:
//
//   text_base = PAGE_OFFSET + phys_base < PAGE_OFFSET + linear_sz
//
// This plugin tightens text_base_max using linear_sz:
//
//   text_base_max = min(text_base_max,
//                       PAGE_OFFSET + min(MemTotal, 512 MiB) − MIN_IMAGE_SIZE)
//
// PAGE_OFFSET = KASLR_BASE_MIN is used directly; PPC32 BookE has no vmsplit
// (PAGE_OFFSET is compile-time fixed at 0xc0000000), so PRE_COLLECTION is
// correct — no need to wait for layout_adjust.
//
// KASLR-disabled detection: if MemTotal < 64 MiB, nr_pos = 0 and the kernel
// loads at KERNEL_TEXT_DEFAULT without randomisation. When detected, the
// analysis context is bilaterally pinned.
//
// Note: meminfo_phys_ceiling.c (POST_COLLECTION) also reads MemTotal for
// coupled arches but does not apply the 512 MiB cap. On systems with
// MemTotal > 512 MiB that plugin's bound is too loose; this one is tighter.
//
// Applicable: PPC32 BookE only.
// ---
// <bcoles@gmail.com>

#define _POSIX_C_SOURCE 200809L

#include "../include/kasld_inference.h"

#include <limits.h>
#include <stdio.h>

#if defined(__powerpc__) && !defined(__powerpc64__)

/* BookE KASLR physical window ceiling and minimum linear memory requirement. */
#define BOOKE_PHYS_KASLR_MAX (512UL * 1024 * 1024)
#define BOOKE_KASLR_MIN_RAM (64UL * 1024 * 1024)

/* Conservative minimum kernel image size — never excludes a valid base. */
#define MIN_IMAGE_SIZE (4UL * 1024 * 1024)

static unsigned long read_memtotal_bytes(void) {
  FILE *f = fopen("/proc/meminfo", "r");
  if (!f)
    return 0;

  unsigned long long kb = 0;
  char line[128];

  while (fgets(line, sizeof(line), f)) {
    if (sscanf(line, "MemTotal: %llu kB", &kb) == 1)
      break;
  }

  fclose(f);

  unsigned long long bytes = kb * 1024ULL;
  return (bytes > ULONG_MAX) ? ULONG_MAX : (unsigned long)bytes;
}

#endif /* defined(__powerpc__) && !defined(__powerpc64__) */

static void ppc32_booke_phys_ceiling_run(struct kasld_analysis_ctx *ctx) {
#if defined(__powerpc__) && !defined(__powerpc64__)

  unsigned long mem_bytes = read_memtotal_bytes();
  if (mem_bytes == 0)
    return;

  /* KASLR disabled: nr_pos = linear_sz / SZ_64M == 0 when MemTotal < 64 MiB.
   * The kernel loads at the compile-time default address. Bilateral pin. */
  if (mem_bytes < BOOKE_KASLR_MIN_RAM) {
    unsigned long def = (unsigned long)KERNEL_TEXT_DEFAULT;
    if (def < ctx->text_base_min || def > ctx->text_base_max)
      return;
    if (verbose && !quiet)
      fprintf(stdout,
              "[infer] text_base pinned by ppc32_booke_phys_ceiling:"
              " [%#lx, %#lx] -> %#lx"
              " (MemTotal=%lu MiB < 64 MiB, KASLR disabled)\n",
              ctx->text_base_min, ctx->text_base_max, def, mem_bytes >> 20);
    ctx->text_base_min = def;
    ctx->text_base_max = def;
    return;
  }

  /* Physical range: [0, min(MemTotal, 512 MiB)).
   * PHYS_OFFSET = 0 → text_base = PAGE_OFFSET + phys_base.
   * PAGE_OFFSET = KASLR_BASE_MIN (fixed; no vmsplit on PPC32 BookE). */
  unsigned long cap =
      mem_bytes < BOOKE_PHYS_KASLR_MAX ? mem_bytes : BOOKE_PHYS_KASLR_MAX;

  if (cap <= MIN_IMAGE_SIZE)
    return;

  unsigned long kaslr_min = ctx->arch->kaslr_base_min;
  unsigned long kaslr_align = ctx->arch->kaslr_align;

  unsigned long virt_ceiling = kaslr_min + cap - MIN_IMAGE_SIZE;

  if (kaslr_align > 0 && virt_ceiling > kaslr_min)
    virt_ceiling &= ~(kaslr_align - 1);

  if (virt_ceiling > kaslr_min && virt_ceiling < ctx->text_base_max) {
    if (verbose && !quiet)
      fprintf(stdout,
              "[infer] text_base_max tightened by ppc32_booke_phys_ceiling:"
              " %#lx -> %#lx (MemTotal=%lu MiB cap=%lu MiB)\n",
              ctx->text_base_max, virt_ceiling, mem_bytes >> 20, cap >> 20);
    ctx->text_base_max = virt_ceiling;
  }

#else
  (void)ctx;
#endif /* defined(__powerpc__) && !defined(__powerpc64__) */
}

static const struct kasld_inference ppc32_booke_phys_ceiling = {
    .name = "ppc32_booke_phys_ceiling",
    .phase = KASLD_INFER_PHASE_PRE_COLLECTION,
    .run = ppc32_booke_phys_ceiling_run,
};

KASLD_REGISTER_INFERENCE(ppc32_booke_phys_ceiling);
