// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Inference plugin: MemTotal physical ceiling (POST_COLLECTION)
//
// Reads MemTotal from /proc/meminfo to establish a hard upper bound on how
// far into physical memory the kernel image can reside. The kernel must fit
// entirely below phys_base + kernel_size ≤ phys_floor + MemTotal, so:
//
//   phys_base ≤ phys_floor + MemTotal - min_image_size
//
// where phys_floor is the lowest observed physical DRAM address from collected
// PHYS/DRAM results (e.g. proc-zoneinfo, sysfs_memory_blocks), falling back to
// the compile-time PHYS_OFFSET constant when no results are available.
//
// On decoupled architectures (x86-64, arm64, riscv64, s390), physical and
// virtual KASLR ranges are independent. We tighten phys_base_max directly:
//
//   phys_base_max = min(phys_base_max, phys_floor + MemTotal - MIN_IMAGE_SIZE)
//
// On coupled architectures (x86-32, MIPS32, PPC32 BookE, LoongArch), the
// virtual text base is always phys_to_virt(phys_base) + TEXT_OFFSET, so the
// same constraint maps to a virtual ceiling. On these arches PHYS_OFFSET
// always cancels out in the phys_to_virt() conversion, giving:
//
//   text_base_max = min(text_base_max,
//                       page_offset + MemTotal - MIN_IMAGE_SIZE + TEXT_OFFSET)
//
// where page_offset is the runtime-detected value from ctx->layout->page_offset
// (set by layout_adjust before POST_COLLECTION runs), not the compile-time
// constant. This matters on x86-32 where mmap-brute-vmsplit may detect a
// different vmsplit than the compile-time default.
//
// MIN_IMAGE_SIZE (4 MiB) is deliberately conservative: it is a sound lower
// bound on any production kernel image that will never exclude the true base.
// kaslr_ceiling.c already provides the tighter vmlinuz-derived estimate.
//
// Phase: POST_COLLECTION — layout_adjust must have already run to ensure
// ctx->layout->page_offset reflects the detected runtime PAGE_OFFSET.
// ---
// <bcoles@gmail.com>

#define _POSIX_C_SOURCE 200809L

#include "../include/kasld_inference.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>

/* Minimum kernel image size used as a conservative floor when computing the
 * physical ceiling. The true kernel image is always larger; using a small
 * value keeps the bound sound (never excludes the true base). */
#define MIN_IMAGE_SIZE (4UL * 1024 * 1024)

static unsigned long read_memtotal_bytes(void) {
  FILE *f = fopen("/proc/meminfo", "r");
  if (!f)
    return 0;

  unsigned long long kb = 0;
  char line[128];

  /* /proc/meminfo format: "MemTotal:    16384000 kB\n" */
  while (fgets(line, sizeof(line), f)) {
    if (sscanf(line, "MemTotal: %llu kB", &kb) == 1)
      break;
  }

  fclose(f);

  unsigned long long bytes = kb * 1024ULL;
  return (bytes > ULONG_MAX) ? ULONG_MAX : (unsigned long)bytes;
}

/* Find the lowest physical DRAM address observed in collected results.
 * Returns phys_offset_fallback when no PHYS/DRAM results are present. */
static unsigned long dram_floor(const struct kasld_analysis_ctx *ctx,
                                unsigned long phys_offset_fallback) {
  unsigned long lo = ULONG_MAX;
  for (size_t i = 0; i < ctx->result_count; i++) {
    const struct result *r = &ctx->results[i];
    if (r->type == KASLD_ADDR_PHYS &&
        strcmp(r->section, KASLD_SECTION_DRAM) == 0 && r->raw < lo)
      lo = r->raw;
  }
  return (lo == ULONG_MAX) ? phys_offset_fallback : lo;
}

static void meminfo_phys_ceiling_run(struct kasld_analysis_ctx *ctx) {
  unsigned long mem_bytes = read_memtotal_bytes();
  if (mem_bytes == 0 || mem_bytes <= MIN_IMAGE_SIZE)
    return;

  if (ctx->arch->phys_virt_decoupled) {
    /* Decoupled: tighten the physical KASLR ceiling directly.
     * Use the actual DRAM floor from collected results so that the ceiling
     * is phys_floor + MemTotal (= top of RAM), not a compile-time guess. */
    unsigned long phys_floor =
        dram_floor(ctx, ctx->arch->phys_offset);
    unsigned long ceiling = phys_floor + mem_bytes - MIN_IMAGE_SIZE;

    unsigned long phys_min = ctx->arch->phys_kaslr_base_min;
    unsigned long phys_align = ctx->arch->phys_kaslr_align;

    if (ceiling > phys_min && phys_align > 0)
      ceiling &= ~(phys_align - 1);

    if (ceiling > phys_min && ceiling < ctx->phys_base_max) {
      if (verbose && !quiet)
        fprintf(stderr,
                "[layout] phys_base_max tightened by meminfo_phys_ceiling:"
                " %#lx -> %#lx (MemTotal=%lu bytes)\n",
                ctx->phys_base_max, ceiling, mem_bytes);
      ctx->phys_base_max = ceiling;
    }
  } else {
    /* Coupled: phys_to_virt(ceiling) = page_offset + (ceiling - phys_offset)
     *        = page_offset + mem_bytes - MIN_IMAGE_SIZE.
     * text_base = phys_to_virt(phys_base) + TEXT_OFFSET, so add text_offset.
     * Use the runtime page_offset from layout (set by layout_adjust). */
    unsigned long page_offset = ctx->layout->page_offset;
    unsigned long text_offset = ctx->arch->text_offset;
    unsigned long virt_ceiling =
        page_offset + mem_bytes - MIN_IMAGE_SIZE + text_offset;

    unsigned long kaslr_min = ctx->arch->kaslr_base_min;
    unsigned long kaslr_align = ctx->arch->kaslr_align;

    if (virt_ceiling > kaslr_min && kaslr_align > 0)
      virt_ceiling &= ~(kaslr_align - 1);

    if (virt_ceiling > kaslr_min && virt_ceiling < ctx->text_base_max) {
      if (verbose && !quiet)
        fprintf(stderr,
                "[layout] text_base_max tightened by meminfo_phys_ceiling:"
                " %#lx -> %#lx (MemTotal=%lu bytes)\n",
                ctx->text_base_max, virt_ceiling, mem_bytes);
      ctx->text_base_max = virt_ceiling;
    }
  }
}

static const struct kasld_inference meminfo_phys_ceiling = {
    .name = "meminfo_phys_ceiling",
    .phase = KASLD_INFER_PHASE_POST_COLLECTION,
    .run = meminfo_phys_ceiling_run,
};

KASLD_REGISTER_INFERENCE(meminfo_phys_ceiling);
