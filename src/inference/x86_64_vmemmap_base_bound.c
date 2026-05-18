// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Inference plugin: vmalloc_base + VMALLOC_SIZE_TB → vmemmap_base bounds
// (POST_COLLECTION)
//
// On x86_64 with CONFIG_RANDOMIZE_MEMORY, kernel_randomize_memory() places
// the three memory KASLR regions consecutively, each separated by a random
// PUD-aligned gap of at least PUD_SIZE (1 GiB):
//
//   kaslr_regions[0]: directmap  — base = page_offset_base
//                                  size = directmap_size_tb * 1 TiB
//   kaslr_regions[1]: vmalloc    — base = page_offset_base + directmap_size_tb
//                                         * 1 TiB + (>= PUD_SIZE)
//                                  size = VMALLOC_SIZE_TB * 1 TiB
//   kaslr_regions[2]: vmemmap    — base = vmalloc_base + VMALLOC_SIZE_TB
//                                         * 1 TiB + (>= PUD_SIZE)
//                                  size = directmap_size_tb * 64 / PAGE_SIZE
//                                  TiB
//
// Therefore:
//
//   vmemmap_base_min = vmalloc_base_min + VMALLOC_SIZE_TB * 1 TiB + PUD_SIZE
//   vmemmap_base_max = CPU_ENTRY_AREA_BASE − vmemmap_size
//
// This is a continuation of x86_64_vmalloc_base_bound.c — together the two
// plugins chain page_offset_base → vmalloc_base → vmemmap_base via the
// fixed inter-region ordering.
//
// VMALLOC_SIZE_TB:
//   L4 paging: 32 TiB  (kernel constant VMALLOC_SIZE_TB_L4)
//   L5 paging: 12800 TiB
//   Detected via page_offset_min: < L4 VAS floor (0xffff800000000000) → L5,
//   else L4.
//
// CPU_ENTRY_AREA_BASE: 0xfffffe0000000000 on both L4 and L5 (computed as
// -4 << P4D_SHIFT where P4D_SHIFT = 39).
//
// vmemmap_size: derived from max_pfn read from /proc/zoneinfo:
//   vmemmap_size = directmap_size_tb * 64 / 4096 TiB
//   (each PAGE_SIZE page maps to a 64-byte struct page in vmemmap)
//   Rounded up to whole TiB to match kernel_randomize_memory's vmemmap_size
//   alignment.
//
// Source data: shared with x86_64_vmalloc_base_bound.c (max_pfn from
// /proc/zoneinfo). Duplicate parse rather than introduce a shared helper —
// keeps each plugin self-contained.
//
// Phase: POST_COLLECTION — requires vmalloc_base_min from
//        x86_64_vmalloc_base_bound.c (which itself requires page_offset_min
//        from directmap_page_offset_bounds / randomize_memory_page_offset /
//        phys_virt_synth).
// Applicable: x86-64 only.
// ---
// <bcoles@gmail.com>

#define _POSIX_C_SOURCE 200809L

#include "../include/kasld/inference.h"

#include <limits.h>
#include <stdio.h>

#define TB_SHIFT 40
#define PUD_SHIFT 30
#define PAGE_SHIFT 12

/* See x86_64_vmalloc_base_bound.c for the padding rationale. */
#define RANDOMIZE_MEMORY_PHYSICAL_PADDING 10ul

/* CPU_ENTRY_AREA_BASE = -4 << P4D_SHIFT = 0xfffffe0000000000 on x86-64
 * (L4 and L5). Same value on both paging modes — the CPU_ENTRY_AREA_PGD
 * slot is anchored relative to the top of canonical-high. */
#define CPU_ENTRY_AREA_BASE 0xfffffe0000000000ul

/* VMALLOC_SIZE_TB from arch/x86/include/asm/pgtable_64_types.h. */
#define VMALLOC_SIZE_TB_L4 32ul
#define VMALLOC_SIZE_TB_L5 12800ul

/* The L4 vs L5 boundary: __PAGE_OFFSET_BASE_L4 is at 0xffff888000000000.
 * Any page_offset below the L4 VAS start (0xffff800000000000) is L5. */
#define X86_64_L4_VAS_START 0xffff800000000000ul

/* Read max_pfn from /proc/zoneinfo (same logic as
 * x86_64_vmalloc_base_bound.c — kept inline to avoid a shared helper). */
static unsigned long read_max_pfn(void) {
  FILE *f = fopen("/proc/zoneinfo", "r");
  if (!f)
    return 0;

  char line[256];
  unsigned long max_pfn = 0;
  unsigned long cur_spanned = 0;

  while (fgets(line, sizeof(line), f)) {
    unsigned long val;
    if (sscanf(line, " spanned %lu", &val) == 1) {
      cur_spanned = val;
      continue;
    }
    if (sscanf(line, "  start_pfn: %lu", &val) != 1)
      continue;
    unsigned long end_pfn = cur_spanned ? val + cur_spanned : val;
    if (end_pfn > max_pfn)
      max_pfn = end_pfn;
    cur_spanned = 0;
  }
  fclose(f);
  return max_pfn;
}

static void x86_64_vmemmap_base_bound_run(struct kasld_analysis_ctx *ctx) {
#if defined(__x86_64__)
  /* Needs vmalloc_base_min already pinned by x86_64_vmalloc_base_bound. */
  if (ctx->vmalloc_base_min == 0)
    return;

  unsigned long pud_size = 1ul << PUD_SHIFT;
  unsigned long one_tb = 1ul << TB_SHIFT;

  /* Detect paging mode from page_offset_min: L5 if below L4 VAS floor. */
  unsigned long vmalloc_size_tb =
      (ctx->page_offset_min != 0 && ctx->page_offset_min < X86_64_L4_VAS_START)
          ? VMALLOC_SIZE_TB_L5
          : VMALLOC_SIZE_TB_L4;

  /* ---- Lower bound on vmemmap_base ----
   * vmemmap_base >= vmalloc_base + VMALLOC_SIZE_TB * 1 TiB + PUD_SIZE.
   * Use vmalloc_base_min (the tightest lower bound we have). */
  unsigned long lower =
      ctx->vmalloc_base_min + vmalloc_size_tb * one_tb + pud_size;

  /* Overflow / sanity: result must fit below CPU_ENTRY_AREA_BASE. */
  if (lower <= ctx->vmalloc_base_min || lower >= CPU_ENTRY_AREA_BASE)
    return;

  if (lower > ctx->vmemmap_base_min) {
    if (verbose && !quiet && !json_output)
      printf("[infer] vmemmap_base_min: %#lx  "
             "(vmalloc_base_min %#lx + %lu TiB vmalloc + 1 GiB gap)\n",
             lower, ctx->vmalloc_base_min, vmalloc_size_tb);
    ctx->vmemmap_base_min = lower;
  }

  /* ---- Upper bound on vmemmap_base ----
   * vmemmap_base <= CPU_ENTRY_AREA_BASE − vmemmap_size.
   * vmemmap_size matches the kernel's derivation:
   *   vmemmap_size = round_up(directmap_size_tb * 64 / 4096, 1 TiB)
   * Hardcoding the 64-byte struct page size — verifiable via vmlinux's
   * CONFIG_MEMCG and tunable group config but defaulting reliably to 64
   * on mainline since ~v6.0. */
  unsigned long max_pfn = read_max_pfn();
  if (max_pfn) {
    unsigned long page_bytes = max_pfn << PAGE_SHIFT;
    unsigned long memory_tb =
        (page_bytes + one_tb - 1) / one_tb + RANDOMIZE_MEMORY_PHYSICAL_PADDING;
    unsigned long directmap_size_tb = memory_tb < 4096ul ? memory_tb : 4096ul;

    /* vmemmap_size_bytes = directmap_size_tb * 1 TiB * 64 / PAGE_SIZE
     *                    = directmap_size_tb * (1 << 40) * 64 / (1 << 12)
     *                    = directmap_size_tb * (1 << 34)  bytes
     *                    = directmap_size_tb * 16 GiB.
     * Round up to TiB granularity (kernel uses TB alignment). */
    unsigned long vmemmap_size_bytes = directmap_size_tb * (1ul << 34);
    unsigned long vmemmap_size_tb = (vmemmap_size_bytes + one_tb - 1) / one_tb;
    /* At least 1 TiB to match the kernel's minimum alignment. */
    if (vmemmap_size_tb == 0)
      vmemmap_size_tb = 1;

    unsigned long upper = CPU_ENTRY_AREA_BASE - vmemmap_size_tb * one_tb;
    if (upper < ctx->vmemmap_base_max && upper > ctx->vmemmap_base_min) {
      if (verbose && !quiet && !json_output)
        printf("[infer] vmemmap_base_max: %#lx  "
               "(CPU_ENTRY_AREA_BASE − %lu TiB vmemmap; max_pfn %lu)\n",
               upper, vmemmap_size_tb, max_pfn);
      ctx->vmemmap_base_max = upper;
    }
  }
#else
  (void)ctx;
#endif
}

static const struct kasld_inference x86_64_vmemmap_base_bound = {
    .name = "x86_64_vmemmap_base_bound",
    .phase = KASLD_INFER_PHASE_POST_COLLECTION,
    .run = x86_64_vmemmap_base_bound_run,
};

KASLD_REGISTER_INFERENCE(x86_64_vmemmap_base_bound);
