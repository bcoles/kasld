// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Inference plugin: page_offset_base + directmap_size → vmalloc_base lower
// bound (POST_COLLECTION)
//
// On x86_64 with CONFIG_RANDOMIZE_MEMORY, kernel_randomize_memory() places
// the three virtual memory regions consecutively, each offset by a random
// PUD-aligned value:
//
//   kaslr_regions[0]: directmap  — base = page_offset_base
//                                  size = directmap_size_tb TiB
//   kaslr_regions[1]: vmalloc    — base = page_offset_base + directmap_size_tb
//   * 1TiB
//                                        + round_up(1, PUD_SIZE) + rand_1
//   kaslr_regions[2]: vmemmap    — base = vmalloc_base + VMALLOC_SIZE_TB * 1TiB
//                                        + round_up(1, PUD_SIZE) + rand_2
//
// The minimum inter-region gap is exactly PUD_SIZE (1 GiB), because after
// advancing vaddr past each region's size the loop does:
//
//   vaddr = round_up(vaddr + 1, PUD_SIZE);
//
// and vaddr is PUD-aligned going in (region sizes are in whole TiB = multiple
// of PUD_SIZE). So the gap is exactly 1 * PUD_SIZE = 1 GiB.
//
// The directmap size is:
//
//   memory_tb = DIV_ROUND_UP(max_pfn * 4096, 1 TiB) +
//               CONFIG_RANDOMIZE_MEMORY_PHYSICAL_PADDING (default: 10)
//   directmap_size_tb = min(4096, memory_tb)   [when ZONE_DEVICE disabled]
//
// This gives a sound lower bound:
//
//   vmalloc_base_min = page_offset_min + directmap_size_tb * 1TiB + PUD_SIZE
//
// When page_offset_base is exactly pinned (page_offset_min == page_offset_max)
// the bound is tight; otherwise it is a valid-but-loose lower bound.
//
// max_pfn is read from /proc/zoneinfo: max(start_pfn + spanned) across all
// zones. /proc/zoneinfo is world-readable (0444) on all kernel versions.
//
// Phase: POST_COLLECTION — requires page_offset_min from prior plugins
//        (directmap_page_offset_bounds, randomize_memory_page_offset).
// Applicable: x86-64 only (other arches use a different memory layout model).
// ---
// <bcoles@gmail.com>

#define _POSIX_C_SOURCE 200809L

#include "../include/kasld_inference.h"

#include <limits.h>
#include <stdio.h>

#define TB_SHIFT 40
#define PUD_SHIFT 30
#define PAGE_SHIFT 12

/* CONFIG_RANDOMIZE_MEMORY_PHYSICAL_PADDING — added to directmap_size_tb.
 * Hardcoded to the kernel default (10 TiB). Distro kernels virtually always
 * use this value; there is no way to detect it from user space. If a kernel
 * uses a larger padding, vmalloc_base_min will be under-estimated (still a
 * valid lower bound, just slightly loose). */
#define RANDOMIZE_MEMORY_PHYSICAL_PADDING 10ul

/* Read max_pfn from /proc/zoneinfo: highest (start_pfn + spanned) seen.
 * Returns 0 on failure. */
static unsigned long read_max_pfn(void) {
  FILE *f = fopen("/proc/zoneinfo", "r");
  if (!f)
    return 0;

  char line[256];
  unsigned long max_pfn = 0;
  unsigned long cur_spanned = 0;

  /* /proc/zoneinfo per-zone layout (relevant fields):
   *   pages free     N
   *         spanned  N    ← appears before start_pfn within the zone block
   *         ...
   *   start_pfn:     N    ← zone's base PFN; end = start_pfn + spanned
   */
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

static void x86_64_vmalloc_base_bound_run(struct kasld_analysis_ctx *ctx) {
#if defined(__x86_64__)
  /* Only meaningful when page_offset_base is at least partially pinned. */
  if (ctx->page_offset_min == 0)
    return;

  unsigned long max_pfn = read_max_pfn();
  if (!max_pfn)
    return;

  /* directmap_size_tb = DIV_ROUND_UP(max_pfn * PAGE_SIZE, 1 TiB) + padding.
   * Cap at 4096 TiB (1 << (MAX_PHYSMEM_BITS - TB_SHIFT), MAX_PHYSMEM_BITS=52).
   * This matches kernel_randomize_memory() on kernels without ZONE_DEVICE;
   * with ZONE_DEVICE the cap is not applied by the kernel, but 4096 TiB is
   * an architectural ceiling regardless. */
  unsigned long page_bytes =
      max_pfn << PAGE_SHIFT; /* may wrap on 32-bit, but we're x86_64 */
  unsigned long one_tb = 1ul << TB_SHIFT;
  unsigned long memory_tb =
      (page_bytes + one_tb - 1) / one_tb + RANDOMIZE_MEMORY_PHYSICAL_PADDING;
  unsigned long directmap_size_tb = memory_tb < 4096ul ? memory_tb : 4096ul;

  /* vmalloc_base >= page_offset_base + directmap_size_tb * 1 TiB + PUD_SIZE.
   * Use page_offset_min as a conservative substitute for page_offset_base;
   * result is always a valid lower bound. */
  unsigned long pud_size = 1ul << PUD_SHIFT;
  unsigned long candidate =
      ctx->page_offset_min + directmap_size_tb * one_tb + pud_size;

  /* Sanity: candidate must be above page_offset_min and fit in the kernel VAS.
   */
  if (candidate <= ctx->page_offset_min)
    return;

  if (candidate > ctx->vmalloc_base_min) {
    if (verbose && !quiet && !json_output)
      printf("[infer] vmalloc_base_min: %#lx  "
             "(page_offset_min %#lx + %lu TiB directmap + 1 GiB gap;"
             " max_pfn %lu)\n",
             candidate, ctx->page_offset_min, directmap_size_tb, max_pfn);
    ctx->vmalloc_base_min = candidate;
  }
#else
  (void)ctx;
#endif
}

static const struct kasld_inference x86_64_vmalloc_base_bound = {
    .name = "x86_64_vmalloc_base_bound",
    .phase = KASLD_INFER_PHASE_POST_COLLECTION,
    .run = x86_64_vmalloc_base_bound_run,
};

KASLD_REGISTER_INFERENCE(x86_64_vmalloc_base_bound);
