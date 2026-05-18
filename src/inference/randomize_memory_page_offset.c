// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Inference plugin: directmap + phys pair → page_offset_base
// (POST_COLLECTION)
//
// On x86-64 with CONFIG_RANDOMIZE_MEMORY, page_offset_base (the start of the
// directmap region) is independently randomised at 1 GiB (PUD_SIZE)
// granularity. For any directmap virtual address D mapping physical address P:
//   page_offset_base = D - P  (PHYS_OFFSET = 0 on x86-64)
//
// Two pairing paths, attempted in priority order:
//
// Path 1 — Same-(origin, region, name) pairing
// ============================================
// A single component emits both a PHYS result and a VIRT/DIRECTMAP result
// with identical origin, region, AND name. This is the strongest signal:
// they reference the same kernel object. Example: dmesg_backtrace emits
// PHYS/DRAM kernel_bss:cr3 (the CR3 register value) AND on coupled-arch
// builds VIRT/DIRECTMAP kernel_bss:cr3 (= phys_to_virt(cr3)). The
// (origin, region, name) triple unambiguously identifies the pair.
//
// Per-pair: candidate = V_raw − P_raw. Apply 1-GiB alignment + window
// guards. If the candidate survives, bilateral-pin page_offset_base.
//
// This path is a generalisation of phys_virt_synth.c: it accepts PHYS in
// any section (DRAM, TEXT, DATA) when the (region, name) labels match,
// and enforces the stricter 1-GiB PUD alignment required for x86-64
// memory KASLR. phys_virt_synth.c uses kaslr_align (2 MiB) which is too
// loose for the 1-GiB CONFIG_RANDOMIZE_MEMORY granularity and would let
// a 2-MiB-aligned-but-not-1-GiB-aligned candidate slip through.
//
// Path 2 — Cross-origin min(DIRECTMAP) − min(PHYS/DRAM tagged RAM_BASE)
// =====================================================================
// On a typical x86-64 system with DRAM starting at a 1 GiB-aligned boundary:
//   P_min ≈ DRAM base (from e.g. /proc/zoneinfo, /sys/devices/system/memory)
//   D_min ≈ page_offset_base + DRAM base
//   ⟹ D_min - P_min = page_offset_base
//
// P_min sourcing — soundness requires P_min to be a true DRAM-floor witness.
// PHYS results in non-RAM regions (REGION_INITRD, REGION_RESERVED_MEM,
// REGION_KERNEL_IMAGE, etc.) point at addresses that may be 1 GiB-aligned
// above the true DRAM base; using such a value would produce a candidate
// that is 1 GiB-low of true page_offset_base and still pass the alignment
// guard. To prevent that we accept only records with region=REGION_RAM and
// HAS_LO set — the "lowest RAM address" claim emitted by components such as
// sysfs_firmware_memmap.c, proc-zoneinfo.c, and sysfs_memory_blocks.c.
//
// Validity guards (both paths):
//   - Candidate must be 1 GiB-aligned (PUD granularity of randomisation).
//   - Candidate must fall within the current [page_offset_min,
//     page_offset_max] window established by prior inference steps.
//
// Together these guards make false positives extremely unlikely.
//
// Phase: POST_COLLECTION — requires DIRECTMAP virtual and PHYS/DRAM results
//        from earlier components.
// Applicable: x86-64 only (page_offset_base is independently randomised;
//             on coupled-arch systems phys_virt_synth.c synthesises
//             PAGE_OFFSET).
// ---
// <bcoles@gmail.com>

#define _POSIX_C_SOURCE 200809L

#include "../include/kasld/inference.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>

/* Returns 1 if candidate is acceptable (1-GiB-aligned, in window), else 0.
 * On success, *out_candidate is the value to pin. */
#if defined(__x86_64__)
static int validate_candidate(const struct kasld_analysis_ctx *ctx,
                              unsigned long virt, unsigned long phys,
                              unsigned long *out_candidate) {
  const unsigned long pud_size = 1ul << 30;
  if (virt <= phys)
    return 0;
  unsigned long candidate = virt - phys;
  if (candidate & (pud_size - 1))
    return 0;
  if (candidate < ctx->page_offset_min || candidate > ctx->page_offset_max)
    return 0;
  *out_candidate = candidate;
  return 1;
}

static void apply_pin(struct kasld_analysis_ctx *ctx, unsigned long candidate,
                      const char *path_label, unsigned long virt,
                      unsigned long phys, const char *origin) {
  if (verbose && !quiet)
    fprintf(stdout,
            "[infer] virt_page_offset_base pinned by"
            " randomize_memory_page_offset (%s):"
            " [%#lx, %#lx] -> %#lx"
            " (D=%#lx P=%#lx%s%s)\n",
            path_label, ctx->page_offset_min, ctx->page_offset_max, candidate,
            virt, phys, origin ? " origin=" : "", origin ? origin : "");
  ctx->page_offset_min = candidate;
  ctx->page_offset_max = candidate;
}
#endif

static void randomize_memory_page_offset_run(struct kasld_analysis_ctx *ctx) {
#if defined(__x86_64__)

  /* === Path 1: same-(origin, region, name) PHYS + VIRT/DIRECTMAP pairing ===
   *
   * For every VIRT/DIRECTMAP result V with non-empty origin, look for a
   * PHYS result with matching (origin, region, name). Such a triple
   * identifies the same kernel object across both address spaces — the
   * tightest possible signal. Sections on the PHYS side are unrestricted
   * (DRAM, TEXT, DATA, MMIO) because the matching tags carry the
   * semantic equivalence. */
  for (size_t i = 0; i < ctx->result_count; i++) {
    const struct result *v = &ctx->results[i];
    if (!result_in_bounds(v, ctx->layout))
      continue;
    if (v->type != KASLD_TYPE_VIRT)
      continue;
    if (v->origins[0][0] == '\0')
      continue;

    for (size_t j = 0; j < ctx->result_count; j++) {
      const struct result *p = &ctx->results[j];
      if (!result_in_bounds(p, ctx->layout))
        continue;
      if (p->type != KASLD_TYPE_PHYS)
        continue;
      if (strcmp(p->origins[0], v->origins[0]) != 0)
        continue;
      if (p->region != v->region)
        continue;
      if (strcmp(p->name, v->name) != 0)
        continue;

      unsigned long candidate;
      if (!validate_candidate(ctx, anchor_addr(v), anchor_addr(p), &candidate))
        continue;

      apply_pin(ctx, candidate, "same-origin pair", anchor_addr(v),
                anchor_addr(p), v->origins[0]);
      return;
    }
  }

  /* === Path 2: cross-origin min(DIRECTMAP) − min(PHYS/DRAM RAM_BASE) ===
   *
   * No same-origin pair survived; fall back to the layout-landmark
   * heuristic. */
  unsigned long vdmap_min = ULONG_MAX;
  for (size_t i = 0; i < ctx->result_count; i++) {
    const struct result *r = &ctx->results[i];
    if (!result_in_bounds(r, ctx->layout))
      continue;
    if (r->type != KASLD_TYPE_VIRT)
      continue;
    /* Only directmap leaks make sense here: page_offset_base = D − P
     * requires D to be a direct-map address. Other virtual leaks (kernel
     * text, modules, the arch-floor page_offset constant) would yield
     * garbage. */
    if (r->region != REGION_DIRECTMAP)
      continue;
    if (anchor_addr(r) < vdmap_min)
      vdmap_min = anchor_addr(r);
  }
  if (vdmap_min == ULONG_MAX)
    return;

  /* P_min must be a true RAM base — see the file header for why other
   * DRAM-region records (initrd, reserved_mem, etc.) are excluded. */
  unsigned long pdram_min = ULONG_MAX;
  for (size_t i = 0; i < ctx->result_count; i++) {
    const struct result *r = &ctx->results[i];
    if (!result_in_bounds(r, ctx->layout))
      continue;
    if (r->type != KASLD_TYPE_PHYS)
      continue;
    if (r->region != REGION_RAM || !HAS_LO(r))
      continue;
    if (r->lo < pdram_min)
      pdram_min = r->lo;
  }
  if (pdram_min == ULONG_MAX)
    return;

  unsigned long candidate;
  if (!validate_candidate(ctx, vdmap_min, pdram_min, &candidate))
    return;

  apply_pin(ctx, candidate, "cross-origin ram_base", vdmap_min, pdram_min,
            NULL);

#else
  (void)ctx;
#endif /* defined(__x86_64__) */
}

static const struct kasld_inference randomize_memory_page_offset = {
    .name = "randomize_memory_page_offset",
    .phase = KASLD_INFER_PHASE_POST_COLLECTION,
    .run = randomize_memory_page_offset_run,
};

KASLD_REGISTER_INFERENCE(randomize_memory_page_offset);
