// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Inference plugin: kernel-locating PHYS leak → tight phys_base bounds
// (POST_COLLECTION)
//
// Components occasionally leak a *physical* address that is known to lie
// within the kernel image. Examples:
//   - CR3 read (x86-64): swapper_pg_dir lives in the kernel BSS, so its
//     physical address is somewhere in [phys_base, phys_base + image_size).
//   - Kernel symbol address resolved via /proc/kcore on a coupled arch.
//   - Module loader leaking the physical mapping of a kernel page.
//
// These results are emitted as PHYS/* with the region tagged kernel_image,
// kernel_text, or kernel_data — the renderer surfaces them as
// "Kernel image (physical)" etc. They are not handled by dram_bound.c
// (which uses the global RAM floor, agnostic to the kernel image) or by
// phys_virt_synth.c (which requires a paired same-origin VIRT/PHYS leak).
//
// For any kernel-locating PHYS result P:
//   phys_base ≤ P                     (P is at or above the image start)
//   phys_base + image_size > P        (P is strictly inside the image)
//
// Across all observed kernel-locating PHYS results in a single boot:
//   lo = min(P)  →  phys_base_max ≤ lo
//   hi = max(P)  →  phys_base_min  ≥ hi − MAX_KERNEL_IMAGE_SIZE + 1
//
// Soundness note: MAX_KERNEL_IMAGE_SIZE is a generous *upper* bound (256 MiB,
// matching text_cluster_filter.c). Real images are 50–150 MiB; any larger
// build is still bounded. Using an upper bound for the lower-bound formula
// guarantees we never push phys_base_min above the true value. The
// upper-bound computation is exact (no image_size estimate needed).
//
// Conflict guard: if the spread (hi − lo) exceeds MAX_KERNEL_IMAGE_SIZE,
// at least one of the extreme results is misclassified — they cannot both
// lie within a single contiguous kernel image. Skip the plugin in that case
// rather than emit a wrong bound; downstream invalidation by other plugins
// (cluster filter, coupling validate) typically resolves the conflict in a
// later pass.
//
// BSS-resident refinement (combined with image_size_from_text_data_gap):
// When a witness is tagged REGION_KERNEL_BSS, its symbol lives in the
// kernel .bss section, so its offset from _stext is strictly greater than
// data_end_offset (the boundary between .rodata and .bss). Because
// REGION_KERNEL_DATA is contractually limited to .data/.rodata addresses,
// the gap = max(VIRT/KERNEL_DATA) − min(VIRT/KERNEL_TEXT) is always
// ≤ data_end_offset.
// Therefore gap < offset_of(any .bss symbol), and the tightened upper bound
//   phys_base ≤ W − gap
// is sound for all KERNEL_BSS witnesses. No allow-list is needed: emitters
// self-declare .bss residency via the region tag.  The tightening fires when
// gap > 0 (TEXT/DATA pair observed) and W > gap (no underflow).
//
// On coupled architectures (PHYS_VIRT_DECOUPLED=0), the same observation
// projects through phys_to_virt to tighten virt_text_base bounds:
//   virt_text_base = page_offset + (phys_base − phys_offset) + text_offset
// Both the upper and lower phys bounds are mapped accordingly.
//
// Phase: POST_COLLECTION — needs collected PHYS results.
// Cross-arch (decoupled tightens phys_base bounds; coupled also tightens
// virt_text_base bounds).
// ---
// <bcoles@gmail.com>

#define _POSIX_C_SOURCE 200809L

#include "../include/kasld/inference.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>

/* Conservative upper bound on real kernel image size. Production kernels are
 * ~50-150 MiB; 256 MiB covers debug builds. Used only for the lower-bound
 * formula (where we must overestimate to stay sound). */
#define MAX_KERNEL_IMAGE_SIZE (256ul * 1024 * 1024)

/* Plausibility cap on a physical kernel address. Guards against zero or
 * obviously-garbage values (sub-1 MiB or beyond 1 PiB). */
#define MIN_PLAUSIBLE_KERNEL_PHYS (1ul * 1024 * 1024)
#define MAX_PLAUSIBLE_KERNEL_PHYS (1ul << 50)

static int kipb_is_kernel_locating_region(enum kasld_region region) {
  return region == REGION_KERNEL_IMAGE || region == REGION_KERNEL_TEXT ||
         region == REGION_KERNEL_DATA || region == REGION_KERNEL_BSS;
}

/* Compute the virtual TEXT/DATA gap that image_size_from_text_data_gap.c
 * uses. Returns 0 if no valid pair is present (in which case the
 * BSS-resident tightening does not fire). */
static unsigned long compute_virt_gap(const struct kasld_analysis_ctx *ctx) {
  unsigned long min_text = ULONG_MAX;
  unsigned long max_data = 0;

  for (size_t i = 0; i < ctx->result_count; i++) {
    const struct result *r = &ctx->results[i];
    if (!result_in_bounds(r, ctx->layout) || r->type != KASLD_TYPE_VIRT)
      continue;
    if (r->region == REGION_KERNEL_TEXT || r->region == REGION_KERNEL_IMAGE) {
      if (anchor_addr(r) < min_text)
        min_text = anchor_addr(r);
    } else if (r->region == REGION_KERNEL_DATA) {
      if (anchor_addr(r) > max_data)
        max_data = anchor_addr(r);
    }
  }

  if (min_text == ULONG_MAX || max_data <= min_text)
    return 0;
  return max_data - min_text;
}

/* Round v UP to the nearest multiple of align. align must be a power of two
 * and non-zero. */
static unsigned long align_up(unsigned long v, unsigned long align) {
  return (v + align - 1) & ~(align - 1);
}

static unsigned long align_down(unsigned long v, unsigned long align) {
  return v & ~(align - 1);
}

static void kernel_image_phys_bound_run(struct kasld_analysis_ctx *ctx) {
  unsigned long virt_gap = compute_virt_gap(ctx);

  /* Two-track upper-bound source: `lo_raw` is min over all witnesses (used
   * for the conflict guard and as the baseline upper bound on phys_base);
   * `lo_tight` additionally subtracts virt_gap for BSS-resident witnesses,
   * yielding a tighter phys_base_max when the refinement applies. */
  unsigned long lo_raw = ULONG_MAX;
  unsigned long lo_tight = ULONG_MAX;
  unsigned long hi = 0;
  int count = 0;
  int bss_witnesses = 0;

  for (size_t i = 0; i < ctx->result_count; i++) {
    const struct result *r = &ctx->results[i];
    if (!result_in_bounds(r, ctx->layout))
      continue;
    if (r->type != KASLD_TYPE_PHYS)
      continue;
    if (!kipb_is_kernel_locating_region(r->region))
      continue;
    if (anchor_addr(r) < MIN_PLAUSIBLE_KERNEL_PHYS ||
        anchor_addr(r) > MAX_PLAUSIBLE_KERNEL_PHYS)
      continue;

    if (anchor_addr(r) < lo_raw)
      lo_raw = anchor_addr(r);
    if (anchor_addr(r) > hi)
      hi = anchor_addr(r);

    /* BSS-resident witnesses (KERNEL_BSS region) contribute a tightened
     * upper-bound candidate `W - virt_gap` provided gap is available and
     * won't underflow. Other witnesses contribute the raw value. */
    unsigned long contrib = anchor_addr(r);
    if (virt_gap > 0 && r->region == REGION_KERNEL_BSS &&
        anchor_addr(r) > virt_gap) {
      contrib = anchor_addr(r) - virt_gap;
      bss_witnesses++;
    }
    if (contrib < lo_tight)
      lo_tight = contrib;

    count++;
  }

  if (count == 0)
    return;

  /* Conflict guard uses raw values so the BSS-resident refinement cannot
   * trigger a false-positive contradiction. */
  if (hi - lo_raw > MAX_KERNEL_IMAGE_SIZE) {
    if (verbose && !quiet)
      fprintf(stdout,
              "[infer] kernel_image_phys_bound: contradictory PHYS witnesses"
              " (lo=%#lx hi=%#lx spread=%#lx > %#lx); skipping\n",
              lo_raw, hi, hi - lo_raw, (unsigned long)MAX_KERNEL_IMAGE_SIZE);
    return;
  }

  /* `lo` for downstream use: tightest candidate (= lo_tight when BSS
   * refinement applied, else lo_raw). */
  unsigned long lo = lo_tight;

  /* ---- Upper bound on phys_base: phys_base ≤ lo ---- */
  unsigned long new_phys_max = lo;
  unsigned long phys_align = ctx->arch->phys_kaslr_align;
  if (phys_align > 0)
    new_phys_max = align_down(new_phys_max, phys_align);

  if (ctx->arch->phys_virt_decoupled) {
    if (new_phys_max > ctx->phys_base_min &&
        new_phys_max < ctx->phys_base_max) {
      if (verbose && !quiet) {
        if (bss_witnesses > 0)
          fprintf(stdout,
                  "[infer] phys_base_max tightened by kernel_image_phys_bound:"
                  " %#lx -> %#lx (lo=%#lx with bss-gap=%#lx applied to %d"
                  " witness%s, %d total)\n",
                  ctx->phys_base_max, new_phys_max, lo, virt_gap, bss_witnesses,
                  bss_witnesses == 1 ? "" : "es", count);
        else
          fprintf(stdout,
                  "[infer] phys_base_max tightened by kernel_image_phys_bound:"
                  " %#lx -> %#lx (kernel_image_phys_min=%#lx, %d witness%s)\n",
                  ctx->phys_base_max, new_phys_max, lo_raw, count,
                  count == 1 ? "" : "es");
      }
      ctx->phys_base_max = new_phys_max;
    }
  }

  /* ---- Lower bound on phys_base: phys_base ≥ hi − MAX_IMAGE_SIZE + 1 ---- */
  if (hi >= MAX_KERNEL_IMAGE_SIZE) {
    unsigned long new_phys_min = hi - MAX_KERNEL_IMAGE_SIZE + 1;
    if (phys_align > 0)
      new_phys_min = align_up(new_phys_min, phys_align);

    if (ctx->arch->phys_virt_decoupled) {
      if (new_phys_min > ctx->phys_base_min &&
          new_phys_min < ctx->phys_base_max) {
        if (verbose && !quiet)
          fprintf(stdout,
                  "[infer] phys_base_min tightened by kernel_image_phys_bound:"
                  " %#lx -> %#lx (kernel_image_phys_max=%#lx, %d witness%s)\n",
                  ctx->phys_base_min, new_phys_min, hi, count,
                  count == 1 ? "" : "es");
        ctx->phys_base_min = new_phys_min;
      }
    }
  }

  /* ---- Coupled arch: project phys bounds into virtual text-base bounds.
   *
   * On coupled arches phys_to_virt(P) = page_offset + (P − phys_offset),
   * and the kernel text base is phys_to_virt(phys_base) + text_offset:
   *
   *   virt_text_base_max ≤ page_offset + (lo − phys_offset) + text_offset
   *   virt_text_base_min ≥ page_offset + (hi − max_image_size + 1
   *                                       − phys_offset) + text_offset
   *
   * Use the runtime page_offset from layout (set by layout_adjust). */
  if (!ctx->arch->phys_virt_decoupled) {
    unsigned long page_offset = ctx->layout->page_offset;
    unsigned long phys_offset = ctx->arch->phys_offset;
    unsigned long text_offset = ctx->arch->text_offset;
    unsigned long kaslr_align = ctx->arch->kaslr_align;
    unsigned long kaslr_min = ctx->arch->kaslr_base_min;

    if (lo < phys_offset)
      return; /* impossible: a kernel-locating phys below PHYS_OFFSET. */

    unsigned long virt_max = page_offset + (lo - phys_offset) + text_offset;
    if (kaslr_align > 0)
      virt_max = align_down(virt_max, kaslr_align);
    if (virt_max > kaslr_min && virt_max > ctx->text_base_min &&
        virt_max < ctx->text_base_max) {
      if (verbose && !quiet)
        fprintf(
            stdout,
            "[infer] virt_text_base_max tightened by kernel_image_phys_bound:"
            " %#lx -> %#lx (kernel_image_phys_min=%#lx, %d witness%s)\n",
            ctx->text_base_max, virt_max, lo, count, count == 1 ? "" : "es");
      ctx->text_base_max = virt_max;
    }

    if (hi >= MAX_KERNEL_IMAGE_SIZE - 1 + phys_offset) {
      unsigned long phys_min_raw = hi - MAX_KERNEL_IMAGE_SIZE + 1;
      unsigned long virt_min =
          page_offset + (phys_min_raw - phys_offset) + text_offset;
      if (kaslr_align > 0)
        virt_min = align_up(virt_min, kaslr_align);
      if (virt_min > ctx->text_base_min && virt_min < ctx->text_base_max) {
        if (verbose && !quiet)
          fprintf(stdout,
                  "[infer] virt_text_base_min tightened by"
                  " kernel_image_phys_bound: %#lx -> %#lx"
                  " (kernel_image_phys_max=%#lx, %d witness%s)\n",
                  ctx->text_base_min, virt_min, hi, count,
                  count == 1 ? "" : "es");
        ctx->text_base_min = virt_min;
      }
    }
  }
}

static const struct kasld_inference kernel_image_phys_bound = {
    .name = "kernel_image_phys_bound",
    .phase = KASLD_INFER_PHASE_POST_COLLECTION,
    .run = kernel_image_phys_bound_run,
};

KASLD_REGISTER_INFERENCE(kernel_image_phys_bound);
