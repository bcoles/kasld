// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Inference plugin: runtime layout adjustment (LAYOUT_ADJUST)
//
// Fires before POST_COLLECTION and POST_PROBING inference. Promotes all
// runtime layout discoveries into the live layout struct, then revalidates
// every captured result once at the end.
//
// Responsibilities, executed in order:
//   1. Conflict detection: warn when multiple distinct PAGE_OFFSET values
//      are present (indicates a legacy kernel or stale config value).
//   2. Consensus application: if the agreed PAGE_OFFSET differs from the
//      compile-time default, call adjust_for_page_offset() to shift all
//      dependent layout fields atomically.
//   3. Floor clamping (!PHYS_VIRT_DECOUPLED only): raise kernel_base_min
//      to page_offset so the memory map and KASLR analysis use the correct
//      floor. Inactive on all arches that define LEGACY_LAYOUT_BOUNDARY
//      (both are PHYS_VIRT_DECOUPLED), so steps 3 and 4 are never both
//      active simultaneously.
//   4. Legacy VAS detection (LEGACY_LAYOUT_BOUNDARY arches only): if a
//      virtual text address falls below the arch-defined boundary, the
//      kernel is using an older VAS layout. Two sub-modes:
//        LEGACY_COUPLED  — PAGE_OFFSET derived from text address (riscv64
//                          SV39); adjust_for_page_offset() re-applied.
//        !LEGACY_COUPLED — static constants replace modern defaults
//                          (arm64 pre-v5.4).
//      Must execute after step 2 so that PAGE_OFFSET consensus is
//      established first; this step may then override it.
//   5. Single revalidate_results() covering all mutations above.
// ---
// <bcoles@gmail.com>

#define _POSIX_C_SOURCE 200809L

#include "../include/kasld_inference.h"

#include <stdio.h>
#include <string.h>

#ifdef LEGACY_LAYOUT_BOUNDARY
/* Search for a virtual text address below the arch legacy boundary.
 * Intentionally ignores result->valid: on arm64 the modern KERNEL_BASE_MIN
 * is above the legacy range, so legacy addresses fail validation until the
 * layout is switched. The VAS-start check is a minimal sanity gate. */
static unsigned long find_legacy_text(const struct kasld_analysis_ctx *ctx) {
  for (size_t i = 0; i < ctx->result_count; i++) {
    const struct result *r = &ctx->results[i];
    if (r->type == KASLD_ADDR_VIRT &&
        strcmp(r->section, KASLD_SECTION_TEXT) == 0 && r->aligned != 0 &&
        r->aligned >= KERNEL_VAS_START && r->aligned < LEGACY_LAYOUT_BOUNDARY)
      return r->aligned;
  }
  return 0;
}
#endif

static void layout_adjust_run(struct kasld_analysis_ctx *ctx) {
  /* 1. Conflict detection: warn once if multiple distinct PAGE_OFFSET values
   *    are present, e.g. proc-config's CONFIG_PAGE_OFFSET vs proc-cpuinfo's
   *    MMU-inferred value on a legacy kernel. Static flag suppresses repeated
   *    warnings across the sequential probing calls. */
  static int po_conflict_warned = 0;
  unsigned long po_vals[MAX_RESULTS];
  int po_n = 0;

  for (size_t i = 0; i < ctx->result_count; i++) {
    const struct result *r = &ctx->results[i];
    if (r->type != KASLD_ADDR_VIRT ||
        strcmp(r->section, KASLD_SECTION_PAGEOFFSET) != 0 || !r->valid)
      continue;
    int dup = 0;
    for (int j = 0; j < po_n; j++) {
      if (po_vals[j] == r->aligned) {
        dup = 1;
        break;
      }
    }
    if (!dup && po_n < MAX_RESULTS)
      po_vals[po_n++] = r->aligned;
  }

  if (po_n > 1 && !po_conflict_warned) {
    po_conflict_warned = 1;
    if (!quiet) {
      fprintf(stdout, "[infer] layout_adjust: conflicting PAGE_OFFSET sources"
                      " (possible legacy kernel layout):");
      for (int i = 0; i < po_n; i++)
        fprintf(stdout, " 0x%016lx", po_vals[i]);
      fprintf(stdout, "; using 0x%016lx (modern layout assumed)\n",
              po_vals[0] < po_vals[1] ? po_vals[0] : po_vals[1]);
    }
  }

  /* 2. Apply consensus PAGE_OFFSET when it differs from compile-time default.
   *    adjust_for_page_offset() shifts all dependent layout fields atomically.
   */
  unsigned long detected_po =
      group_consensus(KASLD_ADDR_VIRT, KASLD_SECTION_PAGEOFFSET);
  if (detected_po && detected_po != ctx->layout->page_offset)
    adjust_for_page_offset(detected_po);

  /* 3. Floor clamping: on coupled architectures kernel text lives above
   *    PAGE_OFFSET. KERNEL_BASE_MIN may be conservatively low at compile time
   *    (e.g. x86_32 accepts all CONFIG_VMSPLIT_* values at validation time)
   *    but must be clamped to PAGE_OFFSET for the final layout.
   *    VAS start is min(page_offset, modules_start) on arm32 where modules
   *    sit just below PAGE_OFFSET. */
#if !PHYS_VIRT_DECOUPLED
  if (ctx->layout->kernel_base_min < ctx->layout->page_offset) {
    ctx->layout->kernel_base_min = ctx->layout->page_offset;
    ctx->layout->kernel_text_default =
        ctx->layout->page_offset + ctx->layout->text_offset;
    ctx->layout->kernel_vas_start = ctx->layout->page_offset;
    if (ctx->layout->modules_start < ctx->layout->kernel_vas_start)
      ctx->layout->kernel_vas_start = ctx->layout->modules_start;
  }
#endif

  /* 4. Legacy VAS detection: must follow step 2 so that PAGE_OFFSET consensus
   *    is already in place before we check for legacy text addresses. On
   *    LEGACY_COUPLED arches this step may override step 2's PAGE_OFFSET with
   *    a value derived directly from the leaked text address. */
#ifdef LEGACY_LAYOUT_BOUNDARY
  unsigned long legacy_text = find_legacy_text(ctx);
  if (legacy_text) {
#ifdef LEGACY_COUPLED
    /* PAGE_OFFSET is not reported directly; derive it from the text address.
     * adjust_for_page_offset() handles VAS start and module shifting but, on
     * PHYS_VIRT_DECOUPLED arches, does not update text-tracking fields —
     * apply them explicitly for the coupled legacy layout. */
    ctx->layout->text_offset = LEGACY_TEXT_OFFSET;
    unsigned long legacy_po = legacy_text & LEGACY_PAGE_OFFSET_MASK;
    if (legacy_po != ctx->layout->page_offset)
      adjust_for_page_offset(legacy_po);
    ctx->layout->kernel_text_default = legacy_po + ctx->layout->text_offset;
    ctx->layout->kernel_base_min = legacy_po;
    ctx->layout->kaslr_base_min = legacy_po;
#else
    /* Static constants fully replace modern defaults (e.g. arm64 pre-v5.4). */
    ctx->layout->page_offset = LEGACY_PAGE_OFFSET;
    ctx->layout->kernel_vas_start = LEGACY_KERNEL_VAS_START;
    ctx->layout->modules_start = LEGACY_MODULES_START;
    ctx->layout->modules_end = LEGACY_MODULES_END;
    ctx->layout->text_offset = LEGACY_TEXT_OFFSET;
    ctx->layout->kernel_text_default = LEGACY_KERNEL_TEXT_DEFAULT;
    ctx->layout->kernel_base_min = LEGACY_KERNEL_BASE_MIN;
    ctx->layout->kaslr_base_min = LEGACY_KASLR_BASE_MIN;
    ctx->layout->kaslr_base_max = LEGACY_KASLR_BASE_MAX;
#endif
  }
#endif

  /* 5. Single revalidation covering all layout mutations above. */
  revalidate_results();
}

static const struct kasld_inference layout_adjust = {
    .name = "layout_adjust",
    .phase = KASLD_INFER_PHASE_LAYOUT_ADJUST,
    .run = layout_adjust_run,
};

KASLD_REGISTER_INFERENCE(layout_adjust);
