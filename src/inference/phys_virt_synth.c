// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Inference plugin: physical-to-virtual synthesis (POST_COLLECTION)
//
// Narrows ctx->page_offset_min/page_offset_max by synthesising PAGE_OFFSET
// from component pairs that leak both a physical DRAM address and the
// corresponding virtual directmap address.
//
// The synthesis: for a given physical address P and its virtual directmap
// address V = phys_to_virt(P):
//
//   PAGE_OFFSET = V - P + PHYS_OFFSET
//
// Components on coupled architectures (PHYS_VIRT_DECOUPLED == 0) emit a
// KASLD_ADDR_PHYS/KASLD_SECTION_DRAM result AND a
// KASLD_ADDR_VIRT/KASLD_SECTION_DIRECTMAP result for the same physical
// address. The orchestrator tags each result with the component name as
// 'origin', so pairs from the same component can be identified.
//
// Per-origin minimum pairing: min(VIRT/DIRECTMAP) and min(PHYS/DRAM) from
// the same origin identify the pair for the lowest leaked address. Because
// phys_to_virt() is monotone on all KASLD architectures (it adds a constant
// offset), the minimum virtual address corresponds to the minimum physical
// address within the same component's output.
//
// On decoupled architectures (x86_64, arm64, riscv64, s390), components emit
// only one side of the pair, so no synthesis candidates are produced and the
// plugin is a no-op.
//
// The plugin collects po_candidates from all origins. If candidates agree
// within kaslr_align (i.e. max - min <= kaslr_align), page_offset_min/max
// are tightened to the range [min_candidate, max_candidate]. Disagreeing
// candidates indicate a cross-component mismatch and are left unconstrainted.
// ---
// <bcoles@gmail.com>

#define _POSIX_C_SOURCE 200809L

#include "../include/kasld_inference.h"

#include <limits.h>
#include <string.h>

#define SYNTH_MAX_ORIGINS 128

struct synth_origin {
  char origin[ORIGIN_LEN];
  unsigned long virt_min;
  unsigned long phys_min;
};

static void phys_virt_synth_run(struct kasld_analysis_ctx *ctx) {
  unsigned long phys_offset = ctx->arch->phys_offset;
  unsigned long kaslr_align = ctx->arch->kaslr_align;

  struct synth_origin origs[SYNTH_MAX_ORIGINS];
  int n_origs = 0;

  /* Build per-origin min(VIRT/DIRECTMAP) and min(PHYS/DRAM). */
  for (size_t i = 0; i < ctx->result_count; i++) {
    const struct result *r = &ctx->results[i];
    if (!r->valid || r->origin[0] == '\0')
      continue;

    int is_virt_dmap = (r->type == KASLD_ADDR_VIRT &&
                        strcmp(r->section, KASLD_SECTION_DIRECTMAP) == 0);
    int is_phys_dram = (r->type == KASLD_ADDR_PHYS &&
                        strcmp(r->section, KASLD_SECTION_DRAM) == 0);
    if (!is_virt_dmap && !is_phys_dram)
      continue;

    struct synth_origin *entry = NULL;
    for (int j = 0; j < n_origs; j++) {
      if (strcmp(origs[j].origin, r->origin) == 0) {
        entry = &origs[j];
        break;
      }
    }
    if (!entry) {
      if (n_origs >= SYNTH_MAX_ORIGINS)
        continue;
      entry = &origs[n_origs++];
      strncpy(entry->origin, r->origin, ORIGIN_LEN - 1);
      entry->origin[ORIGIN_LEN - 1] = '\0';
      entry->virt_min = ULONG_MAX;
      entry->phys_min = ULONG_MAX;
    }

    if (is_virt_dmap && r->raw < entry->virt_min)
      entry->virt_min = r->raw;
    if (is_phys_dram && r->raw < entry->phys_min)
      entry->phys_min = r->raw;
  }

  /* Collect PAGE_OFFSET candidates from origins that have both. */
  unsigned long cand_lo = ULONG_MAX;
  unsigned long cand_hi = 0;

  for (int i = 0; i < n_origs; i++) {
    unsigned long virt = origs[i].virt_min;
    unsigned long phys = origs[i].phys_min;

    if (virt == ULONG_MAX || phys == ULONG_MAX)
      continue;
    if (phys < phys_offset || virt < phys)
      continue;

    unsigned long po = virt - phys + phys_offset;

    if (po < ctx->page_offset_min || po > ctx->page_offset_max)
      continue;

    if (po < cand_lo)
      cand_lo = po;
    if (po > cand_hi)
      cand_hi = po;
  }

  if (cand_lo == ULONG_MAX)
    return;

  /* Only tighten when candidates agree within one alignment slot.
   * Spreading wider means we have at least one mismatched pair. */
  if (cand_hi - cand_lo > kaslr_align)
    return;

  if (cand_lo > ctx->page_offset_min)
    ctx->page_offset_min = cand_lo;
  if (cand_hi < ctx->page_offset_max)
    ctx->page_offset_max = cand_hi;
}

static const struct kasld_inference phys_virt_synth = {
    .name = "phys_virt_synth",
    .phase = KASLD_INFER_PHASE_POST_COLLECTION,
    .run = phys_virt_synth_run,
};

KASLD_REGISTER_INFERENCE(phys_virt_synth);
