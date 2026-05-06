// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Inference plugin: directmap addresses → PAGE_OFFSET bounds
// (POST_COLLECTION)
//
// Any virtual address in the directmap satisfies:
//
//   PAGE_OFFSET ≤ V < PAGE_OFFSET + phys_span
//
// where phys_span is the virtual extent of the directmap (the distance from
// PAGE_OFFSET to the end of the last mapped physical region). On flat-memory
// systems phys_span equals MemTotal; on NUMA systems with holes the directmap
// maps non-contiguous regions and phys_span > MemTotal.
//
// Given the minimum observed directmap virtual address V_min, this yields:
//
//   Upper bound: PAGE_OFFSET ≤ V_min
//     → page_offset_max = min(page_offset_max, V_min)
//
//   Lower bound: PAGE_OFFSET > V_min - phys_span
//     → page_offset_min = max(page_offset_min, V_min - phys_span)
//
// The upper bound is always sound: any single directmap leak pins PAGE_OFFSET
// to within phys_span below the leaked address. When V_min happens to map
// PHYS_OFFSET (the lowest installed RAM), it equals PAGE_OFFSET exactly and
// both bounds collapse to the same value.
//
// The lower bound uses MemTotal as an approximation of phys_span. This is
// sound on flat-memory systems, including x86-64 with CONFIG_RANDOMIZE_MEMORY
// (where the directmap still spans exactly MemTotal bytes from page_offset_base
// regardless of randomization). On NUMA systems with memory holes the highest
// physical DRAM address can exceed PHYS_OFFSET + MemTotal, meaning a directmap
// leak from a high-address node gives V_min > PAGE_OFFSET + MemTotal and
// "lower = V_min - MemTotal > PAGE_OFFSET" would be unsound. To guard against
// this, we scan collected PHYS/DRAM results for any address beyond
// PHYS_OFFSET + MemTotal; if found, we skip the lower bound rather than risk
// excluding the true PAGE_OFFSET from the search space.
//
// Phase: POST_COLLECTION — requires collected results from components.
// ---
// <bcoles@gmail.com>

#define _POSIX_C_SOURCE 200809L

#include "../include/kasld_inference.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>

/* Read MemTotal from /proc/meminfo. Returns 0 on failure. */
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

static void directmap_page_offset_bounds_run(struct kasld_analysis_ctx *ctx) {
  /* Find the minimum virtual directmap address across all valid results. */
  unsigned long vdmap_min = ULONG_MAX;

  for (size_t i = 0; i < ctx->result_count; i++) {
    const struct result *r = &ctx->results[i];
    if (!r->valid)
      continue;
    if (r->type != KASLD_ADDR_VIRT)
      continue;
    if (strcmp(r->section, KASLD_SECTION_DIRECTMAP) != 0)
      continue;
    if (r->raw < vdmap_min)
      vdmap_min = r->raw;
  }

  if (vdmap_min == ULONG_MAX)
    return; /* No valid directmap results collected. */

  /* Upper bound: PAGE_OFFSET ≤ V_min.
   * Guard: V_min must lie within the current [min, max] window; if it falls
   * below page_offset_min the address is likely bogus and we skip to avoid
   * violating the max ≥ min invariant. */
  if (vdmap_min >= ctx->page_offset_min && vdmap_min < ctx->page_offset_max) {
    if (verbose && !quiet)
      fprintf(stdout,
              "[infer] page_offset_max tightened by"
              " directmap_page_offset_bounds: %#lx -> %#lx\n",
              ctx->page_offset_max, vdmap_min);
    ctx->page_offset_max = vdmap_min;
  }

  /* Lower bound: PAGE_OFFSET > V_min - MemTotal.
   * Only sound when all physical RAM lies within [PHYS_OFFSET,
   * PHYS_OFFSET + MemTotal). On NUMA systems with memory holes the highest
   * DRAM address can exceed this range: a directmap leak from a high-address
   * node would then give V_min > PAGE_OFFSET + MemTotal, making the lower
   * bound unsound. Detect this by scanning PHYS/DRAM results and skip. */
  unsigned long mem_bytes = read_memtotal_bytes();
  if (mem_bytes == 0)
    return;

  if (ctx->arch->phys_offset <= ULONG_MAX - mem_bytes) {
    unsigned long phys_limit = ctx->arch->phys_offset + mem_bytes;
    for (size_t i = 0; i < ctx->result_count; i++) {
      const struct result *r = &ctx->results[i];
      if (!r->valid)
        continue;
      if (r->type == KASLD_ADDR_PHYS &&
          strcmp(r->section, KASLD_SECTION_DRAM) == 0 && r->raw >= phys_limit)
        return; /* NUMA hole detected; lower bound would be unsound */
    }
  }

  /* Guard against unsigned underflow when MemTotal > V_min. */
  if (vdmap_min < mem_bytes)
    return;

  unsigned long lower = vdmap_min - mem_bytes;

  if (lower > ctx->page_offset_min && lower < ctx->page_offset_max) {
    if (verbose && !quiet)
      fprintf(stdout,
              "[infer] page_offset_min tightened by"
              " directmap_page_offset_bounds: %#lx -> %#lx"
              " (MemTotal=%lu bytes)\n",
              ctx->page_offset_min, lower, mem_bytes);
    ctx->page_offset_min = lower;
  }
}

static const struct kasld_inference directmap_page_offset_bounds = {
    .name = "directmap_page_offset_bounds",
    .phase = KASLD_INFER_PHASE_POST_COLLECTION,
    .run = directmap_page_offset_bounds_run,
};

KASLD_REGISTER_INFERENCE(directmap_page_offset_bounds);
