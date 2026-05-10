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
              "[infer] virt_page_offset_max tightened by"
              " directmap_page_offset_bounds: %#lx -> %#lx\n",
              ctx->page_offset_max, vdmap_min);
    ctx->page_offset_max = vdmap_min;
  }

  /* Lower bound: PAGE_OFFSET > V_min - phys_span,
   * where phys_span is the highest physical address mapped in the directmap.
   *
   * Anchored at PHYS_OFFSET, phys_span = (P_floor - phys_offset) + mem_bytes.
   * On systems where the firmware reports DRAM starting at phys_offset,
   * P_floor == phys_offset and phys_span == mem_bytes. On systems with a
   * low-memory hole — e.g. arm64/MIPS boards where PHYS_OFFSET=0 but DRAM
   * begins at 1 GiB — P_floor > phys_offset and phys_span > mem_bytes. The
   * earlier formulation `lower = V_min - mem_bytes` (which assumed
   * P_floor == phys_offset) could push page_offset_min above the true
   * PAGE_OFFSET when V_min came from a high-physical-address leak.
   *
   * To stay sound we use the *observed* DRAM floor from PHYS/DRAM results.
   * If no PHYS/DRAM evidence exists we cannot bound P_floor and must skip
   * the lower-bound update.
   *
   * On NUMA systems with memory holes the highest physical DRAM address can
   * exceed P_floor + mem_bytes: detect via PHYS/DRAM scan and skip rather
   * than risk excluding the true PAGE_OFFSET. */
  unsigned long mem_bytes = read_memtotal_bytes();
  if (mem_bytes == 0)
    return;

  unsigned long phys_floor = ULONG_MAX;
  for (size_t i = 0; i < ctx->result_count; i++) {
    const struct result *r = &ctx->results[i];
    if (!r->valid)
      continue;
    if (r->type != KASLD_ADDR_PHYS)
      continue;
    if (strcmp(r->section, KASLD_SECTION_DRAM) != 0)
      continue;
    if (r->raw < phys_floor)
      phys_floor = r->raw;
  }

  if (phys_floor == ULONG_MAX)
    return; /* No PHYS/DRAM witness — cannot bound P_floor soundly. */

  if (phys_floor < ctx->arch->phys_offset)
    return; /* Inconsistent: a leak below PHYS_OFFSET indicates misclassified
             * results. Skip rather than produce a wrong bound. */

  unsigned long phys_floor_offset = phys_floor - ctx->arch->phys_offset;

  if (phys_floor_offset > ULONG_MAX - mem_bytes)
    return; /* Overflow guard. */

  unsigned long phys_span = phys_floor_offset + mem_bytes;

  /* NUMA-hole guard: any PHYS/DRAM result above phys_floor + mem_bytes
   * indicates a hole that exceeds our phys_span estimate. Skip in that case. */
  unsigned long phys_limit = phys_floor + mem_bytes;
  for (size_t i = 0; i < ctx->result_count; i++) {
    const struct result *r = &ctx->results[i];
    if (!r->valid)
      continue;
    if (r->type == KASLD_ADDR_PHYS &&
        strcmp(r->section, KASLD_SECTION_DRAM) == 0 && r->raw >= phys_limit)
      return;
  }

  /* Guard against unsigned underflow when phys_span > V_min. */
  if (vdmap_min < phys_span)
    return;

  unsigned long lower = vdmap_min - phys_span;

  if (lower > ctx->page_offset_min && lower < ctx->page_offset_max) {
    if (verbose && !quiet)
      fprintf(stdout,
              "[infer] virt_page_offset_min tightened by"
              " directmap_page_offset_bounds: %#lx -> %#lx"
              " (phys_floor=%#lx phys_span=%#lx)\n",
              ctx->page_offset_min, lower, phys_floor, phys_span);
    ctx->page_offset_min = lower;
  }
}

static const struct kasld_inference directmap_page_offset_bounds = {
    .name = "directmap_page_offset_bounds",
    .phase = KASLD_INFER_PHASE_POST_COLLECTION,
    .run = directmap_page_offset_bounds_run,
};

KASLD_REGISTER_INFERENCE(directmap_page_offset_bounds);
