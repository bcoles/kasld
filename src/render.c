// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rendering layer entry point: shared helpers used across the per-mode
// renderers, plus the render_summary() dispatcher that routes a fully-
// resolved struct summary to the chosen output mode.
//
// The output modes themselves live in src/render/*.c:
//   render/text.c      — default and verbose (-v) text, readout, layout maps
//   render/json.c      — JSON output (--json / -j), plus json_print_escaped
//   render/oneline.c   — one-line summary (--oneline / -1)
//   render/markdown.c  — markdown table (--markdown / -m)
//   render/hardening.c — hardening assessment (-H), text + JSON flavours
//
// Cross-file glue (shared helpers, per-mode entry points) is declared in
// src/include/kasld/render_internal.h.
//
// Resolution (the engine) runs in the orchestrator layer BEFORE
// render_summary() is called — rendering is a pure consumer and never
// drives inference.
// ---
// <bcoles@gmail.com>

#include "include/kasld/internal.h"
#include "include/kasld/render_internal.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>

/* Human-readable size: format bytes as "N.N KiB/MiB/GiB/TiB" */
const char *human_size(unsigned long bytes, char *buf, size_t bufsz) {
#if ULONG_MAX > 0xFFFFFFFFul
  if (bytes >= TB)
    snprintf(buf, bufsz, "%.1f TiB", (double)bytes / (double)TB);
  else
#endif
      if (bytes >= GB)
    snprintf(buf, bufsz, "%.1f GiB", (double)bytes / (double)GB);
  else if (bytes >= MB)
    snprintf(buf, bufsz, "%.1f MiB", (double)bytes / (double)MB);
  else if (bytes >= KB)
    snprintf(buf, bufsz, "%.1f KiB", (double)bytes / (double)KB);
  else
    snprintf(buf, bufsz, "%lu B", bytes);
  return buf;
}

/* -------------------------------------------------------------------------
 * Result-model helpers
 *
 * Mirror the orchestrator's anchor_addr() and the result_in_bounds()
 * convention. methods[0]/origins[0] are the earliest contributor for a
 * merged record; for the renderer this is the canonical display value.
 * -------------------------------------------------------------------------
 */
/* anchor_addr() is defined as a static inline in kasld/internal.h. */

const char *result_method(const struct result *r) {
  if (!r || r->provenance_count == 0 || r->methods[0][0] == '\0')
    return "unknown";
  return r->methods[0];
}

const char *result_origin(const struct result *r) {
  if (!r || r->provenance_count == 0)
    return "";
  return r->origins[0];
}

const char *result_section(const struct result *r) {
  if (!r)
    return "";
  return region_info[r->region].section_name;
}

int in_bounds(const struct result *r) { return result_in_bounds(r, &layout); }

/* -------------------------------------------------------------------------
 * Output helpers
 * -------------------------------------------------------------------------
 */
/* Display heading for a (type, section) bucket. Every section can in
 * principle receive both virt and phys observations — components like
 * dmesg_check_for_initrd emit each leaked initrd address twice (one
 * V/INITRD sample, one P/INITRD sample via directmap_virt_to_phys()) —
 * so the heading must distinguish the two so the user doesn't see a
 * "Physical DRAM" line full of 0xc000... virt addresses on a coupled
 * arch. Phys-rooted sections (dram / mmio) carry a type-aware label so
 * that a VIRT directmap mirror renders as "(virtual mirror via direct
 * map)" instead of "Physical" — the address IS virtual, but the
 * underlying region is the same phys instance. */
const char *section_display_name(enum kasld_addr_type type,
                                 const char *section) {
  int virt = (type == KASLD_TYPE_VIRT);
  if (strcmp(section, "text") == 0)
    return virt ? "Kernel text (virtual)" : "Kernel text (physical)";
  if (strcmp(section, "module") == 0)
    return virt ? "Kernel modules (virtual)" : "Kernel modules (physical)";
  if (strcmp(section, "directmap") == 0)
    return "Direct map (virtual)"; /* directmap is virt by definition */
  if (strcmp(section, "data") == 0)
    return virt ? "Kernel data (virtual)" : "Kernel data (physical)";
  if (strcmp(section, "bss") == 0)
    return virt ? "Kernel BSS (virtual)" : "Kernel BSS (physical)";
  if (strcmp(section, "dram") == 0)
    return virt ? "DRAM region (virtual mirror)" : "Physical DRAM";
  if (strcmp(section, "mmio") == 0)
    return virt ? "MMIO region (virtual mirror)" : "Physical MMIO";
  if (strcmp(section, "pageoffset") == 0)
    return NULL; /* metadata, not a leak group */
  return "Unknown";
}

/* (type, section) span across all in-bounds results. */
void section_range(enum kasld_addr_type type, const char *section,
                   unsigned long *out_lo, unsigned long *out_hi) {
  unsigned long lo = 0, hi = 0;
  int found = 0;
  for (int i = 0; i < num_results; i++) {
    const struct result *r = &results[i];
    if (r->type != type || strcmp(result_section(r), section) != 0)
      continue;
    if (!in_bounds(r))
      continue;
    unsigned long rlo =
        HAS_LO(r) ? r->lo : (HAS_SAMPLE(r) ? r->sample : anchor_addr(r));
    unsigned long rhi =
        HAS_HI(r) ? r->hi : (HAS_SAMPLE(r) ? r->sample : anchor_addr(r));
    if (!found || rlo < lo)
      lo = rlo;
    if (rhi > hi)
      hi = rhi;
    found = 1;
  }
  *out_lo = found ? lo : 0;
  *out_hi = found ? hi : 0;
}

/* Pick the most-base-like in-bounds record for a (type, section, optional
 * region_filter): every observation in a section satisfies
 *
 *     addr = region_base + non_negative_offset
 *
 * so the address closest to the base is the most informative consensus for
 * "where does this region start?" — true for every section the renderer
 * emits (text/data/bss start at their lowest address; directmap, dram,
 * mmio, module each have an offset-from-base interpretation per
 * observation). Picking by address alone would be fragile against a
 * spurious low-confidence outlier, and picking by "first highest-conf"
 * (the previous rule) gave order-dependent output that surfaced confusing
 * results — e.g. directmap consensus landing on a NUMA top instead of the
 * directmap base when three CONF_PARSED dmesg observations tied on
 * confidence. The ordering used here is layered:
 *
 *   1. Highest CONF (an exact landmark trumps a dmesg snippet).
 *   2. Prefer POS_BASE over POS_INTERIOR/POS_TOP at that confidence
 *      (an explicit "base of this region" observation trumps a sample
 *      that merely lives inside the region).
 *   3. Lowest anchor address (closest to the base — the tightest
 *      upper bound on the true base among same-grade observations).
 *
 * `region_filter`: REGION_UNKNOWN includes every region in the section;
 * any other value restricts to that exact region. Subgroup-displayed
 * blocks (e.g. "Physical DRAM / crashkernel") must pass the same filter
 * they use for the displayed records, otherwise the printed `==>` value
 * may not appear in the printed record list — exposed on ppc64 where the
 * section-wide DRAM consensus (the lowest initrd record) was being
 * displayed in the crashkernel subgroup's `==>` line.
 *
 * Returns NULL when no in-bounds record matches. Shared by
 * section_consensus and section_consensus_info so the printed value and
 * the printed source/conflict counts always describe the same record.
 */
static const struct result *
section_consensus_pick(enum kasld_addr_type type, const char *section,
                       enum kasld_region region_filter) {
  const struct result *anchor = NULL;
  int best_w = -1;
  int best_is_base = 0;
  unsigned long best_addr = 0;
  for (int i = 0; i < num_results; i++) {
    const struct result *r = &results[i];
    if (r->type != type || strcmp(result_section(r), section) != 0)
      continue;
    if (region_filter != REGION_UNKNOWN && r->region != region_filter)
      continue;
    if (!in_bounds(r))
      continue;
    int w = conf_weight(r->conf);
    int is_base = (r->pos == POS_BASE);
    unsigned long a = anchor_addr(r);
    int better = 0;
    if (w > best_w)
      better = 1; /* layer 1: higher confidence wins outright */
    else if (w == best_w && is_base && !best_is_base)
      better = 1; /* layer 2: prefer POS_BASE at this confidence */
    else if (w == best_w && is_base == best_is_base &&
             (!anchor || a < best_addr))
      better = 1; /* layer 3: prefer the lowest anchor (closest to base) */
    if (better) {
      best_w = w;
      best_is_base = is_base;
      best_addr = a;
      anchor = r;
    }
  }
  return anchor;
}

/* Scan results[] for (type, section, optional region_filter) and report:
 *   *best_method      — method of the consensus record
 *   *n_sources        — number of records matching the filter whose anchor
 *                       address equals the consensus anchor (i.e.
 *                       "agreeing" sources)
 *   *n_conflicts      — count of in-bounds records (within the filter)
 *                       with a different anchor
 *
 * The filter scope MUST match what the displayed records use, so the
 * printed `==>` line is computed over the same set the user sees.
 */
void section_consensus_info(enum kasld_addr_type type, const char *section,
                            enum kasld_region region_filter,
                            const char **best_method, int *n_sources,
                            int *n_conflicts) {
  const struct result *anchor =
      section_consensus_pick(type, section, region_filter);
  if (!anchor) {
    *best_method = "unknown";
    *n_sources = 0;
    *n_conflicts = 0;
    return;
  }
  *best_method = result_method(anchor);

  unsigned long best_addr = anchor_addr(anchor);
  int sources = 0, conflicts = 0;
  for (int i = 0; i < num_results; i++) {
    const struct result *r = &results[i];
    if (r->type != type || strcmp(result_section(r), section) != 0)
      continue;
    if (region_filter != REGION_UNKNOWN && r->region != region_filter)
      continue;
    if (!in_bounds(r))
      continue;
    if (anchor_addr(r) == best_addr)
      sources++;
    else
      conflicts++;
  }
  *n_sources = sources;
  *n_conflicts = conflicts;
}

/* Anchor address for a (type, section, optional region_filter). See
 * section_consensus_pick for the selection rule; returns 0 when no
 * in-bounds record matches. */
unsigned long section_consensus(enum kasld_addr_type type, const char *section,
                                enum kasld_region region_filter) {
  const struct result *anchor =
      section_consensus_pick(type, section, region_filter);
  return anchor ? anchor_addr(anchor) : 0;
}

/* Count of CONF_DERIVED records currently in results[]. Shared between
 * text and markdown renderers (both gate the "Derived" block on it). */
int count_derived(void) {
  int n = 0;
  for (int i = 0; i < num_results; i++)
    if (results[i].conf == CONF_DERIVED)
      n++;
  return n;
}

/* -------------------------------------------------------------------------
 * Summary renderer: dispatch a fully-computed summary to the chosen format.
 * Pure consumer — resolution (the engine) runs in the orchestrator layer
 * (emit_summary -> compute_kaslr_info) BEFORE this is called, so rendering
 * never drives inference.
 * -------------------------------------------------------------------------
 */
void render_summary(const struct summary *s) {
  if (json_output)
    render_json(s);
  else if (oneline_output)
    render_oneline(s);
  else if (markdown_output)
    render_markdown(s);
  else
    render_text(s);
}
