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
#include "include/kasld/report.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>

/* Human-readable size: format bytes as "N.N KiB/MiB/GiB/TiB" */
const char *human_size(unsigned long bytes, char *buf, size_t bufsz) {
#if ULONG_MAX > 0xFFFFFFFFul
  if (bytes >= PB)
    snprintf(buf, bufsz, "%.1f PiB", (double)bytes / (double)PB);
  else if (bytes >= TB)
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
 * convention. A merged record carries method_set (the union of its
 * contributors' methods); the single display value is the strongest method
 * present, which stays consistent with the record's resolved confidence.
 * -------------------------------------------------------------------------
 */
/* anchor_addr() is defined as a static inline in kasld/internal.h. */

const char *result_method(const struct result *r) {
  if (!r)
    return "unknown";
  return kasld_method_set_strongest(r->method_set);
}

const char *result_section(const struct result *r) {
  if (!r)
    return "";
  return region_info[r->region].section_name;
}

int in_bounds(const struct result *r) { return result_in_bounds(r, &layout); }

/* Canonical section iteration order shared by every renderer's per-(type,
 * section) grouping. NULL-terminated. type_order stays per-mode (markdown
 * lists physical first), so only the section list is shared here. */
const char *const kasld_render_sections[] = {
    "text", "module", "directmap", "data", "bss", "dram", "mmio", NULL};

/* The guaranteed image-base window is still a range, not pinned to one value —
 * so a concrete base presented against it is speculative, not proven. The
 * single authoritative test of the window-vs-pin distinction for renderers. */
int kaslr_virt_is_window(void) {
  return layout.virt_kaslr_text_max != layout.virt_kaslr_text_min;
}
int kaslr_phys_is_window(void) {
  return layout.phys_kaslr_text_max != layout.phys_kaslr_text_min;
}

/* The compile-time default, phrased as a remark on the resolved image base.
 *
 * The default is a link-time constant, not a measurement, so it fits neither
 * grade the output uses: it is not proven, and it is not a guess drawn from
 * evidence. Every format states it as a plain sentence — which cannot be
 * mistaken for a resolved value — carrying the only thing evidence has to say
 * about it: whether the resolved bounds leave it standing. One sentence, built
 * here, so no two formats can word the same fact differently.
 *
 * The verdict is a property of the bounds and never of how a format drew them,
 * so a single test covers a pin, a closed range and either half-bound: the
 * default is ruled out exactly when a known edge lies on the wrong side of it.
 * An unknown edge rules nothing out. A pin that is not the default falls out of
 * the same test, with no separate case.
 *
 * Containment is not corroboration. An Alpine armv7 kernel built VMSPLIT_2G has
 * _text at 0x80008000 while the arch default 0xc0008000 sits inside the proven
 * bounds, so the surviving verdict claims only that the default is possible.
 *
 * Returns NULL when there is nothing to say: no default, nothing resolved, or
 * the default IS the resolved base — restating a printed address reads as a
 * competing claim. `addr_text` is the caller's rendering of `def`, so each
 * format keeps its own address style. */
const char *default_base_remark(unsigned long def, unsigned long lo,
                                unsigned long hi, const char *addr_text,
                                char *buf, size_t bufsz) {
  if (!def || (!lo && !hi) || (def == lo && def == hi))
    return NULL;
  int ruled_out = (lo && def < lo) || (hi && def > hi);
  snprintf(buf, bufsz,
           "The compile-time default for this architecture is %s, %s.",
           addr_text, ruled_out ? "ruled out" : "still possible");
  return buf;
}

/* Slot pitch without a trailing ".0" — the pitch is exact by construction, so
 * the decimal is noise. Trimmed here rather than in human_size(), which also
 * formats measured sizes elsewhere (and oneline's fixed-schema `dram=`).
 * The map's gap sizes share it: a gap between two exact edges is exact too,
 * and "16.0 MiB" claims a precision the ".0" does not carry. */
const char *kasld_grain(unsigned long align, char *buf, size_t sz) {
  char t[32];
  human_size(align, t, sizeof(t));
  char *dot = strstr(t, ".0");
  if (dot)
    memmove(dot, dot + 2, strlen(dot + 2) + 1);
  snprintf(buf, sz, "%s", t);
  return buf;
}

/* The displacement of a base from the un-randomized one it was drawn against,
 * as a trailing note on the address rather than a column: it is the same value
 * in another coordinate system, and only a concrete base has one. */
const char *readout_slide(long slide, char *buf, size_t sz) {
  unsigned long mag = (unsigned long)(slide < 0 ? -slide : slide);
  snprintf(buf, sz, "slide %s0x%lx", slide < 0 ? "-" : "+", mag);
  return buf;
}

/* What a component actually disclosed this run, read off the records the
 * orchestrator attributed to it rather than off a declaration.
 *
 * Both kinds carry their producer: an address record's origin_set is indexed by
 * discovery slot, and a scalar fact stores the slot outright. A component that
 * reached OUTCOME_SUCCESS emitted at least one of the two by construction --
 * kasld_classify_outcome() sets it from had_tagged, and handle_component_line()
 * counts only address and scalar records toward that, never an R disposition.
 * So for any succeeding component this answers exactly, and cannot drift from
 * what was actually observed the way a hand-declared field can.
 *
 * Returns NULL when the component disclosed nothing this run, which is the
 * caller's cue that it has nothing to say rather than an invitation to guess.
 */
const char *component_disclosed(int slot) {
  int virt = 0, phys = 0, facts = 0;
  if (slot < 0)
    return NULL;
  for (int i = 0; i < num_results; i++) {
    if (!origin_set_has(&results[i].origins, slot))
      continue;
    if (results[i].type == KASLD_TYPE_VIRT)
      virt = 1;
    else if (results[i].type == KASLD_TYPE_PHYS)
      phys = 1;
  }
  for (int i = 0; i < num_scalar_facts; i++)
    if (scalar_facts[i].origin == slot)
      facts = 1;
  if (virt && phys)
    return DISCLOSE_BOTH;
  if (virt)
    return DISCLOSE_VIRT;
  if (phys)
    return DISCLOSE_PHYS;
  if (facts)
    return DISCLOSE_FACTS;
  return NULL;
}

/* The same phrase from a DECLARED `discloses:` value, for the report sections
 * that list a component whether or not it produced anything -- a side channel
 * that stayed flat, or a compiled-in surface that never ran. There is nothing
 * to observe there, so the technique's own claim is all there is.
 *
 * Returns NULL for an absent or unrecognised value. Callers must not substitute
 * a default: an unstated disclosure is unknown, and rendering it as one of the
 * kinds states something the component never claimed. */
const char *disclosure_descr(const char *declared) {
  if (!declared)
    return NULL;
  if (strcmp(declared, "virtual") == 0)
    return DISCLOSE_VIRT;
  if (strcmp(declared, "physical") == 0)
    return DISCLOSE_PHYS;
  if (strcmp(declared, "both") == 0)
    return DISCLOSE_BOTH;
  if (strcmp(declared, "facts") == 0)
    return DISCLOSE_FACTS;
  return NULL;
}

/* ---------------------------------------------------------------------------
 * The Layout table's row model.
 *
 * Built once here and rendered by each format, so the text readout and the
 * markdown report cannot describe the same resolved state differently -- the
 * failure this layer has had to be corrected for twice. A row carries only
 * strings: which cells are emphasised, and how, is a presentation decision each
 * renderer makes for itself.
 * ------------------------------------------------------------------------- */

struct layout_row layout_rows[LAYOUT_MAX_ROWS];
int n_layout_rows;

/* Column names, chosen for what each cell actually holds.
 *
 * Certainty, not Basis: the cell says how much the claim can be trusted, and
 * "guaranteed" is a level of assurance rather than a foundation.
 *
 * Window, not Range: the cell holds a pin, a half-bound, or a span whose
 * interior may be carved -- "range" is accurate for only one of the three and
 * asserts a contiguity the others do not have.
 *
 * Candidates, not a count of placements or slots: the quantity being counted is
 * not always a location, and a paging level has candidates but no slots.
 *
 * Grain, not Align: the cell gives the spacing the candidates sit on, which is
 * what makes the count beside it mean anything, and does not claim the value is
 * exact where the engine knows only a floor. */
const char *const layout_hdr[LAYOUT_COLS] = {"Quantity", "Certainty", "Window",
                                             "Candidates", "Grain"};

/* The candidate count, against the set the row narrows: a guaranteed row
 * narrows the window the kernel randomized over, a likely row narrows the
 * guaranteed set above it. One rule for the whole column, so a reader need not
 * work out why some rows carry a denominator and others do not.
 *
 * The column reports the size of the set still to be searched, whether or not
 * evidence shrank it. A row that narrowed nothing still has a size worth
 * stating -- it is what a baseline run is for -- so only the absence of a
 * MODELLED set withholds the figure. That is the sole meaning of "-": no
 * window is modelled for this quantity, so there is no count to give -- vmalloc
 * and vmemmap, whose randomization windows are not modelled at all, and the
 * direct map on a run with no max_pfn, since its window is sized from that
 * observation rather than fixed by the architecture. "Nothing was learned" is
 * carried by the Window column reading `not narrowed`, not by a blank here.
 *
 * `top` is a raw count: 2^bits would over-state it, since ilog2 rounds up. It
 * is dropped as a denominator when it does not exceed the row's own count,
 * since a window that narrowed nothing has no fraction to report. Where the
 * estimate carries no bounds at all, `top` alone is the answer. A likely row is
 * a subset of the guaranteed one by construction, so N > M here would be a
 * visible contract violation. */
static void layout_fmt_space(char *buf, size_t sz, unsigned long slots,
                             unsigned long top) {
  if (!slots && !top)
    snprintf(buf, sz, "-");
  else if (!slots)
    /* No count, but the set it would have been counted against is known. The
     * denominator alone was printed here, which in a column headed Candidates
     * asserts that figure AS the count -- and it is not one: a window with an
     * unstated edge is unbounded, so what remains is not knowable, while the
     * denominator is merely the size of the set the row narrows. Stating it as
     * "- of N" keeps the size of the problem visible and says outright that
     * nothing was counted. A run that narrowed nothing still shows a bare
     * total, because there the count and the denominator are one figure and
     * `slots` carries it. */
    snprintf(buf, sz, "- of %lu", top);
  else if (top > slots)
    snprintf(buf, sz, "%lu of %lu", slots, top);
  else
    snprintf(buf, sz, "%lu", slots);
}

/* Addresses are never zero-padded here, matching the rest of the readout: a
 * 16 MiB physical address does not wear the costume of a 64-bit pointer. */
static void layout_fmt_range(char *buf, size_t sz, unsigned long lo,
                             unsigned long hi, const char *note) {
  char tail[32];
  tail[0] = '\0';
  if (note && *note)
    snprintf(tail, sizeof(tail), " %s", note);
  if (lo && hi && lo == hi)
    snprintf(buf, sz, "0x%lx%s", lo, tail);
  else if (lo && hi)
    snprintf(buf, sz, "0x%lx - 0x%lx%s", lo, hi, tail);
  else if (lo)
    snprintf(buf, sz, ">= 0x%lx%s", lo, tail);
  else if (hi)
    snprintf(buf, sz, "<= 0x%lx%s", hi, tail);
  else
    snprintf(buf, sz, "not narrowed");
}

/* A row. `slots` of 0 withholds the search space -- the caller decides what is
 * a bound worth acting on; `top` is the set the row narrows, and is dropped
 * unless it exceeds `slots`.
 *
 * Not called directly by the projection below: it takes loose scalars, which is
 * what let a row state a number no window held. layout_add_window() is the way
 * in; this stays private to it and to the set-shaped row, which has values
 * rather than edges. */
static void layout_add(const char *quantity, const char *basis,
                       unsigned long slots, unsigned long top, unsigned long lo,
                       unsigned long hi, const char *note,
                       unsigned long align) {
  char gb[32];
  struct layout_row *r;
  if (n_layout_rows >= LAYOUT_MAX_ROWS)
    return;
  r = &layout_rows[n_layout_rows++];
  memset(r, 0, sizeof(*r));
  snprintf(r->cell[0], LAYOUT_CELL, "%s", quantity);
  snprintf(r->cell[1], LAYOUT_CELL, "%s", basis);
  layout_fmt_range(r->cell[2], LAYOUT_CELL, lo, hi, note);
  layout_fmt_space(r->cell[3], LAYOUT_CELL, slots, top);
  r->lo = lo;
  r->hi = hi;
  r->slots = slots;
  r->top = top;
  r->align = align;
  snprintf(r->note, sizeof(r->note), "%s", note ? note : "");
  snprintf(r->cell[4], LAYOUT_CELL, "%s",
           align ? kasld_grain(align, gb, sizeof(gb)) : "-");
  r->dim = (!lo && !hi);
  r->one_address = (lo && lo == hi);
}

/* The set a row narrows: the kernel's own randomization window for a proven
 * row, and the proven row's own count for the speculative one beneath it.
 * Determined by which grade the row carries, so no caller chooses it. */
static unsigned long layout_row_top(const struct kasld_report_quantity *it,
                                    const char *basis) {
  if (strcmp(basis, GRADE_GUARANTEED) != 0)
    return it->guaranteed.candidates;
  /* What the proven row narrows depends on the KIND of quantity. An interval
   * narrows the window the kernel randomizes over, and where the architecture
   * models no such window there is no denominator to state -- a region base is
   * bounded by structure rather than by a randomization range. A set narrows
   * the values the architecture admits, and that count is its denominator: "1
   * of 2" says one of the two paging levels this target could be running. */
  return it->guaranteed.shape == RSHAPE_SET ? it->search_top : it->entropy_top;
}

/* The slide note for a row, or NULL.
 *
 * A slide is the displacement of a RESOLVED value from the un-randomized base,
 * so it belongs to a window that names one address and to no other: measured
 * from one end of a range it is not a measurement of anything. The picked base
 * must also BE that address -- the slide was computed from the pick, and
 * attaching it to a window resolved elsewhere would label one value with the
 * displacement of another. */
static const char *layout_row_slide(const struct kasld_report_quantity *it,
                                    const struct kasld_report_window *w,
                                    char *buf, size_t bufsz) {
  if (!it->has_slide || w->candidates != 1 || !w->has_lo || !w->has_hi)
    return NULL;
  if (w->lo != w->hi)
    return NULL;
  if (it->has_point && it->point != w->lo)
    return NULL;
  return readout_slide(it->slide, buf, bufsz);
}

/* One row, drawn from one resolved window.
 *
 * Everything the row states is read from the model: the addresses from the
 * window's edges, the count from the window's own `candidates`, the pitch from
 * the item's grain. A caller supplies WHICH window to draw and, at most, a note
 * beside it -- it cannot supply the numbers.
 *
 * That is the whole point of the signature. The previous one took the count as
 * a plain parameter, and a caller that believed it had the answer could pass a
 * literal beside a window holding many candidates: a row read "1 of 472" while
 * the engine, and json reading the same engine, said 33. A format that can
 * assert a count can contradict the engine, and two formats asserting
 * separately can contradict each other. Here there is nothing to assert. */
static void layout_add_window(const struct kasld_report_quantity *it,
                              const char *basis,
                              const struct kasld_report_window *w,
                              const char *note) {
  layout_add(it->label, basis, w->candidates, layout_row_top(it, basis),
             w->has_lo ? w->lo : 0, w->has_hi ? w->hi : 0, note, it->align_min);
}

/* A row stating a set of admissible values.
 *
 * The Window cell holds the values, comma-separated, because that IS the set --
 * writing them out is not a flattening the way squeezing them into endpoints
 * would be. There is no grid under a set, so the Grain cell stays empty, and
 * the count is exact rather than an upper bound: the values are enumerated, not
 * counted over a pitch. */
static void layout_add_set(const char *quantity, const char *basis,
                           const unsigned long *values, int n_values,
                           unsigned long top) {
  struct layout_row *r;
  int used = 0;
  if (n_layout_rows >= LAYOUT_MAX_ROWS || n_values <= 0)
    return;
  r = &layout_rows[n_layout_rows++];
  memset(r, 0, sizeof(*r));
  snprintf(r->cell[0], LAYOUT_CELL, "%s", quantity);
  snprintf(r->cell[1], LAYOUT_CELL, "%s", basis);
  for (int i = 0; i < n_values && used < LAYOUT_CELL - 1; i++)
    used += snprintf(r->cell[2] + used, (size_t)(LAYOUT_CELL - used), "%s%lu",
                     i ? ", " : "", values[i]);
  layout_fmt_space(r->cell[3], LAYOUT_CELL, (unsigned long)n_values, top);
  snprintf(r->cell[4], LAYOUT_CELL, "-");
  r->slots = (unsigned long)n_values;
  r->top = top;
  r->is_set = 1;
  /* `one_address` stays clear even for a set resolved to a single value: a
   * paging level is a parameter of the search, not a placement recovered by it,
   * so it does not take the weight the readout reserves for an address. A
   * single remaining value is already legible as resolved -- it is the only one
   * in the cell. */
}

/* Build the rows for this run, in the fixed order the readout presents.
 */
/* Project the report model into the table's rows.
 *
 * One loop over the items, not a passage per quantity: the model decides which
 * unknowns this machine has and what is proven about each, so a format's job is
 * to lay them out, never to choose them. That is what stops two formats naming
 * different sets, and what stops a posture quietly presenting its own.
 *
 * An item becomes one row, or two where a speculative answer exists beneath the
 * proven window. A row is a presentation of a grade; the item carries both
 * grades, and which of them becomes a row is decided here rather than stored.
 */
void layout_build(void) {
  const struct kasld_report *rep = render_report();
  char note[48];

  n_layout_rows = 0;
  if (!rep)
    return;

  for (int i = 0; i < rep->n_quantities; i++) {
    const struct kasld_report_quantity *it = &rep->quantities[i];
    const struct kasld_report_window *g = &it->guaranteed;
    int pinned;

    /* A set of admissible values is not a window: it has no endpoints and no
     * grid, so it gets a row shaped for a set rather than being squeezed into
     * the range cell. */
    if (g->shape == RSHAPE_SET) {
      if (!g->present)
        continue;
      layout_add_set(it->label, GRADE_GUARANTEED, g->values, g->n_values,
                     layout_row_top(it, GRADE_GUARANTEED));
      if (kasld_report_likely_is_tighter(it))
        layout_add_set(it->label, GRADE_LIKELY, it->likely.values,
                       it->likely.n_values, layout_row_top(it, GRADE_LIKELY));
      continue;
    }
    if (!g->present)
      continue;

    pinned = g->has_lo && g->has_hi && g->lo == g->hi;

    /* A slide is a displacement from the un-randomized base, so it carries
     * meaning only where something randomized. In the static postures the line
     * above the table already says nothing did, and the note would restate it
     * in a form that reads as evidence of movement. */
    layout_add_window(it, GRADE_GUARANTEED, g,
                      layout_row_slide(it, g, note, sizeof(note)));

    if (pinned)
      continue; /* the proven row already states the single answer */

    /* The speculative window beneath the proven one, where the all-signals
     * resolution reached further.
     *
     * The concrete headline base is NOT drawn here, and that is deliberate. It
     * is picked by scanning the observations, and the observation it comes from
     * has already been given to the engine -- so whatever it establishes is in
     * this window already. Where it witnesses a base the engine pinned it, and
     * the window says one candidate; where it is an interior sample the engine
     * bounded the region, and the window's top edge IS that sample. Drawing the
     * point beside the window therefore adds nothing in the first case and
     * contradicts the window in the second, by presenting a ceiling as an
     * answer and one candidate where the engine counted many. The window is the
     * authority on how much is left; a picked address can only ever name one of
     * the values it admits. */
    if (kasld_report_likely_is_tighter(it)) {
      const struct kasld_report_window *l = &it->likely;
      const char *n = NULL;
      /* The direct map has no compile-time default to slide from, but it does
       * have an offset from the base the kernel would have used un-randomized
       * -- the same value in another coordinate system, so it takes the slide's
       * place. Shown only once the window admits a single value, since an
       * offset measured from one end of a range is not a measurement of the
       * base. Measured against the base for the paging level actually in force:
       * the two are 59.6 PiB apart, so the wrong one renders as a large
       * negative number that still reads as a measurement. */
      if (l->candidates == 1 && l->has_hi && it->q == Q_PAGE_OFFSET &&
          layout.virt_page_offset_unrandomized) {
        long d = (long)(l->hi - layout.virt_page_offset_unrandomized);
        snprintf(note, sizeof(note), "off %s0x%lx", d < 0 ? "-" : "+",
                 (unsigned long)(d < 0 ? -d : d));
        n = note;
      }
      if (!n)
        n = layout_row_slide(it, l, note, sizeof(note));
      layout_add_window(it, GRADE_LIKELY, l, n);
    }
  }
}

/* Whether the row model resolved anything worth drawing.
 *
 * A row is dim exactly when neither edge was bounded, so a model with no
 * un-dim row describes a run that resolved nothing and has no table to show.
 * Asked of the model rather than of the summary's slot counts: the two agree
 * wherever KASLR ran, and diverge exactly where it did not -- a disabled kernel
 * has no slots to count, since nothing was randomized, while its rows carry a
 * fully resolved window. A format gating on the counts therefore drew nothing
 * in the one posture whose answer is already known. */
int layout_has_resolved(void) {
  for (int i = 0; i < n_layout_rows; i++)
    if (!layout_rows[i].dim)
      return 1;
  return 0;
}

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
 * map)" instead of "Physical" - the address IS virtual, but the
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

/* Span of the in-bounds results in a (type, section, optional region_filter).
 * The filter scope MUST match what the caller displays, so the reported span
 * describes the same records the consumer sees — the same requirement the
 * consensus helpers carry. */
void section_range(enum kasld_addr_type type, const char *section,
                   enum kasld_region region_filter, unsigned long *out_lo,
                   unsigned long *out_hi) {
  unsigned long lo = 0, hi = 0;
  int found = 0;
  for (int i = 0; i < num_results; i++) {
    const struct result *r = &results[i];
    if (r->type != type || strcmp(result_section(r), section) != 0)
      continue;
    if (region_filter != REGION_UNKNOWN && r->region != region_filter)
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

/* Count the distinct component origins contributing in-bounds records to a
 * (type, section, optional region_filter). A record may credit several
 * components (merged provenance); each distinct origin counts once. */
int section_source_count(enum kasld_addr_type type, const char *section,
                         enum kasld_region region_filter) {
  struct origin_set seen;
  memset(&seen, 0, sizeof(seen));
  for (int i = 0; i < num_results; i++) {
    const struct result *r = &results[i];
    if (r->type != type || strcmp(result_section(r), section) != 0)
      continue;
    if (region_filter != REGION_UNKNOWN && r->region != region_filter)
      continue;
    if (!in_bounds(r))
      continue;
    /* Contributors are a set, so accumulating across records de-duplicates
     * for free. */
    origin_set_union(&seen, &r->origins);
  }
  return origin_set_count(&seen);
}

/* True when a (type, section, optional region_filter) carries no edge (lo/hi)
 * record — every in-bounds record is a bare interior sample. Such a section
 * has no single "base": the samples corroborate an extent, they do not compete
 * for one address, so consensus/conflict counting does not apply to it. */
int section_is_interior_only(enum kasld_addr_type type, const char *section,
                             enum kasld_region region_filter) {
  int found = 0;
  for (int i = 0; i < num_results; i++) {
    const struct result *r = &results[i];
    if (r->type != type || strcmp(result_section(r), section) != 0)
      continue;
    if (region_filter != REGION_UNKNOWN && r->region != region_filter)
      continue;
    if (!in_bounds(r))
      continue;
    if (HAS_LO(r) || HAS_HI(r))
      return 0; /* an edge claim exists → not interior-only */
    found = 1;
  }
  return found;
}

/* Scan results[] for (type, section, optional region_filter) and report:
 *   *best_method   — method of the consensus record
 *   *n_sources     — for an edge section, records whose anchor equals the
 *                    consensus anchor ("agreeing" sources); for an
 * interior-only section, the distinct contributing components *n_conflicts   —
 * records with a different anchor for an edge section; always 0 for an
 * interior-only section (interior samples corroborate an extent, they never
 * conflict) *interior_only — 1 when the section carries only interior samples
 * (no edge), so callers can present a span instead of a single "base"
 *
 * The filter scope MUST match what the displayed records use, so the
 * printed `==>` line is computed over the same set the user sees.
 */
void section_consensus_info(enum kasld_addr_type type, const char *section,
                            enum kasld_region region_filter,
                            const char **best_method, int *n_sources,
                            int *n_conflicts, int *interior_only) {
  const struct result *anchor =
      section_consensus_pick(type, section, region_filter);
  if (!anchor) {
    *best_method = "unknown";
    *n_sources = 0;
    *n_conflicts = 0;
    *interior_only = 0;
    return;
  }
  *best_method = result_method(anchor);
  /* Sources are the distinct contributing components — the intuitive "how many
   * components found this region", not the records that happen to share the
   * winning address (which undercounts when they corroborate at different
   * points). */
  *n_sources = section_source_count(type, section, region_filter);
  *interior_only = section_is_interior_only(type, section, region_filter);

  /* Conflicts count genuine disagreements about the region's base: distinct
   * lo-edge (base) addresses beyond the first. Interior-only sections have no
   * base to disagree on, and dram/mmio are multi-segment coverings (every
   * segment carries its own base) rather than one contested base — both are 0.
   * Interior samples and top edges are never base claims, so they corroborate
   * the region rather than conflicting with it. */
  if (*interior_only || strcmp(section, "dram") == 0 ||
      strcmp(section, "mmio") == 0) {
    *n_conflicts = 0;
    return;
  }
  unsigned long bases[MAX_RESULTS];
  int nb = 0;
  for (int i = 0; i < num_results; i++) {
    const struct result *r = &results[i];
    if (r->type != type || strcmp(result_section(r), section) != 0)
      continue;
    if (region_filter != REGION_UNKNOWN && r->region != region_filter)
      continue;
    if (!in_bounds(r) || !HAS_LO(r))
      continue;
    int dup = 0;
    for (int j = 0; j < nb; j++)
      if (bases[j] == r->lo) {
        dup = 1;
        break;
      }
    if (!dup && nb < MAX_RESULTS)
      bases[nb++] = r->lo;
  }
  *n_conflicts = nb > 1 ? nb - 1 : 0;
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
/* The report model for the run being rendered.
 *
 * Held here for the duration of a render rather than threaded through every
 * format, because layout_build() is called from five places inside the format
 * modules and none of them should have to carry it. Transitional: it replaces
 * reads of four separate globals with one pointer to the finished model, and it
 * goes away when the formats take the model as a parameter. */
static const struct kasld_report *g_render_report;

const struct kasld_report *render_report(void) { return g_render_report; }

void render_summary(const struct summary *s, const struct kasld_report *rep) {
  g_render_report = rep;
  if (json_output)
    render_json(s);
  else if (oneline_output)
    render_oneline(s);
  else if (markdown_output)
    render_markdown(s);
  else
    render_text(s);
}
