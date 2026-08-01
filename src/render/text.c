// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Text mode renderer — the default output and the verbose (-v) flow, plus
// the supporting "readout", KASLR analysis, derived addresses, and
// virtual + physical ASCII memory layout blocks.
//
// Cross-file helpers (section_consensus, in_bounds, human_size, etc.) are
// declared in include/kasld/render_internal.h and defined in render.c.
// ---
// <bcoles@gmail.com>

#include "include/kasld/internal.h"
#include "include/kasld/render_internal.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <unistd.h>

/* Un-randomized direct-map base — the reference for the direct map's
 * RANDOMIZE_MEMORY offset in the readout. x86_64-only; 0 elsewhere, where the
 * direct-map base promotion that uses it never fires (gated on
 * RANDOMIZE_MEMORY_ALIGN > 0). */
#ifndef PAGE_OFFSET_BASE_L4
#define PAGE_OFFSET_BASE_L4 0ul
#endif

/* Group key for "already printed" tracking. Sections are short, fixed
 * strings from region_info[].section_name — copy by pointer (those are
 * static literals owned by region_info.c). */
struct group_key {
  enum kasld_addr_type type;
  const char *section;
};

static struct group_key printed_groups[32];
static int num_printed_groups;

static int group_already_printed(enum kasld_addr_type type,
                                 const char *section) {
  for (int i = 0; i < num_printed_groups; i++) {
    if (printed_groups[i].type == type &&
        strcmp(printed_groups[i].section, section) == 0)
      return 1;
  }
  return 0;
}

static void mark_group_printed(enum kasld_addr_type type, const char *section) {
  if (num_printed_groups < 32) {
    printed_groups[num_printed_groups].type = type;
    printed_groups[num_printed_groups].section = section;
    num_printed_groups++;
  }
}

/* Extent-position disclosure for a leaked address. Every leak row states
 * whether the address is the region base, an interior sample, or the top edge,
 * so none is ambiguous and the base (the prize) is called out, not left
 * implicit. All three positions are reachable in these rows. Empty
 * only for the shouldn't-reach-here extent/unknown. The caller pads to a fixed
 * width (`%-11s`, the width of " [interior]") where a column follows. */
static const char *pos_note(const struct result *r) {
  switch (r->pos) {
  case POS_BASE:
    return " [base]";
  case POS_INTERIOR:
    return " [interior]";
  case POS_TOP:
    return " [top]";
  default:
    return "";
  }
}

/* Render one validation block.
 *
 * region_filter: when != REGION_UNKNOWN, only include results whose
 *                r->region matches. The block heading shows
 *                "<section> / <region-wire>".
 * region_filter: when REGION_UNKNOWN, include every result in
 *                (type, section). The block heading shows just "<section>". */
static void print_group(enum kasld_addr_type type, const char *section,
                        enum kasld_region region_filter) {
  const char *name = section_display_name(type, section);
  if (!name)
    return;

  int valid_count = 0;
  for (int i = 0; i < num_results; i++) {
    if (results[i].type == type &&
        strcmp(result_section(&results[i]), section) == 0 &&
        in_bounds(&results[i]) &&
        (region_filter == REGION_UNKNOWN || results[i].region == region_filter))
      valid_count++;
  }
  if (!valid_count)
    return;

  /* Separator between groups */
  if (num_printed_groups > 0)
    printf("%s%s%s\n", c(C_DIM), "----------------------------------------",
           c(C_RESET));

  if (region_filter != REGION_UNKNOWN)
    printf("%s%s / %s%s [%d]:\n", c(C_BOLD), name,
           kasld_region_wire(region_filter), c(C_RESET), valid_count);
  else
    printf("%s%s%s [%d]:\n", c(C_BOLD), name, c(C_RESET), valid_count);

  /* Collect indices of matching results, then sort by anchor address */
  int indices[MAX_RESULTS];
  int n_indices = 0;
  for (int i = 0; i < num_results; i++) {
    if (results[i].type == type &&
        strcmp(result_section(&results[i]), section) == 0 &&
        (region_filter == REGION_UNKNOWN || results[i].region == region_filter))
      if (n_indices < MAX_RESULTS)
        indices[n_indices++] = i;
  }
  for (int i = 0; i < n_indices - 1; i++)
    for (int j = i + 1; j < n_indices; j++)
      if (anchor_addr(&results[indices[i]]) >
          anchor_addr(&results[indices[j]])) {
        int tmp = indices[i];
        indices[i] = indices[j];
        indices[j] = tmp;
      }

  unsigned long addrs[MAX_RESULTS];
  int n_addrs = 0;

  for (int k = 0; k < n_indices; k++) {
    struct result *r = &results[indices[k]];

    /* Compact form shows region (and ":name" when known); verbose adds
     * origin and method in parentheses. region+name tells the reader
     * what the address is; origin tells them which component found it. */
    char rn[64 + NAME_LEN + 2];
    if (r->name[0])
      snprintf(rn, sizeof(rn), "%s:%s", kasld_region_wire(r->region), r->name);
    else
      snprintf(rn, sizeof(rn), "%s", kasld_region_wire(r->region));

    unsigned long a = anchor_addr(r);

    if (!in_bounds(r)) {
      if (verbose) {
        char mbuf[64];
        kasld_method_set_str(r->method_set, mbuf, sizeof mbuf);
        printf("  %s0x%016lx%s  %s%s %s(", c(C_RED), a, c(C_RESET), rn,
               pos_note(r), c(C_DIM));
        for (int j = 0; j < r->provenance_count; j++)
          printf("%s%s", j ? ", " : "", r->origins[j]);
        printf(", %s, stale)%s\n", mbuf, c(C_RESET));
      } else
        printf("  %s0x%016lx%s  %s%s %s(stale)%s\n", c(C_RED), a, c(C_RESET),
               rn, pos_note(r), c(C_DIM), c(C_RESET));
      continue;
    }

    if (verbose) {
      char mbuf[64];
      kasld_method_set_str(r->method_set, mbuf, sizeof mbuf);
      printf("  %s0x%016lx%s  %s%s %s(", c(C_GREEN), a, c(C_RESET), rn,
             pos_note(r), c(C_DIM));
      for (int j = 0; j < r->provenance_count; j++)
        printf("%s%s", j ? ", " : "", r->origins[j]);
      printf(", %s)%s\n", mbuf, c(C_RESET));
    } else
      printf("  %s0x%016lx%s  %s%s\n", c(C_GREEN), a, c(C_RESET), rn,
             pos_note(r));

    int dup = 0;
    for (int j = 0; j < n_addrs; j++) {
      if (addrs[j] == a) {
        dup = 1;
        break;
      }
    }
    if (!dup && n_addrs < MAX_RESULTS)
      addrs[n_addrs++] = a;
  }

  if (n_addrs == 1) {
    const char *bm;
    int ns, nc, io;
    section_consensus_info(type, section, region_filter, &bm, &ns, &nc, &io);
    /* A lone interior sample is a point inside the region, not its base — say
     * so, rather than presenting it as the resolved address. */
    printf("  %s==>%s 0x%016lx  %s(%s, %s%d source%s)%s\n", c(C_CYAN),
           c(C_RESET), addrs[0], c(C_DIM), bm, io ? "interior sample; " : "",
           ns, ns == 1 ? "" : "s", c(C_RESET));
  } else if (n_addrs > 1) {
    const char *bm;
    int ns, nc, io;
    section_consensus_info(type, section, region_filter, &bm, &ns, &nc, &io);
    char hbuf[32];
    unsigned long span = addrs[n_addrs - 1] - addrs[0];
    if (io) {
      /* Interior-only: the samples prove the region contains [lo, hi] (a lower
       * bound on its extent). Present that span as the resolved fact — there is
       * no single base to pick, and the samples corroborate rather than
       * conflict, so the count is "N samples from M sources", never conflicts.
       */
      printf("  %s==>%s spans 0x%016lx - 0x%016lx  %s(%s; %d samples, %d "
             "source%s; %s)%s\n",
             c(C_CYAN), c(C_RESET), addrs[0], addrs[n_addrs - 1], c(C_DIM), bm,
             n_addrs, ns, ns == 1 ? "" : "s",
             human_size(span, hbuf, sizeof(hbuf)), c(C_RESET));
    } else {
      unsigned long consensus = section_consensus(type, section, region_filter);
      /* nc is a genuine competing-base count (0 for the multi-segment dram/mmio
       * coverings and for corroborating interior/top records), so it is printed
       * only when a real disagreement exists. */
      if (nc > 0)
        printf("  %s==>%s 0x%016lx  %s(%s, %d source%s, %d conflict%s)%s\n",
               c(C_CYAN), c(C_RESET), consensus, c(C_DIM), bm, ns,
               ns == 1 ? "" : "s", nc, nc == 1 ? "" : "s", c(C_RESET));
      else
        printf("  %s==>%s 0x%016lx  %s(%s, %d source%s)%s\n", c(C_CYAN),
               c(C_RESET), consensus, c(C_DIM), bm, ns, ns == 1 ? "" : "s",
               c(C_RESET));
      printf("  %s   %s range: 0x%016lx - 0x%016lx  (%s)\n", c(C_CYAN),
             c(C_RESET), addrs[0], addrs[n_addrs - 1],
             human_size(span, hbuf, sizeof(hbuf)));
    }
  }

  printf("\n");
}

/* Print one row of the Memory KASLR (CONFIG_RANDOMIZE_MEMORY) table.
 * Each region (virt_page_offset_base, virt_vmalloc_base, virt_vmemmap_base)
 * carries a (min, max) pair that compute_kaslr_info stores using 0 as the "not
 * tightened beyond the compile-time default" sentinel for either side.
 * Four display cases:
 *   both 0:        skip (nothing to show)
 *   only min set:  ">= min"
 *   only max set:  "<= max"
 *   both set, ==:  "<value> (pinned)"
 *   both set, !=:  "min - max" */
/* Speculative "likely" sub-line for a Memory KASLR region, printed (dim,
 * unlabeled name column) directly under the region's guaranteed row. lmin/lmax
 * are 0/0 when there is no likely window. A single value (lmin == lmax) is a
 * pinned best-guess; otherwise a tighter sub-range. */
/* Residual entropy, stated against the entropy the architecture's KASLR
 * started with wherever that is known. "~13 bits" alone does not tell a reader
 * whether almost everything or almost nothing was recovered. `bits_top` of 0
 * means the starting budget was not computed, and the residual stands alone.
 */
static const char *entropy_phrase(int bits, int bits_top, char *buf,
                                  size_t bufsz) {
  if (bits_top > bits)
    snprintf(buf, bufsz, "~%d of %d bits", bits, bits_top);
  else
    snprintf(buf, bufsz, "~%d bits", bits);
  return buf;
}

static void render_memory_kaslr_likely(unsigned long lmin, unsigned long lmax,
                                       unsigned long slots) {
  if (!lmin && !lmax)
    return;
  if (lmin > lmax)
    return; /* defensive: never print a backwards range */
  if (lmin == lmax) {
    printf("  %-21s %s0x%016lx           likely (speculative)%s\n", "",
           c(C_DIM), lmin, c(C_RESET));
    return;
  }
  if (slots > 1)
    printf("  %-21s %s0x%016lx - 0x%016lx  likely (speculative; %lu cand)%s\n",
           "", c(C_DIM), lmin, lmax, slots, c(C_RESET));
  else
    printf("  %-21s %s0x%016lx - 0x%016lx  likely (speculative)%s\n", "",
           c(C_DIM), lmin, lmax, c(C_RESET));
}

static void render_memory_kaslr_bound(const char *name, unsigned long min,
                                      unsigned long max, unsigned long slots,
                                      int bits, unsigned long lmin,
                                      unsigned long lmax,
                                      unsigned long likely_slots) {
  if (!min && !max)
    return;
  /* Defensive: a bottom estimate (lo > hi) would print a backwards range to
   * the user. The resolver in estimate.c rejects bottom-forcing meets, so
   * engine_sync should never sync this — but a malformed runtime cascade
   * shouldn't produce visual garbage. Drop the row rather than emit
   * "0xhigh - 0xlow". */
  if (min && max && min > max)
    return;
  /* Same notation as the compact readout: ".." over a closed candidate window,
   * an explicit grade, and the candidate count separated from the entropy. The
   * direct map appears in both views, so the two must not describe one
   * quantity two different ways. */
  if (min && !max)
    printf("  %-17s guaranteed  >= %s0x%lx%s\n", name, c(C_CYAN), min,
           c(C_RESET));
  else if (!min && max)
    printf("  %-17s guaranteed  <= %s0x%lx%s\n", name, c(C_CYAN), max,
           c(C_RESET));
  else if (min == max)
    printf("  %-17s pinned      %s0x%lx%s\n", name, c(C_GREEN), min,
           c(C_RESET));
  else if (slots > 1)
    printf("  %-17s guaranteed  0x%lx .. 0x%lx  %s%lu slots, ~%d bits%s\n",
           name, min, max, c(C_MAGENTA), slots, bits, c(C_RESET));
  else
    printf("  %-17s guaranteed  0x%lx .. 0x%lx\n", name, min, max);
  render_memory_kaslr_likely(lmin, lmax, likely_slots);
}

/* One verbose-analysis "likely (speculative)" sub-line under an inferred text
 * range. A single surviving slot (min == max) reads as a concrete best-guess
 * (pinned), not a degenerate "0xX - 0xX (1 slots, 0 bits)" range. */
static void render_kaslr_likely_line(unsigned long min, unsigned long max,
                                     unsigned long slots, int bits) {
  if (min == max)
    printf("    likely (speculative): 0x%016lx  %s(pinned)%s\n", min, c(C_DIM),
           c(C_RESET));
  else
    printf("    likely (speculative): 0x%016lx - 0x%016lx  (%s%lu%s slots, "
           "%d bits)\n",
           min, max, c(C_DIM), slots, c(C_RESET), bits);
}

/* -------------------------------------------------------------------------
 * KASLR analysis text renderer (consumes pre-computed summary)
 * -------------------------------------------------------------------------
 */
static void render_kaslr_text(const struct summary *s) {
  if (s->kaslr.disabled || s->kaslr.unsupported)
    return;
  if (!s->kaslr.vtext && !s->kaslr.ptext && s->kaslr.vslots == 0 &&
      s->kaslr.pslots == 0)
    return;

  printf("%s%s%s\n", c(C_DIM), "----------------------------------------",
         c(C_RESET));
  printf("%sKASLR analysis:%s\n", c(C_BOLD), c(C_RESET));

  int no_concrete_text = (!s->kaslr.vtext && !s->kaslr.ptext);
  if (no_concrete_text) {
    /* Inference narrowed the range(s) but no concrete address was found. */
    if (s->kaslr.vslots > 0) {
      printf("  Inferred text range:  0x%016lx - 0x%016lx\n",
             layout.virt_kaslr_text_min, layout.virt_kaslr_text_max);
      printf("  Remaining slots:      %s%lu%s  (%d bits, step %#lx)\n",
             c(C_MAGENTA), s->kaslr.vslots, c(C_RESET), s->kaslr.vbits,
             layout.virt_kaslr_align);
      if (s->kaslr.vlikely_max != 0)
        render_kaslr_likely_line(s->kaslr.vlikely_min, s->kaslr.vlikely_max,
                                 s->kaslr.vlikely_slots, s->kaslr.vlikely_bits);
    }
    if (s->kaslr.pslots > 0) {
      if (s->kaslr.vslots > 0)
        printf("\n");
      printf("  Inferred phys text range:  0x%016lx - 0x%016lx\n",
             layout.phys_kaslr_text_min, layout.phys_kaslr_text_max);
      printf("  Remaining phys slots:      %s%lu%s  (%d bits, step %#lx)\n",
             c(C_MAGENTA), s->kaslr.pslots, c(C_RESET), s->kaslr.pbits,
             layout.phys_kaslr_align);
      if (s->kaslr.plikely_max != 0)
        render_kaslr_likely_line(s->kaslr.plikely_min, s->kaslr.plikely_max,
                                 s->kaslr.plikely_slots, s->kaslr.plikely_bits);
    }
    printf("\n");
    /* Fall through to the Memory KASLR block at the end of the function —
     * memory-region bounds are independent of whether a text address
     * leaked. */
  }

  if (s->kaslr.vtext) {
    /* When the engine could only PROVE a range (guaranteed window is not a
     * single slot) yet a sub-sound-floor leak suggests one base, that base is
     * the LIKELY best-guess, not a proven address. Label it and show the
     * guaranteed range it sits inside instead of a misleading entropy/slot
     * count for a single value. */
    int v_spec = kaslr_virt_is_window();
    printf("  Virtual image base:   %s0x%016lx%s%s\n", c(C_GREEN),
           s->kaslr.vtext, c(C_RESET), v_spec ? "  likely (speculative)" : "");
    if (s->kaslr.vstext && s->kaslr.vstext != s->kaslr.vtext)
      printf("  Virtual _stext:       0x%016lx\n", s->kaslr.vstext);
    printf("  Default image base:   0x%016lx\n",
           layout.virt_image_base_default);
    long abs_vslide = s->kaslr.vslide < 0 ? -s->kaslr.vslide : s->kaslr.vslide;
    /* A slide is exact only for a proven pin; when the base is the likely
     * best-guess inside a range, the slide inherits that grade. */
    printf("  KASLR slide:          %s%s0x%lx%s (%ld)%s\n", c(C_CYAN),
           s->kaslr.vslide < 0 ? "-" : "+", (unsigned long)abs_vslide,
           c(C_RESET), s->kaslr.vslide, v_spec ? "  (likely)" : "");
    char vebuf[48];
    entropy_phrase(s->kaslr.vbits, s->kaslr.vbits_top, vebuf, sizeof(vebuf));
    if (v_spec)
      printf("  Guaranteed range:     0x%016lx - 0x%016lx  (%s%lu%s slots, "
             "%s)\n",
             layout.virt_kaslr_text_min, layout.virt_kaslr_text_max,
             c(C_MAGENTA), s->kaslr.vslots, c(C_RESET), vebuf);
    else if (s->kaslr.vslots > 0)
      printf("  KASLR text entropy:   %s%s%s (%lu slots of %#lx)\n",
             c(C_MAGENTA), vebuf, c(C_RESET), s->kaslr.vslots,
             layout.virt_kaslr_align);
    else
      /* Guaranteed window is a single slot: the visible base IS the only
       * possible value (a sound pin), 0 bits of residual entropy. */
      printf("  KASLR text entropy:   %s0 bits%s (pinned)\n", c(C_DIM),
             c(C_RESET));
    if (!v_spec && s->kaslr.vslot_valid)
      printf("  Observed slot index:  %lu / %lu\n", s->kaslr.vslot_idx,
             s->kaslr.vslots);
    printf("\n");
  }

  if (s->kaslr.has_phys) {
    int p_spec = kaslr_phys_is_window();
    printf("  Physical image base:  %s0x%016lx%s%s\n", c(C_GREEN),
           s->kaslr.ptext, c(C_RESET), p_spec ? "  likely (speculative)" : "");
    if (s->kaslr.pstext && s->kaslr.pstext != s->kaslr.ptext)
      printf("  Physical _stext:      0x%016lx\n", s->kaslr.pstext);
#ifdef KERNEL_PHYS_DEFAULT
    printf("  Default phys base:    0x%016lx\n",
           (unsigned long)KERNEL_PHYS_DEFAULT);
    long abs_pslide = s->kaslr.pslide < 0 ? -s->kaslr.pslide : s->kaslr.pslide;
    printf("  Physical KASLR slide: %s%s0x%lx%s (%ld)%s\n", c(C_CYAN),
           s->kaslr.pslide < 0 ? "-" : "+", (unsigned long)abs_pslide,
           c(C_RESET), s->kaslr.pslide, p_spec ? "  (likely)" : "");
    if (p_spec)
      printf("  Guaranteed phys range: 0x%016lx - 0x%016lx  (%s%lu%s slots, "
             "%d bits)\n",
             layout.phys_kaslr_text_min, layout.phys_kaslr_text_max,
             c(C_MAGENTA), s->kaslr.pslots, c(C_RESET), s->kaslr.pbits);
    else
      printf("  Physical KASLR entropy: %s0 bits%s (pinned)\n", c(C_DIM),
             c(C_RESET));
    printf("\n");
#endif
  } else if (s->kaslr.pslots > 0 && !no_concrete_text) {
    /* Physical range was narrowed by inference but no concrete ptext leaked.
     * Guarded by !no_concrete_text because the no-vtext-and-no-ptext branch
     * above already prints this same line. */
    printf("  Inferred phys text range:  0x%016lx - 0x%016lx\n",
           layout.phys_kaslr_text_min, layout.phys_kaslr_text_max);
    printf("  Remaining phys slots:      %s%lu%s (%d bits, step %#lx)\n",
           c(C_MAGENTA), s->kaslr.pslots, c(C_RESET), s->kaslr.pbits,
           layout.phys_kaslr_align);
    printf("\n");
  }

  /* Memory KASLR (x86_64 CONFIG_RANDOMIZE_MEMORY): show inferred bounds on
   * the three independently-randomized memory regions when any has been
   * narrowed from the compile-time defaults. The x86_64_vmalloc_base_bound and
   * x86_64_vmemmap_base_bound rules chain off virt_page_offset_min to derive
   * vmalloc and vmemmap bounds via the fixed inter-region ordering. */
  if (summary_has_memory_kaslr(s)) {
    printf("Memory KASLR (directmap / vmalloc / vmemmap):\n");
    render_memory_kaslr_bound(
        "Direct map base", s->kaslr.virt_page_offset_min,
        s->kaslr.virt_page_offset_max, s->kaslr.virt_page_offset_slots,
        s->kaslr.virt_page_offset_bits, s->kaslr.virt_page_offset_likely_min,
        s->kaslr.virt_page_offset_likely_max,
        s->kaslr.virt_page_offset_likely_slots);
    render_memory_kaslr_bound(
        "vmalloc base", s->kaslr.virt_vmalloc_min, s->kaslr.virt_vmalloc_max,
        s->kaslr.virt_vmalloc_slots, s->kaslr.virt_vmalloc_bits,
        s->kaslr.virt_vmalloc_likely_min, s->kaslr.virt_vmalloc_likely_max,
        s->kaslr.virt_vmalloc_likely_slots);
    render_memory_kaslr_bound(
        "vmemmap base", s->kaslr.virt_vmemmap_min, s->kaslr.virt_vmemmap_max,
        s->kaslr.virt_vmemmap_slots, s->kaslr.virt_vmemmap_bits,
        s->kaslr.virt_vmemmap_likely_min, s->kaslr.virt_vmemmap_likely_max,
        s->kaslr.virt_vmemmap_likely_slots);
    printf("\n");
  }
}

/* -------------------------------------------------------------------------
 * Derived addresses text renderer
 *
 * Cross-region derivations arrive as ordinary records in results[] with
 * conf == CONF_DERIVED, emitted by components (e.g. via
 * phys_to_directmap_virt() on arches where the compile-time projection is
 * sound). Render those records
 * in the same per-record style as the leak groups, plus the architecture
 * decoupling note when applicable.
 * -------------------------------------------------------------------------
 */
static void render_derived_text(const struct summary *s) {
  int n_derived = count_derived();
  if (n_derived == 0 && !s->decoupled_note)
    return;

  if (n_derived > 0)
    printf("Derived addresses:\n");
  for (int i = 0; i < num_results; i++) {
    const struct result *r = &results[i];
    if (r->conf != CONF_DERIVED)
      continue;
    char label[96];
    if (r->name[0])
      snprintf(label, sizeof(label), "%s:%s", kasld_region_wire(r->region),
               r->name);
    else
      snprintf(label, sizeof(label), "%s", kasld_region_wire(r->region));

    /* Range-form when both bounds present; otherwise single-address. */
    if (HAS_LO(r) && HAS_HI(r)) {
      unsigned long slots =
          layout.image_align ? (r->hi - r->lo) / layout.image_align : 0;
      printf("  %-24s0x%016lx - 0x%016lx  (~%lu slots, %s)%s\n", label, r->lo,
             r->hi, slots, result_method(r), in_bounds(r) ? "" : " [stale]");
    } else {
      unsigned long a = anchor_addr(r);
      printf("  %-24s0x%016lx%s  (%s)%s\n", label, a, pos_note(r),
             result_method(r), in_bounds(r) ? "" : " [stale]");
    }
  }

  if (s->decoupled_note)
    printf("Note: physical and virtual KASLR are independent on this "
           "architecture;\n      physical leaks do not reveal the virtual "
           "text base.\n");

  printf("\n");
}

/* -------------------------------------------------------------------------
 * ASCII memory layout map
 * -------------------------------------------------------------------------
 */
struct map_region {
  unsigned long start;
  unsigned long end;
  const char *label;
  unsigned long leak_lo; /* 0 = no leak for this region */
  unsigned long leak_hi; /* 0 = only one leak (or none) */
  int base_only;         /* 1 = start is a known base but the extent is
                          * unknown (start==end is a drawing convenience, not a
                          * genuine zero-size pin) */
};

static int region_cmp(const void *a, const void *b) {
  const struct map_region *ra = (const struct map_region *)a;
  const struct map_region *rb = (const struct map_region *)b;
  if (ra->start < rb->start)
    return -1;
  if (ra->start > rb->start)
    return 1;
  return 0;
}

/* Render the virtual half of the memory map: kernel text / modules / direct-map
 * regions, the gaps between them, and the VAS-floor annotation. */
static void print_virtual_layout(void) {
  unsigned long vtext_lo, vtext_hi, vmod_lo, vmod_hi, vdmap_lo, vdmap_hi;
  section_range(KASLD_TYPE_VIRT, "text", &vtext_lo, &vtext_hi);
  section_range(KASLD_TYPE_VIRT, "module", &vmod_lo, &vmod_hi);
  section_range(KASLD_TYPE_VIRT, "directmap", &vdmap_lo, &vdmap_hi);

  /* Build virtual memory region list */
  struct map_region regions[8];
  int n = 0;

  regions[n++] = (struct map_region){
      layout.modules_start, layout.modules_end, "modules", vmod_lo, vmod_hi, 0};
  regions[n++] = (struct map_region){layout.virt_image_base_min,
                                     layout.virt_image_base_max,
                                     "kernel text",
                                     vtext_lo,
                                     vtext_hi,
                                     0};

  /* Only show directmap region if it's distinct from text region.
     Use virt_page_offset as both start and end — we know the mapping begins
     there but don't know its true extent. virt_kernel_vas_end would cause
     unsigned overflow in the gap arithmetic (end + 1 wraps to 0). */
  if (layout.virt_page_offset != layout.virt_image_base_min) {
    regions[n++] = (struct map_region){layout.virt_page_offset,
                                       layout.virt_page_offset,
                                       "direct map",
                                       vdmap_lo,
                                       vdmap_hi,
                                       1};
  }

  /* A band must contain the region it names, so it must contain every address
   * proven to be inside that region. The bounds above are the engine's *base*
   * estimates -- where the region starts, not how far it reaches -- so a leak
   * from the region's interior routinely sits above `end`, and the map would
   * draw an address it has just proven is inside the region outside the band
   * that names it. Widen each band to cover its own leaks: the result is the
   * smallest interval known to contain the region's observed parts, which is
   * exactly what the evidence supports.
   *
   * This also retires the degenerate direct-map band. It is built start == end
   * because the mapping's extent is unknown; drawing that literally printed one
   * address as both bookends and read as a zero-size direct map, while the
   * region's own leaks sat gigabytes above it. */
  for (int i = 0; i < n; i++) {
    if (regions[i].leak_lo && regions[i].leak_lo < regions[i].start)
      regions[i].start = regions[i].leak_lo;
    if (regions[i].leak_hi > regions[i].end)
      regions[i].end = regions[i].leak_hi;
    if (regions[i].leak_lo > regions[i].end)
      regions[i].end = regions[i].leak_lo;
  }

  /* Sort by start address */
  qsort(regions, (size_t)n, sizeof(struct map_region), region_cmp);

  /* Widening must not push a band into its neighbour. A stale or misattributed
   * leak can sit above the next region's floor (the kernel-image regions admit
   * any address, so nothing rejects one), and an overlapping band makes the
   * emit loop's gap test fail, dropping the boundary instead of drawing the
   * overlap. Clamp to the neighbour: a leak beyond it is outside this region's
   * possible extent, so the band should stop rather than swallow the next. */
  for (int i = 0; i + 1 < n; i++)
    if (regions[i + 1].start > 0 && regions[i].end >= regions[i + 1].start)
      regions[i].end = regions[i + 1].start - 1;

  printf("%sVirtual address space (%s):%s\n\n", c(C_BOLD),
         TEXT_TRACKS_DIRECTMAP ? "coupled" : "decoupled", c(C_RESET));

  /* Compact column layout: address column at the left bookends each
   * region; region content (label + leaks) is indented to col 6. Gaps
   * between regions are one-line `... N MiB gap ...` separators. Saves
   * ~50% lines vs the previous ASCII-box format and preserves every
   * piece of data (region boundaries, leak addresses, gap sizes, pinned
   * annotation). All output is ASCII-only for terminal portability. */
  const char *INDENT = "      ";

  /* Use the highest of virt_kernel_vas_end and all region.end values so the top
   * label is never below a visible region boundary. virt_kernel_vas_end can be
   * tightened by the virt_page_offset_max inference feedback loop (it reflects
   * the upper bound on PAGE_OFFSET, not the architectural VAS ceiling), so
   * we clamp it up to the highest region boundary we know about. */
  unsigned long map_top = layout.virt_kernel_vas_end;
  for (int i = 0; i < n; i++)
    if (regions[i].end > map_top)
      map_top = regions[i].end;

  printf("  0x%016lx\n", map_top);

  for (int i = n - 1; i >= 0; i--) {
    struct map_region *r = &regions[i];
    int pinned = (r->start == r->end);
    /* A base-only anchor (direct map) is drawn start==end but its extent is
     * unknown, so it is NOT a pinned single value — reserve "(pinned)" for a
     * genuine zero-extent point. */
    /* base_only means the engine proved where the mapping starts but not how
     * far it reaches, so the band's top edge is "as far as evidence shows",
     * not the region's end. Say that rather than implying a measured extent. */
    const char *point_tail = r->base_only ? " (base proven; extent unknown)"
                             : pinned     ? " (pinned)"
                                          : "";

    /* Region label line(s). Leak addresses, if any, fold inline.
     * Pinned regions (start == end) are a single known point — the
     * bookend addresses above and below already say everything; skip
     * the redundant "(no leak)" tail in that case. */
    if (r->leak_lo) {
      if (r->leak_hi && r->leak_hi != r->leak_lo) {
        printf("%s%s%s\n", INDENT, r->label, point_tail);
        printf("%s  leak hi: 0x%016lx\n", INDENT, r->leak_hi);
        printf("%s  leak lo: 0x%016lx\n", INDENT, r->leak_lo);
      } else {
        printf("%s%s%s -- leak 0x%016lx\n", INDENT, r->label, point_tail,
               r->leak_lo);
      }
    } else if (pinned) {
      printf("%s%s%s\n", INDENT, r->label, point_tail);
    } else {
      printf("%s%s %s(no leak)%s\n", INDENT, r->label, c(C_DIM), c(C_RESET));
    }
    printf("  0x%016lx\n", r->start);

    /* Gap to the next (lower) region, if any. The gap address bookend
     * (the next region's `end`) is printed after the separator. */
    if (i > 0 && regions[i - 1].end + 1 < r->start) {
      char hbuf[32];
      unsigned long gap = r->start - regions[i - 1].end - 1;
      printf("%s%s. . .  %s gap  . . .%s\n", INDENT, c(C_DIM),
             human_size(gap, hbuf, sizeof(hbuf)), c(C_RESET));
      /* A base-only region with no leak to widen it has no known ceiling, so
       * there is no upper boundary to draw. Printing its base here would repeat
       * the address about to appear as the lower bookend and render the region
       * as zero-height. Mark it open-ended instead. */
      if (regions[i - 1].base_only &&
          regions[i - 1].start == regions[i - 1].end)
        printf("%s%s^ extent unknown%s\n", INDENT, c(C_DIM), c(C_RESET));
      else
        printf("  0x%016lx\n", regions[i - 1].end);
    }
  }

  /* Only print virt_kernel_vas_start as a footer when it is genuinely below the
   * lowest visible region (i.e. the VAS extends further down than
   * virt_page_offset). virt_kernel_vas_start can be raised by the
   * virt_page_offset_min inference feedback loop, making it larger than
   * layout.virt_page_offset; printing it there would produce two labels in
   * inverted address order. */
  if (n == 0 || layout.virt_kernel_vas_start < regions[0].start) {
    if (n > 0 && regions[0].start > layout.virt_kernel_vas_start + 1) {
      char hbuf[32];
      unsigned long gap = regions[0].start - layout.virt_kernel_vas_start;
      printf("%s%s. . .  %s gap  . . .%s\n", INDENT, c(C_DIM),
             human_size(gap, hbuf, sizeof(hbuf)), c(C_RESET));
    }
    /* Annotate the kernel VAS floor: what lies below it is not a KASLR target
     * (and not inferred here). On 64-bit a non-canonical hole separates the
     * kernel half from user space; 32-bit splits straight into user space. */
    const char *below = (sizeof(unsigned long) > 4)
                            ? "user space + non-canonical hole below"
                            : "user space below";
    printf("  0x%016lx  %s(%s)%s\n", layout.virt_kernel_vas_start, c(C_DIM),
           below, c(C_RESET));
  }
  printf("\n");
}

/* Render the physical half of the memory map: DRAM buckets, the phys text-base
 * window split, and any above/below-DRAM buckets. */
static void print_physical_layout(void) {
  const char *INDENT = "      ";

  /* Physical memory map — unified view of all physical leaks */
  unsigned long ptext =
      section_consensus(KASLD_TYPE_PHYS, "text", REGION_UNKNOWN);

  struct {
    unsigned long addr;
    char label[128];
    enum kasld_region
        region; /* for collapsing repetitive same-region entries */
    /* 1 iff this leak is a kernel-image region (text/data/bss/image). The
     * phys-text-base window box only renders entries with is_text=1; other
     * leaks whose address happens to land in the window are dropped from
     * the visualization, matching the virt layout's per-region semantics. */
    int is_text;
    /* 1 iff this entry is a DRAM boundary marker (ram_base / ram_top). These
     * are promoted to bucket EDGES in the bucket construction below — the
     * address prints between boxes (as a footer/header), not as a line
     * inside a box — so we skip them in the per-bucket leak listing. */
    int is_dram_edge;
  } ppts[MAX_RESULTS];
  int nppts = 0;

  if (ptext && nppts < MAX_RESULTS) {
    ppts[nppts].addr = ptext;
    snprintf(ppts[nppts].label, sizeof(ppts[nppts].label), "[text] kernel");
    ppts[nppts].region = REGION_KERNEL_TEXT;
    ppts[nppts].is_text = 1;
    ppts[nppts].is_dram_edge = 0;
    nppts++;
  }

  /* Boundary markers are single-valued by definition. Pre-compute one
   * consensus address per marker (region, edge) so the layout box shows one
   * line each regardless of how many components reported it.
   * BASE markers use the minimum (absolute lowest address) of any record
   * with HAS_LO; TOP markers use the maximum of any record with HAS_HI.
   * The merge pass collapses base+top contributors into one record with
   * pos=BASE — we must NOT gate boundary selection on `pos`. The
   * `HAS_LO`/`HAS_HI` flags carry the genuine "is this edge known?"
   * signal regardless of pos. */
  enum boundary_edge { BE_LO, BE_HI };
  static const struct {
    enum kasld_region region;
    enum boundary_edge edge;
    const char *label;
  } boundary_markers[] = {
      {REGION_RAM, BE_LO, "ram_base"},
      {REGION_RAM, BE_HI, "ram_top"},
      {REGION_DMA, BE_HI, "dma_top"},
      {REGION_DMA32, BE_HI, "dma32_top"},
  };
  int n_boundary =
      (int)(sizeof(boundary_markers) / sizeof(boundary_markers[0]));

  for (int b = 0; b < n_boundary && nppts < MAX_RESULTS; b++) {
    enum kasld_region breg = boundary_markers[b].region;
    int use_max = (boundary_markers[b].edge == BE_HI);
    unsigned long best = use_max ? 0 : ~0ul;
    int found = 0;

    for (int i = 0; i < num_results; i++) {
      struct result *r = &results[i];
      if (r->type != KASLD_TYPE_PHYS || !in_bounds(r))
        continue;
      if (r->region != breg)
        continue;
      unsigned long a;
      if (use_max) {
        if (!HAS_HI(r))
          continue;
        a = r->hi;
      } else {
        if (!HAS_LO(r))
          continue;
        a = r->lo;
      }
      if (use_max ? a > best : a < best) {
        best = a;
        found = 1;
      }
    }

    if (found) {
      ppts[nppts].addr = best;
      snprintf(ppts[nppts].label, sizeof(ppts[nppts].label), "[dram] %s",
               boundary_markers[b].label);
      ppts[nppts].region = breg;
      ppts[nppts].is_text = 0;
      ppts[nppts].is_dram_edge =
          (breg == REGION_RAM); /* ram_base / ram_top become bucket edges */
      nppts++;
    }
  }

  /* All other physical records: emit one entry per unique address. Skip
   * (region, pos) combinations already consolidated above as boundaries. */
  for (int i = 0; i < num_results; i++) {
    struct result *r = &results[i];
    if (r->type != KASLD_TYPE_PHYS || !in_bounds(r))
      continue;
    const char *sec = result_section(r);
    /* No section allowlist: in_bounds(r) above is the gate. Regions whose
     * physical leaks belong here have open VAS (static_vas={0,ULONG_MAX});
     * virtual-only regions have a kernel-VAS-bounded static_vas/derive_vas
     * that rejects sub-ULONG_MAX physical addresses via in_bounds. */

    /* Skip records already consolidated into a boundary marker above. A
     * record contributes to a boundary if (a) its region matches a marker,
     * AND (b) it carries the corresponding edge bit (HAS_LO for BE_LO,
     * HAS_HI for BE_HI). Records on a boundary region but contributing the
     * other edge or only a sample still get shown below. */
    int is_boundary = 0;
    for (int b = 0; b < n_boundary; b++) {
      if (r->region != boundary_markers[b].region)
        continue;
      if ((boundary_markers[b].edge == BE_HI && HAS_HI(r)) ||
          (boundary_markers[b].edge == BE_LO && HAS_LO(r))) {
        is_boundary = 1;
        break;
      }
    }
    if (is_boundary)
      continue;

    unsigned long a = anchor_addr(r);
    int dup = 0;
    for (int j = 0; j < nppts; j++) {
      if (ppts[j].addr == a) {
        dup = 1;
        break;
      }
    }
    if (!dup && nppts < MAX_RESULTS) {
      ppts[nppts].addr = a;
      if (r->name[0])
        snprintf(ppts[nppts].label, sizeof(ppts[nppts].label), "[%s] %s:%s",
                 sec, kasld_region_wire(r->region), r->name);
      else
        snprintf(ppts[nppts].label, sizeof(ppts[nppts].label), "[%s] %s", sec,
                 kasld_region_wire(r->region));
      ppts[nppts].region = r->region;
      ppts[nppts].is_text = is_kernel_image_region(r->region);
      ppts[nppts].is_dram_edge = 0;
      nppts++;
    }
  }

  /* Sort descending by address (top of memory first). Whole-struct swap so
   * every field (addr, label, is_text) stays paired. */
  for (int i = 0; i < nppts - 1; i++)
    for (int j = i + 1; j < nppts; j++)
      if (ppts[i].addr < ppts[j].addr) {
        char tmp[sizeof(ppts[0])];
        memcpy(tmp, &ppts[i], sizeof(ppts[0]));
        memcpy(&ppts[i], &ppts[j], sizeof(ppts[0]));
        memcpy(&ppts[j], tmp, sizeof(ppts[0]));
      }

  printf("%sPhysical address space:%s\n\n", c(C_BOLD), c(C_RESET));

  /* Extract DRAM edges from boundary markers (if leaked). These promote from
   * "labels inside a bucket" to actual bucket edges, with separate
   * above-DRAM / below-DRAM buckets surfacing any leaks that fall outside
   * [ram_base, ram_top] (typically MMIO mapped above or below DRAM). */
  unsigned long ram_base = 0, ram_top = 0;
  int have_ram_base = 0, have_ram_top = 0;
  for (int i = 0; i < nppts; i++) {
    if (!ppts[i].is_dram_edge)
      continue;
    if (strstr(ppts[i].label, "ram_top")) {
      ram_top = ppts[i].addr;
      have_ram_top = 1;
    } else if (strstr(ppts[i].label, "ram_base")) {
      ram_base = ppts[i].addr;
      have_ram_base = 1;
    }
  }

  /* sysconf fallback for the top label when no ram_top leak was captured. */
  unsigned long ram_end = 0;
  long pages = sysconf(_SC_PHYS_PAGES);
  long page_size = sysconf(_SC_PAGE_SIZE);
  if (pages > 0 && page_size > 0)
    ram_end = PHYS_OFFSET + (unsigned long)pages * (unsigned long)page_size;
  if (nppts > 0 && ppts[0].addr > ram_end)
    ram_end = ppts[0].addr;

  /* Top label: a leaked DRAM edge (ram_top) is measured; the sysconf figure is
   * an estimate — mark it so the reader can tell an observed edge from a
   * derived one. */
  unsigned long top_label = have_ram_top ? ram_top : ram_end;
  if (top_label)
    printf("  0x%016lx%s\n", top_label, have_ram_top ? "" : "  (estimated)");
  else
    printf("  0x????????????????  (end of RAM unknown)\n");

  /* On !TEXT_TRACKS_DIRECTMAP arches the phys text base is independently
   * randomized inside [phys_kaslr_text_min, phys_kaslr_text_max]. Inference
   * tightens both ends so this window can be much narrower than the arch
   * default. When we have a non-trivial window, split the in-DRAM portion
   * into above-window / inside-window / below-window. Coupled arches and
   * arches without phys KASLR leave both bounds at 0 — single DRAM box. */
  unsigned long pmin = layout.phys_kaslr_text_min;
  unsigned long pmax = layout.phys_kaslr_text_max;
  int show_phys_window = (pmax > pmin && pmin > 0);

  /* DRAM range used to clip the in-DRAM buckets and decide above/below
   * buckets. Falls back to PHYS_OFFSET..ULONG_MAX when edges are unknown. */
  unsigned long dram_lo = have_ram_base ? ram_base : (unsigned long)PHYS_OFFSET;
  unsigned long dram_hi = have_ram_top ? ram_top : ULONG_MAX;

  /* Build a flat list of buckets, top to bottom. `footer_addr` is the
   * boundary label printed after the bucket (= bottom edge). `text_only`
   * gates the bucket to kernel-image-region leaks (the virt layout's
   * per-region semantics). Bucket capacity covers the maximal layout:
   * above-DRAM + in-DRAM-above-window + window + in-DRAM-below-window +
   * below-DRAM. */
  struct phys_bucket {
    const char *header;
    unsigned long lo, hi;
    unsigned long footer_addr;
    int text_only;
  } buckets[5];
  int nbuckets = 0;

  /* Above-DRAM bucket: leaks whose address > ram_top (typically high MMIO).
   * Only emitted when we actually have such leaks AND ram_top is known. */
  int any_above_dram = 0;
  if (have_ram_top) {
    for (int i = 0; i < nppts; i++) {
      if (ppts[i].is_dram_edge)
        continue;
      if (ppts[i].addr > ram_top) {
        any_above_dram = 1;
        break;
      }
    }
    if (any_above_dram)
      buckets[nbuckets++] = (struct phys_bucket){"above DRAM", ram_top + 1,
                                                 ULONG_MAX, ram_top, 0};
  }

  if (!show_phys_window) {
    /* Single in-DRAM bucket spanning the whole DRAM range. */
    buckets[nbuckets++] =
        (struct phys_bucket){NULL, dram_lo, dram_hi, dram_lo, 0};
  } else {
    /* In-DRAM above text window. Clipped at ram_top (no longer ULONG_MAX). */
    if (dram_hi > pmax)
      buckets[nbuckets++] =
          (struct phys_bucket){NULL, pmax + 1, dram_hi, pmax, 0};
    /* Text window. */
    buckets[nbuckets++] =
        (struct phys_bucket){"phys kernel text", pmin, pmax, pmin, 1};
    /* In-DRAM below text window. Clipped at ram_base (no longer PHYS_OFFSET).
     */
    if (pmin > dram_lo)
      buckets[nbuckets++] =
          (struct phys_bucket){NULL, dram_lo, pmin - 1, dram_lo, 0};
    else
      /* Window's lower edge IS dram_lo; collapse the trailing label. */
      buckets[nbuckets - 1].footer_addr = dram_lo;
  }

  /* Below-DRAM bucket: leaks whose address < ram_base. Only emitted when
   * we actually have such leaks. PHYS_OFFSET terminates the column. */
  int any_below_dram = 0;
  if (have_ram_base && ram_base > (unsigned long)PHYS_OFFSET) {
    for (int i = 0; i < nppts; i++) {
      if (ppts[i].is_dram_edge)
        continue;
      if (ppts[i].addr < ram_base) {
        any_below_dram = 1;
        break;
      }
    }
    if (any_below_dram)
      buckets[nbuckets++] =
          (struct phys_bucket){"below DRAM", (unsigned long)PHYS_OFFSET,
                               ram_base - 1, (unsigned long)PHYS_OFFSET, 0};
  }

  for (int b = 0; b < nbuckets; b++) {
    const struct phys_bucket *bk = &buckets[b];
    int any = 0;
    for (int i = 0; i < nppts; i++) {
      if (ppts[i].is_dram_edge)
        continue; /* edges print between buckets, not inside */
      if (ppts[i].addr < bk->lo || ppts[i].addr > bk->hi)
        continue;
      if (bk->text_only && !ppts[i].is_text)
        continue;
      any = 1;
      break;
    }
    /* Header label (above-DRAM / phys kernel text / below-DRAM). The
     * in-DRAM-around-the-text-window buckets carry NULL — those get
     * an implicit "in DRAM" tag so the user can tell which bracket a
     * leak sits in. */
    const char *header = bk->header ? bk->header : "in DRAM";
    printf("%s%s\n", INDENT, header);
    if (any) {
      /* Cap repetitive same-region entries (an MMIO-heavy host can have dozens
       * of pci_mmio BARs, which bury the layout — the Results section already
       * lists them). Show the highest few of each region, then a "... N more"
       * summary; regions at or below the cap print in full. */
      enum { PHYS_MAP_REGION_CAP = 6 };
      int total[REGION__COUNT] = {0};
      int shown[REGION__COUNT] = {0};
      for (int i = 0; i < nppts; i++) {
        if (ppts[i].is_dram_edge)
          continue;
        if (ppts[i].addr < bk->lo || ppts[i].addr > bk->hi)
          continue;
        if (bk->text_only && !ppts[i].is_text)
          continue;
        total[ppts[i].region]++;
      }
      for (int i = 0; i < nppts; i++) {
        if (ppts[i].is_dram_edge)
          continue;
        if (ppts[i].addr < bk->lo || ppts[i].addr > bk->hi)
          continue;
        if (bk->text_only && !ppts[i].is_text)
          continue;
        enum kasld_region rg = ppts[i].region;
        if (total[rg] > PHYS_MAP_REGION_CAP && shown[rg] >= PHYS_MAP_REGION_CAP)
          continue; /* tail of an over-cap region — summarised below */
        printf("%s  0x%016lx  %s\n", INDENT, ppts[i].addr, ppts[i].label);
        shown[rg]++;
      }
      for (enum kasld_region rg = 0; rg < REGION__COUNT; rg++)
        if (total[rg] > PHYS_MAP_REGION_CAP)
          printf("%s  %s... %d more %s region%s%s\n", INDENT, c(C_DIM),
                 total[rg] - PHYS_MAP_REGION_CAP, kasld_region_wire(rg),
                 (total[rg] - PHYS_MAP_REGION_CAP) == 1 ? "" : "s", c(C_RESET));
    } else {
      printf("%s  %s(no leak)%s\n", INDENT, c(C_DIM), c(C_RESET));
    }
    printf("  0x%016lx\n", bk->footer_addr);
  }

  printf("\n");
}

/* Render the kernel memory map: virtual layout above, physical layout below. */
void print_memory_map(void) {
  print_virtual_layout();
  print_physical_layout();
}

/* List the kernel-locating leaks that drive the readout. One line per
 * (type, region) consensus pick — skipping noise (generic DRAM/MMIO
 * extents, virt_page_offset metadata). */
static int readout_print_leaks(void) {
  /* Regions worth surfacing in the headline list. */
  struct {
    enum kasld_addr_type type;
    enum kasld_region region;
    const char *label;
  } interesting[] = {
      {KASLD_TYPE_VIRT, REGION_KERNEL_TEXT, "virt kernel text"},
      {KASLD_TYPE_VIRT, REGION_KERNEL_IMAGE, "virt kernel image"},
      {KASLD_TYPE_VIRT, REGION_KERNEL_DATA, "virt kernel data"},
      {KASLD_TYPE_VIRT, REGION_KERNEL_BSS, "virt kernel BSS"},
      {KASLD_TYPE_VIRT, REGION_DIRECTMAP, "virt directmap"},
      {KASLD_TYPE_VIRT, REGION_MODULE, "virt module"},
      {KASLD_TYPE_VIRT, REGION_MODULE_REGION, "virt module region"},
      {KASLD_TYPE_PHYS, REGION_KERNEL_TEXT, "phys kernel text"},
      {KASLD_TYPE_PHYS, REGION_KERNEL_IMAGE, "phys kernel image"},
      {KASLD_TYPE_PHYS, REGION_KERNEL_DATA, "phys kernel data"},
      {KASLD_TYPE_PHYS, REGION_KERNEL_BSS, "phys kernel BSS"},
  };
  int n_int = (int)(sizeof(interesting) / sizeof(interesting[0]));

  /* Pre-collect (label, addr, contributing record) tuples so we can print
   * a "(N)" header. */
  struct {
    const char *label;
    unsigned long addr;
    const struct result *r;
    unsigned long span_lo, span_hi;
    int is_span;
  } found[32];
  int nf = 0;

  for (int k = 0; k < n_int && nf < (int)(sizeof(found) / sizeof(found[0]));
       k++) {
    /* Find the highest-confidence in-bounds record for this (type, region). */
    const struct result *best = NULL;
    int best_w = -1;
    for (int i = 0; i < num_results; i++) {
      const struct result *r = &results[i];
      if (r->type != interesting[k].type || r->region != interesting[k].region)
        continue;
      if (!in_bounds(r))
        continue;
      int w = conf_weight(r->conf);
      if (w > best_w) {
        best_w = w;
        best = r;
      }
    }
    if (!best)
      continue;
    found[nf].label = interesting[k].label;
    found[nf].addr = anchor_addr(best);
    found[nf].r = best;
    nf++;
  }

  if (nf == 0)
    return 0;

  /* Per-row interior-span detection, and the widest address field, up front. A
   * region with only interior samples (no edge) has no base; its samples bound
   * a span, shown as "lo - hi". Computing the max field width first lets the
   * position and origin columns line up whether a row shows one address or a
   * span. */
  int any_span = 0;
  for (int i = 0; i < nf; i++) {
    unsigned long lo = found[i].addr, hi = found[i].addr;
    int span = 1;
    for (int j = 0; j < num_results; j++) {
      const struct result *r = &results[j];
      if (r->type != found[i].r->type || r->region != found[i].r->region ||
          !in_bounds(r))
        continue;
      if (HAS_LO(r) || HAS_HI(r))
        span = 0;
      unsigned long a = anchor_addr(r);
      if (a < lo)
        lo = a;
      if (a > hi)
        hi = a;
    }
    found[i].is_span = span && hi > lo;
    found[i].span_lo = lo;
    found[i].span_hi = hi;
    if (found[i].is_span)
      any_span = 1;
  }
  /* Column widths for the block, computed up front so the position tag, the
   * ".." separator and the provenance continuation each land in one column
   * whatever mix of spans and single addresses the run produced. */
  int digits = 1, label_w = 1;
  for (int i = 0; i < nf; i++) {
    int l = (int)strlen(found[i].label);
    if (l > label_w)
      label_w = l;
    unsigned long v[2] = {found[i].is_span ? found[i].span_lo : found[i].addr,
                          found[i].is_span ? found[i].span_hi : 0ul};
    for (int k = 0; k < 2; k++) {
      if (!v[k])
        continue;
      int n = 0;
      unsigned long t = v[k];
      do {
        n++;
        t >>= 4;
      } while (t);
      if (n > digits)
        digits = n;
    }
  }
  label_w += 2;
  /* pos_note() strings carry a leading space, which serves as this column's
   * gutter. */
  const int posnote_w = (any_span ? 16 : 11) + 1;

  /* Count distinct contributing components across the whole block: a finding
   * is a (type, region) group, and several components can corroborate one, so
   * a bare row count under-reports what produced the evidence. */
  int total_sources = 0;
  {
    char all[MAX_COMPONENTS][ORIGIN_LEN];
    for (int i = 0; i < nf; i++)
      for (int j = 0; j < num_results; j++) {
        const struct result *r = &results[j];
        if (r->type != found[i].r->type || r->region != found[i].r->region ||
            !in_bounds(r))
          continue;
        for (int pi = 0; pi < r->provenance_count; pi++) {
          int dup = 0;
          for (int k = 0; k < total_sources; k++)
            if (strncmp(all[k], r->origins[pi], ORIGIN_LEN) == 0) {
              dup = 1;
              break;
            }
          if (!dup && total_sources < MAX_COMPONENTS)
            snprintf(all[total_sources++], ORIGIN_LEN, "%s", r->origins[pi]);
        }
      }
  }

  /* "Evidence", not "Leaks": the block holds side-channel measurements
   * (prefetch timing) alongside actual disclosures, and only the latter are
   * leaks. */
  printf("%sEvidence%s  (%d finding%s, %d component%s)\n", c(C_BOLD),
         c(C_RESET), nf, nf == 1 ? "" : "s", total_sources,
         total_sources == 1 ? "" : "s");
  for (int i = 0; i < nf; i++) {
    /* Credit every component that found this (type, region), not just the one
     * highest-confidence record: results merge by (type, region, NAME), so the
     * same address tagged under different symbol names (e.g. _stext from
     * proc_kallsyms vs an unnamed text leak) lands in separate merged records.
     * Aggregate provenance across all in-bounds records of this (type, region),
     * de-duplicated. */
    char seen[MAX_COMPONENTS][ORIGIN_LEN];
    int ns = 0;
    for (int j = 0; j < num_results; j++) {
      const struct result *r = &results[j];
      if (r->type != found[i].r->type || r->region != found[i].r->region ||
          !in_bounds(r))
        continue;
      for (int pi = 0; pi < r->provenance_count; pi++) {
        int dup = 0;
        for (int idx = 0; idx < ns; idx++)
          if (strncmp(seen[idx], r->origins[pi], ORIGIN_LEN) == 0) {
            dup = 1;
            break;
          }
        if (!dup && ns < (int)(sizeof(seen) / sizeof(seen[0])))
          snprintf(seen[ns++], ORIGIN_LEN, "%s", r->origins[pi]);
      }
    }

    /* The extent-position tag precedes the value it qualifies: a reader should
     * know what kind of address is coming before reading it, not after. */
    const char *pn =
        found[i].is_span ? " [interior span]" : pos_note(found[i].r);
    char a1[40], a2[40], t[32];
    snprintf(t, sizeof(t), "0x%lx",
             found[i].is_span ? found[i].span_lo : found[i].addr);
    snprintf(a1, sizeof(a1), "%*s", digits + 2, t);
    printf("  %-*s%-*s%s%s%s", label_w, found[i].label, posnote_w, pn,
           c(C_GREEN), a1, c(C_RESET));
    if (found[i].is_span) {
      snprintf(t, sizeof(t), "0x%lx", found[i].span_hi);
      snprintf(a2, sizeof(a2), "%*s", digits + 2, t);
      printf(" .. %s%s%s", c(C_GREEN), a2, c(C_RESET));
    }
    printf("\n");

    if (ns == 0)
      continue;
    /* Provenance on its own line, introduced by "from" and aligned under the
     * value: bare parenthesised names read as kernel symbols rather than as
     * the components that produced the finding. */
    const int indent = 2 + label_w + posnote_w + 5; /* under "from " */
    int col = indent;
    printf("  %-*s%sfrom ", label_w + posnote_w, "", c(C_DIM));
    for (int idx = 0; idx < ns; idx++) {
      int need = (int)strlen(seen[idx]) + (idx ? 2 : 0);
      /* Wrap rather than truncate: which components corroborate a finding is
       * the whole point of the line, so a long list continues on the next one
       * at the same column instead of folding into "+N more". */
      if (idx && col + need > 78) {
        printf(",\n%*s%s", indent, "", seen[idx]);
        col = indent + (int)strlen(seen[idx]);
      } else {
        printf("%s%s", idx ? ", " : "", seen[idx]);
        col += need;
      }
    }
    printf("%s\n", c(C_RESET));
  }
  return nf;
}

/* ---- Compact readout: one block per resolved quantity -------------------
 *
 * A block is a header line naming the quantity and stating its status, then
 * one indented row per epistemic grade. The quantity name owns a line rather
 * than a fixed-width label column, so a long name cannot consume the value
 * column, and a continuation row is owned by its indentation instead of by
 * position alone.
 *
 * Grade is a column on every value row. Within one readout some quantities
 * carry a speculative window and others do not, so an unlabelled row reads as
 * an unstated grade rather than as "guaranteed".
 *
 * Addresses are right-aligned to the widest address in their own block and
 * never zero-padded: relative magnitude stays legible, and a 16 MiB physical
 * address does not wear the costume of a 64-bit kernel pointer.
 * ------------------------------------------------------------------------- */
#define READOUT_GRADE_W 21 /* "likely (speculative)" + 1 */
/* Sized so the status opens at the same column the value fields start at
 * (26), clear of the grade column below it. At 21 the status opened at 24 --
 * inside the grade field, so its "(" landed on top of the ")" of
 * "likely (speculative)" on the row beneath. */
#define READOUT_LABEL_W 23
#define GRADE_LIKELY "likely (speculative)"
#define GRADE_GUARANTEED "guaranteed"

/* Decimal digits in v (at least 1). */
static int readout_dec_digits(unsigned long v) {
  int n = 0;
  do {
    n++;
    v /= 10;
  } while (v);
  return n;
}

static int readout_hex_digits(unsigned long v) {
  int n = 0;
  do {
    n++;
    v >>= 4;
  } while (v);
  return n;
}

static const char *readout_addr(unsigned long v, int digits, char *buf,
                                size_t sz) {
  char t[32];
  snprintf(t, sizeof(t), "0x%lx", v);
  snprintf(buf, sz, "%*s", digits + 2, t);
  return buf;
}

/* Slot pitch without a trailing ".0" — the pitch is exact by construction, so
 * the decimal is noise. Trimmed here rather than in human_size(), which also
 * formats measured sizes elsewhere (and oneline's fixed-schema `dram=`). */
static const char *readout_grain(unsigned long align, char *buf, size_t sz) {
  char t[32];
  human_size(align, t, sizeof(t));
  char *dot = strstr(t, ".0");
  if (dot)
    memmove(dot, dot + 2, strlen(dot + 2) + 1);
  snprintf(buf, sz, "%s", t);
  return buf;
}

/* A displayed window edge must be a value the quantity can actually take:
 * snap the floor up and the ceiling down onto the candidate grid. An edge off
 * the grid is a *bound*, and printing it where a candidate is expected invites
 * the reader to treat a bound as an answer. Left untouched if snapping would
 * wrap or invert the window. */
static void readout_snap(unsigned long *lo, unsigned long *hi,
                         unsigned long align) {
  if (!align || !*lo || !*hi)
    return;
  unsigned long m = align - 1;
  if (*lo > ULONG_MAX - m)
    return;
  unsigned long l = (*lo + m) & ~m, h = *hi & ~m;
  if (l >= *lo && h <= *hi && l <= h) {
    *lo = l;
    *hi = h;
  }
}

/* Blocks are separated by a blank line so a quantity's rows read as one unit;
 * reset per readout by render_readout(). */
static int readout_block_n;

/* One address-field width and one count-field width for the whole Layout
 * section, so the ".." separator, the high endpoint and the candidate count
 * each form a single column down the section rather than one per block. */
static int readout_addr_w = 1;
static int readout_count_w = 1;

static int readout_wmax(int w, unsigned long v) {
  if (!v)
    return w;
  int n = readout_hex_digits(v);
  return n > w ? n : w;
}

static int readout_cmax(int w, unsigned long v) {
  if (!v)
    return w;
  int n = readout_dec_digits(v);
  return n > w ? n : w;
}

static void readout_head(const char *label, const char *status) {
  if (readout_block_n++)
    printf("\n");
  printf("  %s%s%s", c(C_BOLD), label, c(C_RESET));
  if (status && *status) {
    /* Pad to the widest quantity name so statuses form a scannable column.
     * Unlike the old label column this one abuts prose, never an address, so a
     * name that outgrows the pad merely shifts its own status. */
    /* Parenthesised, and deliberately not sharing a column with the value
     * rows below: this is a verdict about the quantity, not a value. It cannot
     * align with the addresses in any case -- those are right-aligned, so a
     * short physical address and a long virtual one start in different
     * columns. The brackets make the difference explicit rather than leaving
     * it to read as a near-miss. */
    int pad = READOUT_LABEL_W - (int)strlen(label);
    printf("%*s%s(%s)%s", pad > 1 ? pad : 1, "", c(C_YELLOW), status,
           c(C_RESET));
  }
  printf("\n");
}

/* One resolved address at `grade`. `note` (the slide) trails the value rather
 * than sitting between the value and its grade: it is the same value in
 * another coordinate system, not a separate metric. */
static void readout_point(const char *grade, unsigned long v, int digits,
                          const char *note) {
  char ab[40];
  printf("    %-*s%s%s%s", READOUT_GRADE_W, grade, c(C_GREEN),
         readout_addr(v, digits, ab, sizeof(ab)), c(C_RESET));
  if (note && *note)
    /* One space, so the note opens in the same column the ".." separator does
     * on a window row: column N is where a row's continuation begins, whether
     * that continuation is a high endpoint or a displacement. Two spaces put
     * it one column right of the separator, which read as a failed match. */
    printf(" %s%s%s", c(C_CYAN), note, c(C_RESET));
  printf("\n");
}

/* A window at `grade`: first and last candidate, then how many and at what
 * pitch. Both edges are inclusive and on the grid, so the printed count
 * reconciles with the printed edges. */
static void readout_window(const char *grade, unsigned long lo,
                           unsigned long hi, int digits, unsigned long slots,
                           int count_w, unsigned long align) {
  char a1[40], a2[40], gb[32];
  printf("    %-*s%s .. %s", READOUT_GRADE_W, grade,
         readout_addr(lo, digits, a1, sizeof(a1)),
         readout_addr(hi, digits, a2, sizeof(a2)));
  if (slots > 0) {
    /* Right-aligned to the widest count in this block, so the pitch that
     * follows it lines up between a block's likely and guaranteed rows. */
    if (align)
      printf("  %s%*lu x %s%s", c(C_MAGENTA), count_w, slots,
             readout_grain(align, gb, sizeof(gb)), c(C_RESET));
    else
      printf("  %s%*lu candidates%s", c(C_MAGENTA), count_w, slots, c(C_RESET));
  }
  printf("\n");
}

/* Half-bound form: only one edge proven. */
static void readout_halfbound(const char *grade, const char *op,
                              unsigned long v, int digits) {
  char ab[40];
  printf("    %-*s%s %s%s%s\n", READOUT_GRADE_W, grade, op, c(C_CYAN),
         readout_addr(v, digits, ab, sizeof(ab)), c(C_RESET));
}

/* Status for a quantity's header: pinned, or how much entropy survives. */
static const char *readout_status(int pinned, int bits, int bits_top, char *buf,
                                  size_t sz) {
  if (pinned) {
    /* "pinned" is the established word for a proven single value across the
     * formats and the verbose block; the readout does not coin a second one. */
    snprintf(buf, sz, "pinned");
    return buf;
  }
  char e[48];
  entropy_phrase(bits, bits_top, e, sizeof(e));
  snprintf(buf, sz, "narrowed to %s", e);
  return buf;
}

/* Window-only form: no concrete base was resolved. The speculative sub-window,
 * when present, sits above the proven one -- the same likely-over-guaranteed
 * order the concrete-base form uses. */
static void readout_window_block(const char *label, unsigned long lo,
                                 unsigned long hi, unsigned long llo,
                                 unsigned long lhi, unsigned long slots,
                                 unsigned long lslots, int bits, int bits_top,
                                 unsigned long align) {
  if (!lo && !hi)
    return;
  char stat[80];
  int pinned = (lo == hi && lo != 0);
  readout_snap(&lo, &hi, align);
  readout_snap(&llo, &lhi, align);
  int w = readout_addr_w;
  /* No slot count means no entropy was resolved (KASLR off, or a quantity the
   * engine bounded without a grid). Report the window and stop rather than
   * fabricate a "~0 bits" residual. */
  const char *status = NULL;
  if (pinned || slots > 0)
    status = readout_status(pinned, bits, bits_top, stat, sizeof(stat));
  readout_head(label, status);
  if (pinned) {
    readout_point(GRADE_GUARANTEED, lo, w, NULL);
    return;
  }
  if (lhi && llo && lhi >= llo)
    readout_window(GRADE_LIKELY, llo, lhi, w, lslots, readout_count_w, align);
  if (lo && hi && hi >= lo)
    readout_window(GRADE_GUARANTEED, lo, hi, w, slots, readout_count_w, align);
  else if (lo)
    readout_halfbound(GRADE_GUARANTEED, ">=", lo, w);
  else if (hi)
    readout_halfbound(GRADE_GUARANTEED, "<=", hi, w);
}

static void render_readout(const struct summary *s) {
  /* Tool + target header is printed by orchestrator.c BEFORE the "Running
   * N components" line and progress bar - conventional CLI ordering
   * (header → work → results). The readout starts directly with the
   * findings so the progress bar is the last thing erased before the
   * answers appear. */

  /* Special-case: arch with no KASLR support, or KASLR disabled. Both are
   * answered with a single text-base line. */
  if (s->kaslr.unsupported) {
    printf("KASLR not supported on this architecture.\n\n");
    if (s->kaslr.default_addr) {
      readout_block_n = 0;
      printf("%sLayout%s\n", c(C_BOLD), c(C_RESET));
      readout_head("Kernel image base", "arch default, no randomization");
      readout_point(GRADE_GUARANTEED, s->kaslr.default_addr, readout_addr_w,
                    NULL);
    }
    printf("\n");
    readout_print_leaks();
    printf("\n[-v: detailed results, memory map, system info]  "
           "[-H: hardening assessment]\n");
    return;
  }
  if (s->kaslr.disabled) {
    printf("%sKASLR is disabled on this kernel%s "
           "(nokaslr / RANDOMIZE_BASE=n / hibernation).\n\n",
           c(C_YELLOW), c(C_RESET));
    /* Prefer the engine-RESOLVED image base over the compile-time default.
     * On every arch where the disabled-pin applies, the engine pins the base
     * to that default (min == max), so this prints the identical line. But
     * where the no-KASLR text base is layout-dependent (legacy riscv64: text
     * in the linear map at a load offset we can't pin), it resolves to a
     * narrowed *window* instead — showing the static default there would
     * misreport the base (it can sit in an entirely different mapping). */
    readout_block_n = 0;
    printf("%sLayout%s\n", c(C_BOLD), c(C_RESET));
    if (layout.virt_kaslr_text_min == layout.virt_kaslr_text_max &&
        layout.virt_kaslr_text_min != 0) {
      readout_head("Kernel image base", "compile-time default, no slide");
      readout_point(GRADE_GUARANTEED, layout.virt_kaslr_text_min,
                    readout_addr_w, NULL);
    } else if (layout.virt_kaslr_text_min || layout.virt_kaslr_text_max) {
      readout_window_block("Kernel image base", layout.virt_kaslr_text_min,
                           layout.virt_kaslr_text_max, 0, 0, s->kaslr.vslots, 0,
                           s->kaslr.vbits, s->kaslr.vbits_top,
                           layout.virt_kaslr_align);
    } else if (s->kaslr.default_addr) {
      readout_head("Kernel image base", "compile-time default, no slide");
      readout_point(GRADE_GUARANTEED, s->kaslr.default_addr, readout_addr_w,
                    NULL);
    }
    printf("\n");
    readout_print_leaks();
    printf("\n[-v: detailed results, memory map, system info]  "
           "[-H: hardening assessment]\n");
    return;
  }

  /* Regular KASLR path: text base lines + memory-KASLR window lines +
   * coupling note + leaks. Each bound row is suppressed if its quantity
   * was never narrowed below the honest top — keeps the output tight. */
  /* Name the block. Without a heading the most important section of the
   * output begins as an unlabelled indented table while the evidence below it
   * is titled. */
  readout_block_n = 0;
  {
    int a = 1, cw = 1;
    a = readout_wmax(a, layout.virt_kaslr_text_min);
    a = readout_wmax(a, layout.virt_kaslr_text_max);
    a = readout_wmax(a, s->kaslr.vtext);
    a = readout_wmax(a, s->kaslr.vstext);
    a = readout_wmax(a, s->kaslr.vlikely_max);
    a = readout_wmax(a, layout.phys_kaslr_text_min);
    a = readout_wmax(a, layout.phys_kaslr_text_max);
    a = readout_wmax(a, s->kaslr.ptext);
    a = readout_wmax(a, s->kaslr.pstext);
    a = readout_wmax(a, s->kaslr.plikely_max);
    a = readout_wmax(a, s->kaslr.virt_page_offset_min);
    a = readout_wmax(a, s->kaslr.virt_page_offset_max);
    a = readout_wmax(a, s->kaslr.virt_page_offset_likely_max);
    cw = readout_cmax(cw, s->kaslr.vslots);
    cw = readout_cmax(cw, s->kaslr.vlikely_slots);
    cw = readout_cmax(cw, s->kaslr.pslots);
    cw = readout_cmax(cw, s->kaslr.plikely_slots);
    cw = readout_cmax(cw, s->kaslr.virt_page_offset_slots);
    cw = readout_cmax(cw, s->kaslr.virt_page_offset_likely_slots);
    readout_addr_w = a;
    /* Capped: a single very wide window (an unconstrained physical range can
     * run to ten digits) would otherwise pad every count in the section out to
     * its width, stranding a three-digit count behind a wall of spaces. Past
     * the cap the outlier overflows its own row instead. */
    readout_count_w = cw > 6 ? 6 : cw;
  }
  printf("%sLayout%s\n", c(C_BOLD), c(C_RESET));

  int vpin = (layout.virt_kaslr_text_min == layout.virt_kaslr_text_max &&
              layout.virt_kaslr_text_min != 0);
  int ppin = (layout.phys_kaslr_text_min == layout.phys_kaslr_text_max &&
              layout.phys_kaslr_text_min != 0);

  /* Three forms: a pinned base shows the address + slide; a concrete likely
   * base (guaranteed window not pinned) shows that address graded "likely" with
   * the guaranteed window beneath; a bare window shows the range + a likely
   * sub-window. When a concrete likely base is shown it IS the speculative
   * answer, so the separate likely-window row is suppressed (it would only
   * restate it). */
  int v_likely_base = (s->kaslr.vtext && !vpin);
  char stat[80], slide[48];
  if (s->kaslr.vtext && vpin) {
    long abs_v = s->kaslr.vslide < 0 ? -s->kaslr.vslide : s->kaslr.vslide;
    int w = readout_addr_w;
    snprintf(slide, sizeof(slide), "slide %s0x%lx",
             s->kaslr.vslide < 0 ? "-" : "+", (unsigned long)abs_v);
    readout_head("Virtual image base",
                 readout_status(1, 0, 0, stat, sizeof(stat)));
    readout_point(GRADE_GUARANTEED, s->kaslr.vtext, w, slide);
    if (s->kaslr.vstext && s->kaslr.vstext != s->kaslr.vtext)
      readout_point("guaranteed _stext", s->kaslr.vstext, w, NULL);
  } else if (v_likely_base) {
    unsigned long glo = layout.virt_kaslr_text_min,
                  ghi = layout.virt_kaslr_text_max;
    readout_snap(&glo, &ghi, layout.virt_kaslr_align);
    long abs_v = s->kaslr.vslide < 0 ? -s->kaslr.vslide : s->kaslr.vslide;
    int w = readout_addr_w;
    snprintf(slide, sizeof(slide), "slide %s0x%lx",
             s->kaslr.vslide < 0 ? "-" : "+", (unsigned long)abs_v);
    readout_head("Virtual image base",
                 readout_status(0, s->kaslr.vbits, s->kaslr.vbits_top, stat,
                                sizeof(stat)));
    readout_point(GRADE_LIKELY, s->kaslr.vtext, w, slide);
    if (s->kaslr.vstext && s->kaslr.vstext != s->kaslr.vtext)
      readout_point("likely _stext", s->kaslr.vstext, w, NULL);
    readout_window(GRADE_GUARANTEED, glo, ghi, w, s->kaslr.vslots,
                   readout_count_w, layout.virt_kaslr_align);
  } else {
    readout_window_block("Virtual image base", layout.virt_kaslr_text_min,
                         layout.virt_kaslr_text_max, s->kaslr.vlikely_min,
                         s->kaslr.vlikely_max, s->kaslr.vslots,
                         s->kaslr.vlikely_slots, s->kaslr.vbits,
                         s->kaslr.vbits_top, layout.virt_kaslr_align);
  }

  int p_likely_base = (s->kaslr.has_phys && s->kaslr.ptext && !ppin);
  if (s->kaslr.has_phys && ppin) {
    long abs_p = s->kaslr.pslide < 0 ? -s->kaslr.pslide : s->kaslr.pslide;
    int w = readout_addr_w;
    snprintf(slide, sizeof(slide), "slide %s0x%lx",
             s->kaslr.pslide < 0 ? "-" : "+", (unsigned long)abs_p);
    readout_head("Physical image base",
                 readout_status(1, 0, 0, stat, sizeof(stat)));
    readout_point(GRADE_GUARANTEED, s->kaslr.ptext, w, slide);
    if (s->kaslr.pstext && s->kaslr.pstext != s->kaslr.ptext)
      readout_point("guaranteed _stext", s->kaslr.pstext, w, NULL);
  } else if (p_likely_base) {
    unsigned long glo = layout.phys_kaslr_text_min,
                  ghi = layout.phys_kaslr_text_max;
    readout_snap(&glo, &ghi, layout.phys_kaslr_align);
    long abs_p = s->kaslr.pslide < 0 ? -s->kaslr.pslide : s->kaslr.pslide;
    int w = readout_addr_w;
    snprintf(slide, sizeof(slide), "slide %s0x%lx",
             s->kaslr.pslide < 0 ? "-" : "+", (unsigned long)abs_p);
    readout_head("Physical image base",
                 readout_status(0, s->kaslr.pbits, 0, stat, sizeof(stat)));
    readout_point(GRADE_LIKELY, s->kaslr.ptext, w, slide);
    if (s->kaslr.pstext && s->kaslr.pstext != s->kaslr.ptext)
      readout_point("likely _stext", s->kaslr.pstext, w, NULL);
    readout_window(GRADE_GUARANTEED, glo, ghi, w, s->kaslr.pslots,
                   readout_count_w, layout.phys_kaslr_align);
  } else if (s->kaslr.pslots > 0 ||
             (layout.phys_kaslr_text_min || layout.phys_kaslr_text_max)) {
    readout_window_block("Physical image base", layout.phys_kaslr_text_min,
                         layout.phys_kaslr_text_max, s->kaslr.plikely_min,
                         s->kaslr.plikely_max, s->kaslr.pslots,
                         s->kaslr.plikely_slots, s->kaslr.pbits, 0,
                         layout.phys_kaslr_align);
  }

  /* virt_page_offset (direct-map base): only when both sides narrowed into a
   * usable range. Half-bound (only min OR only max non-zero, encoding a
   * `>=`/`<=` claim against the unset KERNEL_VIRT_VAS_END/PAGE_OFFSET sentinel)
   * doesn't fit the bounded-row table format — surface those in the verbose
   * Memory-KASLR block instead. */
  {
    unsigned long lo = s->kaslr.virt_page_offset_min;
    unsigned long hi = s->kaslr.virt_page_offset_max;
    unsigned long llo = s->kaslr.virt_page_offset_likely_min;
    unsigned long lhi = s->kaslr.virt_page_offset_likely_max;
    unsigned long align = (unsigned long)RANDOMIZE_MEMORY_ALIGN;
    unsigned long slots = s->kaslr.virt_page_offset_slots;
    int bits = s->kaslr.virt_page_offset_bits;
    /* A concrete likely base — a POS_BASE timing pin (prefetch_directmap)
     * narrowed the likely window to a single-slot bracket at the base — is
     * promoted to a graded headline with the guaranteed window beneath, the
     * same form as the image bases. The best-guess base is the bracket's top
     * (lhi); the slide-less row is used since the direct map has no default to
     * slide from. A wider likely narrowing is not a base pin and stays a dim
     * range sub-line under the plain bounded row. */
    int concrete_likely =
        llo && lhi && lhi >= llo && align && (lhi - llo) <= align;
    if (concrete_likely && lo) {
      /* A POS_BASE timing pin narrowed the likely window to a single-slot
       * bracket at the base; its top (lhi) is the best guess. Unlike the image
       * bases there is usually no sound ceiling on page_offset (a timing
       * directmap recovery is filtered out of the guaranteed window), so the
       * proven row beneath is normally just the floor. */
      unsigned long glo = lo, ghi = hi;
      readout_snap(&glo, &ghi, align);
      int w = readout_addr_w;
      char st[80], off[48];
      /* The direct map has no compile-time default to slide from, but it does
       * have a RANDOMIZE_MEMORY offset from the un-randomized base — the same
       * value in another coordinate system, so it takes the slide's place. */
      long d = (long)(lhi - (unsigned long)PAGE_OFFSET_BASE_L4);
      snprintf(off, sizeof(off), "off %s0x%lx", d < 0 ? "-" : "+",
               (unsigned long)(d < 0 ? -d : d));
      readout_head("Direct map base",
                   readout_status(0, bits, 0, st, sizeof(st)));
      readout_point(GRADE_LIKELY, lhi, w, off);
      if (ghi && ghi >= glo)
        readout_window(GRADE_GUARANTEED, glo, ghi, w, slots, readout_count_w,
                       align);
      else
        readout_halfbound(GRADE_GUARANTEED, ">=", glo, w);
    } else {
      readout_window_block("Direct map base", lo, hi, llo, lhi, slots,
                           s->kaslr.virt_page_offset_likely_slots, bits, 0,
                           align);
    }
  }

  /* Coupling closes the bounds table as a single dim line: it is a static
   * arch property (not a measured quantity), so it recedes from the green/
   * magenta measured rows and explains why physical and virtual bases resolve
   * as separate (or shared) quantities above. Its job is to relate the physical
   * and virtual text bases, so it only earns its place when there is a physical
   * dimension to relate to: always on coupled arches (where one leak yields
   * both — the exploitation-relevant case), and on decoupled arches only when a
   * physical image base row was actually rendered. Suppressed where no physical
   * base is shown, so it never asserts a relationship the reader can't see. */
  int phys_row_shown = (s->kaslr.has_phys && ppin) || p_likely_base ||
                       s->kaslr.pslots > 0 || layout.phys_kaslr_text_min ||
                       layout.phys_kaslr_text_max;
  /* A static arch property, not a measured quantity: presented as a note
   * rather than as a value row, so it does not sit in the value column
   * alongside addresses under an abbreviated label its siblings do not use. */
  if (TEXT_TRACKS_DIRECTMAP || phys_row_shown)
    printf("\n  %sNote: %s%s\n", c(C_DIM), kasld_coupling_descr(), c(C_RESET));
  printf("\n");

  readout_print_leaks();

  /* If the kernel-text function order is non-canonical, a leaked address does
   * not generalise — warn here (the headline) before an operator applies a
   * System.map; -H carries the full detail. Resolved by max confidence (config
   * supersedes the kallsyms heuristic); shown only when reordered. */
  {
    enum kasld_text_order to = resolve_text_order(NULL);
    if (to == TEXT_ORDER_DYNAMIC) {
      printf("\n  %-19s %sfunction order is per-boot randomized - a leak pins "
             "only\n",
             "Caution", c(C_YELLOW));
      printf("  %-19s that symbol; no static System.map resolves the rest "
             "(-H).%s\n",
             "", c(C_RESET));
    } else if (to == TEXT_ORDER_STATIC) {
      printf("\n  %-19s %snon-canonical function order - use this build's "
             "exact\n",
             "Caution", c(C_YELLOW));
      printf("  %-19s System.map, not a generic one (-H).%s\n", "", c(C_RESET));
    }
  }

  printf("\n[-v: detailed results, memory map, system info]  "
         "[-H: hardening assessment]\n");
}

/* -------------------------------------------------------------------------
 * Text renderer (verbose mode — full detail)
 * -------------------------------------------------------------------------
 */
/* Digest of every component disposition read from comp_logs — a verbose-only
 * view (the mitigation posture belongs in the hardening report, not the
 * answer-first default readout). Prints nothing at all, not even a header, when
 * there is nothing to show, so a clean run stays quiet. */
static void render_dispositions_text(void) {
  int shown = 0;
  for (int i = 0; i < num_comp_logs; i++) {
    const struct component_disposition *d = &comp_logs[i].disposition;
    if (d->category == DISP_NONE)
      continue;
    if (!shown) {
      printf("%sComponent dispositions:%s\n", c(C_BOLD), c(C_RESET));
      shown = 1;
    }
    if (d->category == DISP_MITIGATION)
      printf("  %s%s%s %s", c(C_YELLOW), d->gate, c(C_RESET),
             comp_logs[i].name);
    else
      printf("  %s%-12s%s %s", c(C_DIM), kasld_disp_wire(d->category),
             c(C_RESET), comp_logs[i].name);
    if (d->message[0])
      printf(" %s(%s)%s", c(C_DIM), d->message, c(C_RESET));
    printf("\n");
  }
  if (shown)
    printf("\n");
}

void render_text(const struct summary *s) {
  /* Default mode: tight answer-first readout. */
  if (!verbose) {
    render_readout(s);
    /* --map without --verbose: the diagram is a view of the resolved layout,
     * not run narration, so it is reachable without the per-component stream
     * that --verbose also turns on. */
    if (map_mode) {
      printf("\n");
      print_memory_map();
    }
    if (hardening_mode)
      render_hardening_text();
    return;
  }

  /* Verbose mode below: full output (component tally, per-(type, section,
   * region) blocks, KASLR analysis, derived addresses, layout maps). */
  /* Component outcome summary (skip in quiet mode) */
  if (!quiet && s->stats.total > 0) {
    printf("%sComponents: %d total", c(C_DIM), s->stats.total);
    if (s->stats.succeeded)
      printf(", %d succeeded", s->stats.succeeded);
    if (s->stats.unavailable)
      printf(", %d unavailable", s->stats.unavailable);
    if (s->stats.access_denied)
      printf(", %d access denied", s->stats.access_denied);
    if (s->stats.timed_out)
      printf(", %d timed out", s->stats.timed_out);
    if (s->stats.no_result)
      printf(", %d no result", s->stats.no_result);
    printf("%s\n\n", c(C_RESET));
    render_dispositions_text();
  }

  printf("%s========================================%s\n", c(C_BOLD),
         c(C_RESET));
  printf("%s Results%s\n", c(C_BOLD), c(C_RESET));
  printf("%s========================================%s\n\n", c(C_BOLD),
         c(C_RESET));

  if (s->kaslr.unsupported) {
    printf("%s** KASLR is not supported on this architecture **%s\n\n",
           c(C_YELLOW), c(C_RESET));
    if (s->kaslr.default_addr)
      printf("Kernel image base: %s0x%016lx%s (default for arch)\n\n",
             c(C_GREEN), s->kaslr.default_addr, c(C_RESET));
  } else if (s->kaslr.disabled) {
    printf("%s** KASLR is disabled **%s\n\n", c(C_YELLOW), c(C_RESET));
    printf("Detected by:\n");
    /* List components that emitted SF_VIRT_KASLR_DISABLED — the user-facing
     * "kernel sits at default text base" status is about virt text, so the
     * list is the virt-side emitters (nokaslr cmdline, no
     * CONFIG_RANDOMIZE_BASE, dmesg "KASLR disabled", hibernation override,
     * riscv64 no FDT seed, !KASLR_SUPPORTED synth). Components that also
     * emit SF_PHYS_KASLR_DISABLED show up once via the SF_VIRT scan, not
     * twice. */
    for (int i = 0; i < num_scalar_facts; i++) {
      if (scalar_facts[i].fact == SF_VIRT_KASLR_DISABLED &&
          scalar_facts[i].value != 0)
        printf("  %s\n", scalar_facts[i].origin[0] ? scalar_facts[i].origin
                                                   : "(unknown)");
    }
    printf("\n");
    /* Prefer the engine-RESOLVED base over the compile-time default. On arches
     * where "disabled" pins the base, the resolved value equals that default,
     * so this is unchanged; but where the no-KASLR base is layout-dependent
     * (legacy riscv64: text in the linear map at an unpinnable load offset) it
     * resolves to a narrowed *window*, which the static default would misreport
     * (by 128 GiB, in a different mapping entirely). */
    if (layout.virt_kaslr_text_min == layout.virt_kaslr_text_max &&
        layout.virt_kaslr_text_min != 0)
      printf("Kernel image base: %s0x%016lx%s (KASLR off)\n\n", c(C_GREEN),
             layout.virt_kaslr_text_min, c(C_RESET));
    else if (layout.virt_kaslr_text_min || layout.virt_kaslr_text_max)
      printf("Kernel image base: %s0x%016lx - 0x%016lx%s "
             "(KASLR off; base not pinned to a single default)\n\n",
             c(C_GREEN), layout.virt_kaslr_text_min, layout.virt_kaslr_text_max,
             c(C_RESET));
    else if (s->kaslr.default_addr)
      printf("Kernel image base: %s0x%016lx%s (assumes default config)\n\n",
             c(C_GREEN), s->kaslr.default_addr, c(C_RESET));
  }

  /* Print each (type, section) group in a defined order */
  const char *const *section_order = kasld_render_sections;
  enum kasld_addr_type type_order[] = {KASLD_TYPE_VIRT, KASLD_TYPE_PHYS,
                                       KASLD_TYPE_UNKNOWN};

  /* One block per (type, section, region) — cross-source confirmations of the
   * same memory landmark collapse into a single block, making it obvious which
   * regions have multiple agreeing sources. */
  for (int t = 0; type_order[t] != KASLD_TYPE_UNKNOWN; t++) {
    for (int si = 0; section_order[si]; si++) {
      if (group_already_printed(type_order[t], section_order[si]))
        continue;

      /* Enumerate distinct regions in this (type, section) group. */
      enum kasld_region seen[MAX_RESULTS];
      int nseen = 0;
      for (int i = 0; i < num_results; i++) {
        struct result *r = &results[i];
        if (r->type != type_order[t] ||
            strcmp(result_section(r), section_order[si]) != 0)
          continue;
        int dup = 0;
        for (int j = 0; j < nseen; j++)
          if (seen[j] == r->region) {
            dup = 1;
            break;
          }
        if (!dup && nseen < MAX_RESULTS)
          seen[nseen++] = r->region;
      }
      for (int j = 0; j < nseen; j++)
        print_group(type_order[t], section_order[si], seen[j]);

      mark_group_printed(type_order[t], section_order[si]);
    }
  }

  /* Print any remaining groups not in the predefined order */
  for (int i = 0; i < num_results; i++) {
    struct result *r = &results[i];
    const char *sec = result_section(r);
    if (group_already_printed(r->type, sec))
      continue;

    enum kasld_region seen2[MAX_RESULTS];
    int nseen2 = 0;
    for (int j = 0; j < num_results; j++) {
      struct result *r2 = &results[j];
      if (r2->type != r->type || strcmp(result_section(r2), sec) != 0)
        continue;
      int dup = 0;
      for (int k = 0; k < nseen2; k++)
        if (seen2[k] == r2->region) {
          dup = 1;
          break;
        }
      if (!dup && nseen2 < MAX_RESULTS)
        seen2[nseen2++] = r2->region;
    }
    for (int j = 0; j < nseen2; j++)
      print_group(r->type, sec, seen2[j]);
    mark_group_printed(r->type, sec);
  }

  render_kaslr_text(s);
  render_derived_text(s);

  printf("%s%s%s\n", c(C_DIM), "----------------------------------------",
         c(C_RESET));
  print_memory_map();

  if (hardening_mode)
    render_hardening_text();
}
