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
        printf("  %s0x%016lx%s  %s %s(", c(C_RED), a, c(C_RESET), rn, c(C_DIM));
        for (int j = 0; j < r->provenance_count; j++)
          printf("%s%s", j ? ", " : "", r->origins[j]);
        printf(", %s, stale)%s\n", mbuf, c(C_RESET));
      } else
        printf("  %s0x%016lx%s  %s %s(stale)%s\n", c(C_RED), a, c(C_RESET), rn,
               c(C_DIM), c(C_RESET));
      continue;
    }

    if (verbose) {
      char mbuf[64];
      kasld_method_set_str(r->method_set, mbuf, sizeof mbuf);
      printf("  %s0x%016lx%s  %s %s(", c(C_GREEN), a, c(C_RESET), rn, c(C_DIM));
      for (int j = 0; j < r->provenance_count; j++)
        printf("%s%s", j ? ", " : "", r->origins[j]);
      printf(", %s)%s\n", mbuf, c(C_RESET));
    } else
      printf("  %s0x%016lx%s  %s\n", c(C_GREEN), a, c(C_RESET), rn);

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
    int ns, nc;
    section_consensus_info(type, section, region_filter, &bm, &ns, &nc);
    printf("  %s==>%s 0x%016lx  %s(%s, %d source%s)%s\n", c(C_CYAN), c(C_RESET),
           addrs[0], c(C_DIM), bm, ns, ns == 1 ? "" : "s", c(C_RESET));
  } else if (n_addrs > 1) {
    const char *bm;
    int ns, nc;
    section_consensus_info(type, section, region_filter, &bm, &ns, &nc);
    char hbuf[32];
    unsigned long span = addrs[n_addrs - 1] - addrs[0];
    unsigned long consensus = section_consensus(type, section, region_filter);
    printf("  %s==>%s 0x%016lx  %s(%s, %d source%s, %d conflict%s)%s\n",
           c(C_CYAN), c(C_RESET), consensus, c(C_DIM), bm, ns,
           ns == 1 ? "" : "s", nc, nc == 1 ? "" : "s", c(C_RESET));
    printf("  %s   %s range: 0x%016lx - 0x%016lx  (%s)\n", c(C_CYAN),
           c(C_RESET), addrs[0], addrs[n_addrs - 1],
           human_size(span, hbuf, sizeof(hbuf)));
  }

  printf("\n");
}

/* Bits-of-entropy from a candidate count: ceil(log2(v)) for v >= 1, 0 for
 * v == 0. CEIL (not floor) because the user-facing question is "how much
 * brute-force work remains?" — 13 candidates is ~4 bits of worst-case
 * work, not 3. Floor would understate residual entropy on every
 * non-power-of-2 candidate count (common for direct-map / vmalloc /
 * vmemmap windows on RANDOMIZE_MEMORY). Power-of-2 inputs are unaffected
 * (ceil == floor). */
static int ilog2_ul(unsigned long v) {
  if (v <= 1)
    return 0;
  int r = 0;
  unsigned long n = v;
  while (n >>= 1)
    r++;
  /* If v is not a power of 2, round up. */
  if ((v & (v - 1)) != 0)
    r++;
  return r;
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
static void render_memory_kaslr_likely(unsigned long lmin, unsigned long lmax) {
  if (!lmin && !lmax)
    return;
  if (lmin > lmax)
    return; /* defensive: never print a backwards range */
  if (lmin == lmax) {
    printf("  %-21s %s0x%016lx           likely (speculative)%s\n", "",
           c(C_DIM), lmin, c(C_RESET));
    return;
  }
  unsigned long align = (unsigned long)RANDOMIZE_MEMORY_ALIGN;
  unsigned long slots = (align && lmax > lmin) ? (lmax - lmin) / align : 0;
  if (slots > 1)
    printf("  %-21s %s0x%016lx - 0x%016lx  likely (speculative; %lu cand)%s\n",
           "", c(C_DIM), lmin, lmax, slots, c(C_RESET));
  else
    printf("  %-21s %s0x%016lx - 0x%016lx  likely (speculative)%s\n", "",
           c(C_DIM), lmin, lmax, c(C_RESET));
}

static void render_memory_kaslr_bound(const char *name, unsigned long min,
                                      unsigned long max, unsigned long lmin,
                                      unsigned long lmax) {
  if (!min && !max)
    return;
  /* Defensive: a bottom estimate (lo > hi) would print a backwards range to
   * the user. The resolver in estimate.c rejects bottom-forcing meets, so
   * engine_sync should never sync this — but a malformed runtime cascade
   * shouldn't produce visual garbage. Drop the row rather than emit
   * "0xhigh - 0xlow". */
  if (min && max && min > max)
    return;
  if (min && !max)
    printf("  %-21s >= 0x%016lx\n", name, min);
  else if (!min && max)
    printf("  %-21s <= 0x%016lx\n", name, max);
  else if (min == max)
    printf("  %-21s %s0x%016lx%s (pinned)\n", name, c(C_GREEN), min,
           c(C_RESET));
  else {
    /* Bounded both sides: report the residual positional entropy of the region
     * base — how many RANDOMIZE_MEMORY_ALIGN-aligned positions remain in the
     * window (e.g. a direct-map leak narrows virt_page_offset_base to
     * ~RAM/1GiB). */
    unsigned long align = (unsigned long)RANDOMIZE_MEMORY_ALIGN;
    unsigned long slots = (align && max > min) ? (max - min) / align : 0;
    if (slots > 1)
      printf("  %-21s 0x%016lx - 0x%016lx  (%s%lu%s candidates, %d bits)\n",
             name, min, max, c(C_MAGENTA), slots, c(C_RESET), ilog2_ul(slots));
    else
      printf("  %-21s 0x%016lx - 0x%016lx\n", name, min, max);
  }
  render_memory_kaslr_likely(lmin, lmax);
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
    int v_spec = layout.virt_kaslr_text_max != layout.virt_kaslr_text_min;
    printf("  Virtual image base:   %s0x%016lx%s%s\n", c(C_GREEN),
           s->kaslr.vtext, c(C_RESET), v_spec ? "  (likely; speculative)" : "");
    if (s->kaslr.vstext && s->kaslr.vstext != s->kaslr.vtext)
      printf("  Virtual _stext:       0x%016lx\n", s->kaslr.vstext);
    printf("  Default image base:   0x%016lx\n",
           layout.virt_image_base_default);
    long abs_vslide = s->kaslr.vslide < 0 ? -s->kaslr.vslide : s->kaslr.vslide;
    printf("  KASLR slide:          %s%s0x%lx%s (%ld)\n", c(C_CYAN),
           s->kaslr.vslide < 0 ? "-" : "+", (unsigned long)abs_vslide,
           c(C_RESET), s->kaslr.vslide);
    if (v_spec)
      printf("  Guaranteed range:     0x%016lx - 0x%016lx  (%s%lu%s slots, "
             "%d bits)\n",
             layout.virt_kaslr_text_min, layout.virt_kaslr_text_max,
             c(C_MAGENTA), s->kaslr.vslots, c(C_RESET), s->kaslr.vbits);
    else if (s->kaslr.vslots > 0)
      printf("  KASLR text entropy:   %s%d bits%s (%lu slots of %#lx)\n",
             c(C_MAGENTA), s->kaslr.vbits, c(C_RESET), s->kaslr.vslots,
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
    int p_spec = layout.phys_kaslr_text_max != layout.phys_kaslr_text_min;
    printf("  Physical image base:  %s0x%016lx%s%s\n", c(C_GREEN),
           s->kaslr.ptext, c(C_RESET), p_spec ? "  (likely; speculative)" : "");
    if (s->kaslr.pstext && s->kaslr.pstext != s->kaslr.ptext)
      printf("  Physical _stext:      0x%016lx\n", s->kaslr.pstext);
#ifdef KERNEL_PHYS_DEFAULT
    printf("  Default phys base:    0x%016lx\n",
           (unsigned long)KERNEL_PHYS_DEFAULT);
    long abs_pslide = s->kaslr.pslide < 0 ? -s->kaslr.pslide : s->kaslr.pslide;
    printf("  Physical KASLR slide: %s%s0x%lx%s (%ld)\n", c(C_CYAN),
           s->kaslr.pslide < 0 ? "-" : "+", (unsigned long)abs_pslide,
           c(C_RESET), s->kaslr.pslide);
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
  if (s->kaslr.virt_page_offset_min || s->kaslr.virt_vmalloc_min ||
      s->kaslr.virt_vmemmap_min || s->kaslr.virt_page_offset_max ||
      s->kaslr.virt_vmalloc_max || s->kaslr.virt_vmemmap_max) {
    printf("Memory KASLR (directmap / vmalloc / vmemmap):\n");
    render_memory_kaslr_bound(
        "virt_page_offset_base", s->kaslr.virt_page_offset_min,
        s->kaslr.virt_page_offset_max, s->kaslr.virt_page_offset_likely_min,
        s->kaslr.virt_page_offset_likely_max);
    render_memory_kaslr_bound("virt_vmalloc_base", s->kaslr.virt_vmalloc_min,
                              s->kaslr.virt_vmalloc_max,
                              s->kaslr.virt_vmalloc_likely_min,
                              s->kaslr.virt_vmalloc_likely_max);
    render_memory_kaslr_bound("virt_vmemmap_base", s->kaslr.virt_vmemmap_min,
                              s->kaslr.virt_vmemmap_max,
                              s->kaslr.virt_vmemmap_likely_min,
                              s->kaslr.virt_vmemmap_likely_max);
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
      printf("  %-24s0x%016lx  (%s)%s\n", label, a, result_method(r),
             in_bounds(r) ? "" : " [stale]");
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

  regions[n++] = (struct map_region){layout.modules_start, layout.modules_end,
                                     "modules", vmod_lo, vmod_hi};
  regions[n++] = (struct map_region){layout.virt_image_base_min,
                                     layout.virt_image_base_max, "kernel text",
                                     vtext_lo, vtext_hi};

  /* Only show directmap region if it's distinct from text region.
     Use virt_page_offset as both start and end — we know the mapping begins
     there but don't know its true extent. virt_kernel_vas_end would cause
     unsigned overflow in the gap arithmetic (end + 1 wraps to 0). */
  if (layout.virt_page_offset != layout.virt_image_base_min) {
    regions[n++] =
        (struct map_region){layout.virt_page_offset, layout.virt_page_offset,
                            "direct map", vdmap_lo, vdmap_hi};
  }

  /* Sort by start address */
  qsort(regions, (size_t)n, sizeof(struct map_region), region_cmp);

  printf("%sVirtual memory layout (%s):%s\n\n", c(C_BOLD),
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

    /* Region label line(s). Leak addresses, if any, fold inline.
     * Pinned regions (start == end) are a single known point — the
     * bookend addresses above and below already say everything; skip
     * the redundant "(no leak)" tail in that case. */
    if (r->leak_lo) {
      if (r->leak_hi && r->leak_hi != r->leak_lo) {
        printf("%s%s%s\n", INDENT, r->label, pinned ? " (pinned)" : "");
        printf("%s  leak hi: 0x%016lx\n", INDENT, r->leak_hi);
        printf("%s  leak lo: 0x%016lx\n", INDENT, r->leak_lo);
      } else {
        printf("%s%s%s -- leak 0x%016lx\n", INDENT, r->label,
               pinned ? " (pinned)" : "", r->leak_lo);
      }
    } else if (pinned) {
      printf("%s%s (pinned)\n", INDENT, r->label);
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

  printf("%sPhysical memory layout:%s\n\n", c(C_BOLD), c(C_RESET));

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

  /* Top label: ram_top if known (DRAM edge), else the sysconf estimate. */
  unsigned long top_label = have_ram_top ? ram_top : ram_end;
  if (top_label)
    printf("  0x%016lx\n", top_label);
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
      for (int i = 0; i < nppts; i++) {
        if (ppts[i].is_dram_edge)
          continue;
        if (ppts[i].addr < bk->lo || ppts[i].addr > bk->hi)
          continue;
        if (bk->text_only && !ppts[i].is_text)
          continue;
        printf("%s  0x%016lx  %s\n", INDENT, ppts[i].addr, ppts[i].label);
      }
    } else {
      printf("%s  %s(no leak)%s\n", INDENT, c(C_DIM), c(C_RESET));
    }
    printf("  0x%016lx\n", bk->footer_addr);
  }

  printf("\n");
}

/* Render the kernel memory map: virtual layout above, physical layout below. */
static void print_memory_map(void) {
  print_virtual_layout();
  print_physical_layout();
}

/* -------------------------------------------------------------------------
 * Readout renderer (default text mode — answer-first summary)
 *
 * Produces a tight ~15-line summary that answers "where is the kernel
 * text base?" without the layout maps, per-component logs, or system
 * config block. The verbose flow (render_text under --verbose) retains
 * all of that detail.
 *
 * Layout: 2-column with a 20-char label field; values right-padded to
 * an entropy column at the end of the line where applicable. All output
 * is ASCII so it survives any terminal.
 * -------------------------------------------------------------------------
 */
static const char *coupling_descr(void) {
  return TEXT_TRACKS_DIRECTMAP
             ? "physical and virtual text move together (coupled)"
             : "physical and virtual text randomize independently";
}

/* Emit one bound row of the readout. `label` is the left column; the
 * value column contains either a pinned address (when lo == hi) or a
 * range + slot/entropy footer. */
static void readout_bound_row(const char *label, unsigned long lo,
                              unsigned long hi, unsigned long slots, int bits,
                              unsigned long align) {
  if (lo == 0 && hi == 0)
    return; /* quantity not narrowed below honest top OR not applicable */

  if (lo == hi) {
    printf("  %-19s %s0x%016lx%s   pinned\n", label, c(C_GREEN), lo,
           c(C_RESET));
    return;
  }

  /* Two-line form: status + entropy on the first line — the entropy sits in
   * the same column as the "slide ±X" of a fully-resolved row, so the third
   * column reads consistently ("slide" when pinned, "~N bits" when not) — then
   * range + slot-grain on the next line, indented to the value column. */
  if (slots > 0 && bits >= 0) {
    printf("  %-19s %s%-18s%s   %s~%d bits%s\n", label, c(C_YELLOW),
           "not derandomized", c(C_RESET), c(C_MAGENTA), bits, c(C_RESET));
    char hbuf[32];
    if (align)
      printf("  %-19s 0x%016lx - 0x%016lx   (%lu x %s)\n", "", lo, hi, slots,
             human_size(align, hbuf, sizeof(hbuf)));
    else
      printf("  %-19s 0x%016lx - 0x%016lx   (%lu candidates)\n", "", lo, hi,
             slots);
  } else {
    /* Range known but no slot/entropy count — just print the bounds. */
    printf("  %-19s 0x%016lx - 0x%016lx\n", label, lo, hi);
  }
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

  printf("Leaks (%d):\n", nf);
  for (int i = 0; i < nf; i++) {
    /* Credit every component that found this (type, region), not just the one
     * highest-confidence record: results merge by (type, region, NAME), so the
     * same address tagged under different symbol names (e.g. _stext from
     * proc_kallsyms vs an unnamed text leak) lands in separate merged records.
     * Aggregate provenance across all in-bounds records of this (type, region),
     * de-duplicated. seen[] is sized to the structural max so the distinct
     * count is exact; the line shows the first few and folds the rest into
     * "+N more" (verbose lists them all). */
    char seen[MAX_COMPONENTS][ORIGIN_LEN];
    int ns = 0;
    for (int j = 0; j < num_results; j++) {
      const struct result *r = &results[j];
      if (r->type != found[i].r->type || r->region != found[i].r->region ||
          !in_bounds(r))
        continue;
      for (int p = 0; p < r->provenance_count; p++) {
        int dup = 0;
        for (int idx = 0; idx < ns; idx++)
          if (strncmp(seen[idx], r->origins[p], ORIGIN_LEN) == 0) {
            dup = 1;
            break;
          }
        if (!dup && ns < (int)(sizeof(seen) / sizeof(seen[0])))
          snprintf(seen[ns++], ORIGIN_LEN, "%s", r->origins[p]);
      }
    }
    if (ns == 0) {
      printf("  %-19s %s0x%016lx%s\n", found[i].label, c(C_GREEN),
             found[i].addr, c(C_RESET));
      continue;
    }
    /* Names that fit a default ~80-col line; the rest fold into "+N more". */
    const int shown = ns < 3 ? ns : 3;
    printf("  %-19s %s0x%016lx%s   %s(", found[i].label, c(C_GREEN),
           found[i].addr, c(C_RESET), c(C_DIM));
    for (int idx = 0; idx < shown; idx++)
      printf("%s%s", idx ? ", " : "", seen[idx]);
    if (ns > shown)
      printf(", +%d more", ns - shown);
    printf(")%s\n", c(C_RESET));
  }
  return nf;
}

/* Default-readout sub-line for the speculative "likely" window, printed under
 * the guaranteed image-base range when a sub-sound-floor signal narrowed it.
 * hi == 0 means unset (likely == guaranteed) — nothing to add. */
static void readout_likely_row(unsigned long lo, unsigned long hi) {
  if (hi == 0)
    return;
  if (lo == hi)
    printf("  %-19s %s0x%016lx%s   likely (speculative)\n", "", c(C_DIM), lo,
           c(C_RESET));
  else
    printf("  %-19s %s0x%016lx - 0x%016lx%s   likely (speculative)\n", "",
           c(C_DIM), lo, hi, c(C_RESET));
}

static void render_readout(const struct summary *s) {
  /* Tool + target header is printed by orchestrator.c BEFORE the "Running
   * N components" line and progress bar — conventional CLI ordering
   * (header → work → results). The readout starts directly with the
   * findings so the progress bar is the last thing erased before the
   * answers appear. */

  /* Special-case: arch with no KASLR support, or KASLR disabled. Both are
   * answered with a single text-base line. */
  if (s->kaslr.unsupported) {
    printf("KASLR not supported on this architecture.\n\n");
    if (s->kaslr.default_addr)
      printf("  %-19s %s0x%016lx%s   arch default (no randomization)\n",
             "Kernel image base", c(C_GREEN), s->kaslr.default_addr,
             c(C_RESET));
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
    if (layout.virt_kaslr_text_min == layout.virt_kaslr_text_max &&
        layout.virt_kaslr_text_min != 0)
      printf("  %-19s %s0x%016lx%s   compile-time default (no slide)\n",
             "Kernel image base", c(C_GREEN), layout.virt_kaslr_text_min,
             c(C_RESET));
    else if (layout.virt_kaslr_text_min || layout.virt_kaslr_text_max)
      readout_bound_row("Kernel image base", layout.virt_kaslr_text_min,
                        layout.virt_kaslr_text_max, s->kaslr.vslots,
                        s->kaslr.vbits, layout.virt_kaslr_align);
    else if (s->kaslr.default_addr)
      printf("  %-19s %s0x%016lx%s   compile-time default (no slide)\n",
             "Kernel image base", c(C_GREEN), s->kaslr.default_addr,
             c(C_RESET));
    printf("\n");
    readout_print_leaks();
    printf("\n[-v: detailed results, memory map, system info]  "
           "[-H: hardening assessment]\n");
    return;
  }

  /* Regular KASLR path: text base lines + memory-KASLR window lines +
   * coupling note + leaks. Each bound row is suppressed if its quantity
   * was never narrowed below the honest top — keeps the output tight. */
  int vpin = (layout.virt_kaslr_text_min == layout.virt_kaslr_text_max &&
              layout.virt_kaslr_text_min != 0);
  int ppin = (layout.phys_kaslr_text_min == layout.phys_kaslr_text_max &&
              layout.phys_kaslr_text_min != 0);

  if (s->kaslr.vtext && vpin) {
    /* Fully derandomized — show address + slide instead of range. */
    long abs_v = s->kaslr.vslide < 0 ? -s->kaslr.vslide : s->kaslr.vslide;
    printf("  %-19s %s0x%016lx%s   slide %s%s0x%lx%s\n", "Virtual image base",
           c(C_GREEN), s->kaslr.vtext, c(C_RESET), c(C_CYAN),
           s->kaslr.vslide < 0 ? "-" : "+", (unsigned long)abs_v, c(C_RESET));
    if (s->kaslr.vstext && s->kaslr.vstext != s->kaslr.vtext)
      printf("  %-19s %s0x%016lx%s\n", "Virtual _stext", c(C_GREEN),
             s->kaslr.vstext, c(C_RESET));
  } else {
    readout_bound_row("Virtual image base", layout.virt_kaslr_text_min,
                      layout.virt_kaslr_text_max, s->kaslr.vslots,
                      s->kaslr.vbits, layout.virt_kaslr_align);
  }
  readout_likely_row(s->kaslr.vlikely_min, s->kaslr.vlikely_max);

  if (s->kaslr.has_phys && ppin) {
    long abs_p = s->kaslr.pslide < 0 ? -s->kaslr.pslide : s->kaslr.pslide;
    printf("  %-19s %s0x%016lx%s   slide %s%s0x%lx%s\n", "Physical image base",
           c(C_GREEN), s->kaslr.ptext, c(C_RESET), c(C_CYAN),
           s->kaslr.pslide < 0 ? "-" : "+", (unsigned long)abs_p, c(C_RESET));
    if (s->kaslr.pstext && s->kaslr.pstext != s->kaslr.ptext)
      printf("  %-19s %s0x%016lx%s\n", "Physical _stext", c(C_GREEN),
             s->kaslr.pstext, c(C_RESET));
  } else if (s->kaslr.pslots > 0 ||
             (layout.phys_kaslr_text_min || layout.phys_kaslr_text_max)) {
    readout_bound_row("Physical image base", layout.phys_kaslr_text_min,
                      layout.phys_kaslr_text_max, s->kaslr.pslots,
                      s->kaslr.pbits, layout.phys_kaslr_align);
  }
  readout_likely_row(s->kaslr.plikely_min, s->kaslr.plikely_max);

  /* virt_page_offset (direct-map base): only when both sides narrowed into a
   * usable range. Half-bound (only min OR only max non-zero, encoding a
   * `>=`/`<=` claim against the unset KERNEL_VIRT_VAS_END/PAGE_OFFSET sentinel)
   * doesn't fit the bounded-row table format — surface those in the verbose
   * Memory-KASLR block instead. */
  {
    unsigned long lo = s->kaslr.virt_page_offset_min;
    unsigned long hi = s->kaslr.virt_page_offset_max;
    if (lo && hi && hi >= lo) {
      unsigned long align = (unsigned long)RANDOMIZE_MEMORY_ALIGN;
      unsigned long slots = (align && hi > lo) ? (hi - lo) / align : 0;
      int bits = slots > 0 ? ilog2_ul(slots) : 0;
      readout_bound_row("Direct map base", lo, hi, slots, bits, align);
    } else if (lo && !hi) {
      printf("  %-19s >= %s0x%016lx%s\n", "Direct map base", c(C_CYAN), lo,
             c(C_RESET));
    } else if (!lo && hi) {
      printf("  %-19s <= %s0x%016lx%s\n", "Direct map base", c(C_CYAN), hi,
             c(C_RESET));
    }
    readout_likely_row(s->kaslr.virt_page_offset_likely_min,
                       s->kaslr.virt_page_offset_likely_max);
  }

  /* Coupling closes the bounds table as a single dim line: it is a static
   * arch property (not a measured quantity), so it recedes from the green/
   * magenta measured rows and explains why physical and virtual bases resolve
   * as separate (or shared) quantities above. */
  printf("  %-19s %s%s%s\n", "Phys/Virt coupling", c(C_DIM), coupling_descr(),
         c(C_RESET));
  printf("\n");

  readout_print_leaks();

  /* If the kernel-text function order is non-canonical, a leaked address does
   * not generalise — warn here (the headline) before an operator applies a
   * System.map; -H carries the full detail. Resolved by max confidence (config
   * supersedes the kallsyms heuristic); shown only when reordered. */
  {
    enum kasld_text_order to = resolve_text_order(NULL);
    if (to == TEXT_ORDER_DYNAMIC) {
      printf("\n  %-19s %sfunction order is per-boot randomized — a leak pins "
             "only\n",
             "Caution", c(C_YELLOW));
      printf("  %-19s that symbol; no static System.map resolves the rest "
             "(-H).%s\n",
             "", c(C_RESET));
    } else if (to == TEXT_ORDER_STATIC) {
      printf("\n  %-19s %snon-canonical function order — use this build's "
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
void render_text(const struct summary *s) {
  /* Default mode: tight answer-first readout. */
  if (!verbose) {
    render_readout(s);
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
      printf(
          "Likely kernel image base: %s0x%016lx%s (assumes default config)\n\n",
          c(C_GREEN), layout.virt_kaslr_text_min, c(C_RESET));
    else if (layout.virt_kaslr_text_min || layout.virt_kaslr_text_max)
      printf("Kernel image base: %s0x%016lx - 0x%016lx%s "
             "(KASLR off; base not pinned to a single default)\n\n",
             c(C_GREEN), layout.virt_kaslr_text_min, layout.virt_kaslr_text_max,
             c(C_RESET));
    else if (s->kaslr.default_addr)
      printf(
          "Likely kernel image base: %s0x%016lx%s (assumes default config)\n\n",
          c(C_GREEN), s->kaslr.default_addr, c(C_RESET));
  }

  /* Print each (type, section) group in a defined order */
  const char *section_order[] = {"text", "module", "directmap", "data",
                                 "bss",  "dram",   "mmio",      NULL};
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
