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
#include "include/kasld/report.h"

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

/* Extent-position disclosure for a leaked address. Every leak row states
 * whether the address is the region base, an interior sample, or the top edge,
 * so none is ambiguous and the base (the prize) is called out, not left
 * implicit. All three positions are reachable in these rows. Empty
 * only for the shouldn't-reach-here extent/unknown. Most callers emit the
 * string unpadded; readout_print_leaks pads it to posnote_w (12, the width of
 * " [interior]" plus one, or 17 when an interior span is present) so a column
 * can follow. */
/* The position word, bare. `pos_note()` brackets it for prose lines where it
 * qualifies an address inline; in a table the column header names it, so the
 * brackets would say the same thing twice. */
static const char *pos_word(const struct result *r) {
  switch (r->pos) {
  case POS_BASE:
    return "base";
  case POS_INTERIOR:
    return "interior";
  case POS_TOP:
    return "top";
  default:
    return "";
  }
}

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

    /* Compact form shows region (and ":name" when known); verbose adds the
     * contributing components in parentheses. region+name tells the reader what
     * the address is; the components tell them who found it.
     *
     * The parenthetical carries component names and nothing else. A technique
     * category is a property of a component, not of a record: every contributor
     * states its own in its block header, and the group's consensus line states
     * the one behind the pick. Listed here it would repeat that per record, in
     * a vocabulary sharing five of six words with the confidence ladder, as a
     * bare lowercase token indistinguishable in form from the component names
     * beside it. */
    char rn[64 + NAME_LEN + 2];
    if (r->name[0])
      snprintf(rn, sizeof(rn), "%s:%s", kasld_region_wire(r->region), r->name);
    else
      snprintf(rn, sizeof(rn), "%s", kasld_region_wire(r->region));

    unsigned long a = anchor_addr(r);

    if (!in_bounds(r)) {
      if (verbose) {
        printf("  %s0x%016lx%s  %s%s %s(", c(C_RED), a, c(C_RESET), rn,
               pos_note(r), c(C_DIM));
        for (int j = origin_set_next(&r->origins, 0), oi = 0; j >= 0;
             j = origin_set_next(&r->origins, j + 1), oi++)
          printf("%s%s", oi ? ", " : "", kasld_origin_name(j));
        printf(", stale)%s\n", c(C_RESET));
      } else
        printf("  %s0x%016lx%s  %s%s %s(stale)%s\n", c(C_RED), a, c(C_RESET),
               rn, pos_note(r), c(C_DIM), c(C_RESET));
      continue;
    }

    if (verbose) {
      printf("  %s0x%016lx%s  %s%s %s(", c(C_GREEN), a, c(C_RESET), rn,
             pos_note(r), c(C_DIM));
      for (int j = origin_set_next(&r->origins, 0), oi = 0; j >= 0;
           j = origin_set_next(&r->origins, j + 1), oi++)
        printf("%s%s", oi ? ", " : "", kasld_origin_name(j));
      printf(")%s\n", c(C_RESET));
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
    printf("  %s==>%s 0x%016lx  %s(method: %s, %s%d source%s)%s\n", c(C_CYAN),
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
      printf("  %s==>%s spans 0x%016lx - 0x%016lx  %s(method: %s; %d "
             "samples, %d source%s; %s)%s\n",
             c(C_CYAN), c(C_RESET), addrs[0], addrs[n_addrs - 1], c(C_DIM), bm,
             n_addrs, ns, ns == 1 ? "" : "s",
             human_size(span, hbuf, sizeof(hbuf)), c(C_RESET));
    } else {
      unsigned long consensus = section_consensus(type, section, region_filter);
      /* nc is a genuine competing-base count (0 for the multi-segment dram/mmio
       * coverings and for corroborating interior/top records), so it is printed
       * only when a real disagreement exists. */
      if (nc > 0)
        printf("  %s==>%s 0x%016lx  %s(method: %s, %d source%s, %d "
               "conflict%s)%s\n",
               c(C_CYAN), c(C_RESET), consensus, c(C_DIM), bm, ns,
               ns == 1 ? "" : "s", nc, nc == 1 ? "" : "s", c(C_RESET));
      else
        printf("  %s==>%s 0x%016lx  %s(method: %s, %d source%s)%s\n", c(C_CYAN),
               c(C_RESET), consensus, c(C_DIM), bm, ns, ns == 1 ? "" : "s",
               c(C_RESET));
      printf("  %s   %s range: 0x%016lx - 0x%016lx  (%s)\n", c(C_CYAN),
             c(C_RESET), addrs[0], addrs[n_addrs - 1],
             human_size(span, hbuf, sizeof(hbuf)));
    }
  }

  printf("\n");
}

/* -------------------------------------------------------------------------
 * KASLR analysis text renderer (consumes pre-computed summary)
 * -------------------------------------------------------------------------
 */
/* The readout's column budget, enforced against live output by
 * tests/check-render-width. Wrapping keys off it rather than a hand-tuned
 * literal, so the two cannot drift apart. */
#define READOUT_MAX_COLS 100

/* One column for every label in the analysis block below. Derived from the
 * longest label, so renaming one cannot leave the values ragged. */
#define KASLR_LABEL_W 21

/* Defined with the Layout table below; declared here so the verbose analysis
 * can draw the same table without moving it away from its rationale. */
static void layout_render(void);

/* Residual entropy, against the entropy the window started with where that
 * baseline is known: "~5 bits" alone says nothing about how much was
 * recovered. */
static const char *entropy_phrase(int bits, int bits_top, char *buf,
                                  size_t bufsz) {
  if (bits_top > bits)
    snprintf(buf, bufsz, "~%d of %d bits", bits, bits_top);
  else
    snprintf(buf, bufsz, "~%d bits", bits);
  return buf;
}

/* The verbose KASLR analysis: the same Layout table the readout draws, then
 * only what its five columns cannot carry.
 *
 * The table is built from the shared row model, so -v and the default readout
 * cannot report the same resolved state differently. Restating the addresses
 * and counts in a second shape beneath it -- which is what this block used to
 * do -- puts the same numbers on screen twice and leaves a reader working out
 * whether the two disagree.
 *
 * What survives here is what the columns have no room for: the second address
 * some quantities carry (_stext), the constant a slide is measured from, and
 * the residual expressed in bits.
 *
 * The base's slot index is deliberately absent. It is measured from the
 * engine's proven floor rather than the kernel's randomization floor, so it
 * describes the geometry of the evidence, not the placement the kernel chose
 * -- for a ceiling-type leak the base sits at the window's top edge by
 * construction. The position that is a fact about the target follows from the
 * slide (slide / align), which the table already carries. */
static void render_kaslr_text(const struct summary *s) {
  char ebuf[48];
  /* Verbose renders this table instead of the readout, so it builds the rows
   * itself: render_readout() is the !verbose path and never runs here. Built
   * before the guard below, which reads the model it produces. */
  layout_build();

  /* Drawn in every posture, from the shared row model. A posture that renders
   * its own shape also ends up choosing its own rows, and each one that did
   * dropped the likely grade -- so a kernel with KASLR off reported the proven
   * window and never the base the engine had actually resolved.
   *
   * The model, not the summary's slot counts, decides whether there is a table:
   * a disabled kernel randomized nothing and so has no slots to count, while
   * its rows carry a resolved window. */
  if (!layout_has_resolved())
    return;

  printf("%s%s%s\n", c(C_DIM), "----------------------------------------",
         c(C_RESET));
  printf("%sKASLR analysis:%s\n", c(C_BOLD), c(C_RESET));
  layout_render();
  printf("\n");

  {
    const struct kasld_report *rep = render_report();
    const struct kasld_report_quantity *iv =
        kasld_report_find(rep, Q_VIRT_IMAGE_BASE);
    const struct kasld_report_quantity *ip =
        kasld_report_find(rep, Q_PHYS_IMAGE_BASE);
    const struct kasld_report_quantity *id =
        kasld_report_find(rep, Q_PAGE_OFFSET);

    if (iv && iv->has_stext)
      printf("  %-*s 0x%016lx\n", KASLR_LABEL_W, "Virtual _stext:", iv->stext);
    if (ip && ip->has_stext)
      printf("  %-*s 0x%016lx\n", KASLR_LABEL_W, "Physical _stext:", ip->stext);
    /* Beside a resolved base, which is what the default is a remark on. */
    if (iv && iv->has_point)
      printf("  %-*s 0x%016lx\n", KASLR_LABEL_W,
             "Compile-time default:", layout.virt_image_base_default);
    /* Residual entropy against what it narrows, both from the model: the two
     * figures have to come from one place or the pair can disagree. */
    if (iv && iv->guaranteed.candidates > 0)
      printf("  %-*s %s\n", KASLR_LABEL_W, "Virtual entropy:",
             entropy_phrase(iv->guaranteed.bits, iv->top_bits, ebuf,
                            sizeof(ebuf)));
    if (ip && ip->guaranteed.candidates > 0)
      printf("  %-*s %s\n", KASLR_LABEL_W, "Physical entropy:",
             entropy_phrase(ip->guaranteed.bits, ip->top_bits, ebuf,
                            sizeof(ebuf)));
    if (id && id->guaranteed.candidates > 0)
      printf("  %-*s %s\n", KASLR_LABEL_W, "Direct map entropy:",
             entropy_phrase(id->guaranteed.bits, id->top_bits, ebuf,
                            sizeof(ebuf)));
  }
  printf("\n");
}

/* -------------------------------------------------------------------------
 * Derived addresses text renderer
 *
 * Cross-region derivations arrive as ordinary records in results[] with
 * conf == CONF_DERIVED — a component relating two regions it observed, not a
 * linear-map projection: components no longer convert a physical address to
 * its direct-map virtual, because doing so re-states the compile-time
 * PAGE_OFFSET as though it were evidence. Render those records in the same
 * per-record style as the leak groups, plus the architecture decoupling note
 * when applicable.
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
/* Region identity, stable across the sort. Used to express containment: a
 * region names the region it lives INSIDE, not the slot that region happens to
 * occupy once the array is ordered by address. */
enum map_region_id {
  MR_MODULES = 0,
  MR_KERNEL_TEXT,
  MR_DIRECTMAP,
  MR_NONE = -1,
};

struct map_region {
  unsigned long start;
  unsigned long end;
  const char *label;
  unsigned long leak_lo; /* 0 = no leak for this region */
  unsigned long leak_hi; /* 0 = only one leak (or none) */
  int base_only;         /* 1 = start is a known base but the extent is
                          * unknown (start==end is a drawing convenience, not a
                          * genuine zero-size pin) */
  int id;                /* enum map_region_id */
  /* The region enclosing this one, or MR_NONE for a top-level band. Kernel
   * text is MAPPED THROUGH the direct map on TEXT_TRACKS_DIRECTMAP arches: the
   * two are not siblings and no stacking of disjoint bands can describe them.
   * A contained region is drawn indented inside its container's bookends
   * instead of claiming a band of its own. */
  int parent;
  /* 1 = `end` was COMPUTED from the resolved base and the kernel's own RAM
   * extent rather than observed; 0 = `end` is an observed or architectural
   * edge. Every initialiser states it positionally, so a new region cannot
   * inherit the claim by omission. */
  int extent_derived;
};

/* Total order, so the column is byte-identical run to run. Regions really can
 * share a start (riscv32 places its module window at PAGE_OFFSET, s390 leaves
 * both the text and module bands at the VAS floor until something is proven),
 * and leaving those ties to qsort let the same machine draw the map two ways.
 */
static int region_cmp(const void *a, const void *b) {
  const struct map_region *ra = (const struct map_region *)a;
  const struct map_region *rb = (const struct map_region *)b;
  if (ra->start != rb->start)
    return ra->start < rb->start ? -1 : 1;
  if (ra->end != rb->end)
    return ra->end < rb->end ? -1 : 1;
  return ra->id < rb->id ? -1 : (ra->id > rb->id);
}

/* The map shares the readout's address and size vocabulary instead of keeping
 * a second one: un-padded right-aligned hex, and sizes without a trailing
 * ".0" (kasld_grain, shared from render.c). The first two live with the
 * readout below (that is where their rationale is); declared here so the map
 * can call them without moving them away from it. */
static int readout_hex_digits(unsigned long v);
static const char *readout_addr(unsigned long v, int digits, char *buf,
                                size_t sz);

/* Widest hex address the block will draw, so its column is as wide as its
 * contents and no wider. Unlike readout_wmax() a zero address counts: the
 * physical column's bottom bookend is routinely PHYS_OFFSET == 0, and it is a
 * drawn address like any other. */
static int map_addr_w(int w, unsigned long v) {
  int n = readout_hex_digits(v);
  return n > w ? n : w;
}

/* One address bookend at the map's left margin. */
static void print_map_addr(int w, unsigned long v, const char *tail) {
  char ab[40];
  printf("  %s%s\n", readout_addr(v, w, ab, sizeof(ab)), tail ? tail : "");
}

/* One downward boundary transition in the virtual column: the
 * `. . . N gap . . .` separator for the unclaimed span, then the ceiling of the
 * band below it. `above` is the first address NOT in `below` (the floor of
 * whatever sits on top, or the map's own top edge).
 *
 * Shared by the map's top edge and the inter-band gaps so the two render
 * identically. The map's bookends are shared: one address line is
 * simultaneously the floor of the band above and the ceiling of the band below,
 * and it is the band above that prints it. The topmost band has nothing above
 * it, so without this being called for the map's top edge its ceiling is never
 * drawn at all and the reader takes the map's top for the band's own end --
 * e.g. kernel text appearing to run to 0xffffffffffffffff on arm64 while the
 * readout states an image-base window that ends far below. */
static int print_map_boundary(const char *indent, int w, unsigned long above,
                              const struct map_region *below) {
  /* `above - below->end > 1` rather than `below->end + 1 < above`: the latter
   * wraps when the band ends at the top of the address space. */
  if (above - below->end > 1) {
    char hbuf[32];
    unsigned long gap = above - below->end - 1;
    printf("%s%s. . .  %s gap  . . .%s\n", indent, c(C_DIM),
           kasld_grain(gap, hbuf, sizeof(hbuf)), c(C_RESET));
  }
  /* A base-only region with no leak to widen it has no known ceiling, so there
   * is no upper boundary to draw. Printing its base here would repeat the
   * address about to appear as the lower bookend and render the region as
   * zero-height. Mark it open-ended instead -- and report that back, so the
   * band's own label does not go on to say the same thing a second time in
   * different words. */
  if (below->base_only && below->start == below->end) {
    printf("%s%s^ extent unknown%s\n", indent, c(C_DIM), c(C_RESET));
    return 1;
  }
  print_map_addr(w, below->end, NULL);
  return 0;
}

/* Render the virtual half of the memory map: kernel text / modules / direct-map
 * regions, the gaps between them, and the VAS-floor annotation. */
static void print_virtual_layout(void) {
  unsigned long vtext_lo, vtext_hi, vmod_lo, vmod_hi, vdmap_lo, vdmap_hi;
  /* Whole-section spans: the map draws each region band as a single extent,
   * so every record in the section contributes regardless of its region. */
  section_range(KASLD_TYPE_VIRT, "text", REGION_UNKNOWN, &vtext_lo, &vtext_hi);
  section_range(KASLD_TYPE_VIRT, "module", REGION_UNKNOWN, &vmod_lo, &vmod_hi);
  section_range(KASLD_TYPE_VIRT, "directmap", REGION_UNKNOWN, &vdmap_lo,
                &vdmap_hi);

  /* Build virtual memory region list */
  struct map_region regions[8];
  int n = 0;

  /* The direct map's floor. layout.virt_page_offset is SEEDED from the arch's
   * compile-time PAGE_OFFSET and only replaced once the engine pins the
   * quantity, so on a kernel whose split differs from the build default it is a
   * stale constant rather than a measurement. An Alpine armv7 kernel built
   * VMSPLIT_2G is the live witness: virt_page_offset stays at 0xc0000000 while
   * the engine has already proved the direct map starts at or below the
   * 0x81d44600 it was observed at -- and the map drew the constant as the
   * region's "base proven" floor, ABOVE an address proven to be inside the
   * region. The engine's resolved window is authoritative wherever it holds an
   * opinion; the constant is the fallback for when it does not. */
  /* The window is always populated -- seeded from the quantity's own bracket
   * before any component runs, then overwritten by the engine -- so there is no
   * "unset" state to test for, and testing for one is worse than redundant
   * here: zero is a LEGITIMATE linear-map base. s390 built without
   * CONFIG_RANDOMIZE_IDENTITY_BASE has __identity_base == 0, so a proven pin at
   * 0 is a real result, and a truthiness guard reads it as absent and labels
   * the band a mere lower bound. Compare the edges, never their truthiness. */
  unsigned long po_lo = layout.virt_page_offset_min;
  unsigned long po_hi = layout.virt_page_offset_max;
  unsigned long dmap_base = layout.virt_page_offset;
  if (po_lo <= po_hi && (dmap_base < po_lo || dmap_base > po_hi))
    dmap_base = po_lo;
  /* Whether that floor is a proven single value or the low end of a window the
   * engine could not close. The band's label says which; it used to claim
   * "base proven" either way. */
  int dmap_base_pinned = (po_lo == po_hi);

  /* The direct map's reach, DERIVED rather than observed: the linear mapping
   * covers physical RAM, so it spans max_pfn pages from its base. A component
   * used to emit this as though it were a leaked address, computed from the
   * compile-time PAGE_OFFSET -- which the engine then read back as evidence for
   * that same constant. Taken here instead, from the base the engine resolved,
   * it reaches the screen without ever entering the evidence set, and it holds
   * on a kernel whose split differs from this build's, which the constant never
   * could.
   *
   * Gated on a PINNED base. Measured from a floor that is itself a lower bound,
   * the ceiling would carry both uncertainties while reading as a measurement.
   * SF_PHYS_MAX_PFN is the kernel's own direct-map extent (/proc/zoneinfo),
   * taken at or above the sound floor. Each step is guarded against wrap: a
   * 32-bit highmem span added to a high base wraps the word and would draw a
   * ceiling BELOW the floor. */
  unsigned long dmap_end = dmap_base;
  int dmap_extent_derived = 0;
  if (dmap_base_pinned) {
    unsigned long max_pfn = 0, memtotal = 0, obs_page_size = 0;
    int highmem = 0;
    for (int i = 0; i < num_scalar_facts; i++) {
      if (scalar_facts[i].fact == SF_PHYS_MAX_PFN &&
          scalar_facts[i].conf >= CONF_INFERRED)
        max_pfn = scalar_facts[i].value;
      else if (scalar_facts[i].fact == SF_PHYS_MEMTOTAL)
        memtotal = scalar_facts[i].value;
      else if (scalar_facts[i].fact == SF_PHYS_LOWMEM)
        highmem = 1;
      else if (scalar_facts[i].fact == SF_PAGE_SIZE &&
               scalar_facts[i].conf >= CONF_INFERRED)
        obs_page_size = scalar_facts[i].value;
    }
#if ULONG_MAX <= 0xFFFFFFFFul
    /* max_pfn spans ALL RAM, highmem included, but a 32-bit linear map covers
     * lowmem only -- so on a highmem kernel it is not the mapping's reach and
     * would draw a ceiling past where the direct map really ends. LowTotal
     * would be the right span, but it is fakeable inside a container (lxcfs
     * reports the cgroup limit), which is why highmem_32bit_bound caps its own
     * use of it below the sound floor; a drawn band should not rest on it
     * either.
     *
     * So derive only on a kernel proven to have no highmem: SF_PHYS_LOWMEM is
     * emitted ONLY when HighTotal > 0, and SF_PHYS_MEMTOTAL confirms meminfo
     * was readable at all -- without that second test an unreadable
     * /proc/meminfo would look identical to a no-highmem kernel. With no
     * highmem, all RAM is linearly mapped and max_pfn is the reach exactly. */
    if (!memtotal || highmem)
      max_pfn = 0;
#else
    (void)memtotal;
    (void)highmem;
#endif
    /* max_pfn counts the target kernel's pages, so the multiplier is that
     * kernel's page size: the compile-time one only where the architecture
     * admits a single size, and the observed SF_PAGE_SIZE otherwise. With
     * neither, no extent is drawn -- an understated span would draw the direct
     * map ending below where it really does. */
#ifdef pfn_to_phys
    unsigned long span = max_pfn ? pfn_to_phys(max_pfn) : 0;
    (void)obs_page_size; /* the arch admits one page size; the constant is it */
#else
    unsigned long span = 0;
    if (max_pfn && obs_page_size && max_pfn <= ULONG_MAX / obs_page_size)
      span = max_pfn * obs_page_size;
#endif
    if (span) {
      if (1
#if PHYS_OFFSET
          && span > (unsigned long)PHYS_OFFSET
#endif
      ) {
        unsigned long reach = span - (unsigned long)PHYS_OFFSET;
        if (reach - 1 <= ULONG_MAX - dmap_base) {
          dmap_end = dmap_base + reach - 1;
          dmap_extent_derived = 1;
        }
      }
    }
  }

  /* Kernel text is mapped THROUGH the direct map on coupled arches -- the image
   * sits at PAGE_OFFSET + a small offset, inside the linear mapping, not beside
   * it. Record that as containment rather than trying to stack the two as
   * disjoint bands, which is what previously forced the choice between hiding
   * the direct map entirely (it was suppressed whenever its base coincided with
   * the text floor, i.e. on the default configuration of every coupled arch, so
   * the largest kernel region simply never appeared) and drawing it as a
   * sibling *below* the region it contains. The ordering test is a guard, not a
   * formality: a direct-map base above the text floor would not contain it, and
   * indenting text inside it would assert something false. */
  int text_in_directmap = TEXT_TRACKS_DIRECTMAP && dmap_base &&
                          dmap_base <= layout.virt_image_base_min;

  regions[n++] = (struct map_region){layout.modules_start,
                                     layout.modules_end,
                                     "modules",
                                     vmod_lo,
                                     vmod_hi,
                                     0,
                                     MR_MODULES,
                                     MR_NONE,
                                     0};
  regions[n++] = (struct map_region){layout.virt_image_base_min,
                                     layout.virt_image_base_max,
                                     "kernel text",
                                     vtext_lo,
                                     vtext_hi,
                                     0,
                                     MR_KERNEL_TEXT,
                                     text_in_directmap ? MR_DIRECTMAP : MR_NONE,
                                     0};

  /* The direct map is shown whenever its base is known. Use the base as both
     start and end — the mapping begins there, but its true extent is
     unknown. virt_kernel_vas_end would cause unsigned overflow in the gap
     arithmetic (end + 1 wraps to 0). The only case still suppressed is a
     decoupled arch whose direct-map base coincides with the text floor: there
     the two are genuinely indistinguishable and nothing is contained. */
  if (dmap_base &&
      (text_in_directmap || dmap_base != layout.virt_image_base_min)) {
    regions[n++] =
        (struct map_region){dmap_base,    dmap_end, "direct map",
                            vdmap_lo,     vdmap_hi, !dmap_extent_derived,
                            MR_DIRECTMAP, MR_NONE,  dmap_extent_derived};
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

  /* A container must cover what it contains, so the drawn band absorbs its
   * contained regions' extents. This is the only widening the enclosing region
   * needs: everything else about the direct map's reach stays unknown, which
   * its own label continues to say. */
  for (int i = 0; i < n; i++) {
    if (regions[i].parent == MR_NONE)
      continue;
    for (int j = 0; j < n; j++) {
      if (regions[j].id != regions[i].parent)
        continue;
      if (regions[i].start < regions[j].start)
        regions[j].start = regions[i].start;
      if (regions[i].end > regions[j].end)
        regions[j].end = regions[i].end;
    }
  }

  /* Split into the bands the column draws and the regions drawn inside them.
   * `bands` is sorted by start; `regions` keeps insertion order so a band can
   * find its contents by id. */
  struct map_region bands[8];
  int nb = 0;
  for (int i = 0; i < n; i++)
    if (regions[i].parent == MR_NONE)
      bands[nb++] = regions[i];

  /* Sort by start address */
  qsort(bands, (size_t)nb, sizeof(struct map_region), region_cmp);

  /* No neighbour clamp here. Bands are NOT disjoint: on TEXT_TRACKS_DIRECTMAP
   * arches kernel text is nested inside the direct map, so clamping a band to
   * its successor's floor truncates the enclosing region and re-creates the
   * very defect the widening above removes -- a leak printed outside the band
   * that lists it. Where two regions share a start it also inverts one into a
   * zero-height band. A clamp is no help even on disjoint layouts: abutting
   * bands defeat the emit loop's `end + 1 < start` gap test exactly as
   * overlapping ones do, so the boundary is dropped either way. Containment is
   * now representable (see `parent`), so the disjointness assumption the clamp
   * encoded has no way back in. */

  /* "not to scale" is the one thing a column of addresses cannot say for
   * itself: the bands are drawn at a fixed height each, so a 128 TiB gap and a
   * 2 MiB one occupy the same three lines. docs/diagrams/address-space-map.svg
   * has carried the caption since it was drawn; the rendered map had not. */
  printf("%sVirtual address space (%s, not to scale):%s\n\n", c(C_BOLD),
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
   * it is clamped up to the highest known region boundary. */
  unsigned long map_top = layout.virt_kernel_vas_end;
  for (int i = 0; i < nb; i++)
    if (bands[i].end > map_top)
      map_top = bands[i].end;

  /* One address width for the whole column, sized to its widest member. The
   * map used to zero-pad every address to 16 digits, which on a 32-bit arch
   * prefixed every one of them with eight zeros -- the readout dropped that
   * costume and the map kept wearing it. */
  int w = 1;
  w = map_addr_w(w, map_top);
  w = map_addr_w(w, layout.virt_kernel_vas_start);
  for (int i = 0; i < n; i++) {
    w = map_addr_w(w, regions[i].start);
    w = map_addr_w(w, regions[i].end);
    w = map_addr_w(w, regions[i].leak_lo);
    w = map_addr_w(w, regions[i].leak_hi);
  }

  print_map_addr(w, map_top, NULL);

  /* The highest band's ceiling: no band sits above it to print the shared
   * bookend, so draw it here or it never appears and the map silently claims
   * the region reaches the top of the address space. */
  int open_top = 0;
  /* The topmost band always has its ceiling on screen: either the boundary
   * below draws it, or it coincides with the map's own top line, which was
   * just printed. Nothing sits above it to overlap it. */
  int ceiling_drawn = 1;
  if (nb > 0 && map_top > bands[nb - 1].end)
    open_top = print_map_boundary(INDENT, w, map_top, &bands[nb - 1]);

  for (int i = nb - 1; i >= 0; i--) {
    struct map_region *r = &bands[i];
    int pinned = (r->start == r->end);
    /* A base-only anchor (direct map) is drawn start==end but its extent is
     * unknown, so it is NOT a pinned single value — reserve "(pinned)" for a
     * genuine zero-extent point.
     *
     * One phrase for one fact. base_only means the engine placed the mapping's
     * floor but not its reach, and the column already states that where the
     * ceiling would be ("^ extent unknown"); repeating it in the label, in
     * different words, read as two separate caveats. So the tail says it only
     * when the ceiling line did not -- i.e. when a leak or a contained region
     * gave the band a drawn top edge that is NOT the region's own extent.
     *
     * The floor's provenance is the other half. It is a proven address only
     * when the engine pinned the quantity; where it holds a window, the drawn
     * floor is that window's low end and the label must not promote it. */
    char tail[64];
    tail[0] = '\0';
    if (r->base_only)
      snprintf(tail, sizeof(tail), " (base %s%s)",
               r->id == MR_DIRECTMAP && !dmap_base_pinned ? "is a lower bound"
                                                          : "guaranteed",
               open_top ? "" : "; extent unknown");
    else if (r->extent_derived)
      /* Says where the ceiling came from. It is not a leak and not a bound the
       * engine holds; it is arithmetic on the resolved base, and the reader is
       * told so rather than left to assume the region was observed end to end.
       */
      snprintf(tail, sizeof(tail), " (base guaranteed; extent derived)");
    else if (pinned)
      snprintf(tail, sizeof(tail), " (pinned)");
    open_top = 0;

    /* Region label line(s). Leak addresses, if any, fold inline.
     * Pinned regions (start == end) are a single known point — the
     * bookend addresses above and below already say everything; skip
     * the redundant "(no leak)" tail in that case. */
    char a1[40], a2[40];
    if (r->leak_lo) {
      if (r->leak_hi && r->leak_hi != r->leak_lo) {
        printf("%s%s%s\n", INDENT, r->label, tail);
        printf("%s  leak hi: %s\n", INDENT,
               readout_addr(r->leak_hi, w, a1, sizeof(a1)));
        printf("%s  leak lo: %s\n", INDENT,
               readout_addr(r->leak_lo, w, a1, sizeof(a1)));
      } else {
        printf("%s%s%s -- leak %s\n", INDENT, r->label, tail,
               readout_addr(r->leak_lo, w, a1, sizeof(a1)));
      }
    } else if (pinned) {
      printf("%s%s%s\n", INDENT, r->label, tail);
    } else {
      /* tail carries here too: a base-only band whose bookends come from
       * a contained region now has a drawn ceiling, and that ceiling is the
       * contained region's reach, not a measurement of this one's. Dropping the
       * disclaimer would let the drawn edge read as the region's extent. */
      printf("%s%s%s %s(no leak)%s\n", INDENT, r->label, tail, c(C_DIM),
             c(C_RESET));
    }

    /* A band the one above it OVERLAPS has no bookend to carry its top edge:
     * the transition was suppressed (an overlap has no boundary to draw), so
     * the column's last address is the overlapping band's floor, which is
     * BELOW this band's ceiling. The ceiling then went unstated -- and where a
     * leak had widened the band, the leak printed above both of the band's
     * bookends and broke the descending column. Live on aarch64, where the
     * engine's module window spans most of the kernel VAS and so covers the
     * direct map: the direct-map band drew one address as both bookends with
     * its own interior leak sitting 64 MiB above them. State the ceiling here
     * instead; it cannot be a bookend without running the column backwards. */
    if (!ceiling_drawn && r->end != r->start) {
      /* Where the band was widened to cover a leak, that leak IS the ceiling
       * and the line above has already printed it -- say only what is still
       * unsaid, which is where the edge sits. */
      unsigned long shown =
          (r->leak_hi && r->leak_hi != r->leak_lo) ? r->leak_hi : r->leak_lo;
      if (shown == r->end)
        printf("%s  %s^ top edge lies inside the band above%s\n", INDENT,
               c(C_DIM), c(C_RESET));
      else
        printf("%s  %sextends to %s  (inside the band above)%s\n", INDENT,
               c(C_DIM), readout_addr(r->end, w, a1, sizeof(a1)), c(C_RESET));
    }

    /* Regions mapped through this one, drawn inside its bookends with their own
     * span inline — the same sub-entry shape the physical column uses under a
     * bucket header. Nesting is what makes the relationship readable: a
     * contained region has no band of its own to be above or below, so no
     * reading of the column can put kernel text outside the direct map that
     * maps it. The `> ` marker distinguishes a region nested in THIS band from
     * the leak rows beneath it, which sit at the same depth and were otherwise
     * told apart only by their prefix text. */
    for (int j = 0; j < n; j++) {
      const struct map_region *sub = &regions[j];
      if (sub->parent != r->id)
        continue;
      if (sub->start == sub->end)
        printf("%s  > %s  %s\n", INDENT, sub->label,
               readout_addr(sub->start, w, a1, sizeof(a1)));
      else
        printf("%s  > %s  %s - %s\n", INDENT, sub->label,
               readout_addr(sub->start, w, a1, sizeof(a1)),
               readout_addr(sub->end, w, a2, sizeof(a2)));
      if (sub->leak_hi && sub->leak_hi != sub->leak_lo) {
        printf("%s      leak hi: %s\n", INDENT,
               readout_addr(sub->leak_hi, w, a1, sizeof(a1)));
        printf("%s      leak lo: %s\n", INDENT,
               readout_addr(sub->leak_lo, w, a1, sizeof(a1)));
      } else if (sub->leak_lo) {
        printf("%s      leak: %s\n", INDENT,
               readout_addr(sub->leak_lo, w, a1, sizeof(a1)));
      } else {
        printf("%s      %s(no leak)%s\n", INDENT, c(C_DIM), c(C_RESET));
      }
    }

    print_map_addr(w, r->start, NULL);

    /* Gap to the next (lower) band, if any. The gap address bookend
     * (the next band's `end`) is printed after the separator.
     *
     * `bands[i - 1].end < r->start` rather than `end + 1 < start`: the latter
     * wraps to 0 for a band ending at the top of the address space and then
     * reports a gap where the two bands in fact overlap, printing an address
     * ABOVE the one just printed. Bands are not guaranteed disjoint (riscv32's
     * module window covers the direct map), so an overlap has no boundary to
     * draw and the transition is simply omitted. */
    /* The band below has its ceiling on screen unless it OVERLAPS this one:
     * a strictly lower ceiling gets the boundary's own bookend, and an
     * abutting one (end == start) is the address just printed. Only an
     * overlap leaves it unstated -- and only that case needs the annotation
     * above. */
    ceiling_drawn = (i > 0 && bands[i - 1].end <= r->start);
    if (i > 0 && bands[i - 1].end < r->start)
      open_top = print_map_boundary(INDENT, w, r->start, &bands[i - 1]);
  }

  /* Only print virt_kernel_vas_start as a footer when it is genuinely below the
   * lowest visible region (i.e. the VAS extends further down than
   * virt_page_offset). Where the lowest band starts at the VAS floor itself, or
   * below it, the footer would repeat a boundary the map already draws or place
   * two labels in inverted address order. */
  if (nb == 0 || layout.virt_kernel_vas_start < bands[0].start) {
    if (nb > 0 && bands[0].start > layout.virt_kernel_vas_start + 1) {
      char hbuf[32];
      unsigned long gap = bands[0].start - layout.virt_kernel_vas_start;
      printf("%s%s. . .  %s gap  . . .%s\n", INDENT, c(C_DIM),
             kasld_grain(gap, hbuf, sizeof(hbuf)), c(C_RESET));
    }
    /* Annotate the kernel VAS floor: what lies below it is not a KASLR target
     * (and not inferred here). On 64-bit a non-canonical hole separates the
     * kernel half from user space; 32-bit splits straight into user space. */
    const char *below = (sizeof(unsigned long) > 4)
                            ? "user space + non-canonical hole below"
                            : "user space below";
    char foot[96];
    snprintf(foot, sizeof(foot), "  %s(%s)%s", c(C_DIM), below, c(C_RESET));
    print_map_addr(w, layout.virt_kernel_vas_start, foot);
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
     * inside a box — so they are skipped in the per-bucket leak listing. */
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
   * pos=BASE — boundary selection must NOT be gated on `pos`. The
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

  printf("%sPhysical address space (not to scale):%s\n\n", c(C_BOLD),
         c(C_RESET));

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
   * derived one. The ceiling must also sit above everything drawn beneath it
   * (points AND bucket footers), so it is only finalised and printed once the
   * buckets exist — see the fold-in below the bucket construction. */
  unsigned long top_label = have_ram_top ? ram_top : ram_end;
  int top_is_estimate = !have_ram_top;
  /* High MMIO routinely lies above ram_top, and pinning the label to ram_top
   * drew those points outside the map that lists them -- and, when the
   * above-DRAM band's own footer is ram_top too, printed one address as both
   * bookends of a band holding points gigabytes higher. ppts[] is ordered high
   * to low, so its head is the highest point shown. (The sysconf path already
   * did this; the leaked path did not.) */
  if (nppts > 0 && ppts[0].addr > top_label) {
    top_label = ppts[0].addr;
    top_is_estimate = 0; /* an observed address, however it was reached */
  }

  /* On !TEXT_TRACKS_DIRECTMAP arches the phys text base is independently
   * randomized inside [phys_kaslr_text_min, phys_kaslr_text_max]. Inference
   * tightens both ends so this window can be much narrower than the arch
   * default. Given a non-trivial window, split the in-DRAM portion
   * into above-window / inside-window / below-window. Coupled arches and
   * arches without phys KASLR leave both bounds at 0 — single DRAM box. */
  unsigned long pmin = layout.phys_kaslr_text_min;
  unsigned long pmax = layout.phys_kaslr_text_max;

  /* DRAM range used to clip the in-DRAM buckets and decide above/below
   * buckets. Falls back to PHYS_OFFSET..ULONG_MAX when edges are unknown. */
  unsigned long dram_lo = have_ram_base ? ram_base : (unsigned long)PHYS_OFFSET;
  unsigned long dram_hi = have_ram_top ? ram_top : ULONG_MAX;

  /* The window as DRAWN is its intersection with DRAM. The buckets have to
   * PARTITION the address space: the above-DRAM and below-DRAM bands own
   * everything outside [dram_lo, dram_hi], so an in-DRAM band that reaches
   * past a DRAM edge overlaps one of them, and a kernel-image leak landing in
   * the overlap prints twice under two different band headers. The window
   * edges do reach past: pmax is the engine's proven ceiling on the physical
   * image base, which stays at the arch default until an observation narrows
   * it and so routinely sits above a leaked ram_top. (Non-image leaks in the
   * overlap were already single-printed — the window band's `text_only` gate
   * drops them — so the double print is specific to kernel-image records.)
   * Clipping moves no printed address: the [pmax + 1, dram_hi] band is not
   * emitted at all when pmax >= dram_hi, and the window's footer already
   * collapsed to dram_lo when pmin <= dram_lo. It is the band MEMBERSHIP that
   * changes, which is the defect. The engine's window itself is untouched --
   * clipping that would misreport it. */
  unsigned long wlo = pmin > dram_lo ? pmin : dram_lo;
  unsigned long whi = pmax < dram_hi ? pmax : dram_hi;
  /* wlo <= whi is exactly "the window meets DRAM"; when it does not, there is
   * no in-DRAM window to split around and the single DRAM band (which admits
   * every region) shows any leak the above/below bands do not. */
  int show_phys_window =
      (pmax > pmin && pmin > 0 && dram_lo <= dram_hi && wlo <= whi);

  /* The window band's TOP is an edge the column draws, and unlike a footer it
   * is a top edge, so the footer sweep further down never sees it. pmax is
   * engine state and is not clipped, so where the proven ceiling sits above the
   * RAM estimate the ceiling rises to meet it -- otherwise the window band runs
   * off the top of its own map. Raised here rather than after the buckets are
   * built, because the band above the window is bounded by this ceiling. */
  if (show_phys_window && whi > top_label) {
    top_label = whi;
    top_is_estimate = 0;
  }

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
   * Only emitted when such leaks are present AND ram_top is known. */
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
        (struct phys_bucket){"in DRAM", dram_lo, dram_hi, dram_lo, 0};
  } else {
    /* In-DRAM above text window. Clipped at ram_top (no longer ULONG_MAX).
     * Named by its position around the text window: the two in-DRAM bands are
     * different parts of DRAM, and heading both of them "in DRAM" left the
     * reader to work out which was which from the addresses alone. */
    /* Bounded by the drawn ceiling, not by dram_hi. With no known RAM top
     * dram_hi is ULONG_MAX, which made this band unconditional and gave it a
     * top far above anything the column prints: it rendered between two copies
     * of the same address, a labelled region of zero height. Bounding it by
     * top_label draws it only over space the map actually shows, and drops it
     * entirely when the window already reaches the ceiling. No leak is lost
     * with it -- the ceiling dominates the highest point above. */
    unsigned long band_hi = dram_hi < top_label ? dram_hi : top_label;
    if (band_hi > whi)
      buckets[nbuckets++] = (struct phys_bucket){"in DRAM, above kernel text",
                                                 whi + 1, band_hi, whi, 0};
    /* Text window, clipped into DRAM (a window edge outside DRAM belongs to
     * the above-/below-DRAM band, not to this one). */
    buckets[nbuckets++] =
        (struct phys_bucket){"phys kernel text", wlo, whi, wlo, 1};
    /* In-DRAM below text window. Clipped at ram_base (no longer PHYS_OFFSET).
     * When the window's lower edge is at or below dram_lo, wlo == dram_lo and
     * the window band already carries dram_lo as its footer — the trailing
     * label collapses with no separate band. */
    if (wlo > dram_lo)
      buckets[nbuckets++] = (struct phys_bucket){"in DRAM, below kernel text",
                                                 dram_lo, wlo - 1, dram_lo, 0};
  }

  /* Below-DRAM bucket: leaks whose address < ram_base. Only emitted when
   * such leaks are present. PHYS_OFFSET terminates the column. */
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

  /* Finalise the ceiling: it must dominate every edge the column goes on to
   * draw, and the bucket footers are edges too. The `[pmax + 1, dram_hi]`
   * bucket carries `pmax` as its footer, and pmax -- the engine's proven
   * ceiling on the physical image base -- routinely sits above both the leaked
   * ram_top and the sysconf estimate (any host with no DRAM-extent observation,
   * where pmax stays at the arch default). Printing the ceiling first and the
   * footer after ran the column non-monotonic: an address above the stated top
   * of the map. pmax itself is engine state and is NOT clipped -- truncating it
   * would misreport the window -- so the ceiling rises to meet it instead.
   * A bucket footer is a PROVEN bound (pmax is the engine's ceiling, dram_lo a
   * leaked edge) even though it is derived rather than observed, so a ceiling
   * raised to meet one carries no speculative tag. */
  for (int b = 0; b < nbuckets; b++) {
    if (buckets[b].footer_addr > top_label) {
      top_label = buckets[b].footer_addr;
      top_is_estimate = 0;
    }
  }

  /* One address width for the physical column, as in the virtual one. */
  int w = 1;
  w = map_addr_w(w, top_label);
  for (int i = 0; i < nppts; i++)
    w = map_addr_w(w, ppts[i].addr);
  for (int b = 0; b < nbuckets; b++)
    w = map_addr_w(w, buckets[b].footer_addr);

  /* The RAM top is either an address something reported or the sysconf
   * page-count estimate. "likely (speculative)" is the readout's word for a
   * value that is not proven; the map used to coin "(estimated)" for the same
   * idea two blocks further down the same screen. */
  if (top_label)
    print_map_addr(w, top_label, top_is_estimate ? "  likely" : NULL);
  else
    printf("  %*s  (end of RAM unknown)\n", w + 2, "0x?");

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
    printf("%s%s\n", INDENT, bk->header);
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
        char ab[40];
        printf("%s  %s  %s\n", INDENT,
               readout_addr(ppts[i].addr, w, ab, sizeof(ab)), ppts[i].label);
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
    print_map_addr(w, bk->footer_addr, NULL);
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
/* The evidence table's columns. Region and Position say what kind of claim the
 * row makes, Address carries it, and Sources counts the components that
 * independently produced it -- a corroboration count, which is what a reader
 * weighs a finding by. The component NAMES are detail rather than headline, and
 * printing them costs a second line per finding, so they live in -v. */
static const char *const ev_hdr[] = {"Region", "Position", "Address",
                                     "Sources"};

static int readout_print_leaks(void) {
  /* Regions worth surfacing in the headline list. */
  struct {
    enum kasld_addr_type type;
    enum kasld_region region;
    const char *label;
  } interesting[] = {
      {KASLD_TYPE_VIRT, REGION_KERNEL_TEXT, "virt kernel text"},
      /* Named like "virt module region": the address is real and inside the
       * admissible text window, but which region it belongs to was not
       * established. Omitting it would narrow the likely window with no
       * finding on screen to account for the narrowing. */
      {KASLD_TYPE_VIRT, REGION_KERNEL_TEXT_BAND, "virt text region"},
      {KASLD_TYPE_VIRT, REGION_KERNEL_IMAGE, "virt kernel image"},
      {KASLD_TYPE_VIRT, REGION_KERNEL_DATA, "virt kernel data"},
      {KASLD_TYPE_VIRT, REGION_KERNEL_BSS, "virt kernel BSS"},
      {KASLD_TYPE_VIRT, REGION_DIRECTMAP, "virt directmap"},
      {KASLD_TYPE_VIRT, REGION_DIRECTMAP_BAND, "virt directmap region"},
      {KASLD_TYPE_VIRT, REGION_MODULE, "virt module"},
      {KASLD_TYPE_VIRT, REGION_MODULE_BAND, "virt module region"},
      {KASLD_TYPE_PHYS, REGION_KERNEL_TEXT, "phys kernel text"},
      {KASLD_TYPE_PHYS, REGION_KERNEL_IMAGE, "phys kernel image"},
      {KASLD_TYPE_PHYS, REGION_KERNEL_DATA, "phys kernel data"},
      {KASLD_TYPE_PHYS, REGION_KERNEL_BSS, "phys kernel BSS"},
  };
  int n_int = (int)(sizeof(interesting) / sizeof(interesting[0]));

  /* Pre-collect (label, addr, contributing record) tuples so as to print
   * a "(N)" header.
   *
   * `is_edge` splits a region's records into the two independent things that
   * can be known about it, and each row carries only one of them. */
  struct {
    const char *label;
    unsigned long addr;
    const struct result *r;
    unsigned long span_lo, span_hi;
    int is_span;
    int is_edge;
  } found[32];
  int nf = 0;

  for (int k = 0; k < n_int && nf + 1 < (int)(sizeof(found) / sizeof(found[0]));
       k++) {
    /* A region can carry two independent kinds of observation: a resolved edge
     * (base or top) and bare interior samples. They answer different questions
     * -- where the region starts, versus how far it is known to reach -- and
     * neither subsumes the other, so each takes its own row. Ranking them
     * against each other would have to discard one, and confidence cannot
     * order them: an interior sample tying a base on confidence is not a
     * statement about position at all.
     *
     * Within a kind, the highest-confidence record represents it. */
    const struct result *edge = NULL, *sample = NULL;
    int edge_w = -1, sample_w = -1;
    unsigned long slo = 0, shi = 0;
    int n_samples = 0;
    for (int i = 0; i < num_results; i++) {
      const struct result *r = &results[i];
      if (r->type != interesting[k].type || r->region != interesting[k].region)
        continue;
      if (!in_bounds(r))
        continue;
      int w = conf_weight(r->conf);
      if (HAS_LO(r) || HAS_HI(r)) {
        if (w > edge_w) {
          edge_w = w;
          edge = r;
        }
        continue;
      }
      /* Span endpoints come from the samples alone. Measured across every
       * record they would take an edge as an endpoint, and the row would
       * report a resolved base as the low end of an interior span. */
      unsigned long a = anchor_addr(r);
      if (w > sample_w) {
        sample_w = w;
        sample = r;
      }
      if (!n_samples || a < slo)
        slo = a;
      if (!n_samples || a > shi)
        shi = a;
      n_samples++;
    }
    if (edge) {
      found[nf].label = interesting[k].label;
      found[nf].addr = anchor_addr(edge);
      found[nf].r = edge;
      found[nf].is_span = 0;
      found[nf].span_lo = found[nf].span_hi = 0;
      found[nf].is_edge = 1;
      nf++;
    }
    if (sample) {
      found[nf].label = interesting[k].label;
      found[nf].addr = anchor_addr(sample);
      found[nf].r = sample;
      /* Distinct samples from independent sources bound the region's observed
       * extent. Collapsing them onto one address and crediting every source to
       * it would imply they all found that address, when they each found a
       * different point. A lone sample has no extent to state and prints as
       * the single address it is. */
      found[nf].is_span = shi > slo;
      found[nf].span_lo = slo;
      found[nf].span_hi = shi;
      found[nf].is_edge = 0;
      nf++;
    }
  }

  if (nf == 0)
    return 0;

  /* The widest address field, up front, so the position and origin columns
   * line up whether a row shows one address or a span. */
  int any_span = 0;
  for (int i = 0; i < nf; i++)
    if (found[i].is_span)
      any_span = 1;
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
  /* Columns are sized to the run's own content, header included, exactly as
   * the Layout table sizes its own -- the two tables sit one above the other
   * and a reader should not have to learn a second set of rules to read the
   * lower one. */
  if (label_w < (int)strlen(ev_hdr[0]))
    label_w = (int)strlen(ev_hdr[0]);
  const int posnote_w =
      (any_span ? (int)strlen("interior span") : (int)strlen("interior"));

  /* Count distinct contributing components across the whole block: a finding
   * is a (type, region) group, and several components can corroborate one, so
   * a bare row count under-reports what produced the evidence. */
  int total_sources = 0;
  {
    struct origin_set all;
    memset(&all, 0, sizeof(all));
    for (int i = 0; i < nf; i++)
      for (int j = 0; j < num_results; j++) {
        const struct result *r = &results[j];
        if (r->type != found[i].r->type || r->region != found[i].r->region ||
            !in_bounds(r))
          continue;
        origin_set_union(&all, &r->origins);
      }
    total_sources = origin_set_count(&all);
  }

  /* "Evidence", not "Leaks": the block holds side-channel measurements
   * (prefetch timing) alongside actual disclosures, and only the latter are
   * leaks. */
  printf("%sEvidence%s  (%d finding%s, %d component%s)\n", c(C_BOLD),
         c(C_RESET), nf, nf == 1 ? "" : "s", total_sources,
         total_sources == 1 ? "" : "s");

  /* Render each row's cells before any of them print, so the address and source
   * columns can be sized to what they actually hold. */
  char cell_addr[sizeof(found) / sizeof(found[0])][96];
  const char *cell_pos[sizeof(found) / sizeof(found[0])];
  int cell_src[sizeof(found) / sizeof(found[0])];
  int addr_w = (int)strlen(ev_hdr[2]), src_w = (int)strlen(ev_hdr[3]);

  for (int i = 0; i < nf; i++) {
    char t[32], lo[40];
    int n;
    /* Credit every component that found this (type, region) IN THIS ROW'S KIND,
     * not merely the one record that represents it: a finding corroborated by
     * five components and one found once are not the same finding, and the
     * count is the only thing on the row that says which this is. */
    struct origin_set seen;
    memset(&seen, 0, sizeof(seen));
    for (int j = 0; j < num_results; j++) {
      const struct result *r = &results[j];
      if (r->type != found[i].r->type || r->region != found[i].r->region ||
          !in_bounds(r))
        continue;
      if (!!(HAS_LO(r) || HAS_HI(r)) != !!found[i].is_edge)
        continue;
      origin_set_union(&seen, &r->origins);
    }
    cell_src[i] = origin_set_count(&seen);
    cell_pos[i] = found[i].is_span ? "interior span" : pos_word(found[i].r);

    /* The low address is right-aligned within the widest hex value the block
     * draws, so a lone address lines up with the low end of every span beside
     * it and the column reads as one ladder of addresses. */
    snprintf(t, sizeof(t), "0x%lx",
             found[i].is_span ? found[i].span_lo : found[i].addr);
    snprintf(lo, sizeof(lo), "%*s", digits + 2, t);
    if (found[i].is_span) {
      char hi[40];
      snprintf(t, sizeof(t), "0x%lx", found[i].span_hi);
      /* Padded into its own buffer first: composing with a runtime "%*s" width
       * leaves the result's length unbounded to the compiler, and the two ends
       * are the same shape anyway. */
      snprintf(hi, sizeof(hi), "%*s", digits + 2, t);
      snprintf(cell_addr[i], sizeof(cell_addr[i]), "%s - %s", lo, hi);
    } else {
      snprintf(cell_addr[i], sizeof(cell_addr[i]), "%s", lo);
    }
    n = (int)strlen(cell_addr[i]);
    if (n > addr_w)
      addr_w = n;
    n = cell_src[i] < 10 ? 1 : (cell_src[i] < 100 ? 2 : 3);
    if (n > src_w)
      src_w = n;
  }

  printf("  %s%-*s  %-*s  %-*s  %*s%s\n", c(C_BOLD), label_w, ev_hdr[0],
         posnote_w, ev_hdr[1], addr_w, ev_hdr[2], src_w, ev_hdr[3], c(C_RESET));
  printf("  ");
  for (int k = 0; k < label_w; k++)
    putchar('-');
  printf("  ");
  for (int k = 0; k < posnote_w; k++)
    putchar('-');
  printf("  ");
  for (int k = 0; k < addr_w; k++)
    putchar('-');
  printf("  ");
  for (int k = 0; k < src_w; k++)
    putchar('-');
  putchar('\n');

  for (int i = 0; i < nf; i++)
    printf("  %-*s  %-*s  %-*s  %*d\n", label_w, found[i].label, posnote_w,
           cell_pos[i], addr_w, cell_addr[i], src_w, cell_src[i]);
  return nf;
}

static int readout_hex_digits(unsigned long v) {
  int n = 0;
  do {
    n++;
    v >>= 4;
  } while (v);
  return n;
}

/* An address right-aligned to `digits` hex digits, never zero-padded: relative
 * magnitude stays legible, and a 16 MiB physical address does not wear the
 * costume of a 64-bit kernel pointer. The padding is written directly rather
 * than through a runtime "%*s" width, which no bound can be proved through. */
static const char *readout_addr(unsigned long v, int digits, char *buf,
                                size_t sz) {
  char t[32];
  int n = snprintf(t, sizeof(t), "0x%lx", v);
  int want = (digits < 0 ? 0 : digits) + 2;
  int pad = want - n;
  if (sz == 0)
    return buf;
  if (pad < 0)
    pad = 0;
  if ((size_t)pad > sz - 1)
    pad = (int)(sz - 1);
  memset(buf, ' ', (size_t)pad);
  snprintf(buf + pad, sz - (size_t)pad, "%s", t);
  return buf;
}

/* The shared compile-time-default remark, indented into the Layout block and
 * set off from the value rows above it. Addresses in the readout are never
 * zero-padded, so the remark renders the default the same way. */
static void readout_default_remark(unsigned long def, unsigned long lo,
                                   unsigned long hi) {
  char ab[40], rb[160];
  const char *rem;
  snprintf(ab, sizeof(ab), "0x%lx", def);
  rem = default_base_remark(def, lo, hi, ab, rb, sizeof(rb));
  if (rem)
    printf("\n  %s%s%s\n", c(C_DIM), rem, c(C_RESET));
}

/* The compile-time default, judged against the resolved window, for the
 * postures where nothing randomized the image. The window itself is reported by
 * the same table every other posture draws; this adds only whether the build's
 * own default is still a candidate. It is never the answer: the default is a
 * constant of THIS build, and a differently configured kernel does not honour
 * it -- an armv7 kernel built VMSPLIT_2G puts _text at 0x80008000 while the
 * arch default reads 0xc0008000. Judged on the first resolved quantity, the
 * image base, the only one carrying a compile-time default at all.
 *
 * The default is rendered the way the table above it renders every other
 * address -- unpadded. Zero-filling to 16 digits dresses a 32-bit constant as a
 * 64-bit one, and puts two spellings of the same kind of address in one
 * block. */
static void verbose_default_remark(unsigned long default_addr) {
  char ab[40], rb[160];
  const char *rem;
  for (int i = 0; i < n_layout_rows; i++) {
    const struct layout_row *r = &layout_rows[i];
    /* A set row carries no window, so there is nothing for the default to be
     * judged against; its zeroed edges are not bounds. */
    if (r->dim || r->is_set || strcmp(r->cell[1], GRADE_GUARANTEED) != 0)
      continue;
    snprintf(ab, sizeof(ab), "0x%lx", default_addr);
    rem = default_base_remark(default_addr, r->lo, r->hi, ab, rb, sizeof(rb));
    if (rem)
      printf("%s%s%s\n\n", c(C_DIM), rem, c(C_RESET));
    return;
  }
}

/* ---------------------------------------------------------------------------
 * The Layout table.
 *
 * One row per (quantity, certainty). Cells are formatted into fixed buffers
 * before anything prints, so the columns are sized to the run's own content.
 *
 *   Quantity      what is being located. Repeated on a quantity's second row:
 *                 a blank cell in a table means "no value", not "same as
 *                 above", and markdown has no rowspan to borrow.
 *   Certainty     which of the two windows the row reports.
 *   Candidates    how many placements survive, and out of how many where the
 *                 kernel's own randomization window is modelled. It leads the
 *                 numeric columns because it is the brute-force cost of the
 *                 row -- the figure a reader compares between quantities --
 *                 and because a right-aligned count against a fixed left edge
 *                 stays a column, where a trailing one shreds against ranges
 *                 whose printed width varies by twenty characters.
 *   Window        the addresses.
 *   Grain         the grid the candidates sit on; what reconciles the count
 *                 with the range.
 *
 * A quantity the engine never bounded still gets a row, so the set of rows is
 * a property of the architecture rather than of the run: rows do not appear
 * and vanish between boots, and "nothing was narrowed" is stated instead of
 * left to inference. Such a row carries no numbers -- printing the
 * architectural window would put a compile-time constant where a reader
 * expects a measurement.
 * ------------------------------------------------------------------------- */

/* Widest address the table will draw, in hex digits. Both endpoints of every
 * range share it, so the " - " separator and each endpoint form a column
 * without any address being zero-padded into a width it does not occupy. */
static int layout_addr_w(void) {
  int w = 1, i;
  for (i = 0; i < n_layout_rows; i++) {
    int a = readout_hex_digits(layout_rows[i].lo);
    int b = readout_hex_digits(layout_rows[i].hi);
    if (layout_rows[i].lo && a > w)
      w = a;
    if (layout_rows[i].hi && b > w)
      w = b;
  }
  return w;
}

/* Re-render a row's Range cell with its endpoints right-aligned, in place.
 *
 * layout_add() leaves the cell in the unpadded form markdown wants, where a
 * long line simply reflows. A terminal line does not, so the text table pads
 * each endpoint to the widest address in the table -- with spaces, never
 * zeroes, so a 16 MiB physical address keeps its magnitude. A row with no
 * addresses ("not narrowed") has nothing to align and keeps what it has. */
static void layout_pad_range(struct layout_row *r, int aw) {
  char a1[24], a2[24], out[LAYOUT_CELL];
  const char *sep = r->note[0] ? " " : "";
  if (!r->lo && !r->hi)
    return;
  /* Presented exactly as the engine resolved them. Moving an edge onto the
   * candidate grid is a narrowing, and a narrowing is the engine's to make and
   * to prove: done here it would hold only for this format, and the readout
   * would report a different window from the one markdown and json report for
   * the same run. */
  unsigned long lo = r->lo, hi = r->hi;
  if (lo && hi && lo != hi)
    snprintf(out, sizeof(out), "%s - %s%s%s",
             readout_addr(lo, aw, a1, sizeof(a1)),
             readout_addr(hi, aw, a2, sizeof(a2)), sep, r->note);
  else if (lo && hi)
    snprintf(out, sizeof(out), "%s%s%s", readout_addr(lo, aw, a1, sizeof(a1)),
             sep, r->note);
  else if (lo)
    snprintf(out, sizeof(out), ">= %s%s%s",
             readout_addr(lo, aw, a1, sizeof(a1)), sep, r->note);
  else
    snprintf(out, sizeof(out), "<= %s%s%s",
             readout_addr(hi, aw, a1, sizeof(a1)), sep, r->note);
  snprintf(r->cell[2], LAYOUT_CELL, "%s", out);
}

/* One Range cell, padded to `w` from the cell's PLAIN length -- escape bytes
 * are not columns, so the pad is counted before any colour is added.
 *
 * The endpoints and the note trailing them are different kinds of number. An
 * endpoint is an address the quantity can take; the note restates that same
 * placement as a displacement from an un-randomized base, so it is not a
 * candidate at all. Run together they read as one string, and since every
 * other row in this column holds "lo - hi", a second hex value trailing the
 * first invites reading the displacement as a high endpoint. It therefore
 * carries the colour a non-candidate number carries throughout the readout,
 * which is also what the same note wears in the static-posture block.
 *
 * The note is a suffix of the composed cell, so the split is a length rather
 * than a re-format; a cell that does not end in its note (a row with no
 * narrowing carries no endpoints to displace from) prints whole. */
static void layout_print_range(const struct layout_row *r, int w) {
  int n = (int)strlen(r->cell[2]);
  int nl = (int)strlen(r->note);
  int head = n, k;
  const char *weight = "", *hue = "";
  if (r->dim || !nl || n <= nl || strcmp(r->cell[2] + n - nl, r->note) != 0)
    nl = 0;
  else
    /* The note is composed onto the value with a single separating space.
     * That space belongs to neither field, so it stays outside the emphasis
     * and the two runs of colour meet cleanly. */
    head = n - nl - 1;
  /* A row's emphasis rides on its value, not on the word grading it, and the
   * two channels answer different questions.
   *
   * Colour answers "how far can this be trusted?", and only where the row
   * carries an answer at all: green on a proven placement, yellow on one
   * narrowed further than the proof supports. A guaranteed window takes
   * neither -- it is proven, but it names no answer to act on, and it is the
   * state every quantity starts in, so tinting it would put a hue on nearly
   * every row and leave the colour distinguishing nothing.
   *
   * The two hues are ranked the way the results are: the proven answer is the
   * best outcome a run has, so it must not read as the quieter of the two.
   * Weight alone cannot carry that, since bold white is less urgent to the eye
   * than any colour.
   *
   * Weight answers "does this name a single address?" -- the thing the run is
   * for. A window is a narrowing however tight it is, and a row still holding
   * hundreds of candidates must not carry the same weight as one holding a
   * placement. Weight also keeps a tinted value readable, since how much
   * contrast a hue has against a given background is not something this
   * program can know and a long hex value is where that costs most.
   *
   * So a proven placement is bare weight, an unproven one is weight tinted to
   * qualify it, an unproven window is tint alone, and the sound window every
   * quantity starts in takes neither. The Certainty word states the grade
   * outright in every case: the emphasis ranks a row, it does not classify it,
   * so nothing here rests on a reader telling two hues apart.
   *
   * The two are asked separately below, and they are not independent: green
   * needs a single address as well as a proven one, so hue reads whether the
   * row names an answer just as weight does. They stay separate questions all
   * the same -- weight asks WHETHER there is an answer, hue asks how far it can
   * be trusted -- and a single flag answering both would fix their relationship
   * where it was set rather than here, where the ranking is decided. */
  if (!r->dim) {
    if (strcmp(r->cell[1], GRADE_LIKELY) == 0)
      hue = c(C_YELLOW);
    else if (r->one_address)
      hue = c(C_GREEN);
  }
  if (r->one_address)
    weight = c(C_BOLD);
  if (*weight || *hue)
    printf("%s%s%.*s%s", weight, hue, head, r->cell[2], c(C_RESET));
  else
    printf("%.*s", head, r->cell[2]);
  if (nl)
    printf(" %s%s%s", c(C_CYAN), r->note, c(C_RESET));
  for (k = n; k < w; k++)
    putchar(' ');
}

static void layout_render(void) {
  int w[LAYOUT_COLS], i, col, aw;
  if (!n_layout_rows)
    return;
  aw = layout_addr_w();
  for (i = 0; i < n_layout_rows; i++)
    layout_pad_range(&layout_rows[i], aw);
  for (col = 0; col < LAYOUT_COLS; col++) {
    w[col] = (int)strlen(layout_hdr[col]);
    for (i = 0; i < n_layout_rows; i++) {
      int l = (int)strlen(layout_rows[i].cell[col]);
      if (l > w[col])
        w[col] = l;
    }
  }
  printf("  %s", c(C_BOLD));
  for (col = 0; col < LAYOUT_COLS; col++)
    printf("%s%-*s", col ? "  " : "", w[col], layout_hdr[col]);
  printf("%s\n  ", c(C_RESET));
  for (col = 0; col < LAYOUT_COLS; col++) {
    int k;
    if (col)
      printf("  ");
    for (k = 0; k < w[col]; k++)
      putchar('-');
  }
  putchar('\n');
  for (i = 0; i < n_layout_rows; i++) {
    const struct layout_row *r = &layout_rows[i];
    printf("  %s", r->dim ? c(C_DIM) : "");
    printf("%-*s  ", w[0], r->cell[0]);
    /* The grade is a label, read once per row, and it names what the emphasis
     * on the value already shows; colouring it would draw the eye to the word
     * instead of to the address the run was for. It also cannot discriminate
     * much: every quantity draws a guaranteed row whether or not evidence
     * narrowed it, so a run that resolved nothing carries that word down the
     * whole column exactly as one that pinned every base does. Plain, in its
     * own column, it keeps the precision the emphasis cannot state. */
    printf("%-*s", w[1], r->cell[1]);
    printf("  ");
    layout_print_range(r, w[2]);
    printf("  %*s  %s", w[3], r->cell[3], r->cell[4]);
    if (r->dim)
      printf("%s", c(C_RESET));
    putchar('\n');
  }
}

static void render_readout(const struct summary *s) {
  /* Tool + target header is printed by orchestrator.c BEFORE the "Running
   * N components" line and progress bar - conventional CLI ordering
   * (header → work → results). The readout starts directly with the
   * findings so the progress bar is the last thing erased before the
   * answers appear. */

  /* Built BEFORE the posture branches, not inside the randomized path: the row
   * model is the one place that decides which resolved quantities the readout
   * presents, and a posture that returns before building it has to decide again
   * for itself -- which is how the static postures came to show only the image
   * base while JSON reported every quantity the engine had resolved. */
  layout_build();

  /* The posture, stated in words, above one table drawn the same way in every
   * posture.
   *
   * The table's own rule is that a quantity gets a row whether or not the
   * engine bounded it, so the readout's shape is a property of the
   * architecture rather than of the run. A posture that renders a different
   * shape breaks that rule one level up: two runs of one target across a
   * reboot that changed the posture could not be compared, and a reader who
   * knew one form did not recognise the other. Where randomization does not
   * apply, Candidates and Align carry the table's own mark for a cell with
   * nothing to report rather than a fabricated count.
   *
   * Randomization-failed is not the disabled posture -- the boot stub did
   * relocate the image, so it sits at neither a random base nor the link-time
   * default -- but all three want the same treatment here: say which kind of
   * system this is, then report the engine's windows. */
  if (s->kaslr.unsupported)
    printf("KASLR not supported on this architecture.\n\n");
  else if (s->kaslr.disabled)
    printf("%sKASLR is disabled on this kernel%s "
           "(nokaslr / RANDOMIZE_BASE=n / hibernation).\n\n",
           c(C_YELLOW), c(C_RESET));
  else if (s->kaslr.randomization_failed)
    printf("%sKASLR randomization did not run on this kernel%s "
           "(no seed / no PRNG).\nThe boot stub still placed the image, so it "
           "is not at the compile-time default.\n\n",
           c(C_YELLOW), c(C_RESET));

  /* Regular KASLR path: the Layout table, the coupling note, then the leaks.
   * Every quantity the architecture randomizes gets a row whether or not the
   * engine bounded it; a quantity the architecture does not randomize gets
   * none, because the tool has nothing to say about it. */
  layout_render();

  if (s->kaslr.unsupported || s->kaslr.disabled) {
    /* Where nothing randomized the image, whether the compile-time default is
     * still a candidate is worth stating -- but only that. The default is
     * never the answer: it is a constant of THIS build, and a differently
     * configured kernel does not honour it (an armv7 kernel built VMSPLIT_2G
     * puts _text at 0x80008000 while the arch default reads 0xc0008000). The
     * engine's window is the answer; the remark says how the default sits
     * against it, judged on the first resolved quantity -- the image base, the
     * only one carrying a compile-time default at all. */
    unsigned long rem_lo = 0, rem_hi = 0;
    for (int i = 0; i < n_layout_rows; i++) {
      const struct layout_row *r = &layout_rows[i];
      if (r->dim || strcmp(r->cell[1], GRADE_GUARANTEED) != 0)
        continue;
      rem_lo = r->lo;
      rem_hi = r->hi;
      break;
    }
    if (rem_lo || rem_hi)
      readout_default_remark(s->kaslr.default_addr, rem_lo, rem_hi);
    printf("\n");
  } else {
    /* Coupling closes the bounds table as a single dim line: it is a static
     * arch property (not a measured quantity), so it recedes from the measured
     * rows above and explains why physical and virtual bases resolve as
     * separate (or shared) quantities. Its job is to relate the physical and
     * virtual text bases, and a physical image base row is always present, so
     * there is always something to relate to.
     *
     * Gated to the postures where it describes the run: it says the two bases
     * randomize independently, which on a kernel that randomized neither reads
     * as a claim about behaviour that did not occur.
     *
     * Presented as a note rather than as a value row, so it does not sit in the
     * value column alongside addresses under an abbreviated label its siblings
     * do not use. */
    printf("\n  %sNote: %s%s\n", c(C_DIM), kasld_coupling_descr(), c(C_RESET));
    printf("\n");
  }

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
}

/* Trailing hint, printed once by the caller AFTER every block it advertises --
 * emitting it from the readout put it between the readout and the map, where it
 * read as a divider rather than a footer. It names only what this invocation
 * did not already produce: offering --map to a reader who passed --map, or -H
 * to one who passed -H, is noise that makes the real suggestion harder to see.
 * Verbose mode prints no hint at all, having already shown everything. */
static void readout_footer_hint(void) {
  printf("\n[-v: detailed results,%s system info]",
         map_mode ? "" : " memory map,");
  if (!hardening_mode)
    printf("  [-H: hardening assessment]");
  printf("\n");
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
  for (int i = 0; i < num_components; i++) {
    const struct component_disposition *d = &comp_logs[i].disposition;
    if (!comp_logs[i].ran || d->category == DISP_NONE)
      continue;
    if (!shown) {
      printf("%sComponent dispositions:%s\n", c(C_BOLD), c(C_RESET));
      shown = 1;
    }
    if (d->category == DISP_MITIGATION)
      printf("  %s%-12s%s %s", c(C_YELLOW), d->gate, c(C_RESET),
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
  /* Per-render state: which (type, section) groups the verbose pass has
   * already emitted, and whether a separator is due before the next one.
   * Cleared here so a second render starts from an empty set rather than
   * suppressing every group the first one printed. */
  num_printed_groups = 0;

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
    readout_footer_hint();
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
    if (s->stats.crashed)
      printf(", %d crashed", s->stats.crashed);
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

  /* Verbose has its own static-posture blocks below and never reaches
   * render_readout(), so it builds the rows they read. */
  layout_build();

  if (s->kaslr.unsupported) {
    printf("%s** KASLR is not supported on this architecture **%s\n\n",
           c(C_YELLOW), c(C_RESET));
    verbose_default_remark(s->kaslr.default_addr);
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
        printf("  %s\n", kasld_origin_name(scalar_facts[i].origin)[0]
                             ? kasld_origin_name(scalar_facts[i].origin)
                             : "(unknown)");
    }
    printf("\n");
    verbose_default_remark(s->kaslr.default_addr);
  } else if (s->kaslr.randomization_failed) {
    /* The stub relocated the image with no randomness: neither randomized nor
     * at the link-time default. Stated here so the verbose report is not
     * silent about a posture only -1 and -H would otherwise reveal; the
     * resolved bases below remain the answer. */
    printf("%s** KASLR randomization did not run **%s\n\n", c(C_YELLOW),
           c(C_RESET));
    printf("The boot stub still placed the image, so it is not at the "
           "compile-time default.\n\n");
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

/* =========================================================================
 * Banner and the verbose system-config block
 *
 * The -v flow's opening: the tool's own banner, then the environment as it was
 * taken -- hardening settings, confinement, and which sources this vantage can
 * read. Every value here comes out of the snapshot, so this block reaches for
 * no file of its own beyond the readability probes it reports.
 * =========================================================================
 */
/* Print one hardening value from the snapshot.
 *
 * A read that was REFUSED is named apart from one that found nothing. These
 * knobs are world-readable, so a refusal is not ordinary file permissions: it
 * is a policy acting on this vantage, which is a fact about where the analysis
 * is standing rather than an absence of information. The value stays unknown
 * either way; what differs is whether anything is known about why. */
static void print_hardening_value(const char *label, int value) {
  if (value == KASLD_SYSCTL_DENIED)
    printf("%-30s%s(denied)%s\n", label, c(C_DIM), c(C_RESET));
  else if (!kasld_hardening_known(value))
    printf("%-30s%s(unavailable)%s\n", label, c(C_DIM), c(C_RESET));
  else
    printf("%-30s%d\n", label, value);
}

/* The banner carries VERSION, which only the product build defines, so what
 * follows is compiled out of a test binary. Helpers that a test can drive
 * belong above this line. */
#ifndef KASLD_TESTING
void render_banner(void) {
  struct utsname u;
  if (kasld_uname(&u) < 0) {
    perror("uname");
    return;
  }

  /* ASCII mode (non-UTF-8 locale or --ascii): the box-art is Unicode block
   * characters, so emit a plain-text title instead. */
  if (!unicode_output) {
    printf("\n  KASLD v%s  --  Kernel ASLR derandomization\n\n", VERSION);
    return;
  }

  // Delta Corps Priest 1 font from https://www.asciiart.eu/text-to-ascii-art
  printf("\n"
         "     ▄█   ▄█▄    ▄████████    ▄████████  ▄█       ████████▄\n"
         "    ███ ▄███▀   ███    ███   ███    ███ ███       ███   ▀███\n"
         "    ███▐██▀     ███    ███   ███    █▀  ███       ███    ███\n"
         "   ▄█████▀      ███    ███   ███        ███       ███    ███\n"
         "  ▀▀█████▄    ▀███████████ ▀███████████ ███       ███    ███\n"
         "    ███▐██▄     ███    ███          ███ ███       ███    ███\n"
         "    ███ ▀███▄   ███    ███    ▄█    ███ ███▌    ▄ ███   ▄███\n"
         "    ███   ▀█▀   ███    █▀   ▄████████▀  █████▄▄██ ████████▀\n"
         "    ▀                                   ▀ v%s\n\n",
         VERSION);
}

/* Print the container / confinement lines: whether the vantage is
 * containerized, and the seccomp / capability / no-new-privs state that decides
 * which oracles are
 * reachable here. Descriptive — the offensive-recon complement to the sysctl
 * block above.
 *
 * The detail lines are printed ONLY when the process is actually confined
 * (containerized, a seccomp filter, or no_new_privs). On a bare unprivileged
 * host their values (Seccomp: none, caps: none, no_new_privs: no) are the
 * DEFAULTS, not restrictions — printing them there reads as confinement where
 * there is none, so they are suppressed and only the container status shows. */
/* List the cap-gated leaks the effective cap set unlocks (one line each), or
 * nothing if none apply. Shown regardless of confinement: a held cap is a real
 * reachability fact whether or not the process is otherwise restricted. */
static void print_cap_reachable_leaks(const struct kasld_vantage *v) {
  if (!v->have_caps)
    return;
  int shown = 0;
  for (int i = 0; i < KASLD_N_CAP_LEAKS; i++) {
    if (!((v->cap_eff >> kasld_cap_leaks[i].bit) & 1ull))
      continue;
    if (!shown) {
      printf("Cap-reachable leaks:\n");
      shown = 1;
    }
    printf("  %-16s -> %s\n", kasld_cap_leaks[i].cap,
           kasld_cap_leaks[i].source);
  }
}

static void print_confinement(const struct kasld_vantage *v) {
  printf("%-30s%s\n", "Container:", v->container ? v->container : "none");
  char lsmbuf[224];
  printf("%-30s%s\n", "LSM:", kasld_vantage_lsm_str(v, lsmbuf, sizeof(lsmbuf)));
  if (v->sec_context[0])
    printf("%-30s%s\n", "Security context:", v->sec_context);

  /* Identity is always printed: uid 0 versus anything else is the single
   * largest determinant of what is readable, and unlike the seccomp/caps
   * detail below it is meaningful whether or not the process is confined.
   * The effective ids appear only when they differ — a setuid helper.
   * "unknown" rather than a number when the ids could not be read, which no
   * value in the field can express — 0 there would read as root. */
  if (!v->have_ids)
    printf("%-30s%s\n", "Identity:", "unknown");
  else if (v->uid != v->euid || v->gid != v->egid)
    printf("%-30suid=%lu gid=%lu (euid=%lu egid=%lu)\n", "Identity:", v->uid,
           v->gid, v->euid, v->egid);
  else
    printf("%-30suid=%lu gid=%lu\n", "Identity:", v->uid, v->gid);
  if (v->ngroups > 0) {
    /* Named where the tree knows them. The list wraps rather than truncating:
     * which groups are held is the whole point of the line, and a membership
     * dropped for width is one the reader cannot account for. */
    int col = 30;
    printf("%-30s", "Supplementary groups:");
    for (int i = 0; i < v->ngroups; i++) {
      char item[96];
      const char *nm = kasld_group_name(v, i);
      if (nm)
        snprintf(item, sizeof(item), "%lu(%s)", v->groups[i], nm);
      else
        snprintf(item, sizeof(item), "%lu", v->groups[i]);
      int w = (int)strlen(item) + (i ? 1 : 0);
      if (i && col + w > KASLD_READOUT_COLS) {
        printf(",\n%-30s", "");
        col = 30;
        printf("%s", item);
        col += (int)strlen(item);
        continue;
      }
      printf("%s%s", i ? "," : "", item);
      col += w;
    }
    if (v->groups_truncated)
      printf(",...");
    printf("\n");
  }
  /* The seccomp / caps / no-new-privs detail is only meaningful when actually
   * confined — otherwise those values are the unprivileged defaults. */
  if (kasld_vantage_confined(v)) {
    if (v->seccomp >= 0)
      printf("%-30s%s\n", "Seccomp:", kasld_vantage_seccomp_str(v->seccomp));
    char capbuf[24];
    const char *caps = kasld_vantage_caps(v, capbuf, sizeof(capbuf));
    if (caps)
      printf("%-30s%s\n", "Effective capabilities:", caps);
    if (v->no_new_privs >= 0)
      printf("%-30s%s\n",
             "No new privileges:", v->no_new_privs == 1 ? "yes" : "no");
  }
  print_cap_reachable_leaks(v);
}

void render_system_config(void) {
  struct utsname u;
  if (kasld_uname(&u) < 0) {
    perror("uname");
    return;
  }

  printf("%-30s%s\n", "Kernel release:", u.release);
  printf("%-30s%s\n", "Kernel version:", u.version);
  printf("%-30s%s\n", "Kernel arch:", u.machine);

  const struct kasld_hardening *h = &kasld_env.hardening;

  printf("\n");
  print_hardening_value("kernel.kptr_restrict:", h->kptr_restrict);
  print_hardening_value("kernel.dmesg_restrict:", h->dmesg_restrict);
  print_hardening_value("kernel.panic_on_oops:", h->panic_on_oops);
  print_hardening_value("kernel.perf_event_paranoid:", h->perf_event_paranoid);

  /* Lockdown status */
  {
    const char *mode_str;
    switch (h->lockdown) {
    case LOCKDOWN_CONFIDENTIALITY:
      mode_str = "confidentiality";
      break;
    case LOCKDOWN_INTEGRITY:
      mode_str = "integrity";
      break;
    case LOCKDOWN_NONE:
      mode_str = "none";
      break;
    default:
      mode_str = NULL;
      break;
    }
    if (mode_str)
      printf("%-30s%s\n", "Kernel lockdown:", mode_str);
    else
      printf("%-30s%s(unavailable)%s\n", "Kernel lockdown:", c(C_DIM),
             c(C_RESET));
  }

  /* The one snapshot feeds the confinement lines and the oracle rows here, and
   * the JSON/markdown environment blocks read the same object, so no two
   * formats can describe different moments. */
  const struct kasld_vantage *vant = &kasld_env.vantage;

  printf("\n");
  print_confinement(vant);

  printf("\n");

  /* Leak-oracle sources first — the /proc files a container masks (the recon
   * vantage; shared list with the JSON/markdown environment block), then the
   * log/debug/boot sources. */
  for (int i = 0; i < KASLD_N_ORACLES; i++) {
    int readable = vant->oracle_readable[i];
    /* The heading is built from the path it reports on, so a row cannot come
     * to name one source while answering for another. The other formats name
     * the path itself, which is why no heading is carried alongside it. */
    char label[64];
    snprintf(label, sizeof(label), "Readable %s:", kasld_oracle_paths[i]);
    printf("%-30s%s%s%s\n", label, readable ? c(C_GREEN) : c(C_DIM),
           readable ? "yes" : "no", c(C_RESET));
  }

  const char *check_files[][2] = {
      {"Readable /var/log/dmesg:", "/var/log/dmesg"},
      {"Readable /var/log/kern.log:", "/var/log/kern.log"},
      {"Readable /var/log/syslog:", "/var/log/syslog"},
      {"Readable debugfs:", "/sys/kernel/debug"},
      {NULL, NULL},
  };

  for (int i = 0; check_files[i][0]; i++) {
    int readable = kasld_access(check_files[i][1], R_OK) == 0;
    printf("%-30s%s%s%s\n", check_files[i][0], readable ? c(C_GREEN) : c(C_DIM),
           readable ? "yes" : "no", c(C_RESET));
  }

  /* Kernel-release-specific paths */
  char path[KASLD_PATH_MAX];
  int readable;

  snprintf(path, sizeof(path), "/boot/System.map-%s", u.release);
  readable = kasld_access(path, R_OK) == 0;
  printf("%-30s%s%s%s\n",
         "Readable /boot/System.map:", readable ? c(C_GREEN) : c(C_DIM),
         readable ? "yes" : "no", c(C_RESET));

  snprintf(path, sizeof(path), "/boot/config-%s", u.release);
  readable = kasld_access(path, R_OK) == 0;
  printf("%-30s%s%s%s\n",
         "Readable /boot/config:", readable ? c(C_GREEN) : c(C_DIM),
         readable ? "yes" : "no", c(C_RESET));

  printf("\n");
}
#endif /* !KASLD_TESTING */
