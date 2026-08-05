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
        for (int j = origin_set_next(&r->origins, 0), oi = 0; j >= 0;
             j = origin_set_next(&r->origins, j + 1), oi++)
          printf("%s%s", oi ? ", " : "", kasld_origin_name(j));
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
      for (int j = origin_set_next(&r->origins, 0), oi = 0; j >= 0;
           j = origin_set_next(&r->origins, j + 1), oi++)
        printf("%s%s", oi ? ", " : "", kasld_origin_name(j));
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
  if (s->kaslr.disabled || s->kaslr.unsupported)
    return;
  if (!s->kaslr.vtext && !s->kaslr.ptext && s->kaslr.vslots == 0 &&
      s->kaslr.pslots == 0)
    return;

  printf("%s%s%s\n", c(C_DIM), "----------------------------------------",
         c(C_RESET));
  printf("%sKASLR analysis:%s\n", c(C_BOLD), c(C_RESET));
  layout_build(s);
  layout_render();
  printf("\n");

  if (s->kaslr.vstext && s->kaslr.vstext != s->kaslr.vtext)
    printf("  %-*s 0x%016lx\n", KASLR_LABEL_W,
           "Virtual _stext:", s->kaslr.vstext);
  if (s->kaslr.pstext && s->kaslr.pstext != s->kaslr.ptext)
    printf("  %-*s 0x%016lx\n", KASLR_LABEL_W,
           "Physical _stext:", s->kaslr.pstext);
  if (s->kaslr.vtext)
    printf("  %-*s 0x%016lx\n", KASLR_LABEL_W,
           "Compile-time default:", layout.virt_image_base_default);
  if (s->kaslr.vslots > 0)
    printf(
        "  %-*s %s\n", KASLR_LABEL_W, "Virtual entropy:",
        entropy_phrase(s->kaslr.vbits, s->kaslr.vbits_top, ebuf, sizeof(ebuf)));
  if (s->kaslr.pslots > 0)
    printf("  %-*s %s\n", KASLR_LABEL_W, "Physical entropy:",
           entropy_phrase(s->kaslr.pbits, 0, ebuf, sizeof(ebuf)));
  if (s->kaslr.virt_page_offset_slots > 0)
    printf("  %-*s %s\n", KASLR_LABEL_W, "Direct map entropy:",
           entropy_phrase(s->kaslr.virt_page_offset_bits,
                          s->kaslr.virt_page_offset_bits_top, ebuf,
                          sizeof(ebuf)));
  printf("\n");
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
  unsigned long po_lo = layout.virt_page_offset_min;
  unsigned long po_hi = layout.virt_page_offset_max;
  unsigned long dmap_base = layout.virt_page_offset;
  if (po_lo && po_hi && po_lo <= po_hi &&
      (dmap_base < po_lo || dmap_base > po_hi))
    dmap_base = po_lo;
  /* Whether that floor is a proven single value or the low end of a window the
   * engine could not close. The band's label says which; it used to claim
   * "base proven" either way. */
  int dmap_base_pinned = (po_lo && po_lo == po_hi) ||
                         (!po_lo && !po_hi && layout.virt_page_offset != 0);

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
                                     MR_NONE};
  regions[n++] =
      (struct map_region){layout.virt_image_base_min,
                          layout.virt_image_base_max,
                          "kernel text",
                          vtext_lo,
                          vtext_hi,
                          0,
                          MR_KERNEL_TEXT,
                          text_in_directmap ? MR_DIRECTMAP : MR_NONE};

  /* The direct map is shown whenever its base is known. Use the base as both
     start and end — we know the mapping begins there but don't know its true
     extent. virt_kernel_vas_end would cause unsigned overflow in the gap
     arithmetic (end + 1 wraps to 0). The only case still suppressed is a
     decoupled arch whose direct-map base coincides with the text floor: there
     the two are genuinely indistinguishable and nothing is contained. */
  if (dmap_base &&
      (text_in_directmap || dmap_base != layout.virt_image_base_min)) {
    regions[n++] =
        (struct map_region){dmap_base, dmap_base, "direct map", vdmap_lo,
                            vdmap_hi,  1,         MR_DIRECTMAP, MR_NONE};
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
   * we clamp it up to the highest region boundary we know about. */
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
   * virt_page_offset). virt_kernel_vas_start can be raised by the
   * virt_page_offset_min inference feedback loop, making it larger than
   * layout.virt_page_offset; printing it there would produce two labels in
   * inverted address order. */
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
   * default. When we have a non-trivial window, split the in-DRAM portion
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
  for (int i = 0; i < nf; i++) {
    /* Credit every component that found this (type, region), not just the one
     * highest-confidence record: results merge by (type, region, NAME), so the
     * same address tagged under different symbol names (e.g. _stext from
     * proc_kallsyms vs an unnamed text leak) lands in separate merged records.
     * Aggregate provenance across all in-bounds records of this (type, region),
     * de-duplicated. */
    struct origin_set seen;
    memset(&seen, 0, sizeof(seen));
    for (int j = 0; j < num_results; j++) {
      const struct result *r = &results[j];
      if (r->type != found[i].r->type || r->region != found[i].r->region ||
          !in_bounds(r))
        continue;
      origin_set_union(&seen, &r->origins);
    }
    int ns = origin_set_count(&seen);

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
    for (int slot = origin_set_next(&seen, 0), idx = 0; slot >= 0;
         slot = origin_set_next(&seen, slot + 1), idx++) {
      const char *nm = kasld_origin_name(slot);
      int need = (int)strlen(nm) + (idx ? 2 : 0);
      /* Wrap rather than truncate: which components corroborate a finding is
       * the whole point of the line, so a long list continues on the next one
       * at the same column instead of folding into "+N more". A wrap emits the
       * separating comma at the current column, so the last name on a line must
       * end one short of the budget. */
      if (idx && col + need > READOUT_MAX_COLS - 1) {
        printf(",\n%*s%s", indent, "", nm);
        col = indent + (int)strlen(nm);
      } else {
        printf("%s%s", idx ? ", " : "", nm);
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
#define READOUT_GRADE_W 18 /* "guaranteed _stext" + 1 */
/* Sized so the status opens at the same column the value fields start at
 * (26), clear of the grade column below it. At 21 the status opened at 24 --
 * inside the grade field, so its "(" landed on top of the ")" of
 * "likely (speculative)" on the row beneath. */
#define READOUT_LABEL_W 23

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

/* A window at `grade`: first and last candidate, then how many, at what pitch,
 * and what entropy that count leaves. Both edges are inclusive and on the grid,
 * so the printed count reconciles with the printed edges.
 *
 * The residual sits on the row whose count it restates, not on the block
 * header: a header carries no grade, so an entropy figure parked there is read
 * as belonging to whichever row happens to sit under it -- which, in the
 * concrete-base form, is the speculative one it does not describe. Stated here,
 * every window row is self-describing and a point row (which has no spread)
 * correctly carries neither figure. */
static void readout_window(const char *grade, unsigned long lo,
                           unsigned long hi, int digits, unsigned long slots,
                           int count_w, unsigned long align, int bits,
                           int bits_top) {
  char a1[40], a2[40], gb[32], eb[48];
  printf("    %-*s%s .. %s", READOUT_GRADE_W, grade,
         readout_addr(lo, digits, a1, sizeof(a1)),
         readout_addr(hi, digits, a2, sizeof(a2)));
  if (slots > 0) {
    /* Right-aligned to the widest count in this block, so the pitch that
     * follows it lines up between a block's likely and guaranteed rows. */
    if (align)
      printf("  %s%*lu x %s%s", c(C_MAGENTA), count_w, slots,
             kasld_grain(align, gb, sizeof(gb)), c(C_RESET));
    else
      printf("  %s%*lu candidates%s", c(C_MAGENTA), count_w, slots, c(C_RESET));
    printf("  %s%s%s", c(C_DIM), entropy_phrase(bits, bits_top, eb, sizeof(eb)),
           c(C_RESET));
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

/* Status for a quantity's header. Only a pin has one: the residual entropy of
 * a window belongs beside the slot count it restates, on the window row
 * itself. A pinned quantity's row is a bare address with no count to carry
 * that verdict, so the header states it. */
#define READOUT_PINNED "pinned"

/* Window-only form: no concrete base was resolved. The speculative sub-window,
 * when present, sits above the proven one -- the same likely-over-guaranteed
 * order the concrete-base form uses. Each window states its own residual. */
static void readout_window_block(const char *label, unsigned long lo,
                                 unsigned long hi, unsigned long llo,
                                 unsigned long lhi, unsigned long slots,
                                 unsigned long lslots, int bits, int bits_top,
                                 unsigned long align) {
  if (!lo && !hi)
    return;
  int pinned = (lo == hi && lo != 0);
  readout_snap(&lo, &hi, align);
  readout_snap(&llo, &lhi, align);
  int w = readout_addr_w;
  readout_head(label, pinned ? READOUT_PINNED : NULL);
  if (pinned) {
    readout_point(GRADE_GUARANTEED, lo, w, NULL);
    return;
  }
  /* A speculative sub-window is measured against its own width alone: the
   * baseline that makes the proven residual interpretable is a statement about
   * what the kernel randomized, not about how far a guess narrowed it. */
  if (lhi && llo && lhi >= llo)
    readout_window(GRADE_LIKELY, llo, lhi, w, lslots, readout_count_w, align, 0,
                   0);
  if (lo && hi && hi >= lo)
    readout_window(GRADE_GUARANTEED, lo, hi, w, slots, readout_count_w, align,
                   bits, bits_top);
  else if (lo)
    readout_halfbound(GRADE_GUARANTEED, ">=", lo, w);
  else if (hi)
    readout_halfbound(GRADE_GUARANTEED, "<=", hi, w);
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

/* The "no slide" image-base block, shared by the KASLR-unsupported and
 * KASLR-disabled readouts. Both answer the same question with the same
 * evidence, and both must answer it from the ENGINE, not from the compile-time
 * default: the default is a build-time constant that a differently-configured
 * kernel simply does not honour. arm32 is the standing witness -- an Alpine
 * armv7 kernel built VMSPLIT_2G has _text at 0x80008000, and printing the arch
 * default 0xc0008000 as the answer states a wrong address at the GUARANTEED
 * grade while the engine's own window (which contains the truth) sits unused.
 * The default is never the answer here: with nothing resolved the block prints
 * nothing, and the caller keeps the heading off the page.
 *
 * The base carries no status. The line above the block already states the
 * posture in words, so "no slide" / "no randomization" only restates it, and
 * the two postures would otherwise wear different qualifiers for the same
 * kind of result. */
static void readout_static_base_block(unsigned long default_addr,
                                      const struct summary *s) {
  unsigned long lo = layout.virt_kaslr_text_min;
  unsigned long hi = layout.virt_kaslr_text_max;
  if (!lo && !hi)
    return; /* nothing resolved: no heading either */
  readout_block_n = 0;
  printf("%sLayout%s\n", c(C_BOLD), c(C_RESET));
  if (lo == hi) {
    readout_head("Kernel image base", NULL);
    readout_point(GRADE_GUARANTEED, lo, readout_addr_w, NULL);
  } else {
    readout_window_block("Kernel image base", lo, hi, 0, 0, s->kaslr.vslots, 0,
                         s->kaslr.vbits, s->kaslr.vbits_top,
                         layout.virt_kaslr_align);
  }
  readout_default_remark(default_addr, lo, hi);
}

/* The verbose-mode image base for the no-slide postures, answered from the same
 * place the readout answers it: the engine. The banner above already names the
 * posture, so the base carries no qualifier. An edge the engine never resolved
 * is shown as the one-sided bound it is, rather than as a range starting at 0.
 */
static void verbose_static_base_block(unsigned long default_addr) {
  unsigned long lo = layout.virt_kaslr_text_min;
  unsigned long hi = layout.virt_kaslr_text_max;
  char ab[40], rb[160];
  const char *rem;
  if (!lo && !hi)
    return;
  if (lo == hi)
    printf("Kernel image base: %s0x%016lx%s\n", c(C_GREEN), lo, c(C_RESET));
  else if (lo && hi)
    printf("Kernel image base: %s0x%016lx - 0x%016lx%s\n", c(C_GREEN), lo, hi,
           c(C_RESET));
  else if (hi)
    printf("Kernel image base: %s<= 0x%016lx%s\n", c(C_GREEN), hi, c(C_RESET));
  else
    printf("Kernel image base: %s>= 0x%016lx%s\n", c(C_GREEN), lo, c(C_RESET));
  snprintf(ab, sizeof(ab), "0x%016lx", default_addr);
  rem = default_base_remark(default_addr, lo, hi, ab, rb, sizeof(rb));
  if (rem)
    printf("%s%s%s\n", c(C_DIM), rem, c(C_RESET));
  printf("\n");
}

/* ---------------------------------------------------------------------------
 * The Layout table.
 *
 * One row per (quantity, basis). Cells are formatted into fixed buffers before
 * anything prints, so the columns are sized to the run's own content.
 *
 *   Quantity      what is being located. Repeated on a quantity's second row:
 *                 a blank cell in a table means "no value", not "same as
 *                 above", and markdown has no rowspan to borrow.
 *   Basis         which of the two windows the row reports.
 *   Search space  how many placements survive, and out of how many where the
 *                 kernel's own randomization window is modelled. It leads the
 *                 numeric columns because it is the brute-force cost of the
 *                 row -- the figure a reader compares between quantities --
 *                 and because a right-aligned count against a fixed left edge
 *                 stays a column, where a trailing one shreds against ranges
 *                 whose printed width varies by twenty characters.
 *   Range         the addresses.
 *   Align         the grid the candidates sit on; what reconciles the count
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
  if (r->lo && r->hi && r->lo != r->hi)
    snprintf(out, sizeof(out), "%s - %s%s%s",
             readout_addr(r->lo, aw, a1, sizeof(a1)),
             readout_addr(r->hi, aw, a2, sizeof(a2)), sep, r->note);
  else if (r->lo && r->hi)
    snprintf(out, sizeof(out), "%s%s%s",
             readout_addr(r->lo, aw, a1, sizeof(a1)), sep, r->note);
  else if (r->lo)
    snprintf(out, sizeof(out), ">= %s%s%s",
             readout_addr(r->lo, aw, a1, sizeof(a1)), sep, r->note);
  else
    snprintf(out, sizeof(out), "<= %s%s%s",
             readout_addr(r->hi, aw, a1, sizeof(a1)), sep, r->note);
  snprintf(r->cell[2], LAYOUT_CELL, "%s", out);
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
    /* Only the grade word is coloured: it is the one cell whose value is a
     * vocabulary rather than a measurement, so colour discriminates it at a
     * glance while the word keeps the precision. */
    if (!r->dim && strcmp(r->cell[1], GRADE_GUARANTEED) == 0)
      printf("%s%-*s%s", c(C_GREEN), w[1], r->cell[1], c(C_RESET));
    else if (!r->dim && strcmp(r->cell[1], GRADE_LIKELY) == 0)
      printf("%s%-*s%s", c(C_YELLOW), w[1], r->cell[1], c(C_RESET));
    else
      printf("%-*s", w[1], r->cell[1]);
    /* A proven single address is the answer the run was for, and with no
     * headline sentence nothing else marks it. Emphasis rather than colour:
     * green already means "guaranteed" in the column to the left, and one
     * colour cannot mean both a grade and a degree of narrowing. */
    if (r->pinned)
      printf("  %s%-*s%s  %*s  %s", c(C_BOLD), w[2], r->cell[2], c(C_RESET),
             w[3], r->cell[3], r->cell[4]);
    else
      printf("  %-*s  %*s  %s", w[2], r->cell[2], w[3], r->cell[3], r->cell[4]);
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

  /* Special-case: arch with no KASLR support, or KASLR disabled. Both are
   * answered with a single text-base line. */
  if (s->kaslr.unsupported) {
    printf("KASLR not supported on this architecture.\n\n");
    readout_static_base_block(s->kaslr.default_addr, s);
    printf("\n");
    readout_print_leaks();
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
    readout_static_base_block(s->kaslr.default_addr, s);
    printf("\n");
    readout_print_leaks();
    return;
  }

  /* Randomization failed: the boot stub ran and relocated the image, but had
   * no randomness to place it with. NOT the disabled posture -- the image did
   * move, so it is neither randomized nor at the link-time default, and the
   * engine's own windows remain the answer. The readout therefore states the
   * posture and continues into the regular path rather than branching away to
   * a single base line. Without this the output is indistinguishable from an
   * active kernel whose window simply never narrowed, and a reader has no way
   * to know the entropy is gone. */
  if (s->kaslr.randomization_failed)
    printf("%sKASLR randomization did not run on this kernel%s "
           "(no seed / no PRNG).\nThe boot stub still placed the image, so it "
           "is not at the compile-time default.\n\n",
           c(C_YELLOW), c(C_RESET));

  /* Regular KASLR path: the Layout table, the coupling note, then the leaks.
   * Every quantity the architecture randomizes gets a row whether or not the
   * engine bounded it; a quantity the architecture does not randomize gets
   * none, because the tool has nothing to say about it. */
  layout_build(s);
  layout_render();

  /* Coupling closes the bounds table as a single dim line: it is a static
   * arch property (not a measured quantity), so it recedes from the green/
   * magenta measured rows and explains why physical and virtual bases resolve
   * as separate (or shared) quantities above. Its job is to relate the physical
   * and virtual text bases, so it only earns its place when there is a physical
   * dimension to relate to: always on coupled arches (where one leak yields
   * both — the exploitation-relevant case), and on decoupled arches only when a
   * physical image base row was actually rendered. Suppressed where no physical
   * base is shown, so it never asserts a relationship the reader can't see. */
  int phys_row_shown =
      (s->kaslr.has_phys || s->kaslr.pslots > 0 || layout.phys_kaslr_text_min ||
       layout.phys_kaslr_text_max);
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
    verbose_static_base_block(s->kaslr.default_addr);
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
    verbose_static_base_block(s->kaslr.default_addr);
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
