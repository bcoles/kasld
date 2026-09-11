// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Address-space map — the virtual and physical layout blocks drawn by --map
// and by the verbose flow. A SECTION renderer rather than an output mode: it
// draws one block that a format includes, the way render/hardening.c does, so
// it sits beside the modes in this directory without being one.
//
// The map is not to scale. Each band is drawn at a fixed height with the
// unclaimed span between bands stated as a labelled gap, because the spans
// differ by twelve orders of magnitude and no linear axis can hold them.
//
// Cross-file helpers (section_range, in_bounds, kasld_grain, readout_addr,
// ...) are declared in include/kasld/render_internal.h.
// ---
// <bcoles@gmail.com>

#include "include/kasld/internal.h"
#include "include/kasld/render_internal.h"
#include "include/kasld/report.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
  /* 1 = something proves the region is present in this band -- an address
   * observed inside it, or a base the engine pinned. 0 = the band states where
   * the region MAY lie and nothing has been seen there. Stated positionally
   * for the same reason `extent_derived` is: a new band that claims occupancy
   * by omission would draw an unproven window as solidly as a measured one. */
  int occupied;
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

/* Widest hex address the block will draw, so its column is as wide as its
 * contents and no wider. Unlike readout_wmax() a zero address counts: the
 * physical column's bottom bookend is routinely PHYS_OFFSET == 0, and it is a
 * drawn address like any other. */
static int map_addr_w(int w, unsigned long v) {
  int n = readout_hex_digits(v);
  return n > w ? n : w;
}

/* The rail: a rule down the column, drawn beside every line, saying what is at
 * that height. A column of addresses with indented text beneath each one is a
 * list that a reader assembles into a picture; the rail draws the picture. The
 * one bit it carries that nothing else does is occupancy -- solid where a
 * region sits, dashed where nothing is claimed -- which the old form expressed
 * only as the difference between a label and a gap sentence.
 *
 * Every glyph has a one-column ASCII twin, so --ascii degrades the drawing
 * rather than losing it. The two junctions are deliberately distinct: a
 * boundary is an edge between bands, a tick is a single address inside one,
 * and both now sit in the same address column, where nothing else would tell
 * them apart.
 *
 * The fill carries a THIRD thing, which is what a band drawn solid would
 * otherwise overstate. A band is usually a WINDOW -- kernel text is drawn from
 * the engine's resolved image-base bounds -- so filling it solid says the
 * region occupies all of it, when what is known is that the region lies
 * somewhere inside. Weight says which: solid where something was observed to
 * be in the band, light where the band is only admissible extent, dashed where
 * nothing claims the span at all.
 *
 * Weight, not density, and deliberately: the bars above use density for a
 * different question (a candidate still possible against one ruled out), and
 * the pale glyph of that ladder would mean "possible" there and "unproven"
 * here, a few lines apart in one screen.
 *
 * The fill is one statement about the WHOLE band. A band's rows are its label
 * and leak lines, not a proportional slice of its span, so shading part of a
 * band would invent a vertical scale the column does not have and invite the
 * reader to take row position for address position. */
#define RAIL_SOLID kasld_glyph("\xe2\x96\x88", "#")  /* full block */
#define RAIL_BAND kasld_glyph("\xe2\x94\x82", "|")   /* light vertical */
#define RAIL_GAP kasld_glyph("\xe2\x95\x8e", ":")    /* dashed vertical */
#define RAIL_TOP kasld_glyph("\xe2\x94\x90", "+")    /* down-and-left */
#define RAIL_BOTTOM kasld_glyph("\xe2\x94\x98", "+") /* up-and-left */
#define RAIL_EDGE kasld_glyph("\xe2\x94\xa4", "+")   /* band boundary */
#define RAIL_TICK kasld_glyph("\xe2\x94\xbc", "*")   /* address inside a band */
#define RAIL_ARM kasld_glyph("\xe2\x94\x80", "-")    /* address-to-rail arm */

/* Where the rail sits, in display columns: the two-space margin, the address
 * column (w hex digits plus "0x"), then the arm. Body lines pad to it. */
static int rail_col(int w) { return 2 + w + 2 + 2; }

/* A body line's prefix: blank through the address column, then the rail. The
 * caller writes its text after the two spaces this leaves. */
static void print_rail(int w, const char *glyph) {
  printf("%*s%s  ", rail_col(w), "", glyph);
}

/* One address bookend at the map's left margin, joined to the rail.
 * `junction` is the glyph the rail wears at this height; NULL draws the
 * address alone, for the lines that stand outside the rail. */
static void print_map_addr_j(int w, unsigned long v, const char *junction,
                             const char *tail) {
  char ab[40];
  printf("  %s", readout_addr(v, w, ab, sizeof(ab)));
  if (junction)
    printf(" %s%s", RAIL_ARM, junction);
  printf("%s\n", tail ? tail : "");
}

static void print_map_addr(int w, unsigned long v, const char *tail) {
  print_map_addr_j(w, v, RAIL_EDGE, tail);
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
static int print_map_boundary(int w, unsigned long above,
                              const struct map_region *below) {
  /* `above - below->end > 1` rather than `below->end + 1 < above`: the latter
   * wraps when the band ends at the top of the address space. */
  if (above - below->end > 1) {
    char hbuf[32];
    unsigned long gap = above - below->end - 1;
    print_rail(w, RAIL_GAP);
    printf("%s%s gap%s\n", c(C_DIM), kasld_grain(gap, hbuf, sizeof(hbuf)),
           c(C_RESET));
  }
  /* A base-only region with no leak to widen it has no known ceiling, so there
   * is no upper boundary to draw. Printing its base here would repeat the
   * address about to appear as the lower bookend and render the region as
   * zero-height. Mark it open-ended instead -- and report that back, so the
   * band's own label does not go on to say the same thing a second time in
   * different words. */
  if (below->base_only && below->start == below->end) {
    print_rail(w, RAIL_GAP);
    printf("%s^ extent unknown%s\n", c(C_DIM), c(C_RESET));
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
                                     0,
                                     vmod_lo != 0};
  regions[n++] =
      (struct map_region){layout.virt_image_base_min,
                          layout.virt_image_base_max,
                          "kernel text",
                          vtext_lo,
                          vtext_hi,
                          0,
                          MR_KERNEL_TEXT,
                          text_in_directmap ? MR_DIRECTMAP : MR_NONE,
                          0,
                          vtext_lo != 0 || layout.virt_image_base_min ==
                                               layout.virt_image_base_max};

  /* The direct map is shown whenever its base is known. Use the base as both
     start and end — the mapping begins there, but its true extent is
     unknown. virt_kernel_vas_end would cause unsigned overflow in the gap
     arithmetic (end + 1 wraps to 0). The only case still suppressed is a
     decoupled arch whose direct-map base coincides with the text floor: there
     the two are genuinely indistinguishable and nothing is contained. */
  if (dmap_base &&
      (text_in_directmap || dmap_base != layout.virt_image_base_min)) {
    regions[n++] = (struct map_region){dmap_base,
                                       dmap_end,
                                       "direct map",
                                       vdmap_lo,
                                       vdmap_hi,
                                       !dmap_extent_derived,
                                       MR_DIRECTMAP,
                                       MR_NONE,
                                       dmap_extent_derived,
                                       vdmap_lo != 0 || dmap_base_pinned};
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

  print_map_addr_j(w, map_top, RAIL_TOP, NULL);

  /* The highest band's ceiling: no band sits above it to print the shared
   * bookend, so draw it here or it never appears and the map silently claims
   * the region reaches the top of the address space. */
  /* Whether the VAS-floor footer will print. It draws the column's last line
   * and closes the rail; where the lowest band starts AT the floor it is
   * suppressed, and the closing glyph has to move to that band's own floor or
   * the rail ends on an edge with nothing below it. */
  int has_footer = (nb == 0 || layout.virt_kernel_vas_start < bands[0].start);
  int open_top = 0;
  /* The topmost band always has its ceiling on screen: either the boundary
   * below draws it, or it coincides with the map's own top line, which was
   * just printed. Nothing sits above it to overlap it. */
  int ceiling_drawn = 1;
  if (nb > 0 && map_top > bands[nb - 1].end)
    open_top = print_map_boundary(w, map_top, &bands[nb - 1]);

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
    const char *fill = r->occupied ? RAIL_SOLID : RAIL_BAND;
    char tail[96];
    /* One parenthesis, however many things there are to say. Each clause was
     * composed independently and they met on the line, so a band that had both
     * a provenance note and nothing observed ended "(base guaranteed; extent
     * unknown) (no leak)" -- two brackets the reader has to join up, where the
     * clauses inside one already read as a list. A pinned band is the
     * exception and states only that: its bookends say the rest, and the
     * absence of a leak beside a proven single address is not a caveat. */
    const char *nl = (r->leak_lo || pinned) ? "" : "; no leak";
    tail[0] = '\0';
    if (r->base_only)
      snprintf(tail, sizeof(tail), " (base %s%s%s)",
               r->id == MR_DIRECTMAP && !dmap_base_pinned ? "is a lower bound"
                                                          : "guaranteed",
               open_top ? "" : "; extent unknown", nl);
    else if (r->extent_derived)
      /* Says where the ceiling came from. It is not a leak and not a bound the
       * engine holds; it is arithmetic on the resolved base, and the reader is
       * told so rather than left to assume the region was observed end to end.
       */
      snprintf(tail, sizeof(tail), " (base guaranteed; extent derived%s)", nl);
    else if (pinned)
      snprintf(tail, sizeof(tail), " (pinned)");
    else if (nl[0])
      snprintf(tail, sizeof(tail), " (no leak)");
    open_top = 0;

    /* Region label line(s). Leak addresses, if any, fold inline.
     * Pinned regions (start == end) are a single known point — the
     * bookend addresses above and below already say everything; skip
     * the redundant "(no leak)" tail in that case. */
    char a1[40], a2[40];
    if (r->leak_lo) {
      if (r->leak_hi && r->leak_hi != r->leak_lo) {
        print_rail(w, fill);
        printf("%s%s\n", r->label, tail);
        print_rail(w, fill);
        printf("  leak hi: %s\n", readout_addr(r->leak_hi, w, a1, sizeof(a1)));
        print_rail(w, fill);
        printf("  leak lo: %s\n", readout_addr(r->leak_lo, w, a1, sizeof(a1)));
      } else {
        print_rail(w, fill);
        printf("%s%s -- leak %s\n", r->label, tail,
               readout_addr(r->leak_lo, w, a1, sizeof(a1)));
      }
    } else if (pinned) {
      print_rail(w, fill);
      printf("%s%s\n", r->label, tail);
    } else {
      /* tail carries here too: a base-only band whose bookends come from
       * a contained region now has a drawn ceiling, and that ceiling is the
       * contained region's reach, not a measurement of this one's. Dropping the
       * disclaimer would let the drawn edge read as the region's extent. */
      print_rail(w, fill);
      printf("%s%s%s%s\n", c(C_DIM), r->label, tail, c(C_RESET));
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
      print_rail(w, fill);
      if (shown == r->end)
        printf("  %s^ top edge lies inside the band above%s\n", c(C_DIM),
               c(C_RESET));
      else
        printf("  %sextends to %s  (inside the band above)%s\n", c(C_DIM),
               readout_addr(r->end, w, a1, sizeof(a1)), c(C_RESET));
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
      /* A nested region's rows take the STRONGER of the two occupancies at
       * that height. Both regions are present there -- kernel text is mapped
       * through the direct map, not instead of it -- and the fill answers
       * whether anything is proven present, so an observed sub-region shows
       * as such even inside a container nothing has been seen in. Taking the
       * container's fill alone discards the only evidence that matters here:
       * on a coupled architecture the text band is ALWAYS nested, so a leaked
       * text address could not turn anything solid. */
      const char *subfill =
          (sub->occupied || r->occupied) ? RAIL_SOLID : RAIL_BAND;
      print_rail(w, subfill);
      if (sub->start == sub->end)
        printf("  > %s  %s\n", sub->label,
               readout_addr(sub->start, w, a1, sizeof(a1)));
      else
        printf("  > %s  %s - %s\n", sub->label,
               readout_addr(sub->start, w, a1, sizeof(a1)),
               readout_addr(sub->end, w, a2, sizeof(a2)));
      print_rail(w, subfill);
      if (sub->leak_hi && sub->leak_hi != sub->leak_lo) {
        printf("      leak hi: %s\n",
               readout_addr(sub->leak_hi, w, a1, sizeof(a1)));
        print_rail(w, subfill);
        printf("      leak lo: %s\n",
               readout_addr(sub->leak_lo, w, a1, sizeof(a1)));
      } else if (sub->leak_lo) {
        printf("      leak: %s\n",
               readout_addr(sub->leak_lo, w, a1, sizeof(a1)));
      } else {
        printf("      %s(no leak)%s\n", c(C_DIM), c(C_RESET));
      }
    }

    print_map_addr_j(w, r->start,
                     (i == 0 && !has_footer) ? RAIL_BOTTOM : RAIL_EDGE, NULL);

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
      open_top = print_map_boundary(w, r->start, &bands[i - 1]);
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
      print_rail(w, RAIL_GAP);
      printf("%s%s gap%s\n", c(C_DIM), kasld_grain(gap, hbuf, sizeof(hbuf)),
             c(C_RESET));
    }
    /* Annotate the kernel VAS floor: what lies below it is not a KASLR target
     * (and not inferred here). On 64-bit a non-canonical hole separates the
     * kernel half from user space; 32-bit splits straight into user space. */
    const char *below = (sizeof(unsigned long) > 4)
                            ? "user space + non-canonical hole below"
                            : "user space below";
    char foot[96];
    snprintf(foot, sizeof(foot), "  %s(%s)%s", c(C_DIM), below, c(C_RESET));
    print_map_addr_j(w, layout.virt_kernel_vas_start, RAIL_BOTTOM, foot);
  }
  printf("\n");
}

/* One address the physical column draws, and one band it draws it in. Both are
 * file scope so the membership test below can be written once: which entries a
 * band shows was decided at five sites in this file, and a change to what an
 * entry is had to land in all five to stay consistent.
 * ------------------------------------------------------------------------- */
struct phys_point {
  unsigned long addr;
  char label[128];
  enum kasld_region region; /* for collapsing repetitive same-region entries */
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
};

struct phys_bucket {
  const char *header;
  unsigned long lo, hi;
  unsigned long footer_addr;
  int text_only;
  /* As on a virtual band: 1 where the span is proven to be what it is
   * named -- DRAM whose edges something leaked, or a text window narrowed to
   * one address -- 0 where it is a partition of the column rather than an
   * observed region. Stated positionally at every construction. */
  int occupied;
};

/* An entry the column lists INSIDE a band, as opposed to one promoted to a
 * band edge. A DRAM boundary prints between bands, as a footer or header, so
 * it is never also listed within one. */
static int ppt_is_interior(const struct phys_point *p) {
  return !p->is_dram_edge;
}

/* Whether a band shows this entry: interior, within the band's span, and --
 * where the band is the text window -- a kernel-image region. A leak whose
 * address merely lands in that window is not evidence about the image, and
 * showing it there would read as though it were. */
static int ppt_in_bucket(const struct phys_point *p,
                         const struct phys_bucket *bk) {
  if (!ppt_is_interior(p))
    return 0;
  if (p->addr < bk->lo || p->addr > bk->hi)
    return 0;
  return !bk->text_only || p->is_text;
}

/* Render the physical half of the memory map: DRAM buckets, the phys text-base
 * window split, and any above/below-DRAM buckets. */
static void print_physical_layout(void) {
  /* Physical memory map — unified view of all physical leaks */
  unsigned long ptext =
      section_consensus(KASLD_TYPE_PHYS, "text", REGION_UNKNOWN);

  struct phys_point ppts[MAX_RESULTS];
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

  /* Estimated top, for when no ram_top edge was observed. It comes from the
   * evidence: SF_PHYS_MEMTOTAL is the target's figure, and carries a confidence
   * and an origin. A renderer-side sysconf(_SC_PHYS_PAGES) answers for the
   * machine running the analysis and does not honour KASLD_SYSROOT. */
  unsigned long ram_end = 0;
  {
    unsigned long memtotal = 0;
    for (int i = 0; i < num_scalar_facts; i++)
      if (scalar_facts[i].fact == SF_PHYS_MEMTOTAL) {
        memtotal = scalar_facts[i].value;
        break;
      }
    if (memtotal)
      ram_end = (unsigned long)PHYS_OFFSET + memtotal;
  }
  if (nppts > 0 && ppts[0].addr > ram_end)
    ram_end = ppts[0].addr;

  /* Top label: a leaked DRAM edge (ram_top) is measured; the figure derived
   * from total memory is an estimate — mark it so the reader can tell an
   * observed edge from a derived one. The ceiling must also sit above
   * everything drawn beneath it (points AND bucket footers), so it is only
   * finalised and printed once the
   * buckets exist — see the fold-in below the bucket construction. */
  unsigned long top_label = have_ram_top ? ram_top : ram_end;
  int top_is_estimate = !have_ram_top;
  /* High MMIO routinely lies above ram_top, and pinning the label to ram_top
   * drew those points outside the map that lists them -- and, when the
   * above-DRAM band's own footer is ram_top too, printed one address as both
   * bookends of a band holding points gigabytes higher. ppts[] is ordered high
   * to low, so its head is the highest point shown. (The derived path already
   * does this; the leaked path does not.) */
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

  /* Whether DRAM's placement rests on a leak rather than on the architecture's
   * own floor and an unbounded ceiling. Without one, dram_lo/dram_hi are
   * PHYS_OFFSET and ULONG_MAX -- a partition of the column, not a region
   * something reported -- and the band must not be drawn as though RAM had
   * been observed there. */
  int dram_observed = have_ram_base || have_ram_top;

  /* Build a flat list of buckets, top to bottom. `footer_addr` is the
   * boundary label printed after the bucket (= bottom edge). `text_only`
   * gates the bucket to kernel-image-region leaks (the virt layout's
   * per-region semantics). Bucket capacity covers the maximal layout:
   * above-DRAM + in-DRAM-above-window + window + in-DRAM-below-window +
   * below-DRAM. */
  struct phys_bucket buckets[5];
  int nbuckets = 0;

  /* Above-DRAM bucket: leaks whose address > ram_top (typically high MMIO).
   * Only emitted when such leaks are present AND ram_top is known. */
  int any_above_dram = 0;
  if (have_ram_top) {
    for (int i = 0; i < nppts; i++) {
      if (!ppt_is_interior(&ppts[i]))
        continue;
      if (ppts[i].addr > ram_top) {
        any_above_dram = 1;
        break;
      }
    }
    if (any_above_dram)
      buckets[nbuckets++] = (struct phys_bucket){
          "above DRAM", ram_top + 1, ULONG_MAX, ram_top, 0, 0};
  }

  if (!show_phys_window) {
    /* Single in-DRAM bucket spanning the whole DRAM range. */
    buckets[nbuckets++] = (struct phys_bucket){
        "in DRAM", dram_lo, dram_hi, dram_lo, 0, dram_observed};
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
                                                 whi + 1,
                                                 band_hi,
                                                 whi,
                                                 0,
                                                 dram_observed};
    /* Text window, clipped into DRAM (a window edge outside DRAM belongs to
     * the above-/below-DRAM band, not to this one). */
    buckets[nbuckets++] =
        (struct phys_bucket){"phys kernel text", wlo, whi, wlo, 1, wlo == whi};
    /* In-DRAM below text window. Clipped at ram_base (no longer PHYS_OFFSET).
     * When the window's lower edge is at or below dram_lo, wlo == dram_lo and
     * the window band already carries dram_lo as its footer — the trailing
     * label collapses with no separate band. */
    if (wlo > dram_lo)
      buckets[nbuckets++] = (struct phys_bucket){"in DRAM, below kernel text",
                                                 dram_lo,
                                                 wlo - 1,
                                                 dram_lo,
                                                 0,
                                                 dram_observed};
  }

  /* Below-DRAM bucket: leaks whose address < ram_base. Only emitted when
   * such leaks are present. PHYS_OFFSET terminates the column. */
  int any_below_dram = 0;
  if (have_ram_base && ram_base > (unsigned long)PHYS_OFFSET) {
    for (int i = 0; i < nppts; i++) {
      if (!ppt_is_interior(&ppts[i]))
        continue;
      if (ppts[i].addr < ram_base) {
        any_below_dram = 1;
        break;
      }
    }
    if (any_below_dram)
      buckets[nbuckets++] = (struct phys_bucket){"below DRAM",
                                                 (unsigned long)PHYS_OFFSET,
                                                 ram_base - 1,
                                                 (unsigned long)PHYS_OFFSET,
                                                 0,
                                                 0};
  }

  /* Finalise the ceiling: it must dominate every edge the column goes on to
   * draw, and the bucket footers are edges too. The `[pmax + 1, dram_hi]`
   * bucket carries `pmax` as its footer, and pmax -- the engine's proven
   * ceiling on the physical image base -- routinely sits above both the leaked
   * ram_top and the derived estimate (any host with no DRAM-extent observation,
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

  /* The RAM top is either an address something reported or the estimate
   * derived from the target's total memory. "likely (speculative)" is the
   * readout's word for a value that is not proven, and the map says the same
   * thing the same way rather than coining "(estimated)" two blocks further
   * down the same screen. */
  if (top_label)
    print_map_addr_j(w, top_label, RAIL_TOP,
                     top_is_estimate ? "  likely" : NULL);
  else
    printf("  %*s  (end of RAM unknown)\n", w + 2, "0x?");

  for (int b = 0; b < nbuckets; b++) {
    const struct phys_bucket *bk = &buckets[b];
    int any = 0;
    for (int i = 0; i < nppts; i++) {
      if (!ppt_in_bucket(&ppts[i], bk))
        continue;
      any = 1;
      break;
    }
    const char *fill = bk->occupied ? RAIL_SOLID : RAIL_BAND;
    print_rail(w, fill);
    printf("%s\n", bk->header);
    if (any) {
      /* Cap repetitive same-region entries (an MMIO-heavy host can have dozens
       * of pci_mmio BARs, which bury the layout — the Results section already
       * lists them). Show the highest few of each region, then a "... N more"
       * summary; regions at or below the cap print in full. */
      enum { PHYS_MAP_REGION_CAP = 6 };
      int total[REGION__COUNT] = {0};
      int shown[REGION__COUNT] = {0};
      for (int i = 0; i < nppts; i++) {
        if (!ppt_in_bucket(&ppts[i], bk))
          continue;
        total[ppts[i].region]++;
      }
      for (int i = 0; i < nppts; i++) {
        if (!ppt_in_bucket(&ppts[i], bk))
          continue;
        enum kasld_region rg = ppts[i].region;
        if (total[rg] > PHYS_MAP_REGION_CAP && shown[rg] >= PHYS_MAP_REGION_CAP)
          continue; /* tail of an over-cap region — summarised below */
        char lb[160];
        /* The entry's address joins the column every other address is in, and
         * the tick says it is a point inside the band rather than an edge of
         * one. Drawn at its own indent, as it was, it sat in a second address
         * column right-aligned to a different width, so two kinds of address
         * could not be read as one axis. */
        snprintf(lb, sizeof(lb), "  %s", ppts[i].label);
        print_map_addr_j(w, ppts[i].addr, RAIL_TICK, lb);
        shown[rg]++;
      }
      for (enum kasld_region rg = 0; rg < REGION__COUNT; rg++)
        if (total[rg] > PHYS_MAP_REGION_CAP) {
          print_rail(w, fill);
          printf("  %s... %d more %s region%s%s\n", c(C_DIM),
                 total[rg] - PHYS_MAP_REGION_CAP, kasld_region_wire(rg),
                 (total[rg] - PHYS_MAP_REGION_CAP) == 1 ? "" : "s", c(C_RESET));
        }
    } else {
      print_rail(w, fill);
      printf("  %s(no leak)%s\n", c(C_DIM), c(C_RESET));
    }
    print_map_addr_j(w, bk->footer_addr,
                     b == nbuckets - 1 ? RAIL_BOTTOM : RAIL_EDGE, NULL);
  }

  printf("\n");
}

/* -------------------------------------------------------------------------
 * Placement bars
 *
 * The bands above are not to scale and cannot be: a 3 MiB image sits beside a
 * 63.9 PiB gap, and no linear axis holds both. A quantity's CANDIDATE SET can
 * be drawn to scale, because it is counted rather than spanned -- so each bar
 * draws one resolved window as its own axis, showing where inside it the
 * remaining candidates lie.
 *
 * The axis is the guaranteed window's hull, so the bar describes what is still
 * admissible rather than how far the window has narrowed; the counts beside it
 * state the narrowing, which a bar of a fixed width cannot.
 *
 * Two rounding rules, in opposite directions, because a drawn cell covers many
 * candidates and rounding the wrong way states something the engine did not
 * prove:
 *   - a cell is ADMISSIBLE if any candidate in it is (round outward), so the
 *     drawn window is never narrower than the proven one;
 *   - a cell is CARVED only where a hole covers the whole of it (round
 *     inward), so no candidate is drawn as ruled out on the strength of a
 *     neighbour.
 * A hole too narrow to fill a cell is therefore not drawn at all, and the
 * footnote counts what the picture had to leave out.
 *
 * The likely window is annotated beneath the bar rather than shaded into it,
 * so the fill carries one grade and one meaning. A window narrower than a cell
 * still gets a mark, since one cell is the smallest thing the grid can say and
 * saying nothing would drop the answer.
 * -------------------------------------------------------------------------
 */

/* Cells in a bar. Fixed, never the terminal width: the output is compared byte
 * for byte against documented samples, so a map that reflowed per terminal
 * would describe the terminal rather than the target. Sized so the widest line
 * -- two 64-bit addresses, the brackets and the bar -- stays inside the column
 * budget the readout is held to. */
#define BAR_CELLS 48

enum bar_cell {
  BAR_ADMISSIBLE = 0,
  BAR_CARVED,
};

/* Which cell an offset into the window falls in.
 *
 * `off * BAR_CELLS` overflows on the wide windows -- a page_offset hull can
 * span most of the address space -- so both terms are halved until the product
 * is representable. That costs less than one part in 2^58 of the span, which is
 * orders of magnitude below one cell, while a wrapped product would place the
 * mark anywhere at all. */
static unsigned bar_cell_of(unsigned long off, unsigned long span) {
  while (span > ULONG_MAX / BAR_CELLS) {
    off >>= 1;
    span >>= 1;
  }
  if (!span)
    return 0;
  unsigned long c = (off * BAR_CELLS) / span;
  return c >= BAR_CELLS ? BAR_CELLS - 1 : (unsigned)c;
}

/* Whether a window is one this can draw an axis from: an interval with both
 * edges and more than one address between them. A floor, a set of values or a
 * single pinned address has no span to scale against. */
static int bar_drawable(const struct kasld_report_window *w) {
  return w->present && w->shape == RSHAPE_INTERVAL && w->has_lo && w->has_hi &&
         w->hi > w->lo;
}

/* One quantity's bar, plus the likely-window annotation beneath it. Returns the
 * number of holes the cell grid was too coarse to draw.
 *
 * The bar carries ONE vocabulary -- what the guaranteed window admits -- and
 * the likely window is annotated on a line of its own rather than shaded into
 * it. Shading both entangles two grades in one channel: a likely window that
 * covers almost the whole hull (the ordinary no-evidence case) then fills the
 * bar with the weaker grade and reads as MORE resolved than a bar with no
 * likely window at all, which is backwards. Drawn as a span, the same case
 * reads as what it is -- a bracket nearly as wide as the window, having gained
 * nearly nothing. */
static int print_placement_bar(const struct kasld_report_quantity *it, int aw) {
  const struct kasld_report_window *g = &it->guaranteed;
  unsigned long span = g->hi - g->lo;
  unsigned char cells[BAR_CELLS];
  char a1[40], a2[40];
  char gb[32];
  const char *dot = kasld_glyph("\xc2\xb7", "-");
  int undrawn = 0;
  int lk_a = -1, lk_b = -1;

  memset(cells, BAR_ADMISSIBLE, sizeof(cells));

  /* Carved sub-ranges. Only cells the hole covers entirely are marked, so the
   * two boundary cells stay admissible -- a hole that fits inside one cell
   * therefore marks nothing and is counted for the footnote instead. */
  for (int i = 0; i < g->excluded_listed; i++) {
    unsigned long hlo = g->excluded[i].lo, hhi = g->excluded[i].hi;
    if (hhi < g->lo || hlo > g->hi)
      continue;
    if (hlo < g->lo)
      hlo = g->lo;
    if (hhi > g->hi)
      hhi = g->hi;
    unsigned a = bar_cell_of(hlo - g->lo, span);
    unsigned b = bar_cell_of(hhi - g->lo, span);
    if (b < a + 2) {
      undrawn++;
      continue;
    }
    for (unsigned k = a + 1; k < b; k++)
      cells[k] = BAR_CARVED;
  }

  /* The likely span, where the weaker resolution says more than the proven one
   * and lands inside it. A window narrower than a cell still gets its cell --
   * one mark is the smallest thing the grid can say, and saying nothing would
   * drop the answer entirely. */
  if (kasld_report_likely_is_tighter(it) && it->likely.present &&
      it->likely.has_lo && it->likely.has_hi && it->likely.lo >= g->lo &&
      it->likely.hi <= g->hi) {
    lk_a = (int)bar_cell_of(it->likely.lo - g->lo, span);
    lk_b = (int)bar_cell_of(it->likely.hi - g->lo, span);
  }

  /* The candidate count and its bit form are the same fact twice -- exact,
   * then rounded -- so they sit together; the grain is a different axis and
   * follows. The phrase is not composed here: its shape carries claims about
   * whether a baseline exists and whether ceil(log2) rounded, and a second
   * composition of it is a second chance to assert one by accident. */
  unsigned long top = kasld_entropy_top(it);
  char eb[48];
  printf("  %s%s%s  %lu", c(C_BOLD), it->label, c(C_RESET), g->candidates);
  if (top && g->candidates <= top)
    printf(" of %lu", top);
  printf(" candidate%s", g->candidates == 1 ? "" : "s");
  if (g->bits)
    printf(" %s %s", dot,
           kasld_entropy_phrase(g->bits, it->top_bits, g->candidates, top, eb,
                                sizeof(eb)));
  if (it->align_min)
    printf(" %s %s%s grain", dot, kasld_grain(it->align_min, gb, sizeof(gb)),
           it->align_exact ? "" : " min");
  if (lk_a >= 0 && it->likely.candidates)
    printf(" %s %s %lu", dot, GRADE_LIKELY, it->likely.candidates);
  printf("\n");

  printf("    %s %s", readout_addr(g->lo, aw, a1, sizeof(a1)),
         kasld_glyph("\xe2\x94\x82", "|"));
  for (int k = 0; k < BAR_CELLS; k++) {
    if (cells[k] == BAR_CARVED)
      printf("%s%s%s", c(C_DIM), kasld_glyph("\xe2\x96\x91", "."), c(C_RESET));
    else
      printf("%s", kasld_glyph("\xe2\x96\x88", "#"));
  }
  printf("%s %s\n", kasld_glyph("\xe2\x94\x82", "|"),
         readout_addr(g->hi, aw, a2, sizeof(a2)));

  /* The span sits under the cells it names. The bar's first cell starts at
   * display column `aw + 8`: the four-space indent, the address column (aw hex
   * digits plus its "0x"), the space after it, and the left rail. */
  if (lk_a >= 0) {
    printf("%*s%s", aw + 8 + lk_a, "", c(C_DIM));
    if (lk_b > lk_a) {
      printf("%s", kasld_glyph("\xe2\x94\x94", "["));
      for (int k = lk_a + 1; k < lk_b; k++)
        printf("%s", kasld_glyph("\xe2\x94\x80", "-"));
      printf("%s", kasld_glyph("\xe2\x94\x98", "]"));
    } else {
      printf("^");
    }
    /* The word, and an address only where the span names ONE -- a range's
     * edges are already in the readout and repeating them here runs the line
     * past the column budget on a 64-bit target. */
    printf(" %s", GRADE_LIKELY);
    if (it->likely.lo == it->likely.hi)
      printf(" 0x%lx", it->likely.lo);
    printf("%s\n", c(C_RESET));
  }
  return undrawn;
}

/* The bars for the quantities the map draws a band for, so every bar has a
 * band above it and no bar describes a region the map never shows. */
static void print_placement_bars(void) {
  static const enum kasld_quantity drawn[] = {
      Q_VIRT_IMAGE_BASE,
      Q_PHYS_IMAGE_BASE,
      Q_PAGE_OFFSET,
      Q_MODULE_BASE,
  };
  const struct kasld_report *rp = render_report();
  const struct kasld_report_quantity *found[4];
  int nf = 0, aw = 0, undrawn = 0, truncated = 0, carved = 0;
  size_t i;

  if (!rp)
    return;
  for (i = 0; i < sizeof(drawn) / sizeof(drawn[0]); i++) {
    const struct kasld_report_quantity *it = kasld_report_find(rp, drawn[i]);
    if (!it || !bar_drawable(&it->guaranteed))
      continue;
    found[nf++] = it;
    aw = map_addr_w(aw, it->guaranteed.lo);
    aw = map_addr_w(aw, it->guaranteed.hi);
  }
  if (!nf)
    return;

  printf("%sCandidates within each resolved window (to scale):%s\n\n",
         c(C_BOLD), c(C_RESET));
  for (i = 0; i < (size_t)nf; i++) {
    const struct kasld_report_window *g = &found[i]->guaranteed;
    undrawn += print_placement_bar(found[i], aw);
    carved += g->n_excluded;
    if (g->excluded_listed < g->n_excluded)
      truncated += g->n_excluded - g->excluded_listed;
    if (i + 1 < (size_t)nf)
      printf("\n");
  }

  /* What the picture leaves out. An undrawn hole stays shaded as admissible,
   * so the bar is never narrower than the proven window -- the safe direction
   * -- but it does mean the counts are the authority and the shading is the
   * illustration. The carved TOTAL belongs to the readout, which already
   * states it; what only this block can say is which of it went undrawn.
   *
   * The two omissions have different causes and the line names whichever
   * applies: a hole can be too narrow for a cell, or it can be one the model
   * had no room to carry. Attributing both to the grid would state a reason
   * that is false for the second. */
  if (carved && undrawn + truncated) {
    const char *why = !truncated ? "narrower than one cell"
                      : !undrawn ? "beyond the ranges the report retains"
                                 : "narrower than one cell, or beyond the "
                                   "ranges the report retains";
    int n = undrawn + truncated;
    printf("\n  %s%d of the %d carved sub-range%s %s not drawn (%s);\n"
           "  the candidate counts above already exclude %s.%s\n",
           c(C_DIM), n, carved, carved == 1 ? "" : "s", n == 1 ? "is" : "are",
           why, n == 1 ? "it" : "them", c(C_RESET));
  }
  printf("\n");
}

/* Render the kernel memory map: the candidate bars, then the virtual layout
 * and the physical layout. */
void print_memory_map(void) {
  print_placement_bars();
  print_virtual_layout();
  print_physical_layout();
}
