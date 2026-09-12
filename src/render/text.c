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

/* One quantity's excluded interior ranges, where it has any. */
static void readout_excluded(const char *label,
                             const struct kasld_report_quantity *it) {
  const struct kasld_report_window *w;
  if (!it || it->guaranteed.n_excluded <= 0)
    return;
  w = &it->guaranteed;
  printf("  %s excludes %d range%s%s:\n", label, w->n_excluded,
         w->n_excluded == 1 ? "" : "s",
         w->excluded_listed < w->n_excluded ? " (first few)" : "");
  for (int i = 0; i < w->excluded_listed; i++)
    printf("      %s0x%lx - 0x%lx%s\n", c(C_DIM), w->excluded[i].lo,
           w->excluded[i].hi, c(C_RESET));
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
static void render_kaslr_text(void) {
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
             kasld_entropy_phrase(iv->guaranteed.bits, iv->top_bits,
                                  iv->guaranteed.candidates,
                                  kasld_entropy_top(iv), ebuf, sizeof(ebuf)));
    if (ip && ip->guaranteed.candidates > 0)
      printf("  %-*s %s\n", KASLR_LABEL_W, "Physical entropy:",
             kasld_entropy_phrase(ip->guaranteed.bits, ip->top_bits,
                                  ip->guaranteed.candidates,
                                  kasld_entropy_top(ip), ebuf, sizeof(ebuf)));
    if (id && id->guaranteed.candidates > 0)
      printf("  %-*s %s\n", KASLR_LABEL_W, "Direct map entropy:",
             kasld_entropy_phrase(id->guaranteed.bits, id->top_bits,
                                  id->guaranteed.candidates,
                                  kasld_entropy_top(id), ebuf, sizeof(ebuf)));

    /* The sub-ranges carved out of a window's interior.
     *
     * The table above draws each window's HULL, and the count beside it already
     * excludes these -- so the two disagree by exactly this much, and a reader
     * reconciling them has nothing to reconcile with. Naming the ranges is also
     * what makes the count actionable: brute-forcing the hull spends effort on
     * placements the engine ruled out. Listed here rather than in the table,
     * which has no column for a set of ranges. */
    readout_excluded("Virtual image base", iv);
    readout_excluded("Physical image base", ip);
    readout_excluded("Direct map base", id);
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
      char nb[KASLD_DECIMAL_MAX];
      printf("  %-24s0x%016lx - 0x%016lx  (~%s slots, %s)%s\n", label, r->lo,
             r->hi, kasld_decimal(slots, nb, sizeof(nb)), result_method(r),
             in_bounds(r) ? "" : " [stale]");
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
  /* The block opens its own gap, below the early return, so a run with no
   * evidence leaves no stray blank behind. Every block in this readout spaces
   * itself from what precedes it; none spaces the next one, which is what kept
   * two notes apart by two blank lines and this heading apart by none. */
  printf("\n%sEvidence%s  (%d finding%s, %d component%s)\n", c(C_BOLD),
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
  }

  /* Why the Window and Candidates cells disagree.
   *
   * The window is a hull; the count already excludes the sub-ranges carved out
   * of it. Without saying so the two figures beside each other cannot be
   * reconciled -- a reader sees a range and a smaller number and has no way to
   * know which addresses are missing. The readout has no room for the ranges,
   * so it says how many and where to read them; -v and the machine formats
   * carry the list. */
  {
    const struct kasld_report *rp = render_report();
    int carved = 0;
    if (rp)
      for (int i = 0; i < rp->n_quantities; i++)
        carved += rp->quantities[i].guaranteed.n_excluded;
    if (carved > 0)
      printf("\n  %sNote: %d sub-range%s excluded from the windows above; the "
             "counts\n        already reflect them (-v lists the ranges).%s\n",
             c(C_DIM), carved, carved == 1 ? "" : "s", c(C_RESET));
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
    if (s->stats.not_started)
      printf(", %d never started", s->stats.not_started);
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

  render_kaslr_text();
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

/* `replay` is the caller's: this block renders BEFORE the components run, so
 * the report model does not exist yet and the fact cannot be read from it. */
void render_system_config(int replay) {
  struct utsname u = kasld_env.uts;

  /* Identity gates only the lines it feeds. The hardening values, the replay
   * marker and the confinement block below read sysctls, LSM state, cgroup
   * membership and the capability set -- none of which come from uname() -- so
   * a run that cannot name its target still has all of them to report. A
   * capture that masks /proc/version is exactly the vantage those sections
   * describe, and suppressing them there would withhold the report on the
   * targets it is most wanted for. */
  if (kasld_env.have_uts) {
    printf("%-30s%s\n", "Kernel release:", u.release);
    if (u.version[0])
      printf("%-30s%s\n", "Kernel version:", u.version);
    printf("%-30s%s\n", "Kernel arch:", u.machine);
  }
  /* Stated only when it applies: a live run is the ordinary case, and a row
   * reading "live system" on every host would be noise rather than a finding.
   */
  if (replay)
    printf("%-30s%s\n", "Fact source:", "replayed capture");

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
    enum oracle_access acc = vant->oracle_access[i];
    /* Where the table carries no label the heading is built from the path the
     * row reports on, so it cannot come to name one source while answering for
     * another. A label is there for the paths too long to head a 30-column
     * field -- the release-suffixed ones -- and for debugfs, which is named
     * after the filesystem rather than its mount point. The other formats name
     * the resolved path in every case. */
    const char *name =
        kasld_oracles[i].label ? kasld_oracles[i].label : vant->oracle_path[i];
    char label[64];
    snprintf(label, sizeof(label), "Readable %s:", name);
    /* A refusal is the target's hardening and a missing file is not, so the
     * row answers with the reason where the probe established one. "unknown"
     * is not a hedge: it is the answer where nothing observed can tell the two
     * apart, which is every unreadable row of a replay whose capture kept no
     * record. */
    printf("%-30s%s%s%s\n", label,
           acc == ORACLE_READABLE ? c(C_GREEN) : c(C_DIM),
           kasld_oracle_answer(acc), c(C_RESET));
  }

  printf("\n");
}

/* The banner carries VERSION, which only the product build defines, so what
 * follows is compiled out of a test binary. Helpers that a test can drive
 * belong above this line. */
#ifndef KASLD_TESTING
void render_banner(void) {
  /* No identity, no banner. The art shows none of it, but a run that cannot
   * name the target has nothing to head. */
  if (!kasld_env.have_uts)
    return;

  /* ASCII mode (non-UTF-8 locale or --ascii): the box-art is Unicode block
   * characters, so emit a plain-text title instead. */
  if (!unicode_output) {
    printf("\n  KASLD %s  --  Kernel Address Space Layout Derandomization\n\n",
           VERSION);
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

#endif /* !KASLD_TESTING */
