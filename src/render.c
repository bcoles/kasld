// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rendering layer: all output formatting (text, JSON, oneline, markdown).
// Consumes the struct summary produced by the core analysis in orchestrator.c.
// ---
// <bcoles@gmail.com>

#include "include/kasld/internal.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <unistd.h>

/* Human-readable size: format bytes as "N.N KiB/MiB/GiB/TiB" */
static const char *human_size(unsigned long bytes, char *buf, size_t bufsz) {
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

static const char *result_method(const struct result *r) {
  if (!r || r->provenance_count == 0 || r->methods[0][0] == '\0')
    return "unknown";
  return r->methods[0];
}

static const char *result_origin(const struct result *r) {
  if (!r || r->provenance_count == 0)
    return "";
  return r->origins[0];
}

static const char *result_section(const struct result *r) {
  if (!r)
    return "";
  return region_info[r->region].section_name;
}

static int in_bounds(const struct result *r) {
  return result_in_bounds(r, &layout);
}

/* -------------------------------------------------------------------------
 * Output helpers
 * -------------------------------------------------------------------------
 */
static const char *section_display_name(enum kasld_addr_type type,
                                        const char *section) {
  if (type == KASLD_TYPE_DEFAULT_VIRT)
    return NULL;
  if (strcmp(section, "text") == 0)
    return type == KASLD_TYPE_VIRT ? "Kernel text (virtual)"
                                   : "Kernel text (physical)";
  if (strcmp(section, "module") == 0)
    return "Kernel modules (virtual)";
  if (strcmp(section, "directmap") == 0)
    return "Direct map (virtual)";
  if (strcmp(section, "data") == 0)
    return "Kernel data (virtual)";
  if (strcmp(section, "bss") == 0)
    return "Kernel BSS (virtual)";
  if (strcmp(section, "dram") == 0)
    return "Physical DRAM";
  if (strcmp(section, "mmio") == 0)
    return "Physical MMIO";
  if (strcmp(section, "pageoffset") == 0)
    return NULL; /* metadata, not a leak group */
  return "Unknown";
}

/* Kernel-locating regions are leaks that directly disclose where the kernel
 * image sits in memory. They typically arrive tagged with a generic section
 * (e.g. PHYS/DRAM for a CR3 read) but the region pinpoints them as
 * kernel-base evidence. The compact Results renderer promotes these to
 * their own line so the prize isn't buried inside a generic "Physical DRAM"
 * range that also covers ram_base, ram_top, initrd, swiotlb, etc. */
static int is_kernel_locating_region(enum kasld_region region) {
  return region == REGION_KERNEL_IMAGE || region == REGION_KERNEL_TEXT ||
         region == REGION_KERNEL_DATA || region == REGION_KERNEL_BSS;
}

/* Display label for a kernel-locating region presented inline as its own
 * Results line. Only relevant when the underlying section is generic
 * (DRAM / MMIO); for sections that already imply kernel scope (text, data,
 * module) the section label is sufficient. */
static const char *kernel_region_display_name(enum kasld_addr_type type,
                                              enum kasld_region region) {
  int phys = (type == KASLD_TYPE_PHYS);
  switch (region) {
  case REGION_KERNEL_IMAGE:
    return phys ? "Kernel image (physical)" : "Kernel image (virtual)";
  case REGION_KERNEL_TEXT:
    return phys ? "Kernel text (physical)" : "Kernel text (virtual)";
  case REGION_KERNEL_DATA:
    return phys ? "Kernel data (physical)" : "Kernel data (virtual)";
  case REGION_KERNEL_BSS:
    return phys ? "Kernel BSS (physical)" : "Kernel BSS (virtual)";
  default:
    return NULL;
  }
}

/* Predicate matching the Results-renderer subgroup filter.
 *   include_region == REGION_UNKNOWN && exclude_kernel_locating == 0: all
 *     in-bounds results for (type, section).
 *   include_region == REGION_UNKNOWN && exclude_kernel_locating == 1: skip
 *     kernel-locating regions (used for the catch-all line when
 *     kernel-locating regions have been promoted to dedicated lines).
 *   include_region != REGION_UNKNOWN: only that exact region. */
static int subgroup_match(const struct result *r, enum kasld_addr_type type,
                          const char *section, enum kasld_region include_region,
                          int exclude_kernel_locating) {
  if (r->type != type || strcmp(result_section(r), section) != 0 ||
      !in_bounds(r))
    return 0;
  if (include_region != REGION_UNKNOWN)
    return r->region == include_region;
  if (exclude_kernel_locating && is_kernel_locating_region(r->region))
    return 0;
  return 1;
}

/* Inline (type, region) lo/hi scan over in-bounds results.
 * Returns 1 if at least one match. */
static int region_range(enum kasld_addr_type type, enum kasld_region region,
                        unsigned long *out_lo, unsigned long *out_hi) {
  unsigned long lo = 0, hi = 0;
  int found = 0;
  for (int i = 0; i < num_results; i++) {
    const struct result *r = &results[i];
    if (r->type != type || r->region != region)
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
  if (found) {
    *out_lo = lo;
    *out_hi = hi;
  }
  return found;
}

/* (type, section) span across all in-bounds results. */
static void section_range(enum kasld_addr_type type, const char *section,
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

/* Convenience: return the anchor address for the canonical record at
 * (type, region), or 0 if no in-bounds record exists. */
static unsigned long region_anchor(enum kasld_addr_type type,
                                   enum kasld_region region) {
  const struct result *r = select_anchor(type, region);
  if (!r || !in_bounds(r))
    return 0;
  return anchor_addr(r);
}

/* Scan results[] for (type, section) and report:
 *   *best_method      — method of the highest-conf record (CONF_PARSED first)
 *   *n_sources        — number of records matching (type, section, in_bounds)
 *                       whose anchor address equals the anchor-record's
 *                       anchor (i.e. "agreeing" sources)
 *   *n_conflicts      — count of in-bounds records with a different anchor
 */
static void section_consensus_info(enum kasld_addr_type type,
                                   const char *section,
                                   const char **best_method, int *n_sources,
                                   int *n_conflicts) {
  const struct result *anchor = NULL;
  int best_w = -1;
  unsigned long best_addr = 0;
  /* First pass: find the best (highest-conf) in-bounds record. */
  for (int i = 0; i < num_results; i++) {
    const struct result *r = &results[i];
    if (r->type != type || strcmp(result_section(r), section) != 0)
      continue;
    if (!in_bounds(r))
      continue;
    int w = conf_weight(r->conf);
    if (w > best_w) {
      best_w = w;
      anchor = r;
      best_addr = anchor_addr(r);
    }
  }
  if (!anchor) {
    *best_method = "unknown";
    *n_sources = 0;
    *n_conflicts = 0;
    return;
  }
  *best_method = result_method(anchor);

  int sources = 0, conflicts = 0;
  for (int i = 0; i < num_results; i++) {
    const struct result *r = &results[i];
    if (r->type != type || strcmp(result_section(r), section) != 0)
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

/* Anchor address for a (type, section): the address of the highest-conf
 * in-bounds record in that subgroup. */
static unsigned long section_consensus(enum kasld_addr_type type,
                                       const char *section) {
  const struct result *anchor = NULL;
  int best_w = -1;
  for (int i = 0; i < num_results; i++) {
    const struct result *r = &results[i];
    if (r->type != type || strcmp(result_section(r), section) != 0)
      continue;
    if (!in_bounds(r))
      continue;
    int w = conf_weight(r->conf);
    if (w > best_w) {
      best_w = w;
      anchor = r;
    }
  }
  return anchor ? anchor_addr(anchor) : 0;
}

/* Compute and print one compact-mode Results line for a (type, section)
 * subgroup filtered by region. Mirrors the format used by the original
 * single-group renderer. Silently no-ops when no results match. */
static void print_compact_subgroup(const char *display_name,
                                   enum kasld_addr_type type,
                                   const char *section,
                                   enum kasld_region include_region,
                                   int exclude_kernel_locating) {
  unsigned long lo = 0, hi = 0;
  int count = 0;
  int found = 0;

  /* Aligned-address scoreboard for consensus selection (mirrors
   * the old method-weighted scoring; now uses conf_weight). */
  unsigned long addrs[MAX_RESULTS];
  int scores[MAX_RESULTS];
  int hits[MAX_RESULTS];
  int n_addrs = 0;

  for (int i = 0; i < num_results; i++) {
    const struct result *r = &results[i];
    if (!subgroup_match(r, type, section, include_region,
                        exclude_kernel_locating))
      continue;

    unsigned long a = anchor_addr(r);
    if (!found || a < lo)
      lo = a;
    if (a > hi)
      hi = a;
    found = 1;
    count++;

    int w = conf_weight(r->conf);
    int seen = 0;
    for (int j = 0; j < n_addrs; j++) {
      if (addrs[j] == a) {
        scores[j] += w;
        hits[j]++;
        seen = 1;
        break;
      }
    }
    if (!seen && n_addrs < MAX_RESULTS) {
      addrs[n_addrs] = a;
      scores[n_addrs] = w;
      hits[n_addrs] = 1;
      n_addrs++;
    }
  }

  if (count == 0)
    return;

  /* Pick consensus: highest score; ties → most hits; ties → lowest addr. */
  int best = 0;
  for (int i = 1; i < n_addrs; i++) {
    if (scores[i] > scores[best] ||
        (scores[i] == scores[best] && hits[i] > hits[best]) ||
        (scores[i] == scores[best] && hits[i] == hits[best] &&
         addrs[i] < addrs[best]))
      best = i;
  }
  unsigned long consensus = addrs[best];

  /* Method label and conflict count over the filtered subset. */
  const char *top_method = NULL;
  int top_weight = 0;
  int sources_at_consensus = 0;
  int conflicts = 0;
  for (int i = 0; i < num_results; i++) {
    const struct result *r = &results[i];
    if (!subgroup_match(r, type, section, include_region,
                        exclude_kernel_locating))
      continue;
    if (anchor_addr(r) == consensus) {
      sources_at_consensus++;
      int w = conf_weight(r->conf);
      if (w > top_weight) {
        top_weight = w;
        top_method = result_method(r);
      }
    } else {
      conflicts++;
    }
  }
  if (!top_method)
    top_method = "unknown";

  char hbuf[32];
  printf("  %-26s", display_name);
  if (lo != hi) {
    unsigned long span = hi - lo;
    printf("%s0x%016lx - 0x%016lx%s  (%s, %d source%s, %d conflict%s, %s)\n",
           c(C_GREEN), lo, hi, c(C_RESET), human_size(span, hbuf, sizeof(hbuf)),
           sources_at_consensus, sources_at_consensus == 1 ? "" : "s",
           conflicts, conflicts == 1 ? "" : "s", top_method);
  } else {
    printf("%s0x%016lx%s  (%d source%s)\n", c(C_GREEN), consensus, c(C_RESET),
           count, count == 1 ? "" : "s");
  }
}

/* Enumerate distinct kernel-locating regions present in this (type, section)
 * subgroup. Returns the count; up to MAX_RESULTS entries written into out. */
static int collect_kernel_regions(enum kasld_addr_type type,
                                  const char *section,
                                  enum kasld_region out[]) {
  int n = 0;
  for (int i = 0; i < num_results; i++) {
    const struct result *r = &results[i];
    if (r->type != type || strcmp(result_section(r), section) != 0 ||
        !in_bounds(r))
      continue;
    if (!is_kernel_locating_region(r->region))
      continue;
    int dup = 0;
    for (int j = 0; j < n; j++) {
      if (out[j] == r->region) {
        dup = 1;
        break;
      }
    }
    if (!dup && n < MAX_RESULTS)
      out[n++] = r->region;
  }
  return n;
}

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
      if (verbose)
        printf("  %s0x%016lx%s  %s %s(%s, %s, stale)%s\n", c(C_RED), a,
               c(C_RESET), rn, c(C_DIM), result_origin(r), result_method(r),
               c(C_RESET));
      else
        printf("  %s0x%016lx%s  %s %s(stale)%s\n", c(C_RED), a, c(C_RESET), rn,
               c(C_DIM), c(C_RESET));
      continue;
    }

    if (verbose)
      printf("  %s0x%016lx%s  %s %s(%s, %s)%s\n", c(C_GREEN), a, c(C_RESET), rn,
             c(C_DIM), result_origin(r), result_method(r), c(C_RESET));
    else
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
    section_consensus_info(type, section, &bm, &ns, &nc);
    printf("  %s==>%s 0x%016lx  %s(%s, %d source%s)%s\n", c(C_CYAN), c(C_RESET),
           addrs[0], c(C_DIM), bm, ns, ns == 1 ? "" : "s", c(C_RESET));
  } else if (n_addrs > 1) {
    const char *bm;
    int ns, nc;
    section_consensus_info(type, section, &bm, &ns, &nc);
    char hbuf[32];
    unsigned long span = addrs[n_addrs - 1] - addrs[0];
    unsigned long consensus = section_consensus(type, section);
    printf("  %s==>%s 0x%016lx  %s(%s, %d source%s, %d conflict%s)%s\n",
           c(C_CYAN), c(C_RESET), consensus, c(C_DIM), bm, ns,
           ns == 1 ? "" : "s", nc, nc == 1 ? "" : "s", c(C_RESET));
    printf("  %s   %s range: 0x%016lx - 0x%016lx  (%s)\n", c(C_CYAN),
           c(C_RESET), addrs[0], addrs[n_addrs - 1],
           human_size(span, hbuf, sizeof(hbuf)));
  }

  printf("\n");
}

/* Print one row of the Memory KASLR (CONFIG_RANDOMIZE_MEMORY) table.
 * Each region (page_offset_base, vmalloc_base, vmemmap_base) carries a
 * (min, max) pair that compute_kaslr_info stores using 0 as the "not
 * tightened beyond the compile-time default" sentinel for either side.
 * Four display cases:
 *   both 0:        skip (nothing to show)
 *   only min set:  ">= min"
 *   only max set:  "<= max"
 *   both set, ==:  "<value> (pinned)"
 *   both set, !=:  "min - max" */
static void render_memory_kaslr_bound(const char *name, unsigned long min,
                                      unsigned long max) {
  if (!min && !max)
    return;
  if (min && !max) {
    printf("  %-20s >= 0x%016lx\n", name, min);
    return;
  }
  if (!min && max) {
    printf("  %-20s <= 0x%016lx\n", name, max);
    return;
  }
  if (min == max) {
    printf("  %-20s %s0x%016lx%s (pinned)\n", name, c(C_GREEN), min,
           c(C_RESET));
    return;
  }
  printf("  %-20s 0x%016lx - 0x%016lx\n", name, min, max);
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
             layout.kaslr_base_min, layout.kaslr_base_max);
      printf("  Remaining slots:      %s%lu%s  (%d bits, step %#lx)\n",
             c(C_MAGENTA), s->kaslr.vslots, c(C_RESET), s->kaslr.vbits,
             layout.kaslr_align);
    }
    if (s->kaslr.pslots > 0) {
      if (s->kaslr.vslots > 0)
        printf("\n");
      printf("  Inferred phys text range:  0x%016lx - 0x%016lx\n",
             layout.phys_kaslr_base_min, layout.phys_kaslr_base_max);
      printf("  Remaining phys slots:      %s%lu%s  (%d bits, step %#lx)\n",
             c(C_MAGENTA), s->kaslr.pslots, c(C_RESET), s->kaslr.pbits,
             layout.phys_kaslr_align);
    }
    printf("\n");
    /* Fall through to the Memory KASLR block at the end of the function —
     * memory-region bounds are independent of whether a text address
     * leaked. */
  }

  if (s->kaslr.vtext) {
    printf("  Virtual text base:    %s0x%016lx%s\n", c(C_GREEN), s->kaslr.vtext,
           c(C_RESET));
    printf("  Default text base:    0x%016lx\n", layout.kernel_text_default);
    long abs_vslide = s->kaslr.vslide < 0 ? -s->kaslr.vslide : s->kaslr.vslide;
    printf("  KASLR slide:          %s%s0x%lx%s (%ld)\n", c(C_CYAN),
           s->kaslr.vslide < 0 ? "-" : "+", (unsigned long)abs_vslide,
           c(C_RESET), s->kaslr.vslide);
    if (s->kaslr.vslots > 0)
      printf("  KASLR text entropy:   %s%d bits%s (%lu slots of %#lx)\n",
             c(C_MAGENTA), s->kaslr.vbits, c(C_RESET), s->kaslr.vslots,
             layout.kaslr_align);
    else
      printf("  KASLR text entropy:   %s0 bits%s (no randomization range)\n",
             c(C_DIM), c(C_RESET));
    if (s->kaslr.vslot_valid)
      printf("  Observed slot index:  %lu / %lu\n", s->kaslr.vslot_idx,
             s->kaslr.vslots);
    printf("\n");
  }

  if (s->kaslr.has_phys) {
    printf("  Physical text base:   %s0x%016lx%s\n", c(C_GREEN), s->kaslr.ptext,
           c(C_RESET));
#ifdef KERNEL_PHYS_DEFAULT
    printf("  Default phys base:    0x%016lx\n",
           (unsigned long)KERNEL_PHYS_DEFAULT);
    long abs_pslide = s->kaslr.pslide < 0 ? -s->kaslr.pslide : s->kaslr.pslide;
    printf("  Physical KASLR slide: %s%s0x%lx%s (%ld)\n", c(C_CYAN),
           s->kaslr.pslide < 0 ? "-" : "+", (unsigned long)abs_pslide,
           c(C_RESET), s->kaslr.pslide);
    if (s->kaslr.pslots > 0)
      printf("  Physical KASLR entropy: %s%d bits%s (%lu slots of %#lx)\n",
             c(C_MAGENTA), s->kaslr.pbits, c(C_RESET), s->kaslr.pslots,
             layout.phys_kaslr_align);
    else
      printf("  Physical KASLR entropy: %s0 bits%s (no randomization range)\n",
             c(C_DIM), c(C_RESET));
    printf("\n");
#endif
  } else if (s->kaslr.pslots > 0 && !no_concrete_text) {
    /* Physical range was narrowed by inference but no concrete ptext leaked.
     * Guarded by !no_concrete_text because the no-vtext-and-no-ptext branch
     * above already prints this same line. */
    printf("  Inferred phys text range:  0x%016lx - 0x%016lx\n",
           layout.phys_kaslr_base_min, layout.phys_kaslr_base_max);
    printf("  Remaining phys slots:      %s%lu%s (%d bits, step %#lx)\n",
           c(C_MAGENTA), s->kaslr.pslots, c(C_RESET), s->kaslr.pbits,
           layout.phys_kaslr_align);
    printf("\n");
  }

  /* Memory KASLR (x86_64 CONFIG_RANDOMIZE_MEMORY): show inferred bounds on
   * the three independently-randomised memory regions when any has been
   * narrowed from the compile-time defaults. The plugins
   * x86_64_vmalloc_base_bound and x86_64_vmemmap_base_bound chain off
   * page_offset_min to derive vmalloc and vmemmap bounds via the fixed
   * inter-region ordering. */
  if (s->kaslr.page_offset_min || s->kaslr.vmalloc_min ||
      s->kaslr.vmemmap_min || s->kaslr.page_offset_max ||
      s->kaslr.vmalloc_max || s->kaslr.vmemmap_max) {
    printf("Memory KASLR (directmap / vmalloc / vmemmap):\n");
    render_memory_kaslr_bound("page_offset_base", s->kaslr.page_offset_min,
                              s->kaslr.page_offset_max);
    render_memory_kaslr_bound("vmalloc_base", s->kaslr.vmalloc_min,
                              s->kaslr.vmalloc_max);
    render_memory_kaslr_bound("vmemmap_base", s->kaslr.vmemmap_min,
                              s->kaslr.vmemmap_max);
    printf("\n");
  }
}

/* -------------------------------------------------------------------------
 * Derived addresses text renderer
 *
 * The old s->derived[] array is gone. Cross-region derivations now arrive
 * as ordinary records in results[] with conf == CONF_DERIVED, emitted by
 * inference plugins during the convergence loop. Render those records in
 * the same per-record style as the leak groups, plus the architecture
 * decoupling note when applicable.
 * -------------------------------------------------------------------------
 */
static int count_derived(void) {
  int n = 0;
  for (int i = 0; i < num_results; i++)
    if (results[i].conf == CONF_DERIVED)
      n++;
  return n;
}

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
          layout.kernel_align ? (r->hi - r->lo) / layout.kernel_align : 0;
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

static void print_memory_map(void) {
  unsigned long vtext_lo, vtext_hi, vmod_lo, vmod_hi, vdmap_lo, vdmap_hi;
  section_range(KASLD_TYPE_VIRT, "text", &vtext_lo, &vtext_hi);
  section_range(KASLD_TYPE_VIRT, "module", &vmod_lo, &vmod_hi);
  section_range(KASLD_TYPE_VIRT, "directmap", &vdmap_lo, &vdmap_hi);

  /* Build virtual memory region list */
  struct map_region regions[8];
  int n = 0;

  regions[n++] = (struct map_region){layout.modules_start, layout.modules_end,
                                     "modules", vmod_lo, vmod_hi};
  regions[n++] =
      (struct map_region){layout.kernel_base_min, layout.kernel_base_max,
                          "kernel text", vtext_lo, vtext_hi};

  /* Only show directmap region if it's distinct from text region.
     Use page_offset as both start and end — we know the mapping begins
     there but don't know its true extent. kernel_vas_end would cause
     unsigned overflow in the gap arithmetic (end + 1 wraps to 0). */
  if (layout.page_offset != layout.kernel_base_min) {
    regions[n++] = (struct map_region){layout.page_offset, layout.page_offset,
                                       "direct map", vdmap_lo, vdmap_hi};
  }

  /* Sort by start address */
  qsort(regions, (size_t)n, sizeof(struct map_region), region_cmp);

  printf("%sVirtual memory layout (%s):%s\n\n", c(C_BOLD),
         PHYS_VIRT_DECOUPLED ? "decoupled" : "coupled", c(C_RESET));

  /* Print map top-down (highest address first) — 64-char inner width */
  const char *box_top =
      "+------------------------------------------------------------------+";
  const char *box_sep =
      "|                                                                  |";

  /* Use the highest of kernel_vas_end and all region.end values so the top
   * label is never below a visible region boundary. kernel_vas_end can be
   * tightened by the page_offset_max inference feedback loop (it reflects
   * the upper bound on PAGE_OFFSET, not the architectural VAS ceiling), so
   * we clamp it up to the highest region boundary we know about. */
  unsigned long map_top = layout.kernel_vas_end;
  for (int i = 0; i < n; i++)
    if (regions[i].end > map_top)
      map_top = regions[i].end;

  printf("  0x%016lx\n", map_top);

  for (int i = n - 1; i >= 0; i--) {
    struct map_region *r = &regions[i];

    printf("  %s\n", box_top);
    printf("  |  %-62s  |\n", r->label);

    if (r->leak_lo) {
      if (r->leak_hi && r->leak_hi != r->leak_lo) {
        printf("  |    0x%016lx  %-40s  |\n", r->leak_hi, "(hi)");
        printf("  |    0x%016lx  %-40s  |\n", r->leak_lo, "(lo)");
      } else {
        /* Single witness — either no hi, or hi==lo (e.g. one sample-only
         * record, or one record where the merged extent happens to be a
         * single address). Show as one line. */
        printf("  |    0x%016lx%42s  |\n", r->leak_lo, "");
      }
    } else {
      printf("  |  %s%-62s%s  |\n", c(C_DIM), "(no leak)", c(C_RESET));
    }

    printf("  %s\n", box_top);
    printf("  0x%016lx\n", r->start);

    /* Show gap if there's a non-trivial space before the next region.
     * A gap above an inference-tightened region exposes the boundary
     * that the inference produced — e.g. when kaslr_ceiling drops
     * kernel_base_max from KASLR_BASE_MAX to text_base_default +
     * KERNEL_IMAGE_SIZE, the gap is the "text base cannot be here"
     * area. Label both ends of the gap so the boundary is readable. */
    if (i > 0 && regions[i - 1].end + 1 < r->start) {
      char hbuf[32];
      unsigned long gap = r->start - regions[i - 1].end - 1;
      printf("  %s\n", box_top);
      printf("  %s|%66s|%s\n", c(C_DIM), "", c(C_RESET));
      printf("  %s|  ...  %-59s|%s\n", c(C_DIM),
             human_size(gap, hbuf, sizeof(hbuf)), c(C_RESET));
      printf("  %s|%66s|%s\n", c(C_DIM), "", c(C_RESET));
      printf("  %s\n", box_top);
      printf("  0x%016lx\n", regions[i - 1].end);
    }
  }

  /* Only print kernel_vas_start as a footer when it is genuinely below the
   * lowest visible region (i.e. the VAS extends further down than page_offset).
   * kernel_vas_start can be raised by the page_offset_min inference feedback
   * loop, making it larger than layout.page_offset; printing it there would
   * produce two labels in inverted address order. */
  if (n == 0 || layout.kernel_vas_start < regions[0].start) {
    if (n > 0 && regions[0].start > layout.kernel_vas_start + 1) {
      char hbuf[32];
      unsigned long gap = regions[0].start - layout.kernel_vas_start;
      printf("  %s\n", box_top);
      printf("  %s|%66s|%s\n", c(C_DIM), "", c(C_RESET));
      printf("  %s|  ...  %-59s|%s\n", c(C_DIM),
             human_size(gap, hbuf, sizeof(hbuf)), c(C_RESET));
      printf("  %s|%66s|%s\n", c(C_DIM), "", c(C_RESET));
      printf("  %s\n", box_top);
    }
    printf("  0x%016lx\n", layout.kernel_vas_start);
  }
  printf("\n");

  /* Physical memory map — unified view of all physical leaks */
  unsigned long ptext = section_consensus(KASLD_TYPE_PHYS, "text");

  struct {
    unsigned long addr;
    char label[128];
    /* 1 iff this leak is a kernel-image region (text/data/bss/image). The
     * phys-text-base window box only renders entries with is_text=1; other
     * leaks whose address happens to land in the window are dropped from
     * the visualization, matching the virt layout's per-region semantics. */
    int is_text;
  } ppts[MAX_RESULTS];
  int nppts = 0;

  if (ptext && nppts < MAX_RESULTS) {
    ppts[nppts].addr = ptext;
    snprintf(ppts[nppts].label, sizeof(ppts[nppts].label), "[text] kernel");
    ppts[nppts].is_text = 1;
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
  unsigned long ram_end = 0;
  long pages = sysconf(_SC_PHYS_PAGES);
  long page_size = sysconf(_SC_PAGE_SIZE);
  if (pages > 0 && page_size > 0)
    ram_end = PHYS_OFFSET + (unsigned long)pages * (unsigned long)page_size;

  /* Use the highest leaked address if it exceeds the sysconf estimate */
  if (nppts > 0 && ppts[0].addr > ram_end)
    ram_end = ppts[0].addr;

  if (ram_end) {
    printf("  0x%016lx\n", ram_end);
  } else {
    printf("  0x????????????????  (end of RAM unknown)\n");
  }

  /* On PHYS_VIRT_DECOUPLED arches the phys text base is independently
   * randomized inside [phys_kaslr_base_min, phys_kaslr_base_max]. Inference
   * tightens both ends (kaslr_ceiling, dram_bound, meminfo_phys_ceiling,
   * ...) so this window can be much narrower than the arch default. When
   * we have a non-trivial window, split the leak dump into three buckets
   * (above-window / inside-window / below-window) with the window edges
   * labeled, mirroring how the virtual layout exposes the inferred text
   * range. Coupled arches and arches without phys KASLR leave both bounds
   * at 0 — fall back to the single-box rendering. */
  unsigned long pmin = layout.phys_kaslr_base_min;
  unsigned long pmax = layout.phys_kaslr_base_max;
  int show_phys_window = (pmax > pmin && pmin > 0);

  /* Build a flat list of buckets. `footer_addr` is the boundary label printed
   * after the bucket (= the address at the bottom edge of the bucket = the
   * top edge of the next bucket). PHYS_OFFSET always terminates the list.
   * `text_only` gates the bucket to kernel-image-region leaks; unrelated
   * leaks whose address happens to fall in the window range are dropped
   * (matching the virt layout's per-region semantics — virt "kernel text"
   * shows only text-section leaks, not every virt leak in [base_min,
   * base_max]). */
  struct phys_bucket {
    const char *header;
    unsigned long lo, hi;
    unsigned long footer_addr;
    int text_only;
  } buckets[3];
  int nbuckets = 0;

  if (!show_phys_window) {
    buckets[nbuckets++] =
        (struct phys_bucket){NULL, (unsigned long)PHYS_OFFSET, ULONG_MAX,
                             (unsigned long)PHYS_OFFSET, 0};
  } else {
    if (ram_end > pmax)
      buckets[nbuckets++] =
          (struct phys_bucket){NULL, pmax + 1, ULONG_MAX, pmax, 0};
    buckets[nbuckets++] =
        (struct phys_bucket){"phys kernel text", pmin, pmax, pmin, 1};
    if (pmin > (unsigned long)PHYS_OFFSET)
      buckets[nbuckets++] =
          (struct phys_bucket){NULL, (unsigned long)PHYS_OFFSET, pmin - 1,
                               (unsigned long)PHYS_OFFSET, 0};
    else
      /* Window's lower edge IS PHYS_OFFSET; collapse the trailing label. */
      buckets[nbuckets - 1].footer_addr = (unsigned long)PHYS_OFFSET;
  }

  for (int b = 0; b < nbuckets; b++) {
    const struct phys_bucket *bk = &buckets[b];
    int any = 0;
    for (int i = 0; i < nppts; i++) {
      if (ppts[i].addr < bk->lo || ppts[i].addr > bk->hi)
        continue;
      if (bk->text_only && !ppts[i].is_text)
        continue;
      any = 1;
      break;
    }
    printf("  %s\n", box_top);
    if (bk->header)
      printf("  |  %-62s  |\n", bk->header);
    if (any) {
      for (int i = 0; i < nppts; i++) {
        if (ppts[i].addr < bk->lo || ppts[i].addr > bk->hi)
          continue;
        if (bk->text_only && !ppts[i].is_text)
          continue;
        char str[164];
        snprintf(str, sizeof(str), "0x%016lx  %s", ppts[i].addr, ppts[i].label);
        printf("  |  %-62.62s  |\n", str);
      }
    } else {
      printf("  |  %s%-62s%s  |\n", c(C_DIM), "(no leak)", c(C_RESET));
    }
    printf("  %s\n", box_top);
    printf("  0x%016lx\n", bk->footer_addr);
  }

  printf("\n");
  (void)box_sep;
}

/* -------------------------------------------------------------------------
 * Hardening report renderer (--hardening, text mode)
 * -------------------------------------------------------------------------
 */

/* Known sysctl gates */
struct sysctl_gate {
  const char *name;    /* meta value prefix, e.g. "dmesg_restrict" */
  const char *display; /* display string, e.g. "kernel.dmesg_restrict" */
  int *value_ptr;      /* pointer to stored runtime value */
  int threshold;       /* blocking threshold (value >= threshold blocks) */
};

static int sysctl_gate_active(const struct sysctl_gate *g) {
  return *g->value_ptr >= 0 && *g->value_ptr >= g->threshold;
}

/* Check if a component's sysctl meta matches a given gate */
static int component_has_gate(const struct component_log *cl,
                              const struct sysctl_gate *g) {
  const char *vals[8];
  int nvals = meta_get_all(&cl->meta, "sysctl", vals, 8);
  for (int v = 0; v < nvals; v++) {
    /* meta value is like "dmesg_restrict>=1" — match the name prefix */
    size_t nlen = strlen(g->name);
    if (strncmp(vals[v], g->name, nlen) == 0 && vals[v][nlen] == '>')
      return 1;
  }
  return 0;
}

/* Check if a component has any mitigation keys */
static int has_mitigation_keys(const struct component_meta *m) {
  static const char *mitigation_keys[] = {
      "sysctl", "config", "patch", "cve", "hardware", "lockdown", NULL};
  for (int k = 0; mitigation_keys[k]; k++) {
    if (meta_get(m, mitigation_keys[k]))
      return 1;
  }
  return 0;
}

static void render_hardening_text(void) {
  printf("\n%s========================================%s\n", c(C_BOLD),
         c(C_RESET));
  printf("%s Hardening Assessment%s\n", c(C_BOLD), c(C_RESET));
  printf("%s========================================%s\n\n", c(C_BOLD),
         c(C_RESET));

  /* Count non-detection components with metadata */
  int total_meta = 0, succeeded = 0;
  for (int i = 0; i < num_comp_logs; i++) {
    const char *method = meta_get(&comp_logs[i].meta, "method");
    if (!method)
      continue;
    if (strcmp(method, "detection") == 0)
      continue;
    total_meta++;
    if (comp_logs[i].outcome == OUTCOME_SUCCESS)
      succeeded++;
  }

  printf("Hardening assessment: %s%d of %d%s leak techniques succeeded "
         "against current defenses.\n\n",
         succeeded > 0 ? c(C_YELLOW) : c(C_GREEN), succeeded, total_meta,
         c(C_RESET));

  /* ---- Section 1: Active Defenses ---- */
  printf("%sActive defenses:%s\n", c(C_BOLD), c(C_RESET));

  struct sysctl_gate gates[] = {
      {"kptr_restrict", "kernel.kptr_restrict", &sysctl_kptr_restrict, 1},
      {"dmesg_restrict", "kernel.dmesg_restrict", &sysctl_dmesg_restrict, 1},
      {"perf_event_paranoid", "kernel.perf_event_paranoid",
       &sysctl_perf_event_paranoid, 2},
  };
  int ngates = (int)(sizeof(gates) / sizeof(gates[0]));
  int any_active = 0;

  for (int g = 0; g < ngates; g++) {
    if (*gates[g].value_ptr < 0)
      continue; /* sysctl unavailable */

    int active = sysctl_gate_active(&gates[g]);
    int gated = 0, blocked = 0, bypassed = 0;
    const char *blocked_names[8];
    int nblocked_names = 0;

    for (int i = 0; i < num_comp_logs; i++) {
      if (!component_has_gate(&comp_logs[i], &gates[g]))
        continue;
      gated++;
      if (comp_logs[i].outcome == OUTCOME_ACCESS_DENIED) {
        blocked++;
        if (nblocked_names < 8)
          blocked_names[nblocked_names++] = comp_logs[i].name;
      } else if (comp_logs[i].outcome == OUTCOME_SUCCESS) {
        bypassed++;
      }
    }

    if (gated == 0)
      continue;

    if (active) {
      any_active = 1;
      printf("  %-34s = %-4d %s\xe2\x9c\x93%s  ", gates[g].display,
             *gates[g].value_ptr, c(C_GREEN), c(C_RESET));
      if (blocked > 0 && blocked <= 5) {
        printf("blocked ");
        for (int n = 0; n < nblocked_names; n++) {
          if (n > 0)
            printf(", ");
          printf("%s", blocked_names[n]);
        }
      } else if (blocked > 0) {
        printf("blocked %d of %d gated components", blocked, gated);
      }
      if (bypassed > 0) {
        if (blocked > 0)
          printf("; ");
        printf("%d bypassed (fallback?)", bypassed);
      }
      if (blocked == 0 && bypassed == 0)
        printf("%d gated component%s", gated, gated == 1 ? "" : "s");
      printf("\n");
    }
  }

  /* Lockdown status */
  const char *lockdown_str = NULL;
  switch (sysctl_lockdown) {
  case LOCKDOWN_INTEGRITY:
    lockdown_str = "integrity";
    break;
  case LOCKDOWN_CONFIDENTIALITY:
    lockdown_str = "confidentiality";
    break;
  default:
    break;
  }
  if (lockdown_str) {
    any_active = 1;
    printf("  %-34s        %s\xe2\x9c\x93%s  %s mode\n", "Kernel lockdown",
           c(C_GREEN), c(C_RESET), lockdown_str);
  } else {
    printf("  %-34s        %s\xe2\x9c\x97%s  inactive\n", "Kernel lockdown",
           c(C_DIM), c(C_RESET));
  }

  if (!any_active)
    printf("  %s(no active runtime defenses)%s\n", c(C_DIM), c(C_RESET));

  printf("\n");

  /* ---- Section 2: Available Hardening ---- */
  printf("%sAvailable hardening:%s\n", c(C_BOLD), c(C_RESET));

  int any_suggestions = 0;

  for (int g = 0; g < ngates; g++) {
    if (*gates[g].value_ptr < 0)
      continue;
    if (sysctl_gate_active(&gates[g]))
      continue; /* already active */

    int gated = 0;
    for (int i = 0; i < num_comp_logs; i++) {
      if (component_has_gate(&comp_logs[i], &gates[g]))
        gated++;
    }
    if (gated == 0)
      continue;

    any_suggestions = 1;
    printf("  %s\xe2\x86\x92%s Set %s = %d\n", c(C_CYAN), c(C_RESET),
           gates[g].display, gates[g].threshold);
    printf("    Would affect: %d component%s\n", gated, gated == 1 ? "" : "s");
  }

  /* Suggest lockdown if not active and any component has lockdown tag */
  if (sysctl_lockdown < LOCKDOWN_INTEGRITY) {
    int lockdown_gated = 0;
    for (int i = 0; i < num_comp_logs; i++) {
      if (meta_get(&comp_logs[i].meta, "lockdown"))
        lockdown_gated++;
    }
    if (lockdown_gated > 0) {
      any_suggestions = 1;
      printf("  %s\xe2\x86\x92%s Enable kernel lockdown (integrity mode)\n",
             c(C_CYAN), c(C_RESET));
      printf("    Blocks klogctl() even with CAP_SYSLOG.\n");
    }
  }

  /* Suggest restricting fallback paths if dmesg_restrict is active
     but dmesg components still succeeded */
  if (sysctl_dmesg_restrict >= 1) {
    int fallback_bypassed = 0;
    for (int i = 0; i < num_comp_logs; i++) {
      if (comp_logs[i].outcome != OUTCOME_SUCCESS)
        continue;
      if (!component_has_gate(&comp_logs[i], &gates[1])) /* dmesg gate */
        continue;
      if (meta_get(&comp_logs[i].meta, "fallback"))
        fallback_bypassed++;
    }
    if (fallback_bypassed > 0) {
      any_suggestions = 1;
      printf("  %s\xe2\x86\x92%s Restrict dmesg fallback files to root\n",
             c(C_CYAN), c(C_RESET));
      printf("    %d dmesg component%s may have succeeded via log files\n",
             fallback_bypassed, fallback_bypassed == 1 ? "" : "s");
    }
  }

  if (!any_suggestions)
    printf("  All available runtime hardening is active.\n");

  printf("\n");

  /* ---- Section 3: Patched Vulnerabilities ---- */
  printf("%sPatched vulnerabilities:%s\n", c(C_BOLD), c(C_RESET));

  int vuln_total = 0;
  struct {
    const char *name;
    const char *cve;
    const char *patch;
  } unpatched[16];
  int nunpatched = 0;

  for (int i = 0; i < num_comp_logs; i++) {
    const char *patch = meta_get(&comp_logs[i].meta, "patch");
    const char *cve = meta_get(&comp_logs[i].meta, "cve");
    if (!patch && !cve)
      continue;
    vuln_total++;
    if (comp_logs[i].outcome == OUTCOME_SUCCESS && nunpatched < 16) {
      unpatched[nunpatched].name = comp_logs[i].name;
      unpatched[nunpatched].cve = cve;
      unpatched[nunpatched].patch = patch;
      nunpatched++;
    }
  }

  if (vuln_total == 0) {
    printf("  No vulnerability-based components in metadata.\n");
  } else {
    printf("  %d of %d vulnerability-based components did not leak "
           "(likely patched or blocked).\n",
           vuln_total - nunpatched, vuln_total);
    if (nunpatched > 0) {
      printf("  %s%d component%s succeeded%s — kernel may lack fixes for:\n",
             c(C_YELLOW), nunpatched, nunpatched == 1 ? "" : "s", c(C_RESET));
      for (int i = 0; i < nunpatched; i++) {
        printf("    %s", unpatched[i].name);
        if (unpatched[i].cve)
          printf(" (%s", unpatched[i].cve);
        if (unpatched[i].patch)
          printf("%sfixed %s", unpatched[i].cve ? ", " : "(",
                 unpatched[i].patch);
        if (unpatched[i].cve || unpatched[i].patch)
          printf(")");
        printf("\n");
      }
    }
  }

  printf("\n");

  /* ---- Section 4: Compile-Time Attack Surface ---- */
  printf("%sCompile-time attack surface:%s\n", c(C_BOLD), c(C_RESET));

  struct {
    const char *name;
    const char *config;
    const char *addr;
  } config_surface[32];
  int nconfig = 0;

  for (int i = 0; i < num_comp_logs; i++) {
    if (comp_logs[i].outcome != OUTCOME_SUCCESS)
      continue;
    const char *configs[4];
    int ncfg = meta_get_all(&comp_logs[i].meta, "config", configs, 4);
    if (ncfg == 0)
      continue;
    const char *addr = meta_get(&comp_logs[i].meta, "addr");
    for (int j = 0; j < ncfg && nconfig < 32; j++) {
      config_surface[nconfig].name = comp_logs[i].name;
      config_surface[nconfig].config = configs[j];
      config_surface[nconfig].addr = addr;
      nconfig++;
    }
  }

  if (nconfig == 0) {
    printf("  No compile-time surface exposed.\n");
  } else {
    /* Group by addr type */
    int phys_count = 0, virt_count = 0;
    for (int i = 0; i < nconfig; i++) {
      if (config_surface[i].addr &&
          strcmp(config_surface[i].addr, "physical") == 0)
        phys_count++;
      else
        virt_count++;
    }
    if (phys_count > 0)
      printf("  %d component%s leak%s physical addresses via compiled-in "
             "features:\n",
             phys_count, phys_count == 1 ? "" : "s",
             phys_count == 1 ? "s" : "");
    for (int i = 0; i < nconfig; i++) {
      if (config_surface[i].addr &&
          strcmp(config_surface[i].addr, "physical") == 0)
        printf("    %-28s %s\n", config_surface[i].name,
               config_surface[i].config);
    }
    if (virt_count > 0)
      printf("  %d component%s leak%s virtual addresses via compiled-in "
             "features:\n",
             virt_count, virt_count == 1 ? "" : "s",
             virt_count == 1 ? "s" : "");
    for (int i = 0; i < nconfig; i++) {
      if (!config_surface[i].addr ||
          strcmp(config_surface[i].addr, "physical") != 0)
        printf("    %-28s %s\n", config_surface[i].name,
               config_surface[i].config);
    }
    if (phys_count > 0 && sizeof(unsigned long) >= 8)
      printf("  %sNote: on 64-bit architectures with decoupled KASLR, "
             "physical addresses alone cannot derive the kernel virtual text "
             "base.%s\n",
             c(C_DIM), c(C_RESET));
  }

  printf("\n");

  /* ---- Section 5: Hardware Side-Channels ---- */
  printf("%sHardware side-channels:%s\n", c(C_BOLD), c(C_RESET));

  struct {
    const char *name;
    const char *hardware;
    const char *addr;
    int outcome;
  } hw_comps[32];
  int nhw = 0, hw_succeeded = 0;

  for (int i = 0; i < num_comp_logs; i++) {
    const char *hw = meta_get(&comp_logs[i].meta, "hardware");
    if (!hw)
      continue;
    const char *method = meta_get(&comp_logs[i].meta, "method");
    if (!method || strcmp(method, "detection") == 0)
      continue;
    if (nhw < 32) {
      hw_comps[nhw].name = comp_logs[i].name;
      hw_comps[nhw].hardware = hw;
      hw_comps[nhw].addr = meta_get(&comp_logs[i].meta, "addr");
      hw_comps[nhw].outcome = comp_logs[i].outcome;
      nhw++;
      if (comp_logs[i].outcome == OUTCOME_SUCCESS)
        hw_succeeded++;
    }
  }

  if (nhw == 0) {
    printf("  No hardware-mitigated components.\n");
  } else if (hw_succeeded == 0) {
    printf("  %d hardware-gated component%s did not succeed (CPU mitigations "
           "active or attack not applicable).\n",
           nhw, nhw == 1 ? "" : "s");
  } else {
    printf("  %s%d of %d%s hardware-gated components succeeded:\n", c(C_YELLOW),
           hw_succeeded, nhw, c(C_RESET));
    for (int i = 0; i < nhw; i++) {
      if (hw_comps[i].outcome != OUTCOME_SUCCESS)
        continue;
      printf("    %-28s %s", hw_comps[i].name, hw_comps[i].hardware);
      if (hw_comps[i].addr)
        printf(" — leaks %s address", hw_comps[i].addr);
      printf("\n");
    }
    if (hw_succeeded < nhw) {
      printf("  %d of %d hardware-gated component%s did not succeed.\n",
             nhw - hw_succeeded, nhw, nhw - hw_succeeded == 1 ? "" : "s");
    }
  }

  printf("\n");

  /* ---- Section 6: No Known Mitigation ---- */
  printf("%sNo known mitigation:%s\n", c(C_BOLD), c(C_RESET));

  int any_unmit = 0;
  for (int i = 0; i < num_comp_logs; i++) {
    if (comp_logs[i].outcome != OUTCOME_SUCCESS)
      continue;
    const char *method = meta_get(&comp_logs[i].meta, "method");
    if (!method)
      continue;
    if (strcmp(method, "detection") == 0)
      continue;
    if (has_mitigation_keys(&comp_logs[i].meta))
      continue;
    any_unmit = 1;
    const char *addr = meta_get(&comp_logs[i].meta, "addr");
    printf("  %-28s %s%s%s\n", comp_logs[i].name, addr ? "leaks " : "",
           addr ? addr : "no mitigation", addr ? " addresses" : "");
  }

  if (!any_unmit)
    printf("  All components have at least one mitigation key.\n");

  printf("\n");
}

/* -------------------------------------------------------------------------
 * JSON renderer
 * -------------------------------------------------------------------------
 */
static void json_print_escaped(const char *s) {
  putchar('"');
  for (; *s; s++) {
    switch (*s) {
    case '"':
      fputs("\\\"", stdout);
      break;
    case '\\':
      fputs("\\\\", stdout);
      break;
    case '\b':
      fputs("\\b", stdout);
      break;
    case '\f':
      fputs("\\f", stdout);
      break;
    case '\n':
      fputs("\\n", stdout);
      break;
    case '\r':
      fputs("\\r", stdout);
      break;
    case '\t':
      fputs("\\t", stdout);
      break;
    default:
      if ((unsigned char)*s < 0x20)
        printf("\\u%04x", (unsigned char)*s);
      else
        putchar(*s);
    }
  }
  putchar('"');
}

static const char *outcome_name(enum component_outcome o) {
  switch (o) {
  case OUTCOME_SUCCESS:
    return "success";
  case OUTCOME_TIMEOUT:
    return "timeout";
  case OUTCOME_ACCESS_DENIED:
    return "access_denied";
  case OUTCOME_UNAVAILABLE:
    return "unavailable";
  case OUTCOME_NO_RESULT:
    return "no_result";
  }
  return "unknown";
}

static void render_json_group(enum kasld_addr_type gt, const char *gs) {
  const char *display = section_display_name(gt, gs);
  if (!display)
    return;

  unsigned long consensus = section_consensus(gt, gs);
  unsigned long lo, hi;
  section_range(gt, gs, &lo, &hi);

  const char *bm;
  int ns, nc;
  section_consensus_info(gt, gs, &bm, &ns, &nc);

  printf("    {\n");
  printf("      \"type\": \"%c\",\n", kasld_type_wire(gt));
  printf("      \"section\": \"%s\",\n", gs);
  printf("      \"display\": ");
  json_print_escaped(display);
  printf(",\n");
  printf("      \"consensus\": \"0x%016lx\",\n", consensus);
  printf("      \"consensus_method\": ");
  json_print_escaped(bm);
  printf(",\n");
  printf("      \"consensus_sources\": %d,\n", ns);
  printf("      \"conflicts\": %d,\n", nc);
  printf("      \"lo\": \"0x%016lx\"", lo);
  if (hi)
    printf(",\n      \"hi\": \"0x%016lx\"", hi);

  printf(",\n      \"results\": [\n");
  int first = 1;
  for (int i = 0; i < num_results; i++) {
    if (results[i].type != gt || strcmp(result_section(&results[i]), gs) != 0)
      continue;
    const struct result *r = &results[i];
    if (!first)
      printf(",\n");
    first = 0;
    unsigned long a = anchor_addr(r);
    printf("        {\n");
    printf("          \"raw\": \"0x%016lx\",\n", a);
    printf("          \"aligned\": \"0x%016lx\",\n", a);
    printf("          \"region\": ");
    json_print_escaped(kasld_region_wire(r->region));
    printf(",\n");
    printf("          \"name\": ");
    json_print_escaped(r->name);
    printf(",\n");
    printf("          \"origin\": ");
    json_print_escaped(result_origin(r));
    printf(",\n");
    printf("          \"method\": ");
    json_print_escaped(result_method(r));
    printf(",\n");
    printf("          \"valid\": %s\n", in_bounds(r) ? "true" : "false");
    printf("        }");
  }
  printf("\n      ]\n");
  printf("    }");
}

/* -------------------------------------------------------------------------
 * Hardening report JSON renderer (--hardening --json)
 * -------------------------------------------------------------------------
 */
static void render_hardening_json(void) {
  struct sysctl_gate gates[] = {
      {"kptr_restrict", "kernel.kptr_restrict", &sysctl_kptr_restrict, 1},
      {"dmesg_restrict", "kernel.dmesg_restrict", &sysctl_dmesg_restrict, 1},
      {"perf_event_paranoid", "kernel.perf_event_paranoid",
       &sysctl_perf_event_paranoid, 2},
  };
  int ngates = (int)(sizeof(gates) / sizeof(gates[0]));

  printf("  \"hardening\": {\n");

  /* Exposure summary */
  int total_meta = 0, succeeded_count = 0;
  for (int i = 0; i < num_comp_logs; i++) {
    const char *method = meta_get(&comp_logs[i].meta, "method");
    if (!method || strcmp(method, "detection") == 0)
      continue;
    total_meta++;
    if (comp_logs[i].outcome == OUTCOME_SUCCESS)
      succeeded_count++;
  }
  printf("    \"exposure\": {\n");
  printf("      \"succeeded\": %d,\n", succeeded_count);
  printf("      \"total\": %d,\n", total_meta);
  printf("      \"note\": \"Detection-only components excluded\"\n");
  printf("    },\n");

  /* Active defenses */
  printf("    \"active_defenses\": [\n");
  int first_def = 1;
  for (int g = 0; g < ngates; g++) {
    if (*gates[g].value_ptr < 0)
      continue;
    int active = sysctl_gate_active(&gates[g]);

    const char *gated_names[64];
    const char *blocked_names[64];
    const char *bypassed_names[64];
    int ngated = 0, nblocked = 0, nbypassed = 0;

    for (int i = 0; i < num_comp_logs; i++) {
      if (!component_has_gate(&comp_logs[i], &gates[g]))
        continue;
      if (ngated < 64)
        gated_names[ngated] = comp_logs[i].name;
      ngated++;
      if (comp_logs[i].outcome == OUTCOME_ACCESS_DENIED && nblocked < 64)
        blocked_names[nblocked++] = comp_logs[i].name;
      else if (comp_logs[i].outcome == OUTCOME_SUCCESS && nbypassed < 64)
        bypassed_names[nbypassed++] = comp_logs[i].name;
    }

    if (ngated == 0)
      continue;

    if (!first_def)
      printf(",\n");
    first_def = 0;

    printf("      {\n");
    printf("        \"gate\": \"%s\",\n", gates[g].display);
    printf("        \"value\": %d,\n", *gates[g].value_ptr);
    printf("        \"threshold\": %d,\n", gates[g].threshold);
    printf("        \"active\": %s,\n", active ? "true" : "false");

    printf("        \"components_gated\": [");
    for (int i = 0; i < ngated && i < 64; i++) {
      if (i > 0)
        printf(", ");
      json_print_escaped(gated_names[i]);
    }
    printf("],\n");

    printf("        \"components_blocked\": [");
    for (int i = 0; i < nblocked; i++) {
      if (i > 0)
        printf(", ");
      json_print_escaped(blocked_names[i]);
    }
    printf("],\n");

    printf("        \"components_bypassed\": [");
    for (int i = 0; i < nbypassed; i++) {
      if (i > 0)
        printf(", ");
      json_print_escaped(bypassed_names[i]);
    }
    printf("]\n");
    printf("      }");
  }
  printf("\n    ],\n");

  /* Lockdown */
  const char *lockdown_str;
  switch (sysctl_lockdown) {
  case LOCKDOWN_INTEGRITY:
    lockdown_str = "integrity";
    break;
  case LOCKDOWN_CONFIDENTIALITY:
    lockdown_str = "confidentiality";
    break;
  case LOCKDOWN_NONE:
    lockdown_str = "none";
    break;
  default:
    lockdown_str = "unavailable";
    break;
  }
  printf("    \"lockdown\": {\n");
  printf("      \"mode\": \"%s\",\n", lockdown_str);
  printf("      \"active\": %s\n",
         sysctl_lockdown >= LOCKDOWN_INTEGRITY ? "true" : "false");
  printf("    },\n");

  /* Available hardening */
  printf("    \"available_hardening\": [\n");
  int first_sug = 1;
  for (int g = 0; g < ngates; g++) {
    if (*gates[g].value_ptr < 0)
      continue;
    if (sysctl_gate_active(&gates[g]))
      continue;
    int gated = 0;
    for (int i = 0; i < num_comp_logs; i++) {
      if (component_has_gate(&comp_logs[i], &gates[g]))
        gated++;
    }
    if (gated == 0)
      continue;

    if (!first_sug)
      printf(",\n");
    first_sug = 0;

    printf("      {\n");
    printf("        \"action\": \"Set %s = %d\",\n", gates[g].display,
           gates[g].threshold);
    printf("        \"impact\": %d,\n", gated);
    printf("        \"detail\": \"Blocks unprivileged access for %d "
           "component%s\"\n",
           gated, gated == 1 ? "" : "s");
    printf("      }");
  }

  if (sysctl_lockdown < LOCKDOWN_INTEGRITY) {
    int lockdown_gated = 0;
    for (int i = 0; i < num_comp_logs; i++) {
      if (meta_get(&comp_logs[i].meta, "lockdown"))
        lockdown_gated++;
    }
    if (lockdown_gated > 0) {
      if (!first_sug)
        printf(",\n");
      first_sug = 0;
      printf("      {\n");
      printf("        \"action\": \"Enable kernel lockdown (integrity mode)\","
             "\n");
      printf("        \"impact\": %d,\n", lockdown_gated);
      printf("        \"detail\": \"Blocks klogctl() even with CAP_SYSLOG\"\n");
      printf("      }");
    }
  }
  printf("\n    ],\n");

  /* Patched vulnerabilities */
  printf("    \"patched_vulnerabilities\": {\n");
  int vuln_total = 0;
  struct {
    const char *name;
    const char *cve;
    const char *patch;
  } unpatched_json[16];
  int nunpatched_json = 0;

  for (int i = 0; i < num_comp_logs; i++) {
    const char *patch = meta_get(&comp_logs[i].meta, "patch");
    const char *cve = meta_get(&comp_logs[i].meta, "cve");
    if (!patch && !cve)
      continue;
    vuln_total++;
    if (comp_logs[i].outcome == OUTCOME_SUCCESS && nunpatched_json < 16) {
      unpatched_json[nunpatched_json].name = comp_logs[i].name;
      unpatched_json[nunpatched_json].cve = cve;
      unpatched_json[nunpatched_json].patch = patch;
      nunpatched_json++;
    }
  }

  printf("      \"total\": %d,\n", vuln_total);
  printf("      \"likely_patched\": %d,\n", vuln_total - nunpatched_json);
  printf("      \"possibly_unpatched\": [\n");
  for (int i = 0; i < nunpatched_json; i++) {
    if (i > 0)
      printf(",\n");
    printf("        {\"component\": ");
    json_print_escaped(unpatched_json[i].name);
    if (unpatched_json[i].cve) {
      printf(", \"cve\": ");
      json_print_escaped(unpatched_json[i].cve);
    }
    if (unpatched_json[i].patch) {
      printf(", \"patch\": ");
      json_print_escaped(unpatched_json[i].patch);
    }
    printf("}");
  }
  printf("\n      ]\n");
  printf("    },\n");

  /* Compile-time surface */
  printf("    \"compile_time_surface\": [\n");
  int first_cfg = 1;
  for (int i = 0; i < num_comp_logs; i++) {
    if (comp_logs[i].outcome != OUTCOME_SUCCESS)
      continue;
    const char *configs[4];
    int ncfg = meta_get_all(&comp_logs[i].meta, "config", configs, 4);
    if (ncfg == 0)
      continue;
    const char *addr = meta_get(&comp_logs[i].meta, "addr");
    for (int j = 0; j < ncfg; j++) {
      if (!first_cfg)
        printf(",\n");
      first_cfg = 0;
      printf("      {\"component\": ");
      json_print_escaped(comp_logs[i].name);
      printf(", \"config\": ");
      json_print_escaped(configs[j]);
      if (addr) {
        printf(", \"addr\": ");
        json_print_escaped(addr);
      }
      printf("}");
    }
  }
  printf("\n    ],\n");

  /* No mitigation */
  printf("    \"no_mitigation\": [\n");
  int first_nomit = 1;
  for (int i = 0; i < num_comp_logs; i++) {
    if (comp_logs[i].outcome != OUTCOME_SUCCESS)
      continue;
    const char *method = meta_get(&comp_logs[i].meta, "method");
    if (!method || strcmp(method, "detection") == 0)
      continue;
    if (has_mitigation_keys(&comp_logs[i].meta))
      continue;
    if (!first_nomit)
      printf(",\n");
    first_nomit = 0;
    const char *addr = meta_get(&comp_logs[i].meta, "addr");
    printf("      {\"component\": ");
    json_print_escaped(comp_logs[i].name);
    if (addr) {
      printf(", \"addr\": ");
      json_print_escaped(addr);
    }
    printf("}");
  }
  printf("\n    ]\n");

  printf("  }\n");
}

static void render_json(const struct summary *s) {
  struct utsname u;
  int have_uname = (uname(&u) == 0);

  printf("{\n");
  printf("  \"version\": \"%s\",\n", VERSION);
  printf("  \"arch\": \"%s\",\n", have_uname ? u.machine : "unknown");

  /* kernel */
  printf("  \"kernel\": {\n");
  if (have_uname) {
    printf("    \"release\": ");
    json_print_escaped(u.release);
    printf(",\n    \"version\": ");
    json_print_escaped(u.version);
    printf(",\n    \"machine\": ");
    json_print_escaped(u.machine);
    printf("\n");
  }
  printf("  },\n");

  /* layout */
  printf("  \"layout\": {\n");
  printf("    \"page_offset\": \"0x%016lx\",\n", layout.page_offset);
  printf("    \"kernel_base_min\": \"0x%016lx\",\n", layout.kernel_base_min);
  printf("    \"kernel_base_max\": \"0x%016lx\",\n", layout.kernel_base_max);
  printf("    \"kernel_align\": \"0x%lx\",\n", layout.kernel_align);
  printf("    \"kernel_text_default\": \"0x%016lx\",\n",
         layout.kernel_text_default);
  printf("    \"modules_start\": \"0x%016lx\",\n", layout.modules_start);
  printf("    \"modules_end\": \"0x%016lx\",\n", layout.modules_end);
  printf("    \"phys_virt_decoupled\": %s\n",
         PHYS_VIRT_DECOUPLED ? "true" : "false");
  printf("  },\n");

  /* kaslr */
  printf("  \"kaslr\": {\n");
  printf("    \"disabled\": %s,\n", s->kaslr.disabled ? "true" : "false");
  printf("    \"unsupported\": %s", s->kaslr.unsupported ? "true" : "false");

  if (s->kaslr.vtext) {
    printf(",\n    \"virtual\": {\n");
    printf("      \"text_base\": \"0x%016lx\",\n", s->kaslr.vtext);
    printf("      \"default_base\": \"0x%016lx\",\n",
           layout.kernel_text_default);
    printf("      \"slide_bytes\": %ld,\n", s->kaslr.vslide);
    printf("      \"entropy_bits\": %d,\n", s->kaslr.vbits);
    printf("      \"slots\": %lu", s->kaslr.vslots);
    if (s->kaslr.vslot_valid)
      printf(",\n      \"slot_index\": %lu", s->kaslr.vslot_idx);
    printf("\n    }");
  } else if (!s->kaslr.disabled && !s->kaslr.unsupported &&
             s->kaslr.vslots > 0) {
    printf(",\n    \"inferred\": {\n");
    printf("      \"range_min\": \"0x%016lx\",\n", layout.kaslr_base_min);
    printf("      \"range_max\": \"0x%016lx\",\n", layout.kaslr_base_max);
    printf("      \"slots\": %lu,\n", s->kaslr.vslots);
    printf("      \"entropy_bits\": %d\n", s->kaslr.vbits);
    printf("    }");
  }

  if (s->kaslr.has_phys) {
    printf(",\n    \"physical\": {\n");
    printf("      \"text_base\": \"0x%016lx\",\n", s->kaslr.ptext);
#ifdef KERNEL_PHYS_DEFAULT
    printf("      \"default_base\": \"0x%016lx\",\n",
           (unsigned long)KERNEL_PHYS_DEFAULT);
#endif
    printf("      \"slide_bytes\": %ld,\n", s->kaslr.pslide);
    printf("      \"entropy_bits\": %d,\n", s->kaslr.pbits);
    printf("      \"slots\": %lu\n", s->kaslr.pslots);
    printf("    }");
  } else if (!s->kaslr.disabled && !s->kaslr.unsupported &&
             s->kaslr.pslots > 0) {
    printf(",\n    \"inferred_physical\": {\n");
    printf("      \"range_min\": \"0x%016lx\",\n", layout.phys_kaslr_base_min);
    printf("      \"range_max\": \"0x%016lx\",\n", layout.phys_kaslr_base_max);
    printf("      \"slots\": %lu,\n", s->kaslr.pslots);
    printf("      \"entropy_bits\": %d\n", s->kaslr.pbits);
    printf("    }");
  }

  /* Memory KASLR (CONFIG_RANDOMIZE_MEMORY) — directmap / vmalloc / vmemmap
   * base bounds derived from the structural placement chain. Emitted only
   * when at least one region has been narrowed from its compile-time
   * default. Untightened sides emit JSON `null` so consumers can
   * distinguish "no bound" from "bound that happens to be zero". */
  if (s->kaslr.page_offset_min || s->kaslr.page_offset_max ||
      s->kaslr.vmalloc_min || s->kaslr.vmalloc_max || s->kaslr.vmemmap_min ||
      s->kaslr.vmemmap_max) {
    printf(",\n    \"memory_kaslr\": {\n");
    int first = 1;
    struct {
      const char *name;
      unsigned long min, max;
    } regions[] = {
        {"page_offset_base", s->kaslr.page_offset_min,
         s->kaslr.page_offset_max},
        {"vmalloc_base", s->kaslr.vmalloc_min, s->kaslr.vmalloc_max},
        {"vmemmap_base", s->kaslr.vmemmap_min, s->kaslr.vmemmap_max},
    };
    for (size_t i = 0; i < sizeof(regions) / sizeof(regions[0]); i++) {
      if (!regions[i].min && !regions[i].max)
        continue;
      printf("%s      \"%s\": { \"min\": ", first ? "" : ",\n",
             regions[i].name);
      if (regions[i].min)
        printf("\"0x%016lx\"", regions[i].min);
      else
        printf("null");
      printf(", \"max\": ");
      if (regions[i].max)
        printf("\"0x%016lx\"", regions[i].max);
      else
        printf("null");
      printf(" }");
      first = 0;
    }
    printf("\n    }");
  }

  printf("\n  },\n");

  /* groups — build ordered list of unique (type, section) keys */
  const char *section_order[] = {"text", "module", "directmap", "data",
                                 "bss",  "dram",   "mmio",      NULL};
  enum kasld_addr_type type_order[] = {KASLD_TYPE_VIRT, KASLD_TYPE_PHYS,
                                       KASLD_TYPE_UNKNOWN};

  struct group_key gkeys[64];
  int ngkeys = 0;

  for (int t = 0; type_order[t] != KASLD_TYPE_UNKNOWN; t++) {
    for (int si = 0; section_order[si]; si++) {
      int has = 0;
      for (int i = 0; i < num_results; i++) {
        if (results[i].type == type_order[t] &&
            strcmp(result_section(&results[i]), section_order[si]) == 0 &&
            in_bounds(&results[i])) {
          has = 1;
          break;
        }
      }
      if (has && ngkeys < 64) {
        gkeys[ngkeys].type = type_order[t];
        gkeys[ngkeys].section = section_order[si];
        ngkeys++;
      }
    }
  }

  /* Append any remaining groups not in predefined order */
  for (int i = 0; i < num_results; i++) {
    if (results[i].type == KASLD_TYPE_DEFAULT_VIRT)
      continue;
    const char *sec = result_section(&results[i]);
    int already = 0;
    for (int j = 0; j < ngkeys; j++) {
      if (gkeys[j].type == results[i].type &&
          strcmp(gkeys[j].section, sec) == 0) {
        already = 1;
        break;
      }
    }
    if (!already && ngkeys < 64) {
      gkeys[ngkeys].type = results[i].type;
      gkeys[ngkeys].section = sec;
      ngkeys++;
    }
  }

  printf("  \"groups\": [\n");
  int first_group = 1;
  for (int g = 0; g < ngkeys; g++) {
    if (!section_display_name(gkeys[g].type, gkeys[g].section))
      continue;
    /* Verify group has at least one in-bounds result */
    int has = 0;
    for (int i = 0; i < num_results; i++) {
      if (results[i].type == gkeys[g].type &&
          strcmp(result_section(&results[i]), gkeys[g].section) == 0 &&
          in_bounds(&results[i])) {
        has = 1;
        break;
      }
    }
    if (!has)
      continue;
    if (!first_group)
      printf(",\n");
    first_group = 0;
    render_json_group(gkeys[g].type, gkeys[g].section);
  }
  printf("\n  ],\n");

  /* derived — records with conf == CONF_DERIVED */
  printf("  \"derived\": [\n");
  int first_d = 1;
  for (int i = 0; i < num_results; i++) {
    const struct result *r = &results[i];
    if (r->conf != CONF_DERIVED)
      continue;
    if (!first_d)
      printf(",\n");
    first_d = 0;
    printf("    {\n");
    printf("      \"type\": \"%c\",\n", kasld_type_wire(r->type));
    printf("      \"section\": \"%s\",\n", result_section(r));
    if (HAS_LO(r) && HAS_HI(r)) {
      printf("      \"addr\": \"0x%016lx\"", r->lo);
      printf(",\n      \"addr_hi\": \"0x%016lx\"", r->hi);
    } else {
      printf("      \"addr\": \"0x%016lx\"", anchor_addr(r));
    }
    printf(",\n      \"label\": ");
    json_print_escaped(kasld_region_wire(r->region));
    printf(",\n      \"via\": ");
    json_print_escaped(result_method(r));
    printf("\n    }");
  }

  /* Close derived array — with trailing comma if stats/components follow */
  printf("\n  ],\n");

  /* Component statistics — always present */
  printf("  \"component_stats\": {\n");
  printf("    \"total\": %d,\n", s->stats.total);
  printf("    \"succeeded\": %d,\n", s->stats.succeeded);
  printf("    \"unavailable\": %d,\n", s->stats.unavailable);
  printf("    \"access_denied\": %d,\n", s->stats.access_denied);
  printf("    \"timed_out\": %d,\n", s->stats.timed_out);
  printf("    \"no_result\": %d\n", s->stats.no_result);
  printf("  }");

  if ((verbose || hardening_mode) && num_comp_logs > 0) {
    printf(",\n");

    /* components — present with --verbose or --hardening */
    printf("  \"components\": [\n");
    for (int i = 0; i < num_comp_logs; i++) {
      struct component_log *cl = &comp_logs[i];
      if (i > 0)
        printf(",\n");
      printf("    {\n");
      printf("      \"name\": ");
      json_print_escaped(cl->name);
      printf(",\n");
      printf("      \"exit_code\": %d,\n", cl->exit_code);
      printf("      \"outcome\": \"%s\"", outcome_name(cl->outcome));
      if (cl->explain) {
        printf(",\n      \"explain\": ");
        json_print_escaped(cl->explain);
      }
      if (hardening_mode && cl->meta.num_entries > 0) {
        printf(",\n      \"meta\": {\n");
        /* Build meta object: single values as strings, multiple as arrays */
        int first_key = 1;
        for (int j = 0; j < cl->meta.num_entries; j++) {
          /* Check if this key was already emitted */
          int already = 0;
          for (int k = 0; k < j; k++) {
            if (strcmp(cl->meta.entries[k].key, cl->meta.entries[j].key) == 0) {
              already = 1;
              break;
            }
          }
          if (already)
            continue;

          /* Count values for this key */
          const char *vals[16];
          int nvals =
              meta_get_all(&cl->meta, cl->meta.entries[j].key, vals, 16);

          if (!first_key)
            printf(",\n");
          first_key = 0;

          printf("        ");
          json_print_escaped(cl->meta.entries[j].key);
          printf(": ");

          if (nvals == 1) {
            json_print_escaped(vals[0]);
          } else {
            printf("[");
            for (int v = 0; v < nvals; v++) {
              if (v > 0)
                printf(", ");
              json_print_escaped(vals[v]);
            }
            printf("]");
          }
        }
        printf("\n      }");
      }
      if (verbose && cl->num_lines > 0) {
        printf(",\n      \"output\": [\n");
        for (int j = 0; j < cl->num_lines; j++) {
          printf("        ");
          json_print_escaped(cl->lines[j]);
          if (j < cl->num_lines - 1)
            printf(",");
          printf("\n");
        }
        printf("      ]");
      }
      printf("\n    }");
    }
    printf("\n  ]");
    if (hardening_mode)
      printf(",");
    printf("\n");
  } else {
    if (hardening_mode)
      printf(",");
    printf("\n");
  }

  if (hardening_mode)
    render_hardening_json();

  printf("}\n");
}

/* -------------------------------------------------------------------------
 * Text renderer
 * -------------------------------------------------------------------------
 */
static void render_text(const struct summary *s) {
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
      printf("Kernel text base: %s0x%016lx%s (default for arch)\n\n",
             c(C_GREEN), s->kaslr.default_addr, c(C_RESET));
  } else if (s->kaslr.disabled) {
    printf("%s** KASLR is disabled **%s\n\n", c(C_YELLOW), c(C_RESET));
    printf("Detected by:\n");
    for (int i = 0; i < num_results; i++) {
      /* List components that emitted a non-fallback DEFAULT result —
       * those are the ones reporting "nokaslr" / "unsupported" markers. */
      if (results[i].type == KASLD_TYPE_DEFAULT_VIRT &&
          results[i].name[0] != '\0' && strcmp(results[i].name, "text") != 0)
        printf("  %s (%s)\n", result_origin(&results[i]), results[i].name);
    }
    printf("\n");
    if (s->kaslr.default_addr)
      printf(
          "Likely kernel text base: %s0x%016lx%s (assumes default config)\n\n",
          c(C_GREEN), s->kaslr.default_addr, c(C_RESET));
  }

  /* Print each (type, section) group in a defined order */
  const char *section_order[] = {"text", "module", "directmap", "data",
                                 "bss",  "dram",   "mmio",      NULL};
  enum kasld_addr_type type_order[] = {KASLD_TYPE_VIRT, KASLD_TYPE_PHYS,
                                       KASLD_TYPE_UNKNOWN};

  if (verbose) {
    /* Verbose: one block per (type, section, region) — cross-source
     * confirmations of the same memory landmark collapse into a single
     * block, making it obvious which regions have multiple agreeing sources. */
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
      if (r->type == KASLD_TYPE_DEFAULT_VIRT)
        continue;
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
  } else {
    /* Compact: one line per (type, section) for non-kernel-locating
     * regions, plus one line per kernel-locating region (kernel_image,
     * kernel_text, kernel_data, kernel_bss) so direct kernel-base
     * disclosures are not buried inside a generic "Physical DRAM" /
     * "Physical MMIO" range. */
    for (int t = 0; type_order[t] != KASLD_TYPE_UNKNOWN; t++) {
      for (int si = 0; section_order[si]; si++) {
        if (group_already_printed(type_order[t], section_order[si]))
          continue;

        const char *catchall_name =
            section_display_name(type_order[t], section_order[si]);
        if (!catchall_name)
          continue;

        /* Promote each kernel-locating region present in this subgroup to
         * its own line. Print these before the catch-all so the prize is
         * visible at the top. */
        enum kasld_region kr_seen[MAX_RESULTS];
        int nkr =
            collect_kernel_regions(type_order[t], section_order[si], kr_seen);
        for (int k = 0; k < nkr; k++) {
          const char *kr_name =
              kernel_region_display_name(type_order[t], kr_seen[k]);
          if (!kr_name)
            kr_name = catchall_name;
          print_compact_subgroup(kr_name, type_order[t], section_order[si],
                                 kr_seen[k], 0);
        }

        /* Catch-all line covers the rest. When kernel-locating regions
         * were promoted, exclude them from the catch-all so its lo/hi
         * span reflects only background landmarks (ram_base, ram_top,
         * initrd, etc.). When no kernel-locating regions were present,
         * this is identical to the original "all results" behaviour. */
        print_compact_subgroup(catchall_name, type_order[t], section_order[si],
                               REGION_UNKNOWN, nkr > 0);

        mark_group_printed(type_order[t], section_order[si]);
      }
    }

    /* Any remaining groups not in predefined order — same kernel-locating
     * promotion as the predefined-order pass above. */
    for (int i = 0; i < num_results; i++) {
      struct result *r = &results[i];
      if (r->type == KASLD_TYPE_DEFAULT_VIRT)
        continue;
      const char *sec = result_section(r);
      if (group_already_printed(r->type, sec))
        continue;

      const char *catchall_name = section_display_name(r->type, sec);
      if (!catchall_name)
        continue;

      enum kasld_region kr_seen[MAX_RESULTS];
      int nkr = collect_kernel_regions(r->type, sec, kr_seen);
      for (int k = 0; k < nkr; k++) {
        const char *kr_name = kernel_region_display_name(r->type, kr_seen[k]);
        if (!kr_name)
          kr_name = catchall_name;
        print_compact_subgroup(kr_name, r->type, sec, kr_seen[k], 0);
      }
      print_compact_subgroup(catchall_name, r->type, sec, REGION_UNKNOWN,
                             nkr > 0);

      mark_group_printed(r->type, sec);
    }
    printf("\n");
  }

  render_kaslr_text(s);
  render_derived_text(s);

  printf("%s%s%s\n", c(C_DIM), "----------------------------------------",
         c(C_RESET));
  print_memory_map();

  if (hardening_mode)
    render_hardening_text();
}

/* -------------------------------------------------------------------------
 * One-line summary renderer (--oneline)
 * -------------------------------------------------------------------------
 */
static void render_oneline(const struct summary *s) {
  struct utsname u;
  int have_uname = (uname(&u) == 0);

  /* arch */
  printf("arch=%s", have_uname ? u.machine : "unknown");

  /* KASLR state */
  if (s->kaslr.unsupported)
    printf(" kaslr=unsupported");
  else if (s->kaslr.disabled)
    printf(" kaslr=off");
  else
    printf(" kaslr=on");

  /* Virtual text consensus */
  unsigned long vtext = section_consensus(KASLD_TYPE_VIRT, "text");
  if (vtext)
    printf(" text=0x%lx", vtext);

  /* Physical text consensus */
  unsigned long ptext = section_consensus(KASLD_TYPE_PHYS, "text");
  if (ptext)
    printf(" ptext=0x%lx", ptext);

  /* KASLR slide */
  if (s->kaslr.vtext) {
    long abs_vs = s->kaslr.vslide < 0 ? -s->kaslr.vslide : s->kaslr.vslide;
    printf(" slide=%s0x%lx(%ld)", s->kaslr.vslide < 0 ? "-" : "+",
           (unsigned long)abs_vs, s->kaslr.vslide);
  }

  /* Entropy */
  if (s->kaslr.vtext && s->kaslr.vbits > 0)
    printf(" entropy=%dbits", s->kaslr.vbits);

  /* Direct map */
  unsigned long vdmap = section_consensus(KASLD_TYPE_VIRT, "directmap");
  if (vdmap)
    printf(" dmap=0x%lx", vdmap);

  /* Physical DRAM range */
  unsigned long pdram_lo, pdram_hi;
  section_range(KASLD_TYPE_PHYS, "dram", &pdram_lo, &pdram_hi);
  if (pdram_lo) {
    char hbuf[32];
    unsigned long top = pdram_hi ? pdram_hi : pdram_lo;
    printf(" dram=[0x%lx..0x%lx](%s)", pdram_lo, top,
           human_size(top - pdram_lo, hbuf, sizeof(hbuf)));
  }

  /* Number of results */
  printf(" results=%d", num_results);

  printf("\n");
}

/* -------------------------------------------------------------------------
 * Markdown table renderer (--markdown)
 * -------------------------------------------------------------------------
 */
static void render_markdown(const struct summary *s) {
  struct utsname u;
  int have_uname = (uname(&u) == 0);

  /* Header info */
  printf("# KASLD Results\n\n");
  if (have_uname)
    printf("**Kernel:** %s (%s, %s)\n\n", u.release, u.machine, u.version);

  /* Component outcome summary */
  if (s->stats.total > 0) {
    printf("*Components: %d total", s->stats.total);
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
    printf("*\n\n");
  }

  if (s->kaslr.unsupported)
    printf("> **KASLR is not supported on this architecture**\n\n");
  else if (s->kaslr.disabled)
    printf("> **KASLR is disabled**\n\n");

  /* KASLR summary */
  if (s->kaslr.vtext || s->kaslr.has_phys) {
    printf("## KASLR Analysis\n\n");
    printf("| Metric | Value |\n");
    printf("|:-------|:------|\n");
    if (s->kaslr.vtext) {
      long abs_vs = s->kaslr.vslide < 0 ? -s->kaslr.vslide : s->kaslr.vslide;
      printf("| Virtual text base | `0x%016lx` |\n", s->kaslr.vtext);
      printf("| Default text base | `0x%016lx` |\n",
             layout.kernel_text_default);
      printf("| KASLR slide | %s0x%lx (%ld) |\n",
             s->kaslr.vslide < 0 ? "-" : "+", (unsigned long)abs_vs,
             s->kaslr.vslide);
      printf("| Virtual entropy | %d bits (%lu slots) |\n", s->kaslr.vbits,
             s->kaslr.vslots);
      if (s->kaslr.vslot_valid)
        printf("| Observed slot | %lu / %lu |\n", s->kaslr.vslot_idx,
               s->kaslr.vslots);
    }
    if (s->kaslr.has_phys) {
      printf("| Physical text base | `0x%016lx` |\n", s->kaslr.ptext);
      printf("| Physical entropy | %d bits (%lu slots) |\n", s->kaslr.pbits,
             s->kaslr.pslots);
    }
    printf("\n");
  }

  /* Result groups */
  const char *section_order[] = {"text", "module", "directmap", "data",
                                 "bss",  "dram",   "mmio",      NULL};
  enum kasld_addr_type type_order[] = {KASLD_TYPE_PHYS, KASLD_TYPE_VIRT,
                                       KASLD_TYPE_UNKNOWN};

  printf("## Leak Results\n\n");

  if (verbose) {
    /* Verbose: individual result rows */
    printf("| Type | Section | Address | Region | Name | Origin | Method |\n");
    printf("|:-----|:--------|:--------|:-------|:-----|:-------|:-------|\n");

    for (int t = 0; type_order[t] != KASLD_TYPE_UNKNOWN; t++) {
      for (int si = 0; section_order[si]; si++) {
        int idx[MAX_RESULTS];
        int nidx = 0;
        for (int i = 0; i < num_results; i++) {
          struct result *r = &results[i];
          if (r->type != type_order[t] ||
              strcmp(result_section(r), section_order[si]) != 0)
            continue;
          if (r->type == KASLD_TYPE_DEFAULT_VIRT)
            continue;
          idx[nidx++] = i;
        }
        for (int a = 0; a < nidx - 1; a++)
          for (int b = a + 1; b < nidx; b++)
            if (anchor_addr(&results[idx[a]]) > anchor_addr(&results[idx[b]])) {
              int tmp = idx[a];
              idx[a] = idx[b];
              idx[b] = tmp;
            }
        for (int k = 0; k < nidx; k++) {
          struct result *r = &results[idx[k]];
          unsigned long a = anchor_addr(r);
          printf("| %c | %s | `0x%016lx` | %s | %s | %s | %s%s |\n",
                 kasld_type_wire(r->type), result_section(r), a,
                 kasld_region_wire(r->region), r->name, result_origin(r),
                 result_method(r), in_bounds(r) ? "" : " (stale)");
        }
      }
    }

    /* Any remaining sections */
    for (int i = 0; i < num_results; i++) {
      struct result *r = &results[i];
      if (r->type == KASLD_TYPE_DEFAULT_VIRT)
        continue;
      const char *sec = result_section(r);
      int in_order = 0;
      for (int si = 0; section_order[si]; si++) {
        if (strcmp(sec, section_order[si]) == 0) {
          in_order = 1;
          break;
        }
      }
      if (!in_order) {
        unsigned long a = anchor_addr(r);
        printf("| %c | %s | `0x%016lx` | %s | %s | %s%s |\n",
               kasld_type_wire(r->type), sec, a, kasld_region_wire(r->region),
               result_origin(r), result_method(r),
               in_bounds(r) ? "" : " (stale)");
      }
    }
  } else {
    /* Compact: one summary row per group */
    char hbuf[32];
    printf("| Section | Address | Sources |\n");
    printf("|:--------|:--------|--------:|\n");

    for (int t = 0; type_order[t] != KASLD_TYPE_UNKNOWN; t++) {
      for (int si = 0; section_order[si]; si++) {
        const char *name =
            section_display_name(type_order[t], section_order[si]);
        if (!name)
          continue;
        int count = 0;
        for (int i = 0; i < num_results; i++) {
          if (results[i].type == type_order[t] &&
              strcmp(result_section(&results[i]), section_order[si]) == 0 &&
              in_bounds(&results[i]))
            count++;
        }
        if (!count)
          continue;

        unsigned long consensus =
            section_consensus(type_order[t], section_order[si]);
        unsigned long lo, hi;
        section_range(type_order[t], section_order[si], &lo, &hi);

        if (hi && hi != lo) {
          unsigned long span = hi - lo;
          printf("| %s | `0x%016lx` - `0x%016lx` (%s) | %d |\n", name, lo, hi,
                 human_size(span, hbuf, sizeof(hbuf)), count);
        } else {
          printf("| %s | `0x%016lx` | %d |\n", name, consensus, count);
        }
      }
    }

    /* Any remaining groups */
    for (int i = 0; i < num_results; i++) {
      struct result *r = &results[i];
      if (r->type == KASLD_TYPE_DEFAULT_VIRT)
        continue;
      const char *sec = result_section(r);
      const char *name = section_display_name(r->type, sec);
      if (!name)
        continue;

      /* Check if already covered by predefined order */
      int in_order = 0;
      for (int si = 0; section_order[si]; si++) {
        if (strcmp(sec, section_order[si]) == 0) {
          in_order = 1;
          break;
        }
      }
      if (in_order)
        continue;

      /* Deduplicate: only emit first occurrence of this group */
      int already = 0;
      for (int j = 0; j < i; j++) {
        if (results[j].type == r->type &&
            strcmp(result_section(&results[j]), sec) == 0) {
          already = 1;
          break;
        }
      }
      if (already)
        continue;

      int count = 0;
      for (int j = 0; j < num_results; j++) {
        if (results[j].type == r->type &&
            strcmp(result_section(&results[j]), sec) == 0 &&
            in_bounds(&results[j]))
          count++;
      }
      if (!count)
        continue;

      unsigned long consensus = section_consensus(r->type, sec);
      unsigned long lo, hi;
      section_range(r->type, sec, &lo, &hi);

      if (hi && hi != lo) {
        unsigned long span = hi - lo;
        printf("| %s | `0x%016lx` - `0x%016lx` (%s) | %d |\n", name, lo, hi,
               human_size(span, hbuf, sizeof(hbuf)), count);
      } else {
        printf("| %s | `0x%016lx` | %d |\n", name, consensus, count);
      }
    }
  }

  printf("\n");

  /* Derived addresses (records with conf == CONF_DERIVED) */
  int n_derived = count_derived();
  if (n_derived > 0) {
    printf("## Derived Addresses\n\n");
    printf("| Address | Label | Via |\n");
    printf("|:--------|:------|:----|\n");
    for (int i = 0; i < num_results; i++) {
      const struct result *r = &results[i];
      if (r->conf != CONF_DERIVED)
        continue;
      char label[NAME_LEN + 32];
      if (r->name[0])
        snprintf(label, sizeof(label), "%s:%s", kasld_region_wire(r->region),
                 r->name);
      else
        snprintf(label, sizeof(label), "%s", kasld_region_wire(r->region));
      if (HAS_LO(r) && HAS_HI(r))
        printf("| `0x%016lx` - `0x%016lx` | %s | %s |\n", r->lo, r->hi, label,
               result_method(r));
      else
        printf("| `0x%016lx` | %s | %s |\n", anchor_addr(r), label,
               result_method(r));
    }
    printf("\n");
  }
  (void)region_range; /* helper retained for future use */
  (void)region_anchor;
}

/* -------------------------------------------------------------------------
 * Summary orchestrator: compute, then dispatch to renderer
 * -------------------------------------------------------------------------
 */
void print_summary(void) {
  struct summary s = {0};

  compute_component_stats(&s);
  inject_kaslr_defaults(&s);
  compute_kaslr_info(&s);
  /* compute_derived_addrs() is gone — cross-region derivations now arrive
   * as ordinary CONF_DERIVED results via inference plugins. */

  if (json_output)
    render_json(&s);
  else if (oneline_output)
    render_oneline(&s);
  else if (markdown_output)
    render_markdown(&s);
  else
    render_text(&s);
}
