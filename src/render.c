// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rendering layer: all output formatting (text, JSON, oneline, markdown).
// Consumes the struct summary produced by the core analysis in orchestrator.c.
// ---
// <bcoles@gmail.com>

#include "include/kasld_internal.h"

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
 * Output helpers
 * -------------------------------------------------------------------------
 */
static const char *section_display_name(char type, const char *section) {
  if (type == KASLD_ADDR_DEFAULT)
    return NULL;
  if (strcmp(section, KASLD_SECTION_TEXT) == 0)
    return type == KASLD_ADDR_VIRT ? "Kernel text (virtual)"
                                   : "Kernel text (physical)";
  if (strcmp(section, KASLD_SECTION_MODULE) == 0)
    return "Kernel modules (virtual)";
  if (strcmp(section, KASLD_SECTION_DIRECTMAP) == 0)
    return "Direct map (virtual)";
  if (strcmp(section, KASLD_SECTION_DATA) == 0)
    return "Kernel data (virtual)";
  if (strcmp(section, KASLD_SECTION_DRAM) == 0)
    return "Physical DRAM";
  if (strcmp(section, KASLD_SECTION_MMIO) == 0)
    return "Physical MMIO";
  if (strcmp(section, KASLD_SECTION_PAGEOFFSET) == 0)
    return NULL; /* metadata, not a leak group */
  return "Unknown";
}

struct group_key {
  char type;
  char section[SECTION_LEN];
};

static struct group_key printed_groups[32];
static int num_printed_groups;

static int group_already_printed(char type, const char *section) {
  for (int i = 0; i < num_printed_groups; i++) {
    if (printed_groups[i].type == type &&
        strcmp(printed_groups[i].section, section) == 0)
      return 1;
  }
  return 0;
}

static void mark_group_printed(char type, const char *section) {
  if (num_printed_groups < 32) {
    printed_groups[num_printed_groups].type = type;
    strncpy(printed_groups[num_printed_groups].section, section,
            SECTION_LEN - 1);
    num_printed_groups++;
  }
}

static void print_group(char type, const char *section) {
  const char *name = section_display_name(type, section);
  if (!name)
    return;

  int valid_count = 0;
  for (int i = 0; i < num_results; i++) {
    if (results[i].type == type && strcmp(results[i].section, section) == 0 &&
        results[i].valid)
      valid_count++;
  }
  if (!valid_count)
    return;

  /* Separator between groups */
  if (num_printed_groups > 0)
    printf("%s%s%s\n", c(C_DIM), "----------------------------------------",
           c(C_RESET));

  printf("%s%s%s [%d]:\n", c(C_BOLD), name, c(C_RESET), valid_count);

  /* Collect indices of matching results, then sort by aligned address */
  int indices[MAX_RESULTS];
  int n_indices = 0;
  for (int i = 0; i < num_results; i++) {
    if (results[i].type == type && strcmp(results[i].section, section) == 0)
      if (n_indices < MAX_RESULTS)
        indices[n_indices++] = i;
  }
  for (int i = 0; i < n_indices - 1; i++)
    for (int j = i + 1; j < n_indices; j++)
      if (results[indices[i]].aligned > results[indices[j]].aligned) {
        int tmp = indices[i];
        indices[i] = indices[j];
        indices[j] = tmp;
      }

  unsigned long addrs[MAX_RESULTS];
  int n_addrs = 0;

  for (int k = 0; k < n_indices; k++) {
    struct result *r = &results[indices[k]];

    if (!r->valid) {
      if (verbose)
        printf("  %s0x%016lx%s  %s %s(%s, out of range)%s\n", c(C_RED), r->raw,
               c(C_RESET), r->label, c(C_DIM), r->method, c(C_RESET));
      else
        printf("  %s0x%016lx%s  %s %s(out of range)%s\n", c(C_RED), r->raw,
               c(C_RESET), r->label, c(C_DIM), c(C_RESET));
      continue;
    }

    if (verbose)
      printf("  %s0x%016lx%s  %s %s(%s)%s\n", c(C_GREEN), r->aligned,
             c(C_RESET), r->label, c(C_DIM), r->method, c(C_RESET));
    else
      printf("  %s0x%016lx%s  %s\n", c(C_GREEN), r->aligned, c(C_RESET),
             r->label);

    int dup = 0;
    for (int j = 0; j < n_addrs; j++) {
      if (addrs[j] == r->aligned) {
        dup = 1;
        break;
      }
    }
    if (!dup && n_addrs < MAX_RESULTS)
      addrs[n_addrs++] = r->aligned;
  }

  if (n_addrs == 1) {
    const char *bm;
    int ns, nc;
    group_consensus_info(type, section, &bm, &ns, &nc);
    printf("  %s==>%s 0x%016lx  %s(%s, %d source%s)%s\n", c(C_CYAN), c(C_RESET),
           addrs[0], c(C_DIM), bm, ns, ns == 1 ? "" : "s", c(C_RESET));
  } else if (n_addrs > 1) {
    const char *bm;
    int ns, nc;
    group_consensus_info(type, section, &bm, &ns, &nc);
    char hbuf[32];
    unsigned long span = addrs[n_addrs - 1] - addrs[0];
    unsigned long consensus = group_consensus(type, section);
    printf("  %s==>%s 0x%016lx  %s(%s, %d source%s, %d conflict%s)%s\n",
           c(C_CYAN), c(C_RESET), consensus, c(C_DIM), bm, ns,
           ns == 1 ? "" : "s", nc, nc == 1 ? "" : "s", c(C_RESET));
    printf("  %s   %s range: 0x%016lx - 0x%016lx  (%s)\n", c(C_CYAN),
           c(C_RESET), addrs[0], addrs[n_addrs - 1],
           human_size(span, hbuf, sizeof(hbuf)));
  }

  printf("\n");
}

/* -------------------------------------------------------------------------
 * KASLR analysis text renderer (consumes pre-computed summary)
 * -------------------------------------------------------------------------
 */
static void render_kaslr_text(const struct summary *s) {
  if (!s->kaslr.vtext && !s->kaslr.ptext)
    return;

  printf("%s%s%s\n", c(C_DIM), "----------------------------------------",
         c(C_RESET));
  printf("%sKASLR analysis:%s\n", c(C_BOLD), c(C_RESET));

  if (s->kaslr.vtext) {
    char hbuf[32];
    printf("  Virtual text base:    %s0x%016lx%s\n", c(C_GREEN), s->kaslr.vtext,
           c(C_RESET));
    printf("  Default text base:    0x%016lx\n", layout.kernel_text_default);
    printf("  KASLR slide:          %s%+ld%s (%s)\n", c(C_CYAN),
           s->kaslr.vslide, c(C_RESET),
           human_size((unsigned long)(s->kaslr.vslide < 0 ? -s->kaslr.vslide
                                                          : s->kaslr.vslide),
                      hbuf, sizeof(hbuf)));
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
    char hbuf[32];
    printf("  Physical text base:   %s0x%016lx%s\n", c(C_GREEN), s->kaslr.ptext,
           c(C_RESET));
#ifdef KERNEL_PHYS_DEFAULT
    printf("  Default phys base:    0x%016lx\n",
           (unsigned long)KERNEL_PHYS_DEFAULT);
    printf("  Physical KASLR slide: %s%+ld%s (%s)\n", c(C_CYAN),
           s->kaslr.pslide, c(C_RESET),
           human_size((unsigned long)(s->kaslr.pslide < 0 ? -s->kaslr.pslide
                                                          : s->kaslr.pslide),
                      hbuf, sizeof(hbuf)));
    if (s->kaslr.pslots > 0)
      printf("  Physical KASLR entropy: %s%d bits%s (%lu slots of %#lx)\n",
             c(C_MAGENTA), s->kaslr.pbits, c(C_RESET), s->kaslr.pslots,
             (unsigned long)KASLR_PHYS_ALIGN);
    else
      printf("  Physical KASLR entropy: %s0 bits%s (no randomization range)\n",
             c(C_DIM), c(C_RESET));
    printf("\n");
#endif
  }
}

/* -------------------------------------------------------------------------
 * Derived addresses text renderer (consumes pre-computed summary)
 * -------------------------------------------------------------------------
 */
static void render_derived_text(const struct summary *s) {
  if (s->num_derived == 0 && !s->decoupled_note)
    return;

  if (s->num_derived > 0)
    printf("Derived addresses:\n");
  for (int i = 0; i < s->num_derived; i++) {
    const struct derived_addr *d = &s->derived[i];
    if (d->addr_hi) {
      unsigned long slots = layout.kernel_align
                                ? (d->addr_hi - d->addr) / layout.kernel_align
                                : 0;
      printf("  %-24s0x%016lx - 0x%016lx  (~%lu slots, %s)\n", d->label,
             d->addr, d->addr_hi, slots, d->via);
    } else {
      printf("  %-24s0x%016lx  (%s)\n", d->label, d->addr, d->via);
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
  group_range(KASLD_ADDR_VIRT, KASLD_SECTION_TEXT, &vtext_lo, &vtext_hi);
  group_range(KASLD_ADDR_VIRT, KASLD_SECTION_MODULE, &vmod_lo, &vmod_hi);
  group_range(KASLD_ADDR_VIRT, KASLD_SECTION_DIRECTMAP, &vdmap_lo, &vdmap_hi);

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
     there but don't know its true extent.  kernel_vas_end would cause
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

  printf("  0x%016lx\n", layout.kernel_vas_end);

  for (int i = n - 1; i >= 0; i--) {
    struct map_region *r = &regions[i];

    printf("  %s\n", box_top);
    printf("  |  %-62s  |\n", r->label);

    if (r->leak_lo) {
      if (r->leak_hi) {
        printf("  |    0x%016lx  %-40s  |\n", r->leak_hi, "(hi)");
        printf("  |    0x%016lx  %-40s  |\n", r->leak_lo, "(lo)");
      } else {
        printf("  |    0x%016lx%42s  |\n", r->leak_lo, "");
      }
    } else {
      printf("  |  %s%-62s%s  |\n", c(C_DIM), "(no leak)", c(C_RESET));
    }

    printf("  %s\n", box_top);
    printf("  0x%016lx\n", r->start);

    /* Show gap if there's a non-trivial space before the next region */
    if (i > 0 && regions[i - 1].end + 1 < r->start) {
      char hbuf[32];
      unsigned long gap = r->start - regions[i - 1].end - 1;
      printf("  %s\n", box_top);
      printf("  %s|%66s|%s\n", c(C_DIM), "", c(C_RESET));
      printf("  %s|  ...  %-59s|%s\n", c(C_DIM),
             human_size(gap, hbuf, sizeof(hbuf)), c(C_RESET));
      printf("  %s|%66s|%s\n", c(C_DIM), "", c(C_RESET));
    }
  }

  if (n == 0 || regions[0].start != layout.kernel_vas_start)
    printf("  0x%016lx\n", layout.kernel_vas_start);
  printf("\n");

  /* Physical memory map — unified view of all physical leaks */
  unsigned long ptext = group_consensus(KASLD_ADDR_PHYS, KASLD_SECTION_TEXT);

  struct {
    unsigned long addr;
    char label[128];
  } ppts[MAX_RESULTS];
  int nppts = 0;

  if (ptext && nppts < MAX_RESULTS) {
    ppts[nppts].addr = ptext;
    snprintf(ppts[nppts].label, sizeof(ppts[nppts].label), "[text] kernel");
    nppts++;
  }

  for (int i = 0; i < num_results; i++) {
    struct result *r = &results[i];
    if (r->type != KASLD_ADDR_PHYS || !r->valid)
      continue;
    if (strcmp(r->section, KASLD_SECTION_DRAM) != 0 &&
        strcmp(r->section, KASLD_SECTION_MMIO) != 0)
      continue;
    int dup = 0;
    for (int j = 0; j < nppts; j++) {
      if (ppts[j].addr == r->aligned) {
        dup = 1;
        break;
      }
    }
    if (!dup && nppts < MAX_RESULTS) {
      ppts[nppts].addr = r->aligned;
      snprintf(ppts[nppts].label, sizeof(ppts[nppts].label), "[%s] %s",
               r->section, r->label);
      nppts++;
    }
  }

  /* Sort descending by address (top of memory first) */
  for (int i = 0; i < nppts - 1; i++)
    for (int j = i + 1; j < nppts; j++)
      if (ppts[i].addr < ppts[j].addr) {
        unsigned long ta = ppts[i].addr;
        char tl[128];
        memcpy(tl, ppts[i].label, sizeof(tl));
        ppts[i].addr = ppts[j].addr;
        memcpy(ppts[i].label, ppts[j].label, sizeof(tl));
        ppts[j].addr = ta;
        memcpy(ppts[j].label, tl, sizeof(tl));
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
  printf("  %s\n", box_top);
  if (nppts > 0) {
    for (int i = 0; i < nppts; i++) {
      char str[164];
      snprintf(str, sizeof(str), "0x%016lx  %s", ppts[i].addr, ppts[i].label);
      printf("  |  %-62.62s  |\n", str);
    }
  } else {
    printf("  |  %s%-62s%s  |\n", c(C_DIM), "(no leak)", c(C_RESET));
  }
  printf("  %s\n", box_top);
  printf("  0x%016lx\n", (unsigned long)PHYS_OFFSET);

  printf("\n");

  (void)box_sep;
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

static void render_json_group(char gt, const char *gs) {
  const char *display = section_display_name(gt, gs);
  if (!display)
    return;

  unsigned long consensus = group_consensus(gt, gs);
  unsigned long lo, hi;
  group_range(gt, gs, &lo, &hi);

  const char *bm;
  int ns, nc;
  group_consensus_info(gt, gs, &bm, &ns, &nc);

  printf("    {\n");
  printf("      \"type\": \"%c\",\n", gt);
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
    if (results[i].type != gt || strcmp(results[i].section, gs) != 0)
      continue;
    if (!first)
      printf(",\n");
    first = 0;
    printf("        {\n");
    printf("          \"raw\": \"0x%016lx\",\n", results[i].raw);
    printf("          \"aligned\": \"0x%016lx\",\n", results[i].aligned);
    printf("          \"label\": ");
    json_print_escaped(results[i].label);
    printf(",\n");
    printf("          \"method\": ");
    json_print_escaped(results[i].method);
    printf(",\n");
    printf("          \"valid\": %s\n", results[i].valid ? "true" : "false");
    printf("        }");
  }
  printf("\n      ]\n");
  printf("    }");
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
  }

  printf("\n  },\n");

  /* groups — build ordered list of unique (type, section) keys */
  const char *section_order[] = {KASLD_SECTION_TEXT,
                                 KASLD_SECTION_MODULE,
                                 KASLD_SECTION_DIRECTMAP,
                                 KASLD_SECTION_DATA,
                                 KASLD_SECTION_DRAM,
                                 KASLD_SECTION_MMIO,
                                 NULL};
  char type_order[] = {KASLD_ADDR_VIRT, KASLD_ADDR_PHYS, 0};

  struct group_key gkeys[64];
  int ngkeys = 0;

  for (int t = 0; type_order[t]; t++) {
    for (int si = 0; section_order[si]; si++) {
      int has = 0;
      for (int i = 0; i < num_results; i++) {
        if (results[i].type == type_order[t] &&
            strcmp(results[i].section, section_order[si]) == 0 &&
            results[i].valid) {
          has = 1;
          break;
        }
      }
      if (has && ngkeys < 64) {
        gkeys[ngkeys].type = type_order[t];
        strncpy(gkeys[ngkeys].section, section_order[si], SECTION_LEN - 1);
        ngkeys++;
      }
    }
  }

  /* Append any remaining groups not in predefined order */
  for (int i = 0; i < num_results; i++) {
    if (results[i].type == KASLD_ADDR_DEFAULT)
      continue;
    int already = 0;
    for (int j = 0; j < ngkeys; j++) {
      if (gkeys[j].type == results[i].type &&
          strcmp(gkeys[j].section, results[i].section) == 0) {
        already = 1;
        break;
      }
    }
    if (!already && ngkeys < 64) {
      gkeys[ngkeys].type = results[i].type;
      strncpy(gkeys[ngkeys].section, results[i].section, SECTION_LEN - 1);
      ngkeys++;
    }
  }

  printf("  \"groups\": [\n");
  int first_group = 1;
  for (int g = 0; g < ngkeys; g++) {
    if (!section_display_name(gkeys[g].type, gkeys[g].section))
      continue;
    /* Verify group has at least one valid result */
    int has = 0;
    for (int i = 0; i < num_results; i++) {
      if (results[i].type == gkeys[g].type &&
          strcmp(results[i].section, gkeys[g].section) == 0 &&
          results[i].valid) {
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

  /* derived */
  printf("  \"derived\": [\n");
  for (int i = 0; i < s->num_derived; i++) {
    const struct derived_addr *d = &s->derived[i];
    if (i > 0)
      printf(",\n");
    printf("    {\n");
    printf("      \"type\": \"%c\",\n", d->type);
    printf("      \"section\": \"%s\",\n", d->section);
    printf("      \"addr\": \"0x%016lx\"", d->addr);
    if (d->addr_hi)
      printf(",\n      \"addr_hi\": \"0x%016lx\"", d->addr_hi);
    printf(",\n      \"label\": ");
    json_print_escaped(d->label);
    printf(",\n      \"via\": ");
    json_print_escaped(d->via);
    printf("\n    }");
  }

  /* Close derived array — with trailing comma if components follow */
  if (verbose && num_comp_logs > 0) {
    printf("\n  ],\n");

    /* components — only present with --verbose */
    printf("  \"components\": [\n");
    for (int i = 0; i < num_comp_logs; i++) {
      struct component_log *cl = &comp_logs[i];
      if (i > 0)
        printf(",\n");
      printf("    {\n");
      printf("      \"name\": ");
      json_print_escaped(cl->name);
      printf(",\n");
      printf("      \"exit_code\": %d", cl->exit_code);
      if (cl->num_lines > 0) {
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
    printf("\n  ]\n");
  } else {
    printf("\n  ]\n");
  }

  printf("}\n");
}

/* -------------------------------------------------------------------------
 * Text renderer
 * -------------------------------------------------------------------------
 */
static void render_text(const struct summary *s) {
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
      if (results[i].type == KASLD_ADDR_DEFAULT &&
          strcmp(results[i].label, "default:text") != 0)
        printf("  %s\n", results[i].label);
    }
    printf("\n");
    if (s->kaslr.default_addr)
      printf(
          "Likely kernel text base: %s0x%016lx%s (assumes default config)\n\n",
          c(C_GREEN), s->kaslr.default_addr, c(C_RESET));
  }

  /* Print each (type, section) group in a defined order */
  const char *section_order[] = {KASLD_SECTION_TEXT,
                                 KASLD_SECTION_MODULE,
                                 KASLD_SECTION_DIRECTMAP,
                                 KASLD_SECTION_DATA,
                                 KASLD_SECTION_DRAM,
                                 KASLD_SECTION_MMIO,
                                 NULL};
  char type_order[] = {KASLD_ADDR_VIRT, KASLD_ADDR_PHYS, 0};

  if (verbose) {
    /* Verbose: expanded per-address listing */
    for (int t = 0; type_order[t]; t++) {
      for (int si = 0; section_order[si]; si++) {
        if (!group_already_printed(type_order[t], section_order[si])) {
          print_group(type_order[t], section_order[si]);
          mark_group_printed(type_order[t], section_order[si]);
        }
      }
    }

    /* Print any remaining groups not in the predefined order */
    for (int i = 0; i < num_results; i++) {
      struct result *r = &results[i];
      if (r->type == KASLD_ADDR_DEFAULT)
        continue;
      if (!group_already_printed(r->type, r->section)) {
        print_group(r->type, r->section);
        mark_group_printed(r->type, r->section);
      }
    }
  } else {
    /* Compact: one summary line per group */
    char hbuf[32];

    for (int t = 0; type_order[t]; t++) {
      for (int si = 0; section_order[si]; si++) {
        if (group_already_printed(type_order[t], section_order[si]))
          continue;

        const char *name =
            section_display_name(type_order[t], section_order[si]);
        if (!name)
          continue;

        int count = 0;
        for (int i = 0; i < num_results; i++) {
          if (results[i].type == type_order[t] &&
              strcmp(results[i].section, section_order[si]) == 0 &&
              results[i].valid)
            count++;
        }
        if (!count)
          continue;

        unsigned long consensus =
            group_consensus(type_order[t], section_order[si]);
        unsigned long lo, hi;
        group_range(type_order[t], section_order[si], &lo, &hi);

        printf("  %-26s", name);
        if (hi) {
          const char *bm;
          int ns, nc;
          group_consensus_info(type_order[t], section_order[si], &bm, &ns, &nc);
          unsigned long span = hi - lo;
          printf("%s0x%016lx%s  (%s, %d source%s, %d conflict%s, %s)\n",
                 c(C_GREEN), consensus, c(C_RESET),
                 human_size(span, hbuf, sizeof(hbuf)), ns, ns == 1 ? "" : "s",
                 nc, nc == 1 ? "" : "s", bm);
        } else {
          printf("%s0x%016lx%s  (%d source%s)\n", c(C_GREEN), consensus,
                 c(C_RESET), count, count == 1 ? "" : "s");
        }

        mark_group_printed(type_order[t], section_order[si]);
      }
    }

    /* Any remaining groups not in predefined order */
    for (int i = 0; i < num_results; i++) {
      struct result *r = &results[i];
      if (r->type == KASLD_ADDR_DEFAULT)
        continue;
      if (group_already_printed(r->type, r->section))
        continue;

      const char *name = section_display_name(r->type, r->section);
      if (!name)
        continue;

      int count = 0;
      for (int j = 0; j < num_results; j++) {
        if (results[j].type == r->type &&
            strcmp(results[j].section, r->section) == 0 && results[j].valid)
          count++;
      }
      if (!count)
        continue;

      unsigned long consensus = group_consensus(r->type, r->section);
      unsigned long lo, hi;
      group_range(r->type, r->section, &lo, &hi);

      printf("  %-26s", name);
      if (hi) {
        const char *bm;
        int ns, nc;
        group_consensus_info(r->type, r->section, &bm, &ns, &nc);
        unsigned long span = hi - lo;
        printf("%s0x%016lx%s  (%s, %d source%s, %d conflict%s, %s)\n",
               c(C_GREEN), consensus, c(C_RESET),
               human_size(span, hbuf, sizeof(hbuf)), ns, ns == 1 ? "" : "s", nc,
               nc == 1 ? "" : "s", bm);
      } else {
        printf("%s0x%016lx%s  (%d source%s)\n", c(C_GREEN), consensus,
               c(C_RESET), count, count == 1 ? "" : "s");
      }

      mark_group_printed(r->type, r->section);
    }
    printf("\n");
  }

  render_kaslr_text(s);
  render_derived_text(s);
  printf("%s%s%s\n", c(C_DIM), "----------------------------------------",
         c(C_RESET));
  print_memory_map();
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
  unsigned long vtext = group_consensus(KASLD_ADDR_VIRT, KASLD_SECTION_TEXT);
  if (vtext)
    printf(" text=0x%lx", vtext);

  /* Physical text consensus */
  unsigned long ptext = group_consensus(KASLD_ADDR_PHYS, KASLD_SECTION_TEXT);
  if (ptext)
    printf(" ptext=0x%lx", ptext);

  /* KASLR slide */
  if (s->kaslr.vtext) {
    char hbuf[32];
    printf(" slide=%+ld(%s)", s->kaslr.vslide,
           human_size((unsigned long)(s->kaslr.vslide < 0 ? -s->kaslr.vslide
                                                          : s->kaslr.vslide),
                      hbuf, sizeof(hbuf)));
  }

  /* Entropy */
  if (s->kaslr.vtext && s->kaslr.vbits > 0)
    printf(" entropy=%dbits", s->kaslr.vbits);

  /* Direct map */
  unsigned long vdmap =
      group_consensus(KASLD_ADDR_VIRT, KASLD_SECTION_DIRECTMAP);
  if (vdmap)
    printf(" dmap=0x%lx", vdmap);

  /* Physical DRAM range */
  unsigned long pdram_lo, pdram_hi;
  group_range(KASLD_ADDR_PHYS, KASLD_SECTION_DRAM, &pdram_lo, &pdram_hi);
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
      char hbuf[32];
      printf("| Virtual text base | `0x%016lx` |\n", s->kaslr.vtext);
      printf("| Default text base | `0x%016lx` |\n",
             layout.kernel_text_default);
      printf("| KASLR slide | %+ld (%s) |\n", s->kaslr.vslide,
             human_size((unsigned long)(s->kaslr.vslide < 0 ? -s->kaslr.vslide
                                                            : s->kaslr.vslide),
                        hbuf, sizeof(hbuf)));
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
  const char *section_order[] = {KASLD_SECTION_TEXT,
                                 KASLD_SECTION_MODULE,
                                 KASLD_SECTION_DIRECTMAP,
                                 KASLD_SECTION_DATA,
                                 KASLD_SECTION_DRAM,
                                 KASLD_SECTION_MMIO,
                                 NULL};
  char type_order[] = {KASLD_ADDR_PHYS, KASLD_ADDR_VIRT, 0};

  printf("## Leak Results\n\n");

  if (verbose) {
    /* Verbose: individual result rows */
    printf("| Type | Section | Address | Label | Method |\n");
    printf("|:-----|:--------|:--------|:------|:-------|\n");

    for (int t = 0; type_order[t]; t++) {
      for (int si = 0; section_order[si]; si++) {
        int idx[MAX_RESULTS];
        int nidx = 0;
        for (int i = 0; i < num_results; i++) {
          struct result *r = &results[i];
          if (r->type != type_order[t] ||
              strcmp(r->section, section_order[si]) != 0)
            continue;
          if (r->type == KASLD_ADDR_DEFAULT)
            continue;
          idx[nidx++] = i;
        }
        for (int a = 0; a < nidx - 1; a++)
          for (int b = a + 1; b < nidx; b++)
            if (results[idx[a]].aligned > results[idx[b]].aligned) {
              int tmp = idx[a];
              idx[a] = idx[b];
              idx[b] = tmp;
            }
        for (int k = 0; k < nidx; k++) {
          struct result *r = &results[idx[k]];
          printf("| %c | %s | `0x%016lx` | %s | %s%s |\n", r->type, r->section,
                 r->valid ? r->aligned : r->raw, r->label, r->method,
                 r->valid ? "" : " (invalid)");
        }
      }
    }

    /* Any remaining sections */
    for (int i = 0; i < num_results; i++) {
      struct result *r = &results[i];
      if (r->type == KASLD_ADDR_DEFAULT)
        continue;
      int in_order = 0;
      for (int si = 0; section_order[si]; si++) {
        if (strcmp(r->section, section_order[si]) == 0) {
          in_order = 1;
          break;
        }
      }
      if (!in_order) {
        printf("| %c | %s | `0x%016lx` | %s | %s%s |\n", r->type, r->section,
               r->valid ? r->aligned : r->raw, r->label, r->method,
               r->valid ? "" : " (invalid)");
      }
    }
  } else {
    /* Compact: one summary row per group */
    char hbuf[32];
    printf("| Section | Address | Sources |\n");
    printf("|:--------|:--------|--------:|\n");

    for (int t = 0; type_order[t]; t++) {
      for (int si = 0; section_order[si]; si++) {
        const char *name =
            section_display_name(type_order[t], section_order[si]);
        if (!name)
          continue;
        int count = 0;
        for (int i = 0; i < num_results; i++) {
          if (results[i].type == type_order[t] &&
              strcmp(results[i].section, section_order[si]) == 0 &&
              results[i].valid)
            count++;
        }
        if (!count)
          continue;

        unsigned long consensus =
            group_consensus(type_order[t], section_order[si]);
        unsigned long lo, hi;
        group_range(type_order[t], section_order[si], &lo, &hi);

        if (hi) {
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
      if (r->type == KASLD_ADDR_DEFAULT)
        continue;
      const char *name = section_display_name(r->type, r->section);
      if (!name)
        continue;

      /* Check if already covered by predefined order */
      int in_order = 0;
      for (int si = 0; section_order[si]; si++) {
        if (strcmp(r->section, section_order[si]) == 0) {
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
            strcmp(results[j].section, r->section) == 0) {
          already = 1;
          break;
        }
      }
      if (already)
        continue;

      int count = 0;
      for (int j = 0; j < num_results; j++) {
        if (results[j].type == r->type &&
            strcmp(results[j].section, r->section) == 0 && results[j].valid)
          count++;
      }
      if (!count)
        continue;

      unsigned long consensus = group_consensus(r->type, r->section);
      unsigned long lo, hi;
      group_range(r->type, r->section, &lo, &hi);

      if (hi) {
        unsigned long span = hi - lo;
        printf("| %s | `0x%016lx` - `0x%016lx` (%s) | %d |\n", name, lo, hi,
               human_size(span, hbuf, sizeof(hbuf)), count);
      } else {
        printf("| %s | `0x%016lx` | %d |\n", name, consensus, count);
      }
    }
  }

  printf("\n");

  /* Derived addresses */
  if (s->num_derived > 0) {
    printf("## Derived Addresses\n\n");
    printf("| Address | Label | Via |\n");
    printf("|:--------|:------|:----|\n");
    for (int i = 0; i < s->num_derived; i++) {
      const struct derived_addr *d = &s->derived[i];
      if (d->addr_hi)
        printf("| `0x%016lx` - `0x%016lx` | %s | %s |\n", d->addr, d->addr_hi,
               d->label, d->via);
      else
        printf("| `0x%016lx` | %s | %s |\n", d->addr, d->label, d->via);
    }
    printf("\n");
  }
}

/* -------------------------------------------------------------------------
 * Summary orchestrator: compute, then dispatch to renderer
 * -------------------------------------------------------------------------
 */
void print_summary(void) {
  struct summary s = {0};

  inject_kaslr_defaults(&s);
  compute_kaslr_info(&s);
  compute_derived_addrs(&s);

  if (json_output)
    render_json(&s);
  else if (oneline_output)
    render_oneline(&s);
  else if (markdown_output)
    render_markdown(&s);
  else
    render_text(&s);
}
