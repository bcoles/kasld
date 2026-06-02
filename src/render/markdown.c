// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Markdown table renderer (--markdown). Compact in default mode; per-row
// listing under --verbose.
//
// Cross-file helpers (section_consensus, section_range, section_display_name,
// human_size, count_derived) are declared in include/kasld/render_internal.h
// and defined in render.c.
// ---
// <bcoles@gmail.com>

#include "include/kasld/internal.h"
#include "include/kasld/render_internal.h"

#include <stdio.h>
#include <string.h>
#include <sys/utsname.h>

void render_markdown(const struct summary *s) {
  struct utsname u;
  int have_uname = (kasld_uname(&u) == 0);

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
            section_consensus(type_order[t], section_order[si], REGION_UNKNOWN);
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

      unsigned long consensus = section_consensus(r->type, sec, REGION_UNKNOWN);
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
}
