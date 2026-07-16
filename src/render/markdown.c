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

/* Print a string as a markdown table-cell body. Escapes the column separator
 * '|' (and a preceding '\' so it cannot escape our escape) so a wire-supplied
 * name — length-checked but not character-validated on the way in — cannot
 * break the table layout. A control byte (which a whitespace-tokenised wire
 * field should never carry) collapses to a space. */
static void md_print_cell(const char *s) {
  for (; *s; s++) {
    unsigned char c = (unsigned char)*s;
    if (c < 0x20) {
      putchar(' ');
    } else {
      if (c == '\\' || c == '|')
        putchar('\\');
      putchar((char)c);
    }
  }
}

/* Print the unique contributing component origins for a (type, section) group,
 * comma-separated — the same source attribution the text readout shows inline
 * (e.g. "(perf_event_open, prefetch)"), so the compact markdown table credits
 * which techniques produced each leak rather than just counting them. */
static void print_group_sources(enum kasld_addr_type type,
                                const char *section) {
  const char *seen[64];
  int nseen = 0;
  for (int i = 0; i < num_results; i++) {
    struct result *r = &results[i];
    if (r->type != type || strcmp(result_section(r), section) != 0 ||
        !in_bounds(r))
      continue;
    for (int j = 0; j < r->provenance_count; j++) {
      int dup = 0;
      for (int sd = 0; sd < nseen; sd++)
        if (strcmp(seen[sd], r->origins[j]) == 0) {
          dup = 1;
          break;
        }
      if (!dup && nseen < 64)
        seen[nseen++] = r->origins[j];
    }
  }
  for (int sd = 0; sd < nseen; sd++) {
    if (sd)
      printf(", ");
    md_print_cell(seen[sd]);
  }
  if (!nseen)
    printf("-");
}

/* One Memory KASLR (CONFIG_RANDOMIZE_MEMORY) region-bound row. Mirrors the
 * text renderer's render_memory_kaslr_bound cases (skip / >= / <= / pinned /
 * range); the residual-candidate annotation is text-only (it needs the
 * arch-specific RANDOMIZE_MEMORY_ALIGN, which the table omits for brevity). */
static void md_memory_kaslr_row(const char *name, unsigned long min,
                                unsigned long max, unsigned long lmin,
                                unsigned long lmax) {
  if (!min && !max)
    return;
  if (min && max && min > max)
    return; /* defensive: never emit a backwards range */
  if (min && !max)
    printf("| %s | >= `0x%016lx` |\n", name, min);
  else if (!min && max)
    printf("| %s | <= `0x%016lx` |\n", name, max);
  else if (min == max)
    printf("| %s | `0x%016lx` (pinned) |\n", name, min);
  else
    printf("| %s | `0x%016lx` - `0x%016lx` |\n", name, min, max);
  /* Speculative sub-window from the all-signals snapshot (subset of the row
   * above; may be wrong). Absent unless a sub-floor signal narrowed it. */
  if (lmin == lmax && lmin)
    printf("| %s (likely) | `0x%016lx` (speculative) |\n", name, lmin);
  else if (lmax && lmin <= lmax)
    printf("| %s (likely) | `0x%016lx` - `0x%016lx` (speculative) |\n", name,
           lmin, lmax);
}

/* Environment / recon vantage — same gather + confined-gating as the text
 * block: the confinement rows appear only when actually confined (otherwise the
 * values are unprivileged defaults, not restrictions). Oracle readability
 * always shown, as it is the core recon context of a report. */
static void render_environment_markdown(void) {
  struct kasld_vantage v;
  kasld_gather_vantage(&v);

  printf("## Environment\n\n");
  printf("| Property | Value |\n");
  printf("|:---------|:------|\n");
  printf("| Container | %s |\n", v.container ? v.container : "none");
  if (kasld_vantage_confined(&v)) {
    if (v.seccomp >= 0)
      printf("| Seccomp | %s |\n", kasld_vantage_seccomp_str(v.seccomp));
    char capbuf[24];
    const char *caps = kasld_vantage_caps(&v, capbuf, sizeof(capbuf));
    if (caps)
      printf("| Effective capabilities | %s |\n", caps);
    if (v.no_new_privs >= 0)
      printf("| No new privileges | %s |\n", v.no_new_privs ? "yes" : "no");
  }
  printf("\n");

  printf("Readable leak oracles:\n\n");
  printf("| Source | Readable |\n");
  printf("|:-------|:---------|\n");
  for (int i = 0; i < KASLD_N_ORACLES; i++)
    printf("| `%s` | %s |\n", kasld_oracle_paths[i],
           v.oracle_readable[i] ? "yes" : "no");
  printf("\n");

  /* Cap-gated leaks the effective cap set unlocks (if any). */
  int shown = 0;
  for (int i = 0; v.have_caps && i < KASLD_N_CAP_LEAKS; i++) {
    if (!((v.cap_eff >> kasld_cap_leaks[i].bit) & 1ull))
      continue;
    if (!shown) {
      printf("Capability-reachable leaks:\n\n");
      shown = 1;
    }
    printf("- `%s` \xe2\x86\x92 %s\n", kasld_cap_leaks[i].cap,
           kasld_cap_leaks[i].source);
  }
  if (shown)
    printf("\n");
}

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

  /* KASLR analysis. Mirrors render_kaslr_text: shown only when there is a
   * concrete base, a narrowed text range, or a Memory-KASLR bound — and never
   * when KASLR is disabled/unsupported (covered by the banner above). */
  int mem_kaslr = summary_has_memory_kaslr(s);
  if (!s->kaslr.disabled && !s->kaslr.unsupported &&
      (s->kaslr.vtext || s->kaslr.has_phys || s->kaslr.vslots > 0 ||
       s->kaslr.pslots > 0 || mem_kaslr)) {
    printf("## KASLR Analysis\n\n");
    printf("| Metric | Value |\n");
    printf("|:-------|:------|\n");

    /* A concrete base while the guaranteed window is still a range = the base
     * came from a sub-sound-floor leak: speculative, not proven. Show the
     * guaranteed (inferred) range too, and mark the base speculative. */
    int v_spec = s->kaslr.vtext && kaslr_virt_is_window();
    int p_spec = s->kaslr.has_phys && kaslr_phys_is_window();

    if ((v_spec || !s->kaslr.vtext) && s->kaslr.vslots > 0) {
      printf("| Inferred text range | `0x%016lx` - `0x%016lx` |\n",
             layout.virt_kaslr_text_min, layout.virt_kaslr_text_max);
      printf("| Remaining slots | %lu (%d bits) |\n", s->kaslr.vslots,
             s->kaslr.vbits);
    }
    if ((p_spec || !s->kaslr.ptext) && s->kaslr.pslots > 0) {
      printf("| Inferred phys text range | `0x%016lx` - `0x%016lx` |\n",
             layout.phys_kaslr_text_min, layout.phys_kaslr_text_max);
      printf("| Remaining phys slots | %lu (%d bits) |\n", s->kaslr.pslots,
             s->kaslr.pbits);
    }

    if (s->kaslr.vtext) {
      long abs_vs = s->kaslr.vslide < 0 ? -s->kaslr.vslide : s->kaslr.vslide;
      printf("| Virtual image base | `0x%016lx`%s |\n", s->kaslr.vtext,
             v_spec ? " likely (speculative)" : "");
      if (s->kaslr.vstext && s->kaslr.vstext != s->kaslr.vtext)
        printf("| Virtual _stext | `0x%016lx` |\n", s->kaslr.vstext);
      printf("| Default image base | `0x%016lx` |\n",
             layout.virt_image_base_default);
      printf("| KASLR slide | %s0x%lx (%ld)%s |\n",
             s->kaslr.vslide < 0 ? "-" : "+", (unsigned long)abs_vs,
             s->kaslr.vslide, v_spec ? " (likely)" : "");
      printf("| Virtual entropy | %d bits (%lu slots) |\n", s->kaslr.vbits,
             s->kaslr.vslots);
      if (s->kaslr.vslot_valid)
        printf("| Observed slot | %lu / %lu |\n", s->kaslr.vslot_idx,
               s->kaslr.vslots);
    }
    if (s->kaslr.has_phys) {
      printf("| Physical image base | `0x%016lx`%s |\n", s->kaslr.ptext,
             p_spec ? " likely (speculative)" : "");
      if (s->kaslr.pstext && s->kaslr.pstext != s->kaslr.ptext)
        printf("| Physical _stext | `0x%016lx` |\n", s->kaslr.pstext);
      printf("| Physical entropy | %d bits (%lu slots) |\n", s->kaslr.pbits,
             s->kaslr.pslots);
    }

    /* Memory KASLR (CONFIG_RANDOMIZE_MEMORY) region bounds. */
    md_memory_kaslr_row("Direct map base", s->kaslr.virt_page_offset_min,
                        s->kaslr.virt_page_offset_max,
                        s->kaslr.virt_page_offset_likely_min,
                        s->kaslr.virt_page_offset_likely_max);
    md_memory_kaslr_row(
        "vmalloc base", s->kaslr.virt_vmalloc_min, s->kaslr.virt_vmalloc_max,
        s->kaslr.virt_vmalloc_likely_min, s->kaslr.virt_vmalloc_likely_max);
    md_memory_kaslr_row(
        "vmemmap base", s->kaslr.virt_vmemmap_min, s->kaslr.virt_vmemmap_max,
        s->kaslr.virt_vmemmap_likely_min, s->kaslr.virt_vmemmap_likely_max);

    printf("\n");
  }

  /* Result groups */
  const char *const *section_order = kasld_render_sections;
  enum kasld_addr_type type_order[] = {KASLD_TYPE_PHYS, KASLD_TYPE_VIRT,
                                       KASLD_TYPE_UNKNOWN};

  printf("## Leak Results\n\n");

  if (verbose) {
    /* Verbose: individual result rows */
    printf("| Type | Section | Address | Pos | Region | Name | Origin | Method "
           "|\n");
    printf("|:-----|:--------|:--------|:----|:-------|:-----|:-------|:-------"
           "|\n");

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
          printf("| %c | %s | `0x%016lx` | %s | %s | ",
                 kasld_type_wire(r->type), result_section(r), a,
                 kasld_pos_wire(r->pos), kasld_region_wire(r->region));
          md_print_cell(r->name);
          printf(" | ");
          for (int j = 0; j < r->provenance_count; j++) {
            if (j)
              printf(", ");
            md_print_cell(r->origins[j]);
          }
          printf(" | %s%s |\n", result_method(r),
                 in_bounds(r) ? "" : " (stale)");
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
        printf("| %c | %s | `0x%016lx` | %s | %s | ", kasld_type_wire(r->type),
               sec, a, kasld_pos_wire(r->pos), kasld_region_wire(r->region));
        for (int j = 0; j < r->provenance_count; j++) {
          if (j)
            printf(", ");
          md_print_cell(r->origins[j]);
        }
        printf(" | %s%s |\n", result_method(r), in_bounds(r) ? "" : " (stale)");
      }
    }
  } else {
    /* Compact: one summary row per group */
    char hbuf[32];
    printf("| Section | Address | Sources |\n");
    printf("|:--------|:--------|:--------|\n");

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
          printf("| %s | `0x%016lx` - `0x%016lx` (%s) | ", name, lo, hi,
                 human_size(span, hbuf, sizeof(hbuf)));
        } else {
          printf("| %s | `0x%016lx` | ", name, consensus);
        }
        print_group_sources(type_order[t], section_order[si]);
        printf(" |\n");
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
        printf("| %s | `0x%016lx` - `0x%016lx` (%s) | ", name, lo, hi,
               human_size(span, hbuf, sizeof(hbuf)));
      } else {
        printf("| %s | `0x%016lx` | ", name, consensus);
      }
      print_group_sources(r->type, sec);
      printf(" |\n");
    }
  }

  printf("\n");

  /* Derived addresses (records with conf == CONF_DERIVED) */
  int n_derived = count_derived();
  if (n_derived > 0) {
    printf("## Derived Addresses\n\n");
    printf("| Address | Pos | Label | Via |\n");
    printf("|:--------|:----|:------|:----|\n");
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
        printf("| `0x%016lx` - `0x%016lx` | %s | %s | %s |\n", r->lo, r->hi,
               kasld_pos_wire(r->pos), label, result_method(r));
      else
        printf("| `0x%016lx` | %s | %s | %s |\n", anchor_addr(r),
               kasld_pos_wire(r->pos), label, result_method(r));
    }
    printf("\n");
  }

  render_environment_markdown();

  /* Hardening assessment (-H): same model as the text/json renderers. */
  if (hardening_mode)
    render_hardening_markdown();
}
