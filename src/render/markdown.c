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
#include "include/kasld/report.h"

#include <stdio.h>
#include <string.h>
#include <sys/utsname.h>

/* Print a string as a markdown table-cell body. Escapes the column separator
 * '|' (and a preceding '\' so it cannot escape the escape) so a wire-supplied
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
  struct origin_set seen;
  memset(&seen, 0, sizeof(seen));
  for (int i = 0; i < num_results; i++) {
    struct result *r = &results[i];
    if (r->type != type || strcmp(result_section(r), section) != 0 ||
        !in_bounds(r))
      continue;
    origin_set_union(&seen, &r->origins);
  }
  int nseen = origin_set_count(&seen);
  for (int slot = origin_set_next(&seen, 0), sd = 0; slot >= 0;
       slot = origin_set_next(&seen, slot + 1), sd++) {
    if (sd)
      printf(", ");
    md_print_cell(kasld_origin_name(slot));
  }
  if (!nseen)
    printf("-");
}

/* The "no slide" image-base report, shared by the KASLR-unsupported and
 * KASLR-disabled branches. Both answer the same question with the same
 * evidence, and both answer it from the ENGINE: the compile-time default is a
 * build-time constant that a differently-configured kernel does not honour, so
 * it is never the reported base.
 *
 * The base carries no qualifier. The banner above the block already states the
 * posture, and a pin that happens to land on the compile-time default is still
 * an engine pin -- naming it after the default would describe a coincidence as
 * a provenance. An edge the engine never resolved is reported as the one-sided
 * bound it is, rather than as a range starting at 0. */
/* One quantity's excluded interior ranges, as a list under the table. */
static void md_excluded(const char *label,
                        const struct kasld_report_quantity *it) {
  const struct kasld_report_window *w;
  if (!it || it->guaranteed.n_excluded <= 0)
    return;
  w = &it->guaranteed;
  printf("\n%s excludes %d range%s%s:\n\n", label, w->n_excluded,
         w->n_excluded == 1 ? "" : "s",
         w->excluded_listed < w->n_excluded ? " (first few)" : "");
  for (int i = 0; i < w->excluded_listed; i++)
    printf("- `0x%016lx` - `0x%016lx`\n", w->excluded[i].lo, w->excluded[i].hi);
}

/* The compile-time default, judged against the resolved window, for the
 * postures where nothing randomized the image. The window itself is reported by
 * the same Layout table every other posture carries; this adds only whether the
 * build's own default is still a candidate, and it is never the answer -- the
 * default is a constant of THIS build, which a differently configured kernel
 * does not honour. Judged on the first resolved quantity, the image base, the
 * only one carrying a compile-time default at all. */
static void md_default_remark(const struct summary *s) {
  char ab[40], rb[160];
  const char *rem;
  for (int i = 0; i < n_layout_rows; i++) {
    const struct layout_row *r = &layout_rows[i];
    /* A set row carries no window, so there is nothing for the default to be
     * judged against; its zeroed edges are not bounds. */
    if (r->dim || r->is_set || strcmp(r->cell[1], GRADE_GUARANTEED) != 0)
      continue;
    snprintf(ab, sizeof(ab), "`0x%lx`", s->kaslr.default_addr);
    rem = default_base_remark(s->kaslr.default_addr, r->lo, r->hi, ab, rb,
                              sizeof(rb));
    if (rem)
      printf("%s\n\n", rem);
    return;
  }
}

/* Environment / recon vantage — same gather + confined-gating as the text
 * block: the confinement rows appear only when actually confined (otherwise the
 * values are unprivileged defaults, not restrictions). Oracle readability
 * always shown, as it is the core recon context of a report. */
static void render_environment_markdown(void) {
  const struct kasld_vantage *v = &kasld_env.vantage;

  printf("## Environment\n\n");
  printf("| Property | Value |\n");
  printf("|:---------|:------|\n");
  printf("| Container | %s |\n", v->container ? v->container : "none");
  char lsmbuf[224];
  printf("| LSM | %s |\n", kasld_vantage_lsm_str(v, lsmbuf, sizeof(lsmbuf)));
  if (v->sec_context[0])
    printf("| Security context | %s |\n", v->sec_context);
  if (!v->have_ids)
    printf("| Identity | unknown |\n");
  else if (v->uid != v->euid || v->gid != v->egid)
    printf("| Identity | uid=%lu gid=%lu (euid=%lu egid=%lu) |\n", v->uid,
           v->gid, v->euid, v->egid);
  else
    printf("| Identity | uid=%lu gid=%lu |\n", v->uid, v->gid);
  if (v->ngroups > 0) {
    printf("| Supplementary groups | ");
    for (int i = 0; i < v->ngroups; i++) {
      const char *nm = kasld_group_name(v, i);
      if (nm)
        printf("%s%lu(%s)", i ? "," : "", v->groups[i], nm);
      else
        printf("%s%lu", i ? "," : "", v->groups[i]);
    }
    printf("%s |\n", v->groups_truncated ? ",..." : "");
  }
  if (kasld_vantage_confined(v)) {
    if (v->seccomp >= 0)
      printf("| Seccomp | %s |\n", kasld_vantage_seccomp_str(v->seccomp));
    char capbuf[24];
    const char *caps = kasld_vantage_caps(v, capbuf, sizeof(capbuf));
    if (caps)
      printf("| Effective capabilities | %s |\n", caps);
    if (v->no_new_privs >= 0)
      printf("| No new privileges | %s |\n", v->no_new_privs ? "yes" : "no");
  }
  printf("\n");

  printf("Readable leak oracles:\n\n");
  printf("| Source | Readable |\n");
  printf("|:-------|:---------|\n");
  for (int i = 0; i < KASLD_N_ORACLES; i++)
    printf("| `%s` | %s |\n", v->oracle_path[i],
           v->oracle_readable[i] ? "yes" : "no");
  printf("\n");

  /* Cap-gated leaks the effective cap set unlocks (if any). */
  int shown = 0;
  for (int i = 0; v->have_caps && i < KASLD_N_CAP_LEAKS; i++) {
    if (!((v->cap_eff >> kasld_cap_leaks[i].bit) & 1ull))
      continue;
    if (!shown) {
      printf("Capability-reachable leaks:\n\n");
      shown = 1;
    }
    printf("- `%s` %s %s\n", kasld_cap_leaks[i].cap, GLYPH_ARROW,
           kasld_cap_leaks[i].source);
  }
  if (shown)
    printf("\n");
}

void render_markdown(const struct summary *s) {
  struct utsname u = kasld_env.uts;
  int have_uname = kasld_env.have_uts;
  const struct kasld_report *rep = render_report();

  /* Header info */
  printf("# KASLD Results\n\n");
  if (have_uname)
    printf("**Kernel:** %s (%s%s%s)%s\n\n", u.release, u.machine,
           u.version[0] ? ", " : "", u.version,
           (rep && rep->replay) ? " — *replayed capture*" : "");

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
    if (s->stats.crashed)
      printf(", %d crashed", s->stats.crashed);
    if (s->stats.no_result)
      printf(", %d no result", s->stats.no_result);
    printf("*\n\n");
  }

  /* KASLR unsupported / disabled: no slide, so the kernel base IS the answer —
   * carry it here (the KASLR Analysis table below is skipped in these cases),
   * mirroring the text readout's single kernel-image-base line. */
  /* Built before the posture branches for the same reason the text readout
   * does it: the row model decides which quantities a format presents, and a
   * branch that returns before building it decides again for itself. */
  layout_build();

  if (s->kaslr.unsupported) {
    printf("> **KASLR is not supported on this architecture**\n\n");
  } else if (s->kaslr.disabled) {
    printf("> **KASLR is disabled** (nokaslr / RANDOMIZE_BASE=n / "
           "hibernation)\n\n");
  } else if (s->kaslr.randomization_failed) {
    /* The stub relocated the image with no randomness: neither randomized nor
     * at the link-time default, so no static base line follows — the KASLR
     * Analysis table below carries the engine's windows, which are the answer.
     * Stated so the report is not silent about a posture only -1 and -H would
     * otherwise reveal. */
    printf("> **KASLR randomization did not run** (no seed / no PRNG)\n\n");
    printf("The boot stub still placed the image, so it is not at the "
           "compile-time default.\n\n");
  }

  /* KASLR analysis. Mirrors render_kaslr_text: shown only when there is a
   * concrete base, a narrowed text range, or a Memory-KASLR bound — and never
   * when KASLR is disabled/unsupported (covered by the banner above). */
  /* Drawn in every posture: the row model decides which quantities a format
   * presents, and a posture excluded from the table ends up presenting its own
   * selection instead -- which dropped the likely grade, so a kernel with KASLR
   * off reported the proven window and never the resolved base.
   *
   * The model, not the summary's slot counts, decides whether there is a table
   * at all: a disabled kernel randomized nothing and so has no slots to count,
   * while its rows carry a resolved window. */
  if (layout_has_resolved()) {
    printf("## Layout\n\n");
    /* The same five columns as the text readout, from the same rows: a
     * representation difference between the two views is fine, a difference in
     * what they say is the bug this layer has had corrected twice. */
    layout_build();
    printf("|");
    for (int col = 0; col < LAYOUT_COLS; col++)
      printf(" %s |", layout_hdr[col]);
    printf("\n|:---------|:------|:------|-----------:|:------|\n");
    for (int i = 0; i < n_layout_rows; i++) {
      /* Only the addresses take a code span; the counts and the grid pitch
       * are prose. */
      printf("| %s | %s | `%s` | %s | %s |\n", layout_rows[i].cell[0],
             layout_rows[i].cell[1], layout_rows[i].cell[2],
             layout_rows[i].cell[3], layout_rows[i].cell[4]);
    }
    printf("\n");

    /* Rows the five columns cannot carry: a second address for the same
     * quantity, and which slot the resolved base occupies. */
    printf("| Metric | Value |\n");
    printf("|:-------|:------|\n");
    {
      const struct kasld_report_quantity *iv =
          kasld_report_find(rep, Q_VIRT_IMAGE_BASE);
      const struct kasld_report_quantity *ip =
          kasld_report_find(rep, Q_PHYS_IMAGE_BASE);
      if (iv && iv->has_stext)
        printf("| Virtual _stext | `0x%016lx` |\n", iv->stext);
      if (ip && ip->has_stext)
        printf("| Physical _stext | `0x%016lx` |\n", ip->stext);
      /* Stated beside a resolved base, which is what it is a remark on: with
       * the base unresolved the table above already shows the window the
       * default is judged against. */
      if (iv && iv->has_point)
        printf("| Compile-time default | `0x%016lx` |\n",
               layout.virt_image_base_default);

      /* The sub-ranges carved out of each window's interior.
       *
       * The Window column above draws the convex HULL, and the count beside it
       * already excludes these -- so the two disagree by exactly this much, and
       * naming the ranges is what makes the count actionable: a reader working
       * through the hull would spend effort on placements the engine ruled out.
       * A document has room to list them, so it lists them. */
      md_excluded("Virtual image base", iv);
      md_excluded("Physical image base", ip);
      md_excluded("Direct map base", kasld_report_find(rep, Q_PAGE_OFFSET));
    }

    /* Phys/virt coupling — the static classification the text readout carries,
     * so a markdown report states whether a physical leak reveals the virtual
     * text base or the two randomize independently. Its job is to relate the
     * physical and virtual bases, and a physical image base row is always
     * present, so there is always something to relate to.
     *
     * Gated to the postures where it describes the run, as the text readout
     * gates it: it says the two bases randomize independently, which on a
     * kernel that randomized neither reads as a claim about behaviour that did
     * not occur. */
    if (!s->kaslr.disabled && !s->kaslr.unsupported)
      printf("| Phys/Virt coupling | %s |\n", kasld_coupling_descr());

    printf("\n");
    /* Below the table, matching the text readout: the remark judges the
     * build's default against the window the table has just reported. */
    if (s->kaslr.disabled || s->kaslr.unsupported)
      md_default_remark(s);
  }

  /* Non-canonical kernel-text function order caution — the table analogue of
   * the text readout's headline warning (shown outside -H; the -H Function
   * layout section carries the full detail). A reordered layout means a leaked
   * address no longer generalises through a generic System.map. */
  {
    enum kasld_text_order to = resolve_text_order(NULL);
    if (to == TEXT_ORDER_DYNAMIC)
      printf("> **Caution:** kernel-text function order is per-boot randomized "
             "- a leak pins only that symbol; no static `System.map` resolves "
             "the rest (see `-H`).\n\n");
    else if (to == TEXT_ORDER_STATIC)
      printf("> **Caution:** non-canonical kernel-text function order - use "
             "this build's exact `System.map`, not a generic one (see "
             "`-H`).\n\n");
  }

  /* Memory-layout maps (verbose): the same virtual + physical ASCII
   * address-space diagrams the text readout draws, embedded in a fenced code
   * block so the monospaced alignment survives markdown rendering. Color is
   * forced off around the call so no ANSI escape leaks into the block (markdown
   * never colors, but -m -c would otherwise reach the shared c() macro). */
  if (verbose || map_mode) {
    int saved_color = color_output; /* declared in internal.h */
    color_output = 0;
    printf("## Address space\n\n```\n");
    print_memory_map();
    printf("```\n\n");
    color_output = saved_color;
  }

  /* Component dispositions (verbose): why each component that reported one
   * produced no tagged result. The mitigation posture is in the hardening
   * report; this is the full per-component list for the deep-dive reader. The
   * answer-first default output omits it (see the text renderer). */
  if (verbose) {
    int shown = 0;
    for (int i = 0; i < num_components; i++) {
      if (!comp_logs[i].ran)
        continue;
      const struct component_disposition *d = &comp_logs[i].disposition;
      if (d->category == DISP_NONE)
        continue;
      if (!shown) {
        printf("## Component dispositions\n\n");
        shown = 1;
      }
      if (d->category == DISP_MITIGATION)
        printf("- **%s** - %s", d->gate, comp_logs[i].name);
      else
        printf("- *%s* - %s", kasld_disp_wire(d->category), comp_logs[i].name);
      if (d->message[0])
        printf(" (%s)", d->message);
      printf("\n");
    }
    if (shown)
      printf("\n");
  }

  /* Result groups */
  const char *const *section_order = kasld_render_sections;
  enum kasld_addr_type type_order[] = {KASLD_TYPE_PHYS, KASLD_TYPE_VIRT,
                                       KASLD_TYPE_UNKNOWN};

  /* "Evidence", matching the text readout: the block carries side-channel
   * measurements alongside actual disclosures, and only the latter are leaks.
   */
  printf("## Evidence\n\n");

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
          for (int j = origin_set_next(&r->origins, 0), oi = 0; j >= 0;
               j = origin_set_next(&r->origins, j + 1), oi++) {
            if (oi)
              printf(", ");
            md_print_cell(kasld_origin_name(j));
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
        for (int j = origin_set_next(&r->origins, 0), oi = 0; j >= 0;
             j = origin_set_next(&r->origins, j + 1), oi++) {
          if (oi)
            printf(", ");
          md_print_cell(kasld_origin_name(j));
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

        /* What kind of address a group resolves to. A group carrying an edge
         * resolves to its consensus base: spanning it against the interior
         * samples beside it would answer about the region's extent under a
         * heading that answers about its position, and would print a resolved
         * base as the low end of a range the engine never resolved. Only a
         * group with no edge to name has an extent instead of a base.
         *
         * dram and mmio are the exception, and not an interior-only one: they
         * are multi-segment coverings where every segment carries its own base,
         * so the covering IS the answer and a single address would misreport
         * it. Same rule the json group objects use. */
        int interior_only = section_is_interior_only(
            type_order[t], section_order[si], REGION_UNKNOWN);
        int covering = strcmp(section_order[si], "dram") == 0 ||
                       strcmp(section_order[si], "mmio") == 0;
        unsigned long lo, hi;
        section_range(type_order[t], section_order[si], REGION_UNKNOWN, &lo,
                      &hi);

        unsigned long edge = 0;
        int has_edge = !covering && !interior_only &&
                       section_edge_addr(type_order[t], section_order[si],
                                         REGION_UNKNOWN, &edge);
        if (has_edge)
          printf("| %s | `0x%016lx` | ", name, edge);
        else if (hi && hi != lo)
          printf("| %s | `0x%016lx` - `0x%016lx` (%s) | ", name, lo, hi,
                 human_size(hi - lo, hbuf, sizeof(hbuf)));
        else
          printf("| %s | `0x%016lx` | ", name,
                 section_consensus(type_order[t], section_order[si],
                                   REGION_UNKNOWN));
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
      section_range(r->type, sec, REGION_UNKNOWN, &lo, &hi);

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
