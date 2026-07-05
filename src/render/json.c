// This file is part of KASLD - https://github.com/bcoles/kasld
//
// JSON renderer (--json) for the engine-resolved summary, plus the JSON
// helper json_print_escaped() used by both this file and hardening.c.
//
// Cross-file helpers (section_consensus, in_bounds, result_*, etc.) are
// declared in include/kasld/render_internal.h and defined in render.c.
// ---
// <bcoles@gmail.com>

#include "include/kasld/internal.h"
#include "include/kasld/render_internal.h"

#include <stdio.h>
#include <string.h>
#include <sys/utsname.h>

void json_print_escaped(const char *s) {
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

/* Local mirror of the per-(type, section) key used in the dispatcher below.
 * Kept private to this TU; the text renderer carries its own copy with the
 * "already printed" tracking it needs. */
struct json_group_key {
  enum kasld_addr_type type;
  const char *section;
};

static void render_json_group(enum kasld_addr_type gt, const char *gs) {
  const char *display = section_display_name(gt, gs);
  if (!display)
    return;

  unsigned long consensus = section_consensus(gt, gs, REGION_UNKNOWN);
  unsigned long lo, hi;
  section_range(gt, gs, &lo, &hi);

  const char *bm;
  int ns, nc;
  section_consensus_info(gt, gs, REGION_UNKNOWN, &bm, &ns, &nc);

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
    printf("          \"origins\": [");
    for (int j = 0; j < r->provenance_count; j++) {
      if (j)
        printf(", ");
      json_print_escaped(r->origins[j]);
    }
    printf("],\n");
    printf("          \"method\": ");
    json_print_escaped(
        result_method(r)); /* single strongest, for compatibility */
    printf(",\n");
    printf("          \"methods\": [");
    {
      int firstm = 1;
      for (int m = 0; m < KM_COUNT; m++)
        if (r->method_set & (1u << m)) {
          printf(firstm ? "" : ", ");
          json_print_escaped(kasld_method_name((enum kasld_method)m));
          firstm = 0;
        }
    }
    printf("],\n");
    printf("          \"valid\": %s\n", in_bounds(r) ? "true" : "false");
    printf("        }");
  }
  printf("\n      ]\n");
  printf("    }");
}

void render_json(const struct summary *s) {
  struct utsname u;
  int have_uname = (kasld_uname(&u) == 0);

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
  printf("    \"virt_page_offset\": \"0x%016lx\",\n", layout.virt_page_offset);
  printf("    \"virt_image_base_min\": \"0x%016lx\",\n",
         layout.virt_image_base_min);
  printf("    \"virt_image_base_max\": \"0x%016lx\",\n",
         layout.virt_image_base_max);
  printf("    \"image_align\": \"0x%lx\",\n", layout.image_align);
  printf("    \"virt_image_base_default\": \"0x%016lx\",\n",
         layout.virt_image_base_default);
  /* Phys KASLR window. Symmetric with virt_image_base_min/max above (which is
   * the virt window) — both are the engine-resolved [lo, hi] for the
   * corresponding text-base quantity. Coupled arches and arches without
   * phys KASLR leave both at 0; expose as JSON null so consumers can
   * distinguish "no bound" from "bound at 0". */
  if (layout.phys_kaslr_text_min || layout.phys_kaslr_text_max)
    printf("    \"phys_kaslr_text_min\": \"0x%016lx\",\n"
           "    \"phys_kaslr_text_max\": \"0x%016lx\",\n",
           layout.phys_kaslr_text_min, layout.phys_kaslr_text_max);
  else
    printf("    \"phys_kaslr_text_min\": null,\n"
           "    \"phys_kaslr_text_max\": null,\n");
  if (layout.phys_kaslr_align)
    printf("    \"phys_kaslr_align\": \"0x%lx\",\n", layout.phys_kaslr_align);
  else
    printf("    \"phys_kaslr_align\": null,\n");
  printf("    \"modules_start\": \"0x%016lx\",\n", layout.modules_start);
  printf("    \"modules_end\": \"0x%016lx\",\n", layout.modules_end);
  printf("    \"text_tracks_directmap\": %s,\n",
         TEXT_TRACKS_DIRECTMAP ? "true" : "false");
  printf("    \"directmap_static\": %s\n", DIRECTMAP_STATIC ? "true" : "false");
  printf("  },\n");

  /* kaslr.
   *
   * Two-window vocabulary mapping (the SINGLE authoritative reference; text and
   * markdown render the same two concepts under different surface labels):
   *
   *   concept              JSON key(s)                  text label
   *   -------------------  ---------------------------  ---------------------
   *   guaranteed window    "inferred"/"inferred_phys-   "Inferred text range"
   *   (sound floor; truth   ical"; range_min/max,        / "Guaranteed range"
   *    is contained)        slots, entropy_bits
   *   likely window        "likely"/"likely_physical";  "likely (speculative)"
   *   (all signals, subset  + "speculative": true
   *    of guaranteed, may
   *    be wrong)
   *   concrete base        "virtual"/"physical".        "Virtual/Physical
   *   (headline address)    image_base (+ "speculat-     image base"
   *                         ive": true when the sound
   *                         window is only a range)
   *
   * So a consumer reads: inferred* == guaranteed, likely* == speculative
   * best-guess (always ⊆ inferred*), virtual/physical == the single headline
   * base. memory_kaslr regions carry the same guaranteed min/max + optional
   * nested "likely" (see below). */
  printf("  \"kaslr\": {\n");
  printf("    \"disabled\": %s,\n", s->kaslr.disabled ? "true" : "false");
  printf("    \"unsupported\": %s", s->kaslr.unsupported ? "true" : "false");

  /* A concrete vtext while the guaranteed window is still a RANGE means the
   * base came from a sub-sound-floor leak: it is a speculative best-guess, not
   * proven. Mark it, and ALSO emit the guaranteed range (inferred) so consumers
   * still get the sound window. */
  int v_spec = s->kaslr.vtext && kaslr_virt_is_window();
  if (s->kaslr.vtext) {
    printf(",\n    \"virtual\": {\n");
    printf("      \"image_base\": \"0x%016lx\",\n", s->kaslr.vtext);
    if (s->kaslr.vstext && s->kaslr.vstext != s->kaslr.vtext)
      printf("      \"stext\": \"0x%016lx\",\n", s->kaslr.vstext);
    printf("      \"default_base\": \"0x%016lx\",\n",
           layout.virt_image_base_default);
    printf("      \"slide_bytes\": %ld,\n", s->kaslr.vslide);
    printf("      \"entropy_bits\": %d,\n", s->kaslr.vbits);
    printf("      \"slots\": %lu", s->kaslr.vslots);
    if (s->kaslr.vslot_valid)
      printf(",\n      \"slot_index\": %lu", s->kaslr.vslot_idx);
    if (v_spec)
      printf(",\n      \"speculative\": true");
    printf("\n    }");
  }
  if (!s->kaslr.disabled && !s->kaslr.unsupported && s->kaslr.vslots > 0 &&
      (v_spec || !s->kaslr.vtext)) {
    printf(",\n    \"inferred\": {\n");
    printf("      \"range_min\": \"0x%016lx\",\n", layout.virt_kaslr_text_min);
    printf("      \"range_max\": \"0x%016lx\",\n", layout.virt_kaslr_text_max);
    printf("      \"slots\": %lu,\n", s->kaslr.vslots);
    printf("      \"entropy_bits\": %d\n", s->kaslr.vbits);
    printf("    }");
  }

  /* Speculative "likely" window: a subset of the guaranteed (inferred/virtual)
   * window above, narrowed by sub-sound-floor signals; may be wrong. Emitted
   * only when actually tighter than guaranteed. */
  if (s->kaslr.vlikely_max != 0) {
    printf(",\n    \"likely\": {\n");
    printf("      \"range_min\": \"0x%016lx\",\n", s->kaslr.vlikely_min);
    printf("      \"range_max\": \"0x%016lx\",\n", s->kaslr.vlikely_max);
    printf("      \"slots\": %lu,\n", s->kaslr.vlikely_slots);
    printf("      \"entropy_bits\": %d,\n", s->kaslr.vlikely_bits);
    printf("      \"speculative\": true\n");
    printf("    }");
  }

  int p_spec = s->kaslr.has_phys && kaslr_phys_is_window();
  if (s->kaslr.has_phys) {
    printf(",\n    \"physical\": {\n");
    printf("      \"image_base\": \"0x%016lx\",\n", s->kaslr.ptext);
    if (s->kaslr.pstext && s->kaslr.pstext != s->kaslr.ptext)
      printf("      \"stext\": \"0x%016lx\",\n", s->kaslr.pstext);
#ifdef KERNEL_PHYS_DEFAULT
    printf("      \"default_base\": \"0x%016lx\",\n",
           (unsigned long)KERNEL_PHYS_DEFAULT);
#endif
    printf("      \"slide_bytes\": %ld,\n", s->kaslr.pslide);
    printf("      \"entropy_bits\": %d,\n", s->kaslr.pbits);
    printf("      \"slots\": %lu", s->kaslr.pslots);
    if (p_spec)
      printf(",\n      \"speculative\": true");
    printf("\n    }");
  }
  if (!s->kaslr.disabled && !s->kaslr.unsupported && s->kaslr.pslots > 0 &&
      (p_spec || !s->kaslr.has_phys)) {
    printf(",\n    \"inferred_physical\": {\n");
    printf("      \"range_min\": \"0x%016lx\",\n", layout.phys_kaslr_text_min);
    printf("      \"range_max\": \"0x%016lx\",\n", layout.phys_kaslr_text_max);
    printf("      \"slots\": %lu,\n", s->kaslr.pslots);
    printf("      \"entropy_bits\": %d\n", s->kaslr.pbits);
    printf("    }");
  }

  if (s->kaslr.plikely_max != 0) {
    printf(",\n    \"likely_physical\": {\n");
    printf("      \"range_min\": \"0x%016lx\",\n", s->kaslr.plikely_min);
    printf("      \"range_max\": \"0x%016lx\",\n", s->kaslr.plikely_max);
    printf("      \"slots\": %lu,\n", s->kaslr.plikely_slots);
    printf("      \"entropy_bits\": %d,\n", s->kaslr.plikely_bits);
    printf("      \"speculative\": true\n");
    printf("    }");
  }

  /* Memory KASLR (CONFIG_RANDOMIZE_MEMORY) — directmap / vmalloc / vmemmap
   * base bounds derived from the structural placement chain. Emitted only
   * when at least one region has been narrowed from its compile-time
   * default. Untightened sides emit JSON `null` so consumers can
   * distinguish "no bound" from "bound that happens to be zero". */
  if (summary_has_memory_kaslr(s)) {
    printf(",\n    \"memory_kaslr\": {\n");
    int first = 1;
    struct {
      const char *name;
      unsigned long min, max, lmin, lmax;
    } regions[] = {
        {"virt_page_offset_base", s->kaslr.virt_page_offset_min,
         s->kaslr.virt_page_offset_max, s->kaslr.virt_page_offset_likely_min,
         s->kaslr.virt_page_offset_likely_max},
        {"virt_vmalloc_base", s->kaslr.virt_vmalloc_min,
         s->kaslr.virt_vmalloc_max, s->kaslr.virt_vmalloc_likely_min,
         s->kaslr.virt_vmalloc_likely_max},
        {"virt_vmemmap_base", s->kaslr.virt_vmemmap_min,
         s->kaslr.virt_vmemmap_max, s->kaslr.virt_vmemmap_likely_min,
         s->kaslr.virt_vmemmap_likely_max},
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
      /* Speculative sub-window from the all-signals snapshot; subset of
       * [min, max] and may be wrong. Absent unless a sub-floor signal narrowed
       * the region. */
      if (regions[i].lmax || regions[i].lmin)
        printf(", \"likely\": { \"min\": \"0x%016lx\", \"max\": \"0x%016lx\", "
               "\"speculative\": true }",
               regions[i].lmin, regions[i].lmax);
      printf(" }");
      first = 0;
    }
    printf("\n    }");
  }

  printf("\n  },\n");

  /* groups — build ordered list of unique (type, section) keys */
  const char *const *section_order = kasld_render_sections;
  enum kasld_addr_type type_order[] = {KASLD_TYPE_VIRT, KASLD_TYPE_PHYS,
                                       KASLD_TYPE_UNKNOWN};

  struct json_group_key gkeys[64];
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
