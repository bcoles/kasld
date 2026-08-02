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

/* Local mirror of the per-(type, section, region) key used in the dispatcher
 * below. Kept private to this TU; the text renderer carries its own copy with
 * the "already printed" tracking it needs. */
struct json_group_key {
  enum kasld_addr_type type;
  const char *section;
  enum kasld_region region;
};

/* Upper bound on distinct group keys. A result's section is derived from its
 * region (region_info[].section_name), so section is not an independent axis:
 * the bound is one group per (address type, region) pair. Derived from the
 * enums so adding a region cannot silently overflow the array. */
#define JSON_N_ADDR_TYPES (KASLD_TYPE_VIRT + 1)
#define JSON_GROUP_MAX (JSON_N_ADDR_TYPES * REGION__COUNT)

/* One group per (type, section, region).
 *
 * The group aggregate — consensus, span, source and conflict counts — must
 * describe exactly the records the group carries, so it cannot span regions:
 * a single "dram" section spreads across ram, initrd, cmdline, acpi_table and
 * more, whose bases are unrelated, and an aggregate over their union answers
 * no question a consumer can ask. Every scan below is therefore filtered to
 * `gr`, matching the text renderer's per-region blocks.
 *
 * `display` names the section, so groups that share a section share a display
 * label; `region` is what distinguishes them. */
static void render_json_group(enum kasld_addr_type gt, const char *gs,
                              enum kasld_region gr) {
  const char *display = section_display_name(gt, gs);
  if (!display)
    return;

  unsigned long consensus = section_consensus(gt, gs, gr);
  unsigned long lo, hi;
  section_range(gt, gs, gr, &lo, &hi);

  const char *bm;
  int ns, nc, io;
  section_consensus_info(gt, gs, gr, &bm, &ns, &nc, &io);

  printf("    {\n");
  printf("      \"type\": \"%c\",\n", kasld_type_wire(gt));
  printf("      \"section\": \"%s\",\n", gs);
  printf("      \"region\": ");
  json_print_escaped(kasld_region_wire(gr));
  printf(",\n");
  printf("      \"display\": ");
  json_print_escaped(display);
  printf(",\n");
  printf("      \"consensus\": \"0x%016lx\",\n", consensus);
  printf("      \"consensus_method\": ");
  json_print_escaped(bm);
  printf(",\n");
  printf("      \"consensus_sources\": %d,\n", ns);
  printf("      \"conflicts\": %d,\n", nc);
  /* interior_only: the group carries only interior samples (no edge). consensus
   * is then the lowest sample and lo/hi bound the corroborated span, not a
   * resolved base; consensus_sources counts distinct contributors and conflicts
   * is 0 (interior samples do not compete). */
  printf("      \"interior_only\": %s,\n", io ? "true" : "false");
  printf("      \"lo\": \"0x%016lx\"", lo);
  if (hi)
    printf(",\n      \"hi\": \"0x%016lx\"", hi);

  printf(",\n      \"results\": [\n");
  int first = 1;
  for (int i = 0; i < num_results; i++) {
    if (results[i].type != gt || results[i].region != gr ||
        strcmp(result_section(&results[i]), gs) != 0)
      continue;
    const struct result *r = &results[i];
    if (!first)
      printf(",\n");
    first = 0;
    unsigned long a = anchor_addr(r);
    printf("        {\n");
    printf("          \"raw\": \"0x%016lx\",\n", a);
    printf("          \"aligned\": \"0x%016lx\",\n", a);
    printf("          \"pos\": \"%s\",\n", kasld_pos_wire(r->pos));
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

/* Append one group key per distinct region among the in-bounds results in
 * (type, section), skipping keys already collected so callers may pass the
 * same (type, section) twice. Keys stay in first-appearance order within the
 * section, matching the text renderer's block order.
 *
 * A group is emitted only where an in-bounds record exists, so the render loop
 * needs no emptiness re-check. Dedupe keys on (type, region) alone: the region
 * determines the section, so comparing sections would be redundant. */
static void collect_group_keys(enum kasld_addr_type type, const char *section,
                               struct json_group_key *keys, int *nkeys) {
  for (int i = 0; i < num_results; i++) {
    const struct result *r = &results[i];
    if (r->type != type || strcmp(result_section(r), section) != 0)
      continue;
    if (!in_bounds(r))
      continue;
    int dup = 0;
    for (int j = 0; j < *nkeys; j++)
      if (keys[j].type == type && keys[j].region == r->region) {
        dup = 1;
        break;
      }
    if (dup)
      continue;
    if (*nkeys >= JSON_GROUP_MAX)
      return; /* bound is derived from the enums; not reachable in practice */
    keys[*nkeys].type = type;
    keys[*nkeys].section = section;
    keys[*nkeys].region = r->region;
    (*nkeys)++;
  }
}

/* environment — the recon vantage: container / confinement / which /proc leak
 * oracles are readable here. Shared gather with the text + markdown renderers.
 */
static void render_environment_json(void) {
  struct kasld_vantage v;
  kasld_gather_vantage(&v);

  printf("  \"environment\": {\n");

  printf("    \"container\": ");
  if (v.container)
    json_print_escaped(v.container);
  else
    printf("null");

  printf(",\n    \"seccomp\": ");
  if (v.seccomp < 0)
    printf("null");
  else
    json_print_escaped(kasld_vantage_seccomp_str(v.seccomp));

  printf(",\n    \"capabilities\": ");
  char capbuf[24];
  const char *caps = kasld_vantage_caps(&v, capbuf, sizeof(capbuf));
  if (caps)
    json_print_escaped(caps);
  else
    printf("null");

  printf(",\n    \"no_new_privs\": ");
  if (v.no_new_privs < 0)
    printf("null");
  else
    printf(v.no_new_privs ? "true" : "false");

  printf(",\n    \"readable_oracles\": {\n");
  for (int i = 0; i < KASLD_N_ORACLES; i++) {
    printf("      ");
    json_print_escaped(kasld_oracle_paths[i]);
    printf(": %s%s\n", v.oracle_readable[i] ? "true" : "false",
           i + 1 < KASLD_N_ORACLES ? "," : "");
  }
  printf("    },\n");

  /* Cap-gated leaks the effective cap set unlocks — the recon complement to
   * readable_oracles (covers the non-file leaks too). Empty when none apply. */
  printf("    \"cap_reachable_leaks\": [");
  int first = 1;
  for (int i = 0; v.have_caps && i < KASLD_N_CAP_LEAKS; i++) {
    if (!((v.cap_eff >> kasld_cap_leaks[i].bit) & 1ull))
      continue;
    printf("%s\n      {\"capability\": \"%s\", \"source\": ", first ? "" : ",",
           kasld_cap_leaks[i].cap);
    json_print_escaped(kasld_cap_leaks[i].source);
    printf("}");
    first = 0;
  }
  printf(first ? "]\n" : "\n    ]\n");
  printf("  },\n");
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

  render_environment_json();

  /* layout */
  printf("  \"layout\": {\n");
  /* The kernel address space the regions below sit in. Architectural, but not
   * derivable from `arch` alone -- on x86_64 the 4- and 5-level layouts differ,
   * and the engine resolves which is active. Without these a consumer can
   * place every region and every gap between them, but cannot bound the space
   * itself: no ceiling above the topmost region, no floor below the lowest. */
  printf("    \"virt_kernel_vas_start\": \"0x%016lx\",\n",
         layout.virt_kernel_vas_start);
  printf("    \"virt_kernel_vas_end\": \"0x%016lx\",\n",
         layout.virt_kernel_vas_end);
  printf("    \"virt_page_offset\": \"0x%016lx\",\n", layout.virt_page_offset);
  printf("    \"virt_image_base_min\": \"0x%016lx\",\n",
         layout.virt_image_base_min);
  printf("    \"virt_image_base_max\": \"0x%016lx\",\n",
         layout.virt_image_base_max);
  printf("    \"image_align\": \"0x%lx\",\n", layout.image_align);
  /* The compile-time defaults: where a build of this architecture links the
   * kernel absent any relocation. Build constants, not findings, so they live
   * here among the other architectural constants rather than in the `kaslr`
   * object — and they are emitted unconditionally, since they are known
   * whether or not anything was resolved. A consumer that wants to know
   * whether the default survived compares it against the resolved window
   * (`kaslr.inferred.*`); containment is not corroboration, so the comparison
   * is the consumer's to make. `null` where the architecture defines no
   * physical default. */
  printf("    \"virt_image_base_default\": \"0x%016lx\",\n",
         layout.virt_image_base_default);
#ifdef KERNEL_PHYS_DEFAULT
  printf("    \"phys_image_base_default\": \"0x%016lx\",\n",
         (unsigned long)KERNEL_PHYS_DEFAULT);
#else
  printf("    \"phys_image_base_default\": null,\n");
#endif
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
  printf("    \"unsupported\": %s,\n", s->kaslr.unsupported ? "true" : "false");
  /* Distinct from `disabled`: the boot stub ran and relocated the image, only
   * the randomness was missing. Placement is firmware-determined, so it is
   * neither randomized nor at the link-time default — a consumer that treats
   * this as `disabled` would wrongly assume the latter. Carried here rather
   * than only in the `-H` posture block, so the default JSON can tell a failed
   * kernel from an active one. */
  printf("    \"randomization_failed\": %s",
         s->kaslr.randomization_failed ? "true" : "false");

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
    /* `slide_bytes` is this base measured against
     * `layout.virt_image_base_default`, which carries that constant for every
     * posture. */
    printf("      \"slide_bytes\": %ld,\n", s->kaslr.vslide);
    printf("      \"entropy_bits\": %d,\n", s->kaslr.vbits);
    if (s->kaslr.vbits_top > 0)
      printf("      \"entropy_bits_initial\": %d,\n", s->kaslr.vbits_top);
    printf("      \"slots\": %lu", s->kaslr.vslots);
    if (s->kaslr.vslot_valid)
      printf(",\n      \"slot_index\": %lu", s->kaslr.vslot_idx);
    if (v_spec)
      printf(",\n      \"speculative\": true");
    printf("\n    }");
  }
  /* The proven window is worth emitting whenever the engine resolved one --
   * including on a KASLR-disabled or non-KASLR kernel, where it is often the
   * only thing known about the base. On a VMSPLIT_2G arm32 kernel the engine
   * proves a 2.8 GB window containing _text while the compile-time default is
   * simply wrong, so suppressing it left a machine consumer with nothing.
   * Slots and entropy stay gated on a live slot count: KASLR off means no
   * residual entropy, but it does not mean no window. */
  if ((layout.virt_kaslr_text_min || layout.virt_kaslr_text_max) &&
      (v_spec || !s->kaslr.vtext)) {
    printf(",\n    \"inferred\": {\n");
    printf("      \"range_min\": \"0x%016lx\",\n", layout.virt_kaslr_text_min);
    printf("      \"range_max\": \"0x%016lx\"", layout.virt_kaslr_text_max);
    if (s->kaslr.vslots > 0) {
      printf(",\n      \"slots\": %lu", s->kaslr.vslots);
      if (s->kaslr.vbits_top > 0)
        printf(",\n      \"entropy_bits_initial\": %d", s->kaslr.vbits_top);
      printf(",\n      \"entropy_bits\": %d", s->kaslr.vbits);
    }
    printf("\n    }");
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
    /* `slide_bytes` is this base measured against
     * `layout.phys_image_base_default`, which carries that constant for every
     * posture (and is null where the architecture defines none). */
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
      unsigned long slots, lslots;
      int bits;
    } regions[] = {
        {"virt_page_offset_base", s->kaslr.virt_page_offset_min,
         s->kaslr.virt_page_offset_max, s->kaslr.virt_page_offset_likely_min,
         s->kaslr.virt_page_offset_likely_max, s->kaslr.virt_page_offset_slots,
         s->kaslr.virt_page_offset_likely_slots,
         s->kaslr.virt_page_offset_bits},
        {"virt_vmalloc_base", s->kaslr.virt_vmalloc_min,
         s->kaslr.virt_vmalloc_max, s->kaslr.virt_vmalloc_likely_min,
         s->kaslr.virt_vmalloc_likely_max, s->kaslr.virt_vmalloc_slots,
         s->kaslr.virt_vmalloc_likely_slots, s->kaslr.virt_vmalloc_bits},
        {"virt_vmemmap_base", s->kaslr.virt_vmemmap_min,
         s->kaslr.virt_vmemmap_max, s->kaslr.virt_vmemmap_likely_min,
         s->kaslr.virt_vmemmap_likely_max, s->kaslr.virt_vmemmap_slots,
         s->kaslr.virt_vmemmap_likely_slots, s->kaslr.virt_vmemmap_bits},
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
      /* The hole-aware candidate count and its residual entropy. A consumer
       * cannot derive these from min/max: interior C_EXCLUDE holes are carved
       * at read time inside quantity_slots() and never appear on the wire, so
       * (max - min) / align is the hole-blind number, not this one. */
      if (regions[i].slots > 0)
        printf(", \"slots\": %lu, \"entropy_bits\": %d", regions[i].slots,
               regions[i].bits);
      /* Speculative sub-window from the all-signals snapshot; subset of
       * [min, max] and may be wrong. Absent unless a sub-floor signal narrowed
       * the region. */
      if (regions[i].lmax || regions[i].lmin) {
        printf(", \"likely\": { \"min\": \"0x%016lx\", \"max\": \"0x%016lx\"",
               regions[i].lmin, regions[i].lmax);
        if (regions[i].lslots > 0)
          printf(", \"slots\": %lu", regions[i].lslots);
        printf(", \"speculative\": true }");
      }
      printf(" }");
      first = 0;
    }
    printf("\n    }");
  }

  printf("\n  },\n");

  /* groups — the canonical section order first, then anything outside it, with
   * each (type, section) split into one group per region it carries. */
  const char *const *section_order = kasld_render_sections;
  enum kasld_addr_type type_order[] = {KASLD_TYPE_VIRT, KASLD_TYPE_PHYS,
                                       KASLD_TYPE_UNKNOWN};

  struct json_group_key gkeys[JSON_GROUP_MAX];
  int ngkeys = 0;

  for (int t = 0; type_order[t] != KASLD_TYPE_UNKNOWN; t++)
    for (int si = 0; section_order[si]; si++)
      collect_group_keys(type_order[t], section_order[si], gkeys, &ngkeys);

  /* Any (type, section) outside the canonical order; collect_group_keys skips
   * whatever the loop above already took. */
  for (int i = 0; i < num_results; i++)
    collect_group_keys(results[i].type, result_section(&results[i]), gkeys,
                       &ngkeys);

  printf("  \"groups\": [\n");
  int first_group = 1;
  for (int g = 0; g < ngkeys; g++) {
    /* Metadata-only sections (no leak-group view) have no display name. */
    if (!section_display_name(gkeys[g].type, gkeys[g].section))
      continue;
    if (!first_group)
      printf(",\n");
    first_group = 0;
    render_json_group(gkeys[g].type, gkeys[g].section, gkeys[g].region);
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
    printf(",\n      \"pos\": \"%s\"", kasld_pos_wire(r->pos));
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

  /* components — the complete per-component record: name, exit code, outcome,
   * and the parsed KASLD_META (method/addr/cve/patch/config/sysctl/…). This is
   * the machine-readable posture a fleet/CI layer diffs and aggregates, so it
   * is always present; the raw stdout lines (bulky, and the resolved values
   * already appear in groups/derived) are appended only under --verbose. */
  {
    printf(",\n");
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
      /* Disposition: the fine-grained reason a component produced no result,
       * refining the coarse outcome. Present only when the component reported
       * one. `gate` names the confirmed control for a mitigation. */
      if (cl->disposition.category != DISP_NONE) {
        printf(",\n      \"disposition\": {\n");
        printf("        \"category\": \"%s\"",
               kasld_disp_wire(cl->disposition.category));
        if (cl->disposition.gate[0]) {
          printf(",\n        \"gate\": ");
          json_print_escaped(cl->disposition.gate);
        }
        if (cl->disposition.message[0]) {
          printf(",\n        \"message\": ");
          json_print_escaped(cl->disposition.message);
        }
        printf("\n      }");
      }
      if (cl->explain) {
        printf(",\n      \"explain\": ");
        json_print_escaped(cl->explain);
      }
      if (cl->meta.num_entries > 0) {
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
    printf("\n  ],\n");
  }

  render_hardening_json();

  printf("}\n");
}
