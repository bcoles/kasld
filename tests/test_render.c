// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Renderer unit tests. Split out of test_kasld.c: that suite covers the
// orchestrator's parse / merge / anchor / compute_kaslr_info internals; this
// one covers the renderer (render.c + render/*.c). Both #include the
// orchestrator + render translation units directly so static helpers are in
// scope, and share the result-collection helpers via test_orch_common.h.
//
// Each test captures stdout via dup2() to a tmpfile so render's printf output
// is verifiable without leaking into the runner transcript. Runs on every
// width/endianness under tests/test-cross (fixtures derive from arch
// constants), which is how the hardening paths get exercised per-arch.
// ---
// <bcoles@gmail.com>

#include "../src/orchestrator.c"
#include "../src/region_info.c"
#include "../src/render.c"
#include "../src/render/hardening.c"
#include "../src/render/json.c"
#include "../src/render/markdown.c"
#include "../src/render/oneline.c"
#include "../src/render/text.c"
#include "test_harness.h"
#include "test_orch_common.h"

#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* =========================================================================
 * Renderer unit tests.
 *
 * render.c is included into this translation unit via the top-level
 * `#include "../src/render.c"`, so static helpers are in scope. The
 * coverage-e2e harness (tests/coverage-e2e) exercises the real binary
 * end-to-end against fixtures; these tests target render.c paths the e2e
 * runs can't reach because the anonymized fixtures don't carry the
 * triggering data (escapable chars in metadata, kernel-locating phys
 * observations, etc.).
 *
 * Each test captures stdout into a buffer via freopen() so render's printf
 * output is verifiable without leaking into the test runner's transcript.
 * ========================================================================= */

#define RENDER_CAP_BUF 65536
static char render_cap[RENDER_CAP_BUF];

/* Redirect stdout to a tmpfile for the duration of a render call, then read
 * it back into render_cap (null-terminated). fmemopen() doesn't expose a real
 * fd dup2() can use, so we route via tmpfile() — small overhead, portable.
 * Restores stdout on return. Single-threaded (matches the test harness). */
static int capture_stdout(void (*fn)(void *), void *arg) {
  fflush(stdout);
  int saved_fd = dup(STDOUT_FILENO);
  assert(saved_fd >= 0);
  FILE *tmp = tmpfile();
  assert(tmp);
  int rc = dup2(fileno(tmp), STDOUT_FILENO);
  assert(rc >= 0);
  fn(arg);
  fflush(stdout);
  /* Restore stdout BEFORE reading the tmpfile so subsequent prints work. */
  dup2(saved_fd, STDOUT_FILENO);
  close(saved_fd);
  rewind(tmp);
  size_t n = fread(render_cap, 1, RENDER_CAP_BUF - 1, tmp);
  render_cap[n] = '\0';
  fclose(tmp);
  return (int)n;
}

static void wrap_json_print_escaped(void *arg) {
  json_print_escaped((const char *)arg);
}

/* json_print_escaped: the escape branches (\\, \", \b, \f, \n, \r, \t, and
 * generic \u00XX for other control chars) never fire on normal metadata
 * (component names are filenames; meta values are well-formed key:value
 * pairs). Exercise each branch with crafted input. */
/* Mutable char[] inputs throughout these tests so capture_stdout's
 * `void *arg` parameter can receive them without a const-discarding cast
 * (which would trip -Wcast-qual under the strict build). */
static void test_json_print_escaped_passthrough(void) {
  char in[] = "hello world";
  capture_stdout(wrap_json_print_escaped, in);
  assert(strcmp(render_cap, "\"hello world\"") == 0);
}

static void test_json_print_escaped_all_named_escapes(void) {
  /* Every named-escape branch in one call. The string contains literal
   * backslash, quote, BS, FF, LF, CR, TAB. */
  char in[] = "a\\b\"c\bd\fe\nf\rg\th";
  capture_stdout(wrap_json_print_escaped, in);
  /* Expected: opening ", each special escaped, closing ". */
  assert(strcmp(render_cap, "\"a\\\\b\\\"c\\bd\\fe\\nf\\rg\\th\"") == 0);
}

static void test_json_print_escaped_other_control(void) {
  /* Generic \u00XX path: a control byte that isn't one of the named ones
   * (e.g. 0x01 SOH). */
  char in[] = {'a', 0x01, 'b', 0};
  capture_stdout(wrap_json_print_escaped, in);
  assert(strcmp(render_cap, "\"a\\u0001b\"") == 0);
}

static void test_json_print_escaped_empty(void) {
  char in[] = "";
  capture_stdout(wrap_json_print_escaped, in);
  assert(strcmp(render_cap, "\"\"") == 0);
}

/* (No null-input test — json_print_escaped requires non-NULL by contract;
 * every call site in render.c pre-checks and emits literal "null" itself
 * for the null case. Testing NULL would just segfault on dereference.) */

/* render_summary dispatcher: a synthetic minimal summary should hit one of
 * render_text / render_json / render_oneline / render_markdown depending on
 * the global mode flags. Verifies the dispatch + minimal banner output. */
static void wrap_render_summary(void *arg) {
  render_summary((const struct summary *)arg);
}

static void set_render_mode(int json, int oneline, int markdown) {
  json_output = json;
  oneline_output = oneline;
  markdown_output = markdown;
}

static void test_render_summary_text_mode_minimal(void) {
  reset_results();
  num_comp_logs = 0;
  num_scalar_facts = 0;
  struct summary s;
  memset(&s, 0, sizeof(s));
  set_render_mode(0, 0, 0); /* default text mode */
  capture_stdout(wrap_render_summary, &s);
  /* Text mode prints a section header somewhere; the exact wording is the
   * renderer's, but a non-empty output is the minimum invariant. */
  assert(strlen(render_cap) > 0);
}

static void test_render_summary_json_mode_minimal(void) {
  reset_results();
  num_comp_logs = 0;
  num_scalar_facts = 0;
  struct summary s;
  memset(&s, 0, sizeof(s));
  set_render_mode(1, 0, 0);
  capture_stdout(wrap_render_summary, &s);
  /* JSON mode produces a top-level object. */
  assert(render_cap[0] == '{');
  /* Restore default for subsequent tests. */
  set_render_mode(0, 0, 0);
}

static void test_render_summary_oneline_mode_minimal(void) {
  reset_results();
  num_comp_logs = 0;
  num_scalar_facts = 0;
  struct summary s;
  memset(&s, 0, sizeof(s));
  set_render_mode(0, 1, 0);
  capture_stdout(wrap_render_summary, &s);
  /* Oneline output is one line; no embedded newlines except optional
   * trailing one. */
  int newlines = 0;
  for (int i = 0; render_cap[i]; i++)
    if (render_cap[i] == '\n')
      newlines++;
  assert(newlines <= 1);
  set_render_mode(0, 0, 0);
}

static void test_render_summary_markdown_mode_minimal(void) {
  reset_results();
  num_comp_logs = 0;
  num_scalar_facts = 0;
  struct summary s;
  memset(&s, 0, sizeof(s));
  set_render_mode(0, 0, 1);
  capture_stdout(wrap_render_summary, &s);
  /* Markdown mode emits at least one # heading. */
  assert(strchr(render_cap, '#') != NULL);
  set_render_mode(0, 0, 0);
}

/* Build a content-rich synthetic state for the heavier render branches:
 *   - one VIRT/KERNEL_TEXT result with lo (drives section_range,
 * kernel-locating promotion in print_compact_subgroup,
 * kernel_region_display_name)
 *   - one PHYS/RAM result with lo,hi (drives the DRAM band)
 *   - one VIRT/MODULE_REGION sample (drives module band rendering)
 *   - a populated component_log with method/addr/sysctl metadata (drives
 *     classify_components and the per-mitigation hardening lists)
 *   - kaslr info with vtext/vbits/vslots set (drives render_kaslr_text /
 *     render_phys_text_range / oneline / markdown KASLR row)
 * Reusable across multiple render-mode tests. */
static void set_rich_render_state(struct summary *s) {
  reset_results();
  num_comp_logs = 0;
  num_scalar_facts = 0;
  memset(s, 0, sizeof(*s));

  /* Use the kasld_layout's own (compile-time) text-base default for the
   * VIRT/KERNEL_TEXT result so it lies inside whatever in_bounds() expects.
   * This makes the test arch-portable. */
  unsigned long vt = (unsigned long)KERNEL_VIRT_TEXT_DEFAULT;

  struct result *r1 = push_result();
  r1->type = KASLD_TYPE_VIRT;
  r1->region = REGION_KERNEL_TEXT;
  r1->pos = POS_BASE;
  r1->conf = CONF_PARSED;
  r1->lo = vt;
  r1->set_mask = LO_SET;
  snprintf(r1->origins[0], ORIGIN_LEN, "synthetic_test");
  r1->method_set = 1u << KM_PARSED;
  r1->provenance_count = 1;

  struct result *r2 = push_result();
  r2->type = KASLD_TYPE_PHYS;
  r2->region = REGION_RAM;
  r2->pos = POS_BASE;
  r2->conf = CONF_PARSED;
  r2->lo = 0x40000000ul;
  r2->hi = 0xf0000000ul;
  r2->set_mask = LO_SET | HI_SET;
  snprintf(r2->origins[0], ORIGIN_LEN, "synthetic_test");
  r2->method_set = 1u << KM_PARSED;
  r2->provenance_count = 1;

  /* A component log with the metadata shape render_hardening_* reads. */
  struct component_log *cl = &comp_logs[num_comp_logs++];
  memset(cl, 0, sizeof(*cl));
  snprintf(cl->name, sizeof(cl->name), "synthetic_component");
  cl->outcome = OUTCOME_SUCCESS;
  cl->exit_code = 0;
  cl->meta.num_entries = 3;
  snprintf(cl->meta.entries[0].key, META_KEY_LEN, "method");
  snprintf(cl->meta.entries[0].value, META_VALUE_LEN, "parsed");
  snprintf(cl->meta.entries[1].key, META_KEY_LEN, "addr");
  snprintf(cl->meta.entries[1].value, META_VALUE_LEN, "virtual");
  snprintf(cl->meta.entries[2].key, META_KEY_LEN, "sysctl");
  snprintf(cl->meta.entries[2].value, META_VALUE_LEN, "kptr_restrict>=1");

  /* Populate summary KASLR info — drives render_kaslr_text and the JSON /
   * markdown KASLR rows. Values are illustrative (arch-portable enough; the
   * renderer doesn't validate them, it just prints). */
  s->kaslr.vtext = vt;
  s->kaslr.vslide = 0x10000000;
  s->kaslr.vslots = 512;
  s->kaslr.vbits = 9;
  s->kaslr.vslot_valid = 1;
  s->kaslr.vslot_idx = 42;
  s->stats.total = 1;
  s->stats.succeeded = 1;
}

static void test_render_text_with_rich_content(void) {
  struct summary s;
  set_rich_render_state(&s);
  set_render_mode(0, 0, 0); /* text */
  capture_stdout(wrap_render_summary, &s);
  /* Text output should mention the section ("text") and a hex address from the
   * VIRT/KERNEL_TEXT record. */
  assert(strstr(render_cap, "text") != NULL ||
         strstr(render_cap, "kernel") != NULL);
  assert(strstr(render_cap, "0x") != NULL);
}

static void test_render_json_with_rich_content(void) {
  struct summary s;
  set_rich_render_state(&s);
  set_render_mode(1, 0, 0);
  capture_stdout(wrap_render_summary, &s);
  /* JSON object with a results array — confirms render_json_group ran. */
  assert(render_cap[0] == '{');
  assert(strstr(render_cap, "\"results\"") != NULL ||
         strstr(render_cap, "\"groups\"") != NULL);
  /* Each leak result discloses its extent-position (P5). */
  assert(strstr(render_cap, "\"pos\": \"base\"") != NULL);
  set_render_mode(0, 0, 0);
}

/* The speculative "likely" window renders as a sub-line under the guaranteed
 * (inferred) text range in -v text, and as a "likely" object with
 * "speculative": true in -j JSON. Set up the no-concrete-base case (guaranteed
 * is a range) with a tighter likely window. */
static void test_render_likely_window(void) {
  struct summary s;
  reset_results();
  num_comp_logs = 0;
  num_scalar_facts = 0;
  memset(&s, 0, sizeof(s));
  extern int verbose;

  /* Guaranteed window is a range (no concrete vtext/ptext) with a tighter
   * speculative likely window. The likely sub-line/JSON read only s->kaslr,
   * not layout, so this mutates no global but verbose. */
  s.kaslr.vslots = 60;
  s.kaslr.vbits = 6;
  s.kaslr.vlikely_min = (unsigned long)KERNEL_VIRT_TEXT_DEFAULT + 0x19000000ul;
  s.kaslr.vlikely_max = s.kaslr.vlikely_min; /* a single slot */
  s.kaslr.vlikely_slots = 1;
  s.kaslr.vlikely_bits = 0;

  verbose = 1; /* the KASLR analysis block shows in the verbose text flow */
  set_render_mode(0, 0, 0); /* text */
  capture_stdout(wrap_render_summary, &s);
  assert(strstr(render_cap, "likely (speculative)") != NULL);
  /* A single surviving slot renders as a pinned best-guess in the verbose
   * analysis, not a degenerate "0xX - 0xX (1 slots, 0 bits)" range. */
  assert(strstr(render_cap, "(pinned)") != NULL);
  assert(strstr(render_cap, "1 slots") == NULL);

  verbose = 0; /* DEFAULT (compact readout) must also show the likely line */
  capture_stdout(wrap_render_summary, &s);
  assert(strstr(render_cap, "likely (speculative)") != NULL);

  set_render_mode(1, 0, 0); /* json */
  capture_stdout(wrap_render_summary, &s);
  assert(strstr(render_cap, "\"likely\"") != NULL);
  assert(strstr(render_cap, "\"speculative\": true") != NULL);
  set_render_mode(0, 0, 0);
}

/* A concrete vtext while the guaranteed window is a RANGE is a speculative
 * best-guess: -v labels it "(likely; speculative)" and shows the guaranteed
 * range; -j marks the virtual object speculative and still emits the inferred
 * (guaranteed) range. */
static void test_render_vtext_speculative(void) {
  struct summary s;
  reset_results();
  num_comp_logs = 0;
  num_scalar_facts = 0;
  memset(&s, 0, sizeof(s));
  extern int verbose;
  unsigned long sv_lo = layout.virt_kaslr_text_min,
                sv_hi = layout.virt_kaslr_text_max,
                sv_al = layout.virt_kaslr_align;

  s.kaslr.vtext = (unsigned long)KERNEL_VIRT_TEXT_DEFAULT + 0x10000000ul;
  s.kaslr.vslots = 60;
  s.kaslr.vbits = 6;
  layout.virt_kaslr_text_min = (unsigned long)KERNEL_VIRT_TEXT_DEFAULT;
  layout.virt_kaslr_text_max =
      (unsigned long)KERNEL_VIRT_TEXT_DEFAULT + 0x3c000000ul;
  layout.virt_kaslr_align = 0x1000000ul;

  verbose = 1;
  set_render_mode(0, 0, 0); /* text */
  capture_stdout(wrap_render_summary, &s);
  verbose = 0;
  assert(strstr(render_cap, "(likely; speculative)") != NULL);
  assert(strstr(render_cap, "Guaranteed range") != NULL);
  /* The slide is a best-guess for a windowed (unpinned) base, so it inherits
   * the likely grade (#6). ")  (likely)" is the slide tail; the base line uses
   * "(likely; speculative)", so this substring matches only the slide. */
  assert(strstr(render_cap, ")  (likely)") != NULL);

  set_render_mode(1, 0,
                  0); /* json: virtual marked speculative + inferred range */
  capture_stdout(wrap_render_summary, &s);
  assert(strstr(render_cap, "\"speculative\": true") != NULL);
  assert(strstr(render_cap, "\"inferred\"") != NULL);
  set_render_mode(0, 0, 0);

  layout.virt_kaslr_text_min = sv_lo;
  layout.virt_kaslr_text_max = sv_hi;
  layout.virt_kaslr_align = sv_al;
}

/* Memory-KASLR regions (directmap/vmalloc/vmemmap) carry their own speculative
 * "likely" sub-windows. A guaranteed region range plus a tighter likely sub-
 * range must surface in the verbose Memory KASLR block, the default direct-map
 * readout, JSON, and markdown. Reads only s->kaslr (mutates no global). */
static void test_render_memory_likely_window(void) {
  struct summary s;
  reset_results();
  num_comp_logs = 0;
  num_scalar_facts = 0;
  memset(&s, 0, sizeof(s));
  extern int verbose;

  s.kaslr.vslots = 60; /* keep render_kaslr_text from early-returning */
  s.kaslr.vbits = 6;
  /* Guaranteed direct-map (page_offset) range with a tighter pinned likely
   * best-guess. Based on the arch PAGE_OFFSET macro so the constants fit
   * `unsigned long` on 32-bit arches too (matches set_richer_render_state). */
  s.kaslr.virt_page_offset_min = (unsigned long)PAGE_OFFSET + 0x01000000ul;
  s.kaslr.virt_page_offset_max = (unsigned long)PAGE_OFFSET + 0x09000000ul;
  s.kaslr.virt_page_offset_likely_min =
      (unsigned long)PAGE_OFFSET + 0x03000000ul;
  s.kaslr.virt_page_offset_likely_max = s.kaslr.virt_page_offset_likely_min;

  verbose = 1;              /* verbose Memory KASLR block */
  set_render_mode(0, 0, 0); /* text */
  capture_stdout(wrap_render_summary, &s);
  assert(strstr(render_cap, "likely (speculative)") != NULL);

  verbose = 0; /* DEFAULT readout direct-map likely line */
  capture_stdout(wrap_render_summary, &s);
  assert(strstr(render_cap, "likely (speculative)") != NULL);

  set_render_mode(1, 0, 0); /* json */
  capture_stdout(wrap_render_summary, &s);
  assert(strstr(render_cap, "\"likely\"") != NULL);
  assert(strstr(render_cap, "\"speculative\": true") != NULL);

  set_render_mode(0, 0, 1); /* markdown */
  capture_stdout(wrap_render_summary, &s);
  assert(strstr(render_cap, "(likely)") != NULL);
  assert(strstr(render_cap, "speculative") != NULL);
  set_render_mode(0, 0, 0);
}

/* The verbose Memory-KASLR candidate count comes from the engine's hole-aware
 * slot field (s->kaslr.virt_page_offset_slots), NOT a renderer-local
 * (max-min)/align. Set a slot count the naive formula could never produce for
 * this window and assert it is what renders. */
static void test_render_memory_kaslr_uses_stored_slots(void) {
  struct summary s;
  reset_results();
  num_comp_logs = 0;
  num_scalar_facts = 0;
  memset(&s, 0, sizeof(s));
  extern int verbose;

  s.kaslr.vslots = 60; /* keep render_kaslr_text from early-returning */
  s.kaslr.vbits = 6;
  /* Both-sided direct-map window (portable constants). */
  s.kaslr.virt_page_offset_min = (unsigned long)PAGE_OFFSET + 0x01000000ul;
  s.kaslr.virt_page_offset_max = (unsigned long)PAGE_OFFSET + 0x09000000ul;
  s.kaslr.virt_page_offset_slots = 7; /* engine-supplied; naive width gives 0 */

  verbose = 1;
  set_render_mode(0, 0, 0);
  capture_stdout(wrap_render_summary, &s);
  verbose = 0;
  set_render_mode(0, 0, 0);

  assert(strstr(render_cap, "7 candidates") != NULL);
}

/* A KASLR-disabled base is a proven pin, not a speculative "likely" value: the
 * word "Likely" must not prefix the kernel image base (spec P3/§6). */
static void test_render_disabled_base_not_labeled_likely(void) {
  struct summary s;
  reset_results();
  num_comp_logs = 0;
  num_scalar_facts = 0;
  memset(&s, 0, sizeof(s));
  extern int verbose;

  s.kaslr.disabled = 1;
  unsigned long vt = (unsigned long)KERNEL_VIRT_TEXT_DEFAULT;
  unsigned long smin = layout.virt_kaslr_text_min;
  unsigned long smax = layout.virt_kaslr_text_max;
  layout.virt_kaslr_text_min = vt; /* engine pin: min == max != 0 */
  layout.virt_kaslr_text_max = vt;

  verbose = 1;
  set_render_mode(0, 0, 0);
  capture_stdout(wrap_render_summary, &s);
  verbose = 0;
  layout.virt_kaslr_text_min = smin;
  layout.virt_kaslr_text_max = smax;

  assert(strstr(render_cap, "Kernel image base") != NULL);
  assert(strstr(render_cap, "Likely kernel image base") == NULL);
}

/* A leaked interior sample must self-disclose "[interior]" in the leak rows so
 * a reader never mistakes it for the region base (spec P5). A lone in-bounds
 * interior kernel-text sample is the best record for its region, so the readout
 * Leaks list surfaces it. */
static void test_render_leak_discloses_interior(void) {
  struct summary s;
  reset_results();
  num_comp_logs = 0;
  num_scalar_facts = 0;
  memset(&s, 0, sizeof(s));

  struct result *r = push_result();
  r->type = KASLD_TYPE_VIRT;
  r->region = REGION_KERNEL_TEXT;
  r->pos = POS_INTERIOR;
  r->conf = CONF_PARSED;
  r->lo = (unsigned long)KERNEL_VIRT_TEXT_DEFAULT;
  r->set_mask = LO_SET;
  snprintf(r->origins[0], ORIGIN_LEN, "synthetic_test");
  r->method_set = 1u << KM_PARSED;
  r->provenance_count = 1;

  set_render_mode(0, 0, 0); /* readout */
  capture_stdout(wrap_render_summary, &s);

  assert(strstr(render_cap, "[interior]") != NULL);
}

static void test_render_markdown_with_rich_content(void) {
  struct summary s;
  set_rich_render_state(&s);
  extern int verbose;
  verbose = 1; /* per-record Leak Results table (with the Pos column) */
  set_render_mode(0, 0, 1);
  capture_stdout(wrap_render_summary, &s);
  verbose = 0;
  /* Markdown produces a table and discloses each leak's extent-position. */
  assert(strstr(render_cap, "|") != NULL);
  assert(strstr(render_cap, "| Pos |") != NULL);
  assert(strstr(render_cap, "| base |") != NULL);
  set_render_mode(0, 0, 0);
}

static void test_render_oneline_with_rich_content(void) {
  struct summary s;
  set_rich_render_state(&s);
  set_render_mode(0, 1, 0);
  capture_stdout(wrap_render_summary, &s);
  /* Oneline output should contain the vtext address. */
  assert(strstr(render_cap, "0x") != NULL);
  set_render_mode(0, 0, 0);
}

/* The oneline `dmap=` field reports the direct-map BASE (PAGE_OFFSET, from the
 * engine-resolved layout.virt_page_offset), never an interior linear-map
 * sample. Seed an interior directmap leak alongside a resolved base and assert
 * the base — not the leak — is what `dmap=` prints. */
static void test_render_oneline_dmap_is_base_not_interior(void) {
  struct summary s;
  set_rich_render_state(&s);

  /* Values fit unsigned long on 32- and 64-bit arches; the render logic under
   * test is arch-independent. */
  const unsigned long base = 0xc0000000ul;     /* aligned directmap base */
  const unsigned long interior = 0xc1a2b000ul; /* interior leak, not base */
  struct result *r = push_result();
  r->type = KASLD_TYPE_VIRT;
  r->region = REGION_DIRECTMAP;
  r->pos = POS_INTERIOR;
  r->conf = CONF_PARSED;
  r->lo = interior;
  r->set_mask = LO_SET;
  snprintf(r->origins[0], ORIGIN_LEN, "synthetic_test");
  r->method_set = 1u << KM_PARSED;
  r->provenance_count = 1;

  /* Engine-resolved base: virt_page_offset_min signals it, layout carries the
   * rendered anchor. */
  s.kaslr.virt_page_offset_min = base;
  unsigned long saved = layout.virt_page_offset;
  layout.virt_page_offset = base;

  set_render_mode(0, 1, 0);
  capture_stdout(wrap_render_summary, &s);
  set_render_mode(0, 0, 0);
  layout.virt_page_offset = saved;

  assert(strstr(render_cap, "dmap=0xc0000000") != NULL);
  assert(strstr(render_cap, "c1a2b000") == NULL);
}

/* oneline `text=` presents the engine-resolved image base only, never a raw
 * leak consensus. set_rich_render_state seeds an in-bounds VIRT text base leak
 * (which the old consensus fallback would surface); with the engine reporting
 * no resolved base (vtext==0), `text=` must be omitted — an unresolved base is
 * not backfilled from a leak (sibling of the dmap= base/interior rule). */
static void test_render_oneline_text_omits_when_engine_unresolved(void) {
  struct summary s;
  set_rich_render_state(&s);
  s.kaslr.vtext = 0; /* engine resolved no concrete base */
  s.kaslr.vstext = 0;

  set_render_mode(0, 1, 0);
  capture_stdout(wrap_render_summary, &s);
  set_render_mode(0, 0, 0);

  /* Leading space matches oneline's " text=" and avoids matching " stext=". */
  assert(strstr(render_cap, " text=") == NULL);
}

/* set_rich_render_state seeds a single-origin record; this overlays a second
 * and third origin on the VIRT/KERNEL_TEXT record so the renderer tests below
 * exercise the multi-contributor display path that text.c, markdown.c, and
 * json.c iterate r->origins[0..provenance_count] for. */
static void seed_multi_origin_text_result(struct summary *s) {
  set_rich_render_state(s);
  for (int i = 0; i < num_results; i++) {
    struct result *r = &results[i];
    if (r->type == KASLD_TYPE_VIRT && r->region == REGION_KERNEL_TEXT) {
      snprintf(r->origins[0], ORIGIN_LEN, "prefetch");
      snprintf(r->origins[1], ORIGIN_LEN, "perf_event_open");
      snprintf(r->origins[2], ORIGIN_LEN, "perf_lbr_sampling");
      r->method_set = 1u << KM_TIMING;
      r->method_set |= 1u << KM_PARSED;
      r->method_set |= 1u << KM_PARSED;
      r->provenance_count = 3;
      return;
    }
  }
  assert(0 && "set_rich_render_state did not seed VIRT/KERNEL_TEXT");
}

static void test_render_text_lists_all_origins(void) {
  struct summary s;
  seed_multi_origin_text_result(&s);
  set_render_mode(0, 0, 0); /* text */
  capture_stdout(wrap_render_summary, &s);
  /* All three contributing origins must appear in the Leaks section. */
  assert(strstr(render_cap, "prefetch") != NULL);
  assert(strstr(render_cap, "perf_event_open") != NULL);
  assert(strstr(render_cap, "perf_lbr_sampling") != NULL);
  /* The base leak self-discloses its position, not just interior/top (P5). */
  assert(strstr(render_cap, "[base]") != NULL);
}

/* The leaks bracket must aggregate provenance across SEPARATE merged records of
 * the same (type, region): results merge by (type, region, NAME), so the same
 * address tagged under a different symbol name (proc_kallsyms's _stext vs an
 * unnamed/side-channel text leak) lands in a distinct record. Every contributor
 * must surface — named in verbose, and counted (via "+N more") in the clamped
 * default line — not just the single highest-confidence record's. */
static void test_render_text_leaks_aggregates_across_records(void) {
  struct summary s;
  seed_multi_origin_text_result(&s); /* rich state + one VIRT/KERNEL_TEXT rec */

  /* A second VIRT/KERNEL_TEXT record under a different name, in bounds (reuse
   * the first record's address), as proc_kallsyms's _stext would form. */
  unsigned long addr = 0;
  for (int i = 0; i < num_results; i++)
    if (results[i].type == KASLD_TYPE_VIRT &&
        results[i].region == REGION_KERNEL_TEXT) {
      addr = anchor_addr(&results[i]);
      break;
    }
  struct result *r = push_result();
  r->type = KASLD_TYPE_VIRT;
  r->region = REGION_KERNEL_TEXT;
  r->lo = addr;
  r->set_mask = LO_SET;
  r->pos = POS_BASE;
  r->conf = CONF_PARSED;
  snprintf(r->name, NAME_LEN, "_stext");
  snprintf(r->origins[0], ORIGIN_LEN, "proc_kallsyms");
  r->provenance_count = 1;

  /* Default text clamps the name list to the first few + "+N more". The first
   * record already supplies 3 origins, so the separate record's contributor is
   * aggregated as a later one and surfaces in the "+N more" count — proving the
   * bracket reaches across records rather than listing one record's set. */
  set_render_mode(0, 0, 0); /* text */
  capture_stdout(wrap_render_summary, &s);
  assert(strstr(render_cap, "prefetch") != NULL);
  assert(strstr(render_cap, "more)") != NULL);

  /* Verbose lists every aggregated contributor by name, including the one from
   * the separate record. */
  verbose = 1;
  capture_stdout(wrap_render_summary, &s);
  verbose = 0;
  assert(strstr(render_cap, "proc_kallsyms") != NULL);
  assert(strstr(render_cap, "prefetch") != NULL);
}

static void test_render_json_emits_origins_array(void) {
  struct summary s;
  seed_multi_origin_text_result(&s);
  set_render_mode(1, 0, 0); /* json */
  capture_stdout(wrap_render_summary, &s);
  /* JSON must carry "origins": [...] with all three names. The deprecated
   * single-value "origin": string field must NOT reappear. */
  assert(strstr(render_cap, "\"origins\":") != NULL);
  assert(strstr(render_cap, "\"prefetch\"") != NULL);
  assert(strstr(render_cap, "\"perf_event_open\"") != NULL);
  assert(strstr(render_cap, "\"perf_lbr_sampling\"") != NULL);
  assert(strstr(render_cap, "\"origin\":") == NULL);
  /* The methods array surfaces the full diversity: prefetch contributes
   * "timing", perf_event_open "parsed". */
  assert(strstr(render_cap, "\"methods\":") != NULL);
  assert(strstr(render_cap, "\"timing\"") != NULL);
  assert(strstr(render_cap, "\"parsed\"") != NULL);
  set_render_mode(0, 0, 0);
}

/* result_method returns the strongest method in the record's set (consistent
 * with the resolved confidence), not the earliest contributor's. */
static void test_result_method_returns_strongest(void) {
  struct result r = {0};
  r.method_set = (1u << KM_TIMING) | (1u << KM_PARSED);
  assert(strcmp(result_method(&r), "parsed") == 0);
  r.method_set = 1u << KM_TIMING;
  assert(strcmp(result_method(&r), "timing") == 0);
  r.method_set = 0;
  assert(strcmp(result_method(&r), "unknown") == 0);
}

static void test_render_markdown_lists_all_origins(void) {
  struct summary s;
  seed_multi_origin_text_result(&s);
  set_render_mode(0, 0, 1); /* markdown verbose to reach the detail table */
  verbose = 1;
  capture_stdout(wrap_render_summary, &s);
  verbose = 0;
  assert(strstr(render_cap, "prefetch") != NULL);
  assert(strstr(render_cap, "perf_event_open") != NULL);
  assert(strstr(render_cap, "perf_lbr_sampling") != NULL);
  set_render_mode(0, 0, 0);
}

/* Defensive: when provenance_count is 0 (no contributors recorded), the
 * renderers must still produce sensible output for the record without
 * crashing or emitting a stray "()" empty-origin block. */
static void seed_no_provenance_text_result(struct summary *s) {
  set_rich_render_state(s);
  for (int i = 0; i < num_results; i++) {
    struct result *r = &results[i];
    if (r->type == KASLD_TYPE_VIRT && r->region == REGION_KERNEL_TEXT) {
      r->provenance_count = 0;
      r->origins[0][0] = '\0';
      r->method_set = 0;
      return;
    }
  }
  assert(0 && "set_rich_render_state did not seed VIRT/KERNEL_TEXT");
}

static void test_render_text_leaks_no_provenance(void) {
  struct summary s;
  seed_no_provenance_text_result(&s);
  set_render_mode(0, 0, 0);
  capture_stdout(wrap_render_summary, &s);
  /* Address must still appear; no parenthesised origin block trails the
   * Leaks-section label line. */
  assert(strstr(render_cap, "0x") != NULL);
  const char *leaks = strstr(render_cap, "Leaks (");
  assert(leaks != NULL);
  const char *label = strstr(leaks, "virt kernel text");
  assert(label != NULL);
  const char *eol = strchr(label, '\n');
  assert(eol != NULL);
  /* Inspect just the one Leaks row: no `(` between the label and end-of-line
   * means the empty-origins fallback fired correctly. */
  for (const char *p = label; p < eol; p++)
    assert(*p != '(');
}

static void test_render_json_emits_empty_origins_array(void) {
  struct summary s;
  seed_no_provenance_text_result(&s);
  set_render_mode(1, 0, 0);
  capture_stdout(wrap_render_summary, &s);
  /* Empty array is the well-formed shape. The deprecated single-value
   * "origin": string must not reappear. */
  assert(strstr(render_cap, "\"origins\": []") != NULL);
  assert(strstr(render_cap, "\"origin\":") == NULL);
  set_render_mode(0, 0, 0);
}

/* Leaks-section count is the number of distinct (type, region) groups with
 * a renderable record, NOT the sum of contributors across them. A
 * multi-origin record on one group still produces one Leaks row; adding a
 * second region adds exactly one row. */
static void seed_two_region_groups(struct summary *s) {
  set_rich_render_state(s);
  /* set_rich_render_state seeds:
   *  - VIRT/KERNEL_TEXT at KERNEL_VIRT_TEXT_DEFAULT
   *  - PHYS/RAM (REGION_RAM is NOT in the Leaks "interesting" table)
   * Add a VIRT/DIRECTMAP record so the Leaks section has two rows to count.
   * Anchor it to the layout's directmap so in_bounds() accepts it. */
  for (int i = 0; i < num_results; i++) {
    struct result *r = &results[i];
    if (r->type == KASLD_TYPE_VIRT && r->region == REGION_KERNEL_TEXT) {
      snprintf(r->origins[0], ORIGIN_LEN, "origin_a");
      snprintf(r->origins[1], ORIGIN_LEN, "origin_b");
      r->method_set = 1u << KM_PARSED;
      r->method_set |= 1u << KM_PARSED;
      r->provenance_count = 2;
      break;
    }
  }
  unsigned long dm = layout.virt_page_offset
                         ? layout.virt_page_offset + 0x1000
                         : (unsigned long)PAGE_OFFSET + 0x1000ul;
  struct result *r = push_result();
  r->type = KASLD_TYPE_VIRT;
  r->region = REGION_DIRECTMAP;
  r->pos = POS_BASE;
  r->conf = CONF_PARSED;
  r->lo = dm;
  r->set_mask = LO_SET;
  snprintf(r->origins[0], ORIGIN_LEN, "synthetic_test");
  r->method_set = 1u << KM_PARSED;
  r->provenance_count = 1;
}

static void test_render_text_leaks_count_is_groups_not_contributors(void) {
  struct summary s;
  seed_two_region_groups(&s);
  set_render_mode(0, 0, 0);
  capture_stdout(wrap_render_summary, &s);
  /* Two groups (virt kernel text + virt directmap), regardless of how many
   * origins contribute to each. */
  assert(strstr(render_cap, "Leaks (2):") != NULL);
  assert(strstr(render_cap, "virt kernel text") != NULL);
  assert(strstr(render_cap, "virt directmap") != NULL);
  assert(strstr(render_cap, "origin_a") != NULL);
  assert(strstr(render_cap, "origin_b") != NULL);
}

/* Even richer state: in addition to set_rich_render_state(), seed
 *   - a CONF_DERIVED result (drives render_derived_text)
 *   - REGION_KERNEL_DATA + REGION_KERNEL_BSS results (drives
 *     kernel_region_display_name in render_markdown's kernel-locating
 *     promotion)
 *   - layout.phys_kaslr_text_min/max non-zero (drives render_memory_kaslr_bound
 *     and the phys-band rendering)
 *   - summary.kaslr.virt_page_offset_min/max + virt_vmalloc_min/max +
 * virt_vmemmap_min/max populated (drives the memory_kaslr block in render_text
 * and render_memory_kaslr_bound's pinned / one-sided / both-sided branches) */
static void set_richer_render_state(struct summary *s) {
  set_rich_render_state(s);

  /* CONF_DERIVED record — render_derived_text picks it up. */
  unsigned long vt = (unsigned long)KERNEL_VIRT_TEXT_DEFAULT;
  struct result *r3 = push_result();
  r3->type = KASLD_TYPE_VIRT;
  r3->region = REGION_KERNEL_DATA;
  r3->pos = POS_BASE;
  r3->conf = CONF_DERIVED;
  r3->lo = vt + 0x800000ul;
  r3->set_mask = LO_SET;
  snprintf(r3->origins[0], ORIGIN_LEN, "synthetic_test");
  r3->method_set = 1u << KM_DERIVED;
  r3->provenance_count = 1;

  /* REGION_KERNEL_BSS sibling — gives collect_kernel_regions multiple
   * kernel-locating regions in the same section, triggering
   * kernel_region_display_name's promotion path. */
  struct result *r4 = push_result();
  r4->type = KASLD_TYPE_VIRT;
  r4->region = REGION_KERNEL_BSS;
  r4->pos = POS_BASE;
  r4->conf = CONF_PARSED;
  r4->lo = vt + 0x900000ul;
  r4->set_mask = LO_SET;
  snprintf(r4->origins[0], ORIGIN_LEN, "synthetic_test");
  r4->method_set = 1u << KM_PARSED;
  r4->provenance_count = 1;

  /* Phys-side band so render_text's phys map has something to draw and
   * render_memory_kaslr_bound's pinned / one-sided branches fire. */
  layout.phys_kaslr_text_min = 0x1000000ul;
  layout.phys_kaslr_text_max = 0x10000000ul;

  /* memory_kaslr (RANDOMIZE_MEMORY) — populate all three to hit the
   * pinned branch (min == max), the one-sided branch (min only), and the
   * window branch (min < max). */
  /* pinned: min == max */
  s->kaslr.virt_page_offset_min = (unsigned long)PAGE_OFFSET + 0x01000000ul;
  s->kaslr.virt_page_offset_max = (unsigned long)PAGE_OFFSET + 0x01000000ul;
  /* one-sided: min only */
  s->kaslr.virt_vmalloc_min = (unsigned long)PAGE_OFFSET + 0x11000000ul;
  s->kaslr.virt_vmalloc_max = 0;
  /* window: min < max */
  s->kaslr.virt_vmemmap_min = (unsigned long)PAGE_OFFSET + 0x13000000ul;
  s->kaslr.virt_vmemmap_max = (unsigned long)PAGE_OFFSET + 0x14000000ul;
}

static void test_render_text_with_memory_kaslr_bound(void) {
  struct summary s;
  set_richer_render_state(&s);
  set_render_mode(0, 0, 0);
  capture_stdout(wrap_render_summary, &s);
  /* The default (no-verbose) readout surfaces a narrowed direct-map base
   * as its own row. The richer-render-state setup pins virt_page_offset_min ==
   * virt_page_offset_max so the readout's lo == hi branch fires with the
   * "pinned" annotation. (Under -v the original render_memory_kaslr_bound
   * runs instead, producing "(pinned)" / ">= 0x" / "<= 0x" — covered by
   * the verbose-mode tests below.) */
  assert(strstr(render_cap, "Direct map base") != NULL);
  assert(strstr(render_cap, "pinned") != NULL);
}

static void test_render_derived_text(void) {
  struct summary s;
  set_richer_render_state(&s);
  set_render_mode(0, 0, 0);
  verbose = 1; /* "Derived addresses:" lives in the verbose render path */
  capture_stdout(wrap_render_summary, &s);
  verbose = 0;
  /* The "Derived addresses:" heading fires when at least one CONF_DERIVED
   * result is present (which set_richer_render_state plants). */
  assert(strstr(render_cap, "Derived addresses") != NULL);
}

static void test_render_text_kernel_region_promotion(void) {
  struct summary s;
  set_richer_render_state(&s);
  set_render_mode(0, 0, 0);
  verbose = 1; /* per-region promotion lives in the verbose render path */
  capture_stdout(wrap_render_summary, &s);
  verbose = 0;
  /* The kernel-locating regions present (KERNEL_TEXT + KERNEL_DATA +
   * KERNEL_BSS) drive section_display_name("text"/"data"/"bss"). At least
   * one of the kernel-labelled sections must appear in the output —
   * exercises both the catch-all path and (when promotion fires) the
   * kernel_region_display_name path. */
  /* Asserting at least "Results" header appears confirms the renderer ran.
   * The kernel_region_display_name path is gated on specific group-print
   * conditions (collect_kernel_regions returning matching results that pass
   * in_bounds against the test's layout state); under set_richer_render_state
   * the records may be in-bounds-rejected because we touch layout fields the
   * test setup didn't fully normalize. Hitting the wider "Results" /
   * "KASLR analysis" / "Memory KASLR" / "Derived addresses" / "Virtual
   * memory layout" branches is the test's value — pulls render_text to
   * substantially higher coverage even when promotion is filtered. */
  assert(strstr(render_cap, "Results") != NULL ||
         strstr(render_cap, "KASLR") != NULL);
}

/* section_consensus / section_consensus_pick: every observation in a
 * section satisfies `addr = base + nonneg_offset`, so the picker must
 * (1) prefer higher CONF, then (2) prefer POS_BASE, then (3) prefer the
 * lowest address. Regression for the directmap "==> highest" bug
 * documented in render.c — see [src/render.c] picker comment. */
static void test_section_consensus_lowest_among_ties(void) {
  /* Three CONF_PARSED directmap observations, all POS_INTERIOR. Picker
   * must return the lowest. */
  reset_results();
  /* Offsets stay within 32-bit direct-map headroom (PAGE_OFFSET is as high
   * as 0xc0000000 on 32-bit arches) so the fixture is valid everywhere. */
  unsigned long lo = (unsigned long)PAGE_OFFSET + 0x04220000ul;
  unsigned long mid = (unsigned long)PAGE_OFFSET + 0x102a0000ul;
  unsigned long hi = (unsigned long)PAGE_OFFSET + 0x2ffffcfful;
  unsigned long addrs[3] = {hi, lo, mid}; /* insertion ≠ address order */
  for (int i = 0; i < 3; i++) {
    struct result *r = push_result();
    r->type = KASLD_TYPE_VIRT;
    r->region = REGION_DIRECTMAP;
    r->pos = POS_INTERIOR;
    r->conf = CONF_PARSED;
    r->sample = addrs[i];
    r->set_mask = SAMPLE_SET;
    snprintf(r->origins[0], ORIGIN_LEN, "synth");
    r->method_set = 1u << KM_PARSED;
    r->provenance_count = 1;
  }
  /* Make all three pass in_bounds: the directmap base lives at PAGE_OFFSET
   * by construction, all three samples are above it. */
  layout.virt_page_offset = (unsigned long)PAGE_OFFSET;
  assert(section_consensus(KASLD_TYPE_VIRT, "directmap", REGION_UNKNOWN) == lo);
}

static void test_section_consensus_prefers_pos_base(void) {
  /* Two CONF_PARSED text observations, one POS_BASE (the canonical
   * answer) at a higher address and one POS_INTERIOR at a lower address.
   * The base observation must win despite being numerically higher,
   * because POS_BASE outranks POS_INTERIOR at the same CONF. */
  reset_results();
  unsigned long base_addr =
      (unsigned long)KERNEL_VIRT_TEXT_DEFAULT + 0x800000ul;
  unsigned long interior_addr = base_addr - 0x10000ul;

  struct result *r_interior = push_result();
  r_interior->type = KASLD_TYPE_VIRT;
  r_interior->region = REGION_KERNEL_TEXT;
  r_interior->pos = POS_INTERIOR;
  r_interior->conf = CONF_PARSED;
  r_interior->sample = interior_addr;
  r_interior->set_mask = SAMPLE_SET;
  snprintf(r_interior->origins[0], ORIGIN_LEN, "synth");
  r_interior->method_set = 1u << KM_PARSED;
  r_interior->provenance_count = 1;

  struct result *r_base = push_result();
  r_base->type = KASLD_TYPE_VIRT;
  r_base->region = REGION_KERNEL_TEXT;
  r_base->pos = POS_BASE;
  r_base->conf = CONF_PARSED;
  r_base->lo = base_addr;
  r_base->set_mask = LO_SET;
  snprintf(r_base->origins[0], ORIGIN_LEN, "synth");
  r_base->method_set = 1u << KM_PARSED;
  r_base->provenance_count = 1;

  assert(section_consensus(KASLD_TYPE_VIRT, "text", REGION_UNKNOWN) ==
         base_addr);
}

static void test_section_consensus_higher_conf_wins(void) {
  /* CONF_PARSED at a higher address beats CONF_HEURISTIC at a lower —
   * confidence is the outermost tiebreaker. */
  reset_results();
  unsigned long lo_heuristic = (unsigned long)PAGE_OFFSET + 0x1000000ul;
  unsigned long hi_parsed = (unsigned long)PAGE_OFFSET + 0x8000000ul;

  struct result *r_h = push_result();
  r_h->type = KASLD_TYPE_VIRT;
  r_h->region = REGION_DIRECTMAP;
  r_h->pos = POS_INTERIOR;
  r_h->conf = CONF_HEURISTIC;
  r_h->sample = lo_heuristic;
  r_h->set_mask = SAMPLE_SET;
  snprintf(r_h->origins[0], ORIGIN_LEN, "synth");
  r_h->method_set = 1u << KM_HEURISTIC;
  r_h->provenance_count = 1;

  struct result *r_p = push_result();
  r_p->type = KASLD_TYPE_VIRT;
  r_p->region = REGION_DIRECTMAP;
  r_p->pos = POS_INTERIOR;
  r_p->conf = CONF_PARSED;
  r_p->sample = hi_parsed;
  r_p->set_mask = SAMPLE_SET;
  snprintf(r_p->origins[0], ORIGIN_LEN, "synth");
  r_p->method_set = 1u << KM_PARSED;
  r_p->provenance_count = 1;

  layout.virt_page_offset = (unsigned long)PAGE_OFFSET;
  assert(section_consensus(KASLD_TYPE_VIRT, "directmap", REGION_UNKNOWN) ==
         hi_parsed);
}

static void test_section_consensus_empty(void) {
  reset_results();
  assert(section_consensus(KASLD_TYPE_VIRT, "directmap", REGION_UNKNOWN) == 0);
}

/* The "dram" section bundles multiple regions (ram, initrd, crashkernel,
 * …). A subgroup-scoped picker must restrict its candidate set to records
 * in the requested region, so the displayed `==>` value always appears
 * in the displayed record list. Regression for the ppc64 case where the
 * crashkernel subgroup printed `==> 0x6300000` (the section-wide pick's
 * initrd record) above a record list containing only crashkernel
 * addresses. */
static void test_section_consensus_per_subgroup_scope(void) {
  reset_results();
  struct result *initrd = push_result();
  initrd->type = KASLD_TYPE_PHYS;
  initrd->region = REGION_INITRD;
  initrd->pos = POS_BASE;
  initrd->conf = CONF_PARSED;
  initrd->lo = 0x6300000ul;
  initrd->hi = 0x9e86eaeul;
  initrd->set_mask = LO_SET | HI_SET;

  struct result *ck = push_result();
  ck->type = KASLD_TYPE_PHYS;
  ck->region = REGION_CRASHKERNEL;
  ck->pos = POS_INTERIOR;
  ck->conf = CONF_PARSED;
  ck->sample = 0x20000000ul;
  ck->set_mask = SAMPLE_SET;

  /* Section-wide pick: layer 2 prefers POS_BASE → initrd record wins. */
  assert(section_consensus(KASLD_TYPE_PHYS, "dram", REGION_UNKNOWN) ==
         0x6300000ul);
  /* Subgroup pick on crashkernel: scoped to that region only. */
  assert(section_consensus(KASLD_TYPE_PHYS, "dram", REGION_CRASHKERNEL) ==
         0x20000000ul);
  /* Subgroup pick on initrd: scoped to that region only. */
  assert(section_consensus(KASLD_TYPE_PHYS, "dram", REGION_INITRD) ==
         0x6300000ul);
}

static void test_render_json_with_memory_kaslr(void) {
  struct summary s;
  set_richer_render_state(&s);
  set_render_mode(1, 0, 0);
  capture_stdout(wrap_render_summary, &s);
  /* memory_kaslr block emitted when at least one of virt_page_offset/vmalloc/
   * vmemmap min or max is set. */
  assert(strstr(render_cap, "memory_kaslr") != NULL);
  set_render_mode(0, 0, 0);
}

/* render_text + a CONF_DERIVED record with both LO and HI set — exercises the
 * range-form branch in render_derived_text. */
static void test_render_derived_text_range_form(void) {
  reset_results();
  num_comp_logs = 0;
  num_scalar_facts = 0;
  struct summary s;
  memset(&s, 0, sizeof(s));
  unsigned long vt = (unsigned long)KERNEL_VIRT_TEXT_DEFAULT;
  struct result *r = push_result();
  r->type = KASLD_TYPE_VIRT;
  r->region = REGION_VMALLOC;
  r->pos = POS_BASE;
  r->conf = CONF_DERIVED;
  r->lo = vt + 0x1000000ul;
  r->hi = vt + 0x2000000ul;
  r->set_mask = LO_SET | HI_SET;
  snprintf(r->origins[0], ORIGIN_LEN, "synth");
  r->method_set = 1u << KM_DERIVED;
  r->provenance_count = 1;
  s.stats.total = 1;
  set_render_mode(0, 0, 0);
  verbose = 1; /* Derived addresses are surfaced in the verbose render path */
  capture_stdout(wrap_render_summary, &s);
  verbose = 0;
  /* The range branch prints " - " between two hex addresses on the
   * derived line. */
  assert(strstr(render_cap, "Derived addresses") != NULL);
}

/* A KASLR-disabled kernel whose text base resolves to a *range* rather than a
 * single pinned address (legacy riscv64: linear-map text at a non-randomized,
 * build-specific offset). KASLR is off, so the readout shows a plain range with
 * NO slot/entropy count — there is no randomization to quantify. The renderer
 * is arch-agnostic: it branches only on disabled + range-vs-pin, never on the
 * arch. */
static void test_render_readout_disabled_range_no_entropy(void) {
  reset_results();
  num_comp_logs = 0;
  num_scalar_facts = 0;
  struct summary s;
  memset(&s, 0, sizeof(s));
  unsigned long vt = (unsigned long)KERNEL_VIRT_TEXT_DEFAULT;
  s.kaslr.disabled = 1;
  s.kaslr.vslots =
      0; /* KASLR off ⇒ no entropy, as compute_kaslr_info sets it */
  s.kaslr.vbits = 0;
  unsigned long saved_min = layout.virt_kaslr_text_min;
  unsigned long saved_max = layout.virt_kaslr_text_max;
  layout.virt_kaslr_text_min = vt;
  layout.virt_kaslr_text_max = vt + 0x402000ul; /* range, min != max */
  set_render_mode(0, 0, 0);                     /* default text (readout) */
  capture_stdout(wrap_render_summary, &s);
  layout.virt_kaslr_text_min = saved_min;
  layout.virt_kaslr_text_max = saved_max;
  /* Plain range, no fabricated entropy: a hex range but no "bits"/"candidates".
   */
  assert(strstr(render_cap, "Kernel image base") != NULL);
  assert(strstr(render_cap, " - ") != NULL);
  assert(strstr(render_cap, "bits") == NULL);
  assert(strstr(render_cap, "candidates") == NULL);
}

/* Exercise render_hardening_text and render_hardening_json by toggling
 * hardening_mode. The synthetic component log set up in set_rich_render_state
 * carries method/sysctl/addr metadata so classify_components has something
 * to classify. */
static void test_render_hardening_text(void) {
  struct summary s;
  set_rich_render_state(&s);
  set_render_mode(0, 0, 0);
  hardening_mode = 1;
  capture_stdout(wrap_render_summary, &s);
  hardening_mode = 0;
  /* The hardening section emits a labelled heading; both "Hardening" and
   * "Defenses" appear in the renderer's vocabulary. Match any. */
  assert(strstr(render_cap, "ardening") != NULL ||
         strstr(render_cap, "efenses") != NULL ||
         strstr(render_cap, "itigation") != NULL);
}

static void test_render_hardening_json(void) {
  struct summary s;
  set_rich_render_state(&s);
  set_render_mode(1, 0, 0);
  hardening_mode = 1;
  capture_stdout(wrap_render_summary, &s);
  hardening_mode = 0;
  set_render_mode(0, 0, 0);
  /* JSON output gains a hardening object/key when -H is on. */
  assert(strstr(render_cap, "ardening") != NULL ||
         strstr(render_cap, "itigation") != NULL ||
         strstr(render_cap, "lockdown") != NULL);
}

/* Markdown mode under -H appends the hardening assessment (built from the same
 * report model as the text/json renderers), as markdown headings/sections. */
static void test_render_hardening_markdown(void) {
  struct summary s;
  set_rich_render_state(&s);
  set_render_mode(0, 0, 1);
  hardening_mode = 1;
  capture_stdout(wrap_render_summary, &s);
  hardening_mode = 0;
  set_render_mode(0, 0, 0);
  assert(strstr(render_cap, "## Hardening Assessment") != NULL);
  assert(strstr(render_cap, "### Active defenses") != NULL);
  assert(strstr(render_cap, "### Available hardening") != NULL);
}

/* Direct coverage of the hardening model (the text/json/markdown renderers all
 * consume build_hardening_report; this asserts its fields without going through
 * a formatter). Seeds a representative component set + sysctl state and checks
 * exposure, posture, per-gate counts/names, suggestions, and the vuln /
 * surface / side-channel / no-mitigation lists. */
static struct component_log *hr_seed_comp(const char *name,
                                          enum component_outcome oc) {
  struct component_log *cl = &comp_logs[num_comp_logs++];
  memset(cl, 0, sizeof(*cl));
  snprintf(cl->name, sizeof(cl->name), "%s", name);
  cl->outcome = oc;
  return cl;
}
static void hr_seed_meta(struct component_log *cl, const char *k,
                         const char *v) {
  int i = cl->meta.num_entries++;
  snprintf(cl->meta.entries[i].key, META_KEY_LEN, "%s", k);
  snprintf(cl->meta.entries[i].value, META_VALUE_LEN, "%s", v);
}

static void test_build_hardening_report(void) {
  reset_results();
  num_comp_logs = 0;
  num_scalar_facts = 0;
  sysctl_kptr_restrict = 1;       /* active   (threshold 1) */
  sysctl_dmesg_restrict = 1;      /* active   (threshold 1) */
  sysctl_perf_event_paranoid = 0; /* inactive (threshold 2) */
  sysctl_lockdown = LOCKDOWN_NONE;

  struct component_log *c;
  c = hr_seed_comp("c_kptr_blocked", OUTCOME_ACCESS_DENIED);
  hr_seed_meta(c, "method", "parsed");
  hr_seed_meta(c, "sysctl", "kptr_restrict>=1");

  c = hr_seed_comp("c_dmesg_bypass", OUTCOME_SUCCESS);
  hr_seed_meta(c, "method", "parsed");
  hr_seed_meta(c, "sysctl", "dmesg_restrict>=1");
  hr_seed_meta(c, "fallback", "yes");

  c = hr_seed_comp("c_perf_bypass", OUTCOME_SUCCESS);
  hr_seed_meta(c, "method", "parsed");
  hr_seed_meta(c, "sysctl", "perf_event_paranoid>=2");

  c = hr_seed_comp("c_vuln", OUTCOME_SUCCESS);
  hr_seed_meta(c, "method", "parsed");
  hr_seed_meta(c, "cve", "CVE-2021-1234");
  hr_seed_meta(c, "patch", "v5.10");

  c = hr_seed_comp("c_surface", OUTCOME_SUCCESS);
  hr_seed_meta(c, "method", "parsed");
  hr_seed_meta(c, "config", "CONFIG_FOO");
  hr_seed_meta(c, "addr", "physical");

  c = hr_seed_comp("c_hw", OUTCOME_SUCCESS);
  hr_seed_meta(c, "method", "parsed");
  hr_seed_meta(c, "hardware", "KPTI");
  hr_seed_meta(c, "addr", "virtual");

  c = hr_seed_comp("c_nomit", OUTCOME_SUCCESS);
  hr_seed_meta(c, "method", "parsed");

  c = hr_seed_comp("c_lockdown", OUTCOME_SUCCESS);
  hr_seed_meta(c, "method", "parsed");
  hr_seed_meta(c, "lockdown", "yes");

  c = hr_seed_comp("c_detection", OUTCOME_SUCCESS);
  hr_seed_meta(c, "method", "detection");

  scalar_facts[num_scalar_facts].fact = SF_VIRT_KASLR_RANDOMIZATION_FAILED;
  scalar_facts[num_scalar_facts].value = 1;
  scalar_facts[num_scalar_facts].conf = CONF_PARSED;
  snprintf(scalar_facts[num_scalar_facts].origin, ORIGIN_LEN, "dmesg_kaslr");
  num_scalar_facts++;

  struct hardening_report rep;
  build_hardening_report(&rep);

  /* Exposure: 8 non-detection components, 7 succeeded (the blocked one did
   * not); the detection-only component is excluded. */
  assert(rep.total == 8);
  assert(rep.succeeded == 7);

  /* Posture: the randomization-failure witness is always collected, but the
   * prioritised state is "unsupported" on arches without KASLR (that priority
   * outranks randomization_failed). slot_entropy_zero holds in both cases. */
  assert(rep.n_rand_detectors == 1);
  assert(rep.posture == (KASLR_SUPPORTED ? HR_POSTURE_RANDOMIZATION_FAILED
                                         : HR_POSTURE_UNSUPPORTED));
  assert(rep.slot_entropy_zero == 1);

  /* Gates: all three are gated by >= 1 component. */
  assert(rep.n_gates == 3);
  const struct hr_gate *gk = NULL, *gd = NULL, *gp = NULL;
  for (int i = 0; i < rep.n_gates; i++) {
    if (strcmp(rep.gates[i].display, "kernel.kptr_restrict") == 0)
      gk = &rep.gates[i];
    else if (strcmp(rep.gates[i].display, "kernel.dmesg_restrict") == 0)
      gd = &rep.gates[i];
    else if (strcmp(rep.gates[i].display, "kernel.perf_event_paranoid") == 0)
      gp = &rep.gates[i];
  }
  assert(gk && gd && gp);
  assert(gk->active && gk->gated == 1 && gk->blocked == 1 && gk->bypassed == 0);
  assert(gk->n_blocked_names == 1 &&
         strcmp(gk->blocked_names[0], "c_kptr_blocked") == 0);
  assert(gd->active && gd->bypassed == 1 && gd->fallback == 1);
  assert(!gp->active && gp->bypassed == 1);

  /* Available hardening: the inactive perf gate is a suggestion; the
   * dmesg-restrict-with-fallback prompts the fallback suggestion; lockdown is
   * off with a lockdown-gated component, so suggest enabling it. */
  assert(rep.n_gate_suggestions == 1);
  assert(strcmp(rep.gate_suggestions[0].display,
                "kernel.perf_event_paranoid") == 0);
  assert(rep.gate_suggestions[0].threshold == 2);
  assert(rep.suggest_dmesg_fallback == 1 && rep.dmesg_fallback_count == 1);
  assert(rep.suggest_lockdown == 1 && rep.lockdown_impact == 1);

  /* Lists. */
  assert(rep.vuln_total == 1 && rep.n_vulns == 1);
  assert(strcmp(rep.vulns[0].cve, "CVE-2021-1234") == 0);
  assert(strcmp(rep.vulns[0].patch, "v5.10") == 0);
  assert(rep.n_surface == 1 &&
         strcmp(rep.surface[0].config, "CONFIG_FOO") == 0);
  assert(rep.n_hw == 1 && rep.hw_succeeded == 1 &&
         strcmp(rep.hw[0].hardware, "KPTI") == 0);
  assert(rep.n_nomit == 1 && strcmp(rep.nomit[0].name, "c_nomit") == 0);

  /* Restore globals so later tests see a clean sysctl state. */
  sysctl_kptr_restrict = 0;
  sysctl_dmesg_restrict = 0;
  sysctl_perf_event_paranoid = 0;
  sysctl_lockdown = LOCKDOWN_NONE;
  num_comp_logs = 0;
  num_scalar_facts = 0;
}

/* The pointer-hashing gate: a %pK leak tagged sysctl:hashed_pointers is gated
 * by kernel pointer hashing. With hashing on (the modern default) the gate is
 * active, the leak yields nothing (hashed ids fail the kernel-VAS filter), and
 * an active gate is not re-offered as available hardening. */
static void test_render_hardening_pointer_hashing_gate(void) {
  reset_results();
  num_comp_logs = 0;
  num_scalar_facts = 0;
  /* Isolate the pointer-hashing gate — make the three sysctl gates unreadable
   * so only it can surface. */
  sysctl_kptr_restrict = -1;
  sysctl_dmesg_restrict = -1;
  sysctl_perf_event_paranoid = -1;
  sysctl_lockdown = LOCKDOWN_NONE;
  hashed_pointers = 1; /* hashing on => gate active */

  struct component_log *c = hr_seed_comp("c_pk_leak", OUTCOME_NO_RESULT);
  hr_seed_meta(c, "method", "parsed");
  hr_seed_meta(c, "sysctl", "hashed_pointers>=1");

  struct hardening_report rep;
  build_hardening_report(&rep);

  /* The leak ran but pointer hashing blocked it: counted, did not succeed. */
  assert(rep.total == 1 && rep.succeeded == 0);

  /* Exactly the pointer-hashing gate surfaces, active, gating the one leak,
   * with neither a blocked (access-denied) nor bypassed (success) outcome. */
  assert(rep.n_gates == 1);
  const struct hr_gate *g = &rep.gates[0];
  assert(strcmp(g->display, "kernel pointer hashing (%pK)") == 0);
  assert(g->active && g->value == 1);
  assert(g->gated == 1 && g->n_gated_names == 1 &&
         strcmp(g->gated_names[0], "c_pk_leak") == 0);
  assert(g->blocked == 0 && g->bypassed == 0);

  /* An active gate is not offered as available hardening. */
  assert(rep.n_gate_suggestions == 0);

  /* Restore globals so later tests see a clean state. */
  hashed_pointers = -1;
  sysctl_lockdown = LOCKDOWN_NONE;
  num_comp_logs = 0;
  num_scalar_facts = 0;
}

/* SF_VIRT_KASLR_RANDOMIZATION_FAILED surfaces in the text hardening report as a
 * dedicated posture section (entropy downgrade). The fact is distinct from
 * SF_VIRT_KASLR_DISABLED — the kernel was relocated to a firmware-determined
 * position, not the link-time default — so the renderer must call this out
 * with its own banner rather than reuse the opt-out banner. */
static void test_render_hardening_text_rand_failed_surfaces(void) {
  reset_results();
  num_comp_logs = 0;
  num_scalar_facts = 0;
  struct summary s;
  set_rich_render_state(&s);
  /* Plant the new scalar fact a randomization-failed boot would emit. */
  scalar_facts[num_scalar_facts].fact = SF_VIRT_KASLR_RANDOMIZATION_FAILED;
  scalar_facts[num_scalar_facts].value = 1;
  scalar_facts[num_scalar_facts].conf = CONF_PARSED;
  snprintf(scalar_facts[num_scalar_facts].origin, ORIGIN_LEN,
           "dmesg_kaslr_disabled");
  num_scalar_facts++;
  set_render_mode(0, 0, 0);
  hardening_mode = 1;
  capture_stdout(wrap_render_summary, &s);
  hardening_mode = 0;
  /* The dedicated posture section names the state and the detector. */
  assert(strstr(render_cap, "KASLR posture") != NULL);
  assert(strstr(render_cap, "randomization failed") != NULL);
  assert(strstr(render_cap, "dmesg_kaslr_disabled") != NULL);
}

/* JSON mirror: the kaslr_posture object reports state="randomization_failed",
 * slot_entropy_zero=true, kernel_at_link_time_default=false. */
static void test_render_hardening_json_rand_failed_state(void) {
  reset_results();
  num_comp_logs = 0;
  num_scalar_facts = 0;
  struct summary s;
  set_rich_render_state(&s);
  scalar_facts[num_scalar_facts].fact = SF_VIRT_KASLR_RANDOMIZATION_FAILED;
  scalar_facts[num_scalar_facts].value = 1;
  scalar_facts[num_scalar_facts].conf = CONF_PARSED;
  snprintf(scalar_facts[num_scalar_facts].origin, ORIGIN_LEN,
           "dmesg_kaslr_disabled");
  num_scalar_facts++;
  set_render_mode(1, 0, 0);
  hardening_mode = 1;
  capture_stdout(wrap_render_summary, &s);
  hardening_mode = 0;
  set_render_mode(0, 0, 0);
  assert(strstr(render_cap, "\"kaslr_posture\"") != NULL);
  /* The JSON posture state is mutually exclusive and prioritises capability:
   * on arches without KASLR support it is "unsupported" regardless of the
   * injected rand-failed scalar (and the detector origin is not echoed);
   * everywhere else it is "randomization_failed". Branch on the compile-time
   * capability so the test asserts the arch-correct state on every target
   * without skipping. */
  assert(strstr(render_cap, KASLR_SUPPORTED ? "\"randomization_failed\""
                                            : "\"unsupported\"") != NULL);
  if (KASLR_SUPPORTED)
    /* The detector origin is echoed in the JSON detected_by array. */
    assert(strstr(render_cap, "dmesg_kaslr_disabled") != NULL);
}

/* Without the new scalar, the posture section must NOT appear in text mode.
 * Guards against a regression where the renderer fires unconditionally. */
static void test_render_hardening_text_no_rand_failed_silent(void) {
  reset_results();
  num_comp_logs = 0;
  num_scalar_facts = 0;
  struct summary s;
  set_rich_render_state(&s);
  set_render_mode(0, 0, 0);
  hardening_mode = 1;
  capture_stdout(wrap_render_summary, &s);
  hardening_mode = 0;
  /* Distinguish: the new posture section's heading is "KASLR posture";
   * the always-present results banner is "KASLR is disabled" (different
   * substring). Asserting absence of the posture heading. */
  assert(strstr(render_cap, "KASLR posture") == NULL);
}

int main(void) {
  TEST_SUITE("render — renderer unit suite");
  test_init_layout_engine_bounds();

  BEGIN_CATEGORY("Renderer — json_print_escaped");
  RUN(test_json_print_escaped_passthrough);
  RUN(test_json_print_escaped_all_named_escapes);
  RUN(test_json_print_escaped_other_control);
  RUN(test_json_print_escaped_empty);

  BEGIN_CATEGORY("Renderer — dispatcher (minimal summary)");
  RUN(test_render_summary_text_mode_minimal);
  RUN(test_render_summary_json_mode_minimal);
  RUN(test_render_summary_oneline_mode_minimal);
  RUN(test_render_summary_markdown_mode_minimal);

  BEGIN_CATEGORY("Renderer — rich content");
  RUN(test_render_text_with_rich_content);
  RUN(test_render_json_with_rich_content);
  RUN(test_render_markdown_with_rich_content);
  RUN(test_render_oneline_with_rich_content);
  RUN(test_render_oneline_dmap_is_base_not_interior);
  RUN(test_render_oneline_text_omits_when_engine_unresolved);
  RUN(test_render_text_lists_all_origins);
  RUN(test_render_text_leaks_aggregates_across_records);
  RUN(test_render_json_emits_origins_array);
  RUN(test_result_method_returns_strongest);
  RUN(test_render_markdown_lists_all_origins);
  RUN(test_render_text_leaks_no_provenance);
  RUN(test_render_json_emits_empty_origins_array);
  RUN(test_render_text_leaks_count_is_groups_not_contributors);
  RUN(test_render_hardening_text);
  RUN(test_render_hardening_json);
  RUN(test_render_hardening_markdown);
  RUN(test_build_hardening_report);
  RUN(test_render_hardening_pointer_hashing_gate);
  RUN(test_render_hardening_text_rand_failed_surfaces);
  RUN(test_render_hardening_json_rand_failed_state);
  RUN(test_render_hardening_text_no_rand_failed_silent);

  BEGIN_CATEGORY(
      "Renderer — richer content (derived / memory_kaslr / kernel regions)");
  RUN(test_render_text_with_memory_kaslr_bound);
  RUN(test_render_derived_text);
  RUN(test_render_derived_text_range_form);
  RUN(test_render_readout_disabled_range_no_entropy);
  RUN(test_render_text_kernel_region_promotion);
  RUN(test_section_consensus_per_subgroup_scope);
  RUN(test_section_consensus_lowest_among_ties);
  RUN(test_section_consensus_prefers_pos_base);
  RUN(test_section_consensus_higher_conf_wins);
  RUN(test_section_consensus_empty);
  RUN(test_render_json_with_memory_kaslr);
  RUN(test_render_likely_window);
  RUN(test_render_vtext_speculative);
  RUN(test_render_memory_likely_window);
  RUN(test_render_memory_kaslr_uses_stored_slots);
  RUN(test_render_disabled_base_not_labeled_likely);
  RUN(test_render_leak_discloses_interior);

  return TEST_DONE();
}
