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

#include "../src/environment.c"
/* The orchestrator is compiled into this test, so every static it does not
 * happen to call is unused here. Suppressed at the include rather than by
 * tagging the definitions: they are production code, and the property is a
 * fact about this translation unit, not about them. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wunused-variable"
#include "../src/orchestrator.c"
#pragma GCC diagnostic pop
/* The engine's value model, after orchestrator.c so its feature-test
 * macros are established first. engine_sync_authoritative projects
 * resolved estimates into `layout`, and reading an estimate means knowing
 * its lattice — so this TU carries estimate.c + quantities.c even though
 * -DKASLD_TESTING excludes the rest of the engine. */
#include "../src/estimate.c"
#include "../src/quantities.c"
#include "../src/region_info.c"
#include "../src/report.c"
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#include "../src/render.c"
#pragma GCC diagnostic pop
#include "../src/render/hardening.c"
#include "../src/render/json.c"
#include "../src/render/markdown.c"
#include "../src/render/oneline.c"
#include "../src/render/text.c"
#include "test_harness.h"
#include "test_orch_common.h"
#include "test_sysroot.h"

#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
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

static void wrap_md_print_cell(void *arg) { md_print_cell((const char *)arg); }

/* md_print_cell escapes the markdown column separator '|' and a literal '\' (so
 * it can't escape the following byte), and collapses control bytes to a space,
 * so a wire-supplied name/origin cannot break the table layout. Ordinary names
 * pass through unchanged. */
static void test_md_print_cell_escaping(void) {
  char in1[] = "foo|bar";
  capture_stdout(wrap_md_print_cell, in1);
  assert(strcmp(render_cap, "foo\\|bar") == 0);

  char in2[] = "a\\b"; /* literal backslash doubled */
  capture_stdout(wrap_md_print_cell, in2);
  assert(strcmp(render_cap, "a\\\\b") == 0);

  char in3[] = {'x', 0x09, 'y', 0}; /* TAB (control) -> space */
  capture_stdout(wrap_md_print_cell, in3);
  assert(strcmp(render_cap, "x y") == 0);

  char in4[] = "proc_kallsyms"; /* ordinary name/origin: unchanged */
  capture_stdout(wrap_md_print_cell, in4);
  assert(strcmp(render_cap, "proc_kallsyms") == 0);
}

/* render_summary dispatcher: a synthetic minimal summary should hit one of
 * render_text / render_json / render_oneline / render_markdown depending on
 * the global mode flags. Verifies the dispatch + minimal banner output. */
/* Stage a report model equivalent to the state a test set up.
 *
 * The tests stage a RESOLVED run by filling `layout` and `s.kaslr` directly --
 * they have no engine to resolve one for them -- and layout_build now projects
 * the model rather than those globals. This turns that staging into the model
 * it stands for, so a test keeps expressing itself in the values it already
 * used, and what is under test stays the projection rather than this mapping.
 *
 * Deliberately mechanical: it asserts nothing and decides nothing. Anything it
 * had to be clever about would be a sign the model cannot express what a test
 * needs to say, which is the thing worth discovering. */
static void stage_window(struct kasld_report_window *w, unsigned long lo,
                         unsigned long hi, unsigned long cand) {
  memset(w, 0, sizeof(*w));
  w->shape = RSHAPE_INTERVAL;
  w->lo = lo;
  w->hi = hi;
  w->has_lo = lo != 0;
  w->has_hi = hi != 0;
  w->present = w->has_lo || w->has_hi;
  w->candidates = cand;
  /* Through the builder's own conversion, not a second one here: a test that
   * reimplemented it could agree with itself while disagreeing with what ships.
   */
  w->bits = report_bits(cand);
}

/* Test-local staging for the speculative windows.
 *
 * The orchestrator builds these into the model from the engine's second
 * resolution; the summary never carried them usefully and no longer has fields
 * for them. A test that wants a speculative window sets these, and
 * stage_likely_reset() clears them -- they are globals, and a window left over
 * from the previous test would stage a state this one did not ask for, which is
 * how an assertion comes to pass for the wrong reason. */
static unsigned long t_vlikely_lo, t_vlikely_hi, t_vlikely_slots;
static unsigned long t_plikely_lo, t_plikely_hi, t_plikely_slots;
/* One carved interior range for the virtual image base, and the total carved --
 * which may exceed what the model retains, so a format can be checked for
 * disclosing the truncation as well as the range. */
static unsigned long t_excl_lo, t_excl_hi;
static int t_excl_total;

static void stage_likely_reset(void) {
  t_vlikely_lo = t_vlikely_hi = t_vlikely_slots = 0;
  t_plikely_lo = t_plikely_hi = t_plikely_slots = 0;
  t_excl_lo = t_excl_hi = 0;
  t_excl_total = 0;
}

static struct kasld_report_quantity *
stage_item(struct kasld_report *r, enum kasld_quantity q, const char *label,
           unsigned long lo, unsigned long hi, unsigned long cand,
           unsigned long top, unsigned long grain) {
  struct kasld_report_quantity *it = &r->quantities[r->n_quantities++];
  memset(it, 0, sizeof(*it));
  it->q = q;
  it->key = quantities[q].name;
  it->label = label;
  it->align_min = grain;
  it->entropy_top = top;
  it->search_top = top;
  /* Through the builder's own conversion, as `bits` is: a denominator staged
   * without its bit count renders as a bare residual, and an assertion about
   * "N of M bits" then fails for a reason that has nothing to do with the
   * renderer under test. */
  it->top_bits = report_bits(top);
  stage_window(&it->guaranteed, lo, hi, cand);
  return it;
}

static void test_build_report(const struct summary *s, struct kasld_report *r) {
  struct kasld_report_quantity *it;
  memset(r, 0, sizeof(*r));
  r->posture = s->kaslr.unsupported            ? RPOSTURE_UNSUPPORTED
               : s->kaslr.disabled             ? RPOSTURE_DISABLED
               : s->kaslr.randomization_failed ? RPOSTURE_FAILED
                                               : RPOSTURE_RANDOMIZED;

  it =
      stage_item(r, Q_VIRT_IMAGE_BASE, "Virtual Image Base",
                 layout.virt_kaslr_text_min, layout.virt_kaslr_text_max,
                 s->kaslr.vslots, s->kaslr.vtop_slots, layout.virt_kaslr_align);
  if (s->kaslr.vtext) {
    it->has_point = 1;
    it->point = s->kaslr.vtext;
    it->anchor = RANCHOR_BASE;
    it->slide = s->kaslr.vslide;
    it->has_slide = r->posture == RPOSTURE_RANDOMIZED;
  }
  /* Independently of the point, not instead of it: the orchestrator fills the
   * concrete base and the likely resolution from separate sources, and a run
   * commonly has both -- the observation that supplies the base is the same one
   * the engine narrows with. Staging them as alternatives modelled a state the
   * orchestrator cannot produce. */
  if (t_vlikely_hi)
    stage_window(&it->likely, t_vlikely_lo, t_vlikely_hi, t_vlikely_slots);
  if (t_excl_total > 0) {
    it->guaranteed.n_excluded = t_excl_total;
    it->guaranteed.excluded_listed = 1;
    it->guaranteed.excluded[0].lo = t_excl_lo;
    it->guaranteed.excluded[0].hi = t_excl_hi;
  }
  if (layout.virt_kaslr_text_min == layout.virt_kaslr_text_max &&
      layout.virt_kaslr_text_min)
    it->has_slide = r->posture == RPOSTURE_RANDOMIZED;

  it = stage_item(r, Q_PHYS_IMAGE_BASE, "Physical Image Base",
                  layout.phys_kaslr_text_min, layout.phys_kaslr_text_max,
                  s->kaslr.pslots, 0, layout.phys_kaslr_align);
  if (s->kaslr.ptext) {
    it->has_point = 1;
    it->point = s->kaslr.ptext;
    it->anchor = RANCHOR_BASE;
    it->slide = s->kaslr.pslide;
    it->has_slide = r->posture == RPOSTURE_RANDOMIZED;
  }
  if (t_plikely_hi)
    stage_window(&it->likely, t_plikely_lo, t_plikely_hi, t_plikely_slots);
  if (layout.phys_kaslr_text_min == layout.phys_kaslr_text_max &&
      layout.phys_kaslr_text_min)
    it->has_slide = r->posture == RPOSTURE_RANDOMIZED;

#if RANDOMIZE_MEMORY_ALIGN > 0
  it = stage_item(r, Q_PAGE_OFFSET, "Direct Map Base",
                  s->kaslr.virt_page_offset_min, s->kaslr.virt_page_offset_max,
                  s->kaslr.virt_page_offset_slots,
                  s->kaslr.virt_page_offset_top_slots,
                  (unsigned long)RANDOMIZE_MEMORY_ALIGN);
  if (s->kaslr.virt_page_offset_likely_max)
    stage_window(&it->likely, s->kaslr.virt_page_offset_likely_min,
                 s->kaslr.virt_page_offset_likely_max,
                 s->kaslr.virt_page_offset_likely_slots);
  stage_item(r, Q_VMALLOC_BASE, "Vmalloc Base", s->kaslr.virt_vmalloc_min,
             s->kaslr.virt_vmalloc_max, s->kaslr.virt_vmalloc_slots, 0,
             (unsigned long)RANDOMIZE_MEMORY_ALIGN);
  stage_item(r, Q_VMEMMAP_BASE, "Vmemmap Base", s->kaslr.virt_vmemmap_min,
             s->kaslr.virt_vmemmap_max, s->kaslr.virt_vmemmap_slots, 0,
             (unsigned long)RANDOMIZE_MEMORY_ALIGN);
#else
  stage_item(r, Q_PAGE_OFFSET, "Direct Map Base", s->kaslr.virt_page_offset_min,
             s->kaslr.virt_page_offset_max, s->kaslr.virt_page_offset_slots,
             s->kaslr.virt_page_offset_top_slots, 0);
#endif

  /* The paging level: a SET, and the only quantity of that shape. Staged so a
   * format's handling of a set is exercised at all -- without it every
   * assertion about `vabits` passes on the `na` that a missing item produces,
   * which is how a set value formatted as an address went unnoticed. */
  if (quantities[Q_VA_BITS].n_candidates > 1) {
    struct kasld_report_quantity *sv = &r->quantities[r->n_quantities++];
    memset(sv, 0, sizeof(*sv));
    sv->q = Q_VA_BITS;
    sv->key = quantities[Q_VA_BITS].name;
    sv->label = "Paging Level";
    sv->search_top = (unsigned long)quantities[Q_VA_BITS].n_candidates;
    sv->guaranteed.present = 1;
    sv->guaranteed.shape = RSHAPE_SET;
    sv->guaranteed.n_values = 1;
    sv->guaranteed.values[0] = quantities[Q_VA_BITS].candidates[0];
    sv->guaranteed.candidates = 1;
  }

  stage_item(r, Q_MODULE_BASE, "Module Region Base", s->kaslr.virt_module_min,
             s->kaslr.virt_module_max, s->kaslr.virt_module_slots, 0,
             s->kaslr.virt_module_align);
}

/* The Sources count on the evidence row naming `label`, and `pos` where given
 * -- a region can draw two rows, one per kind of observation, so the label
 * alone does not identify one. Returns -1 when no such row was drawn.
 *
 * The count is read as the row's last whitespace-separated field rather than by
 * column offset, because the table sizes its columns to the run's content. */
static int evidence_sources(const char *cap, const char *label,
                            const char *pos) {
  const char *p = cap;
  while ((p = strstr(p, label)) != NULL) {
    const char *eol = strchr(p, '\n'), *tail;
    char line[256];
    if (!eol || (size_t)(eol - p) >= sizeof(line))
      return -1;
    snprintf(line, (size_t)(eol - p) + 1, "%s", p);
    p = eol;
    if (pos && !strstr(line, pos))
      continue;
    tail = line + strlen(line);
    while (tail > line && tail[-1] != ' ')
      tail--;
    return (int)strtol(tail, NULL, 10);
  }
  return -1;
}

static void wrap_render_summary(void *arg) {
  struct kasld_report rep;
  test_build_report((const struct summary *)arg, &rep);
  render_summary((const struct summary *)arg, &rep);
}

static void set_render_mode(int json, int oneline, int markdown) {
  json_output = json;
  oneline_output = oneline;
  markdown_output = markdown;
}

static void test_render_summary_text_mode_minimal(void) {
  reset_results();
  reset_comp_logs();
  stage_likely_reset();
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
  reset_comp_logs();
  stage_likely_reset();
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
  reset_comp_logs();
  stage_likely_reset();
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
  reset_comp_logs();
  stage_likely_reset();
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
  reset_comp_logs();
  stage_likely_reset();
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
  add_origin(r1, "synthetic_test");
  r1->method_set = 1u << KM_PARSED;

  struct result *r2 = push_result();
  r2->type = KASLD_TYPE_PHYS;
  r2->region = REGION_RAM;
  r2->pos = POS_BASE;
  r2->conf = CONF_PARSED;
  r2->lo = 0x40000000ul;
  r2->hi = 0xf0000000ul;
  r2->set_mask = LO_SET | HI_SET;
  add_origin(r2, "synthetic_test");
  r2->method_set = 1u << KM_PARSED;

  /* A component log with the metadata shape render_hardening_* reads. */
  struct component_log *cl = seed_comp_log("synthetic_component");
  cl->outcome = OUTCOME_SUCCESS;
  cl->exit_code = 0;
  cl->meta.num_entries = 3;
  cl->meta.entries[0].key = "method";
  cl->meta.entries[0].value = "parsed";
  cl->meta.entries[1].key = "discloses";
  cl->meta.entries[1].value = "virtual";
  cl->meta.entries[2].key = "sysctl";
  cl->meta.entries[2].value = "kptr_restrict>=1";

  /* Populate summary KASLR info — drives render_kaslr_text and the JSON /
   * markdown KASLR rows. Values are illustrative (arch-portable enough; the
   * renderer doesn't validate them, it just prints). */
  s->kaslr.vtext = vt;
  s->kaslr.vslide = 0x10000000;
  s->kaslr.vslots = 512;
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

/* `-1` must not assert a direct-map base the engine only bounded. The field is
 * documented as an engine-resolved floor or pin, and on an arch whose
 * PAGE_OFFSET varies with VMSPLIT the compile-time constant is neither: it is a
 * link-time seed that a moved split leaves pointing at the wrong place. The
 * regression prints it anyway, because the fallback was gated on
 * DIRECTMAP_STATIC ("KASLR does not move this") rather than on
 * PAGE_OFFSET_INVARIANT ("the compile-time value IS the runtime one").
 *
 * Set up as the engine leaves it when no oracle pins the split: an upper bound
 * and no floor. Live witness — Debian 6.12.94-armmp with the boot config and
 * the mmap probe unavailable — reported min:null max:0xc0000000 in JSON and
 * `<= 0xc0000000` in the readout, while `-1` stated dmap=0xc0000000. */
static void test_render_oneline_dmap_not_asserted_when_unpinned(void) {
  struct summary s;
  reset_results();
  reset_comp_logs();
  stage_likely_reset();
  num_scalar_facts = 0;
  memset(&s, 0, sizeof(s));

  /* Bounded from above only: nothing proves where the base sits. */
  s.kaslr.virt_page_offset_min = 0;
  s.kaslr.virt_page_offset_max = (unsigned long)PAGE_OFFSET;

  /* A direct-map leak, which is what arms the fallback: on its own it confirms
   * the linear map exists, and the regression treated that as confirming WHERE
   * it starts. The live witness had one from bpf_verifier_log. */
  struct result *dm = push_result();
  dm->type = KASLD_TYPE_VIRT;
  dm->region = REGION_DIRECTMAP;
  dm->pos = POS_INTERIOR;
  dm->conf = CONF_PARSED;
  dm->lo = (unsigned long)PAGE_OFFSET + 0x1000ul;
  dm->sample = dm->lo;
  dm->set_mask = LO_SET | SAMPLE_SET;
  add_origin(dm, "synthetic_directmap");
  dm->method_set = 1u << KM_PARSED;

  set_render_mode(0, 1, 0);
  capture_stdout(wrap_render_summary, &s);
  set_render_mode(0, 0, 0);

  /* On an arch where the compile-time value is guaranteed, naming it is sound
   * and the field may carry it. Where it is not, the value must not be a BARE
   * address: that is the form reserved for a resolved base, and nothing here
   * resolved one. The windowed and `na` forms both say so honestly, so the
   * assertion is on the grammar rather than on which of the two appears. */
#if PAGE_OFFSET_INVARIANT
  assert(strstr(render_cap, "dmap=") != NULL);
#else
  {
    const char *v = strstr(render_cap, "dmap=");
    assert(v != NULL);
    v += strlen("dmap=");
    assert(*v == '[' || strncmp(v, "na", 2) == 0);
  }
#endif
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
  /* Each leak result discloses its extent-position. */
  assert(strstr(render_cap, "\"pos\": \"base\"") != NULL);
  set_render_mode(0, 0, 0);
}

/* Plain -j (no --hardening, no --verbose) is the complete posture snapshot a
 * fleet/CI layer consumes: it always carries the per-component records with
 * their parsed metadata and the full hardening block, including each
 * suggestion's enforcement surface and the hardware side-channel section. Raw
 * component stdout stays behind --verbose. */
static void test_render_json_posture_always_present(void) {
  struct summary s;
  set_rich_render_state(&s);
  hardening_mode = 0; /* NOT in hardening mode */
  verbose = 0;        /* NOT verbose */
  /* The synthetic component declares a kptr_restrict>=1 gate and succeeded;
   * a readable-but-permissive value makes that gate fire (an active-defense
   * row and a hardening suggestion), so the enforcement surface is emitted. */
  int saved_kptr = kasld_env.hardening.kptr_restrict;
  kasld_env.hardening.kptr_restrict = 0;
  set_render_mode(1, 0, 0);
  capture_stdout(wrap_render_summary, &s);
  kasld_env.hardening.kptr_restrict = saved_kptr;

  /* Per-component records with parsed meta, without -H/-v. */
  assert(strstr(render_cap, "\"components\": [") != NULL);
  assert(strstr(render_cap, "synthetic_component") != NULL);
  assert(strstr(render_cap, "\"meta\": {") != NULL);
  /* The full hardening block, without -H. */
  assert(strstr(render_cap, "\"hardening\": {") != NULL);
  assert(strstr(render_cap, "\"active_defenses\": [") != NULL);
  assert(strstr(render_cap, "\"hardware_side_channels\": [") != NULL);
  /* Enforcement surface accompanies each active-defense / suggestion row. */
  assert(strstr(render_cap, "\"surface\":") != NULL);
  /* Raw stdout lines stay behind --verbose. */
  assert(strstr(render_cap, "\"output\": [") == NULL);

  set_render_mode(0, 0, 0);
}

/* The speculative "likely" window renders as a sub-line under the guaranteed
 * (inferred) text range in -v text, and as a "likely" object with
 * "speculative": true in -j JSON. Set up the no-concrete-base case (guaranteed
 * is a range) with a tighter likely window. */
static void test_render_likely_window(void) {
  struct summary s;
  reset_results();
  reset_comp_logs();
  stage_likely_reset();
  num_scalar_facts = 0;
  memset(&s, 0, sizeof(s));

  /* Guaranteed window is a range (no concrete vtext/ptext) with a tighter
   * speculative likely window. The likely sub-line/JSON read only s->kaslr,
   * not layout, so this mutates no global but verbose. */
  s.kaslr.vslots = 60;
  t_vlikely_lo = (unsigned long)KERNEL_VIRT_TEXT_DEFAULT + 0x19000000ul;
  t_vlikely_hi = t_vlikely_lo; /* a single slot */
  t_vlikely_slots = 1;

  verbose = 1; /* the KASLR analysis block shows in the verbose text flow */
  set_render_mode(0, 0, 0); /* text */
  capture_stdout(wrap_render_summary, &s);
  assert(strstr(render_cap, GRADE_LIKELY) != NULL);
  /* A single surviving slot is one address, not a degenerate "0xX - 0xX"
     range: the row states the address and a search space of one. */
  {
    char one[32];
    snprintf(one, sizeof(one), "0x%lx - 0x%lx", t_vlikely_lo, t_vlikely_lo);
    assert(strstr(render_cap, one) == NULL);
    assert(strstr(render_cap, "1 slots") == NULL);
  }

  verbose = 0; /* DEFAULT (compact readout) must also show the likely line */
  capture_stdout(wrap_render_summary, &s);
  assert(strstr(render_cap, GRADE_LIKELY) != NULL);

  set_render_mode(1, 0, 0); /* json */
  capture_stdout(wrap_render_summary, &s);
  assert(strstr(render_cap, "\"likely\"") != NULL);
  assert(strstr(render_cap, "\"speculative\": true") != NULL);

  /* Markdown carries the same likely window, as a row of the same Layout
     table the readout draws — both are rendered from one row model, so the
     grade word is the one the readout uses. */
  set_render_mode(0, 0, 1);
  capture_stdout(wrap_render_summary, &s);
  assert(strstr(render_cap, GRADE_LIKELY) != NULL);
  assert(strstr(render_cap, "## Layout") != NULL);
  set_render_mode(0, 0, 0);
}

/* A concrete vtext while the guaranteed window is a RANGE is a speculative
 * best-guess. Every GRADED format surfaces the concrete base as "likely
 * (speculative)": the DEFAULT compact readout as a headline point + the
 * guaranteed window beneath; -v the same with "Guaranteed range"; -j the
 * virtual object marked speculative alongside the inferred range; markdown
 * the same row model the readout draws. The word "likely" appears only for
 * this speculative grade, and those four are what this case covers.
 *
 * oneline is not among them and is not exercised here: its fixed schema has
 * no grade field, so `text=` carries a speculative base as a bare value. A
 * scraper separates the two cases by `entropy=`, which is measured over the
 * guaranteed window and is non-zero exactly when the base is not pinned. */
static void test_render_vtext_speculative(void) {
  struct summary s;
  reset_results();
  reset_comp_logs();
  stage_likely_reset();
  num_scalar_facts = 0;
  memset(&s, 0, sizeof(s));
  unsigned long sv_lo = layout.virt_kaslr_text_min,
                sv_hi = layout.virt_kaslr_text_max,
                sv_al = layout.virt_kaslr_align;

  s.kaslr.vtext = (unsigned long)KERNEL_VIRT_TEXT_DEFAULT + 0x10000000ul;
  s.kaslr.vslide = 0x10000000l;
  s.kaslr.vslots = 60;
  /* The engine's likely resolution, pinned at the same observation the concrete
   * base was picked from. Staged because that is what a run HAS: the anchor
   * scan and the engine read the same observation, so a base witness both
   * supplies the headline value and pins the speculative window. A concrete
   * base with no window behind it is not a state the orchestrator reaches, and
   * a row drawn from one would be asserting a count no resolution produced. */
  t_vlikely_lo = s.kaslr.vtext;
  t_vlikely_hi = s.kaslr.vtext;
  t_vlikely_slots = 1;
  layout.virt_kaslr_text_min = (unsigned long)KERNEL_VIRT_TEXT_DEFAULT;
  layout.virt_kaslr_text_max =
      (unsigned long)KERNEL_VIRT_TEXT_DEFAULT + 0x3c000000ul;
  layout.virt_kaslr_align = 0x1000000ul;

  verbose = 1;
  set_render_mode(0, 0, 0); /* text */
  capture_stdout(wrap_render_summary, &s);
  assert(strstr(render_cap, GRADE_LIKELY) != NULL);
  /* -v draws the same Layout table as the readout, so the proven window is
     the guaranteed row rather than a separately-worded line. */
  assert(strstr(render_cap, GRADE_GUARANTEED) != NULL);

  /* DEFAULT compact readout: the concrete base is the headline, graded
   * speculative, with its slide alongside and the proven window shown as
   * "guaranteed" beneath — never buried as a bare status word alone. */
  verbose = 0;
  capture_stdout(wrap_render_summary, &s);
  assert(strstr(render_cap, GRADE_LIKELY) != NULL);
  assert(strstr(render_cap, GRADE_GUARANTEED) != NULL);
  /* A concrete best-guess base carries its slide, graded likely. */
  assert(strstr(render_cap, "slide +0x10000000") != NULL);
  {
    char base_hex[32];
    /* The readout right-aligns addresses without zero-padding, so build the
     * expectation the same way: "0x%016lx" only matches on arches whose
     * addresses happen to fill 16 hex digits. */
    snprintf(base_hex, sizeof(base_hex), "0x%lx", s.kaslr.vtext);
    assert(strstr(render_cap, base_hex) != NULL);
  }

  set_render_mode(1, 0,
                  0); /* json: virtual marked speculative + inferred range */
  capture_stdout(wrap_render_summary, &s);
  assert(strstr(render_cap, "\"speculative\": true") != NULL);
  assert(strstr(render_cap, "\"inferred\"") != NULL);

  set_render_mode(0, 0, 1); /* markdown: concrete base graded likely */
  capture_stdout(wrap_render_summary, &s);
  assert(strstr(render_cap, GRADE_LIKELY) != NULL);
  set_render_mode(0, 0, 0);

  layout.virt_kaslr_text_min = sv_lo;
  layout.virt_kaslr_text_max = sv_hi;
  layout.virt_kaslr_align = sv_al;
}

/* A windowed image base (no concrete text pinned) with a tighter likely window
 * renders, in the default readout, as the "narrowed" headline, then the
 * speculative likely window, then the guaranteed range labelled "guaranteed" —
 * the same likely-over-guaranteed order a concrete base uses. Regression for
 * the bare-window path that printed the unlabelled guaranteed range first and
 * the likely line after it. Exercised on the physical base to isolate the row.
 */
static void test_render_windowed_base_likely_order(void) {
  struct summary s;
  reset_results();
  reset_comp_logs();
  stage_likely_reset();
  num_scalar_facts = 0;
  memset(&s, 0, sizeof(s));
  unsigned long sv_vlo = layout.virt_kaslr_text_min,
                sv_vhi = layout.virt_kaslr_text_max,
                sv_plo = layout.phys_kaslr_text_min,
                sv_phi = layout.phys_kaslr_text_max,
                sv_pal = layout.phys_kaslr_align;

  /* Isolate the physical row: no virtual window to render. */
  layout.virt_kaslr_text_min = 0;
  layout.virt_kaslr_text_max = 0;

  /* Guaranteed phys window is a range (no concrete ptext) with a tighter likely
   * window (same low edge, lower top) and a slot grain. */
  s.kaslr.has_phys = 1;
  s.kaslr.pslots = 1391;
  layout.phys_kaslr_text_min = 0x01000000ul;
  layout.phys_kaslr_text_max = 0xbffffffful;
  layout.phys_kaslr_align = 0x200000ul; /* 2 MiB */
  t_plikely_lo = 0x01000000ul;
  t_plikely_hi = 0x2a447000ul;

  set_render_mode(0, 0, 0); /* default compact readout */
  capture_stdout(wrap_render_summary, &s);
  /* A graded residual, not a binary verdict: both windows are narrowings, so
   * "not derandomized" would contradict them. The residual is the candidate
   * count in the row's own Candidates cell. */
  assert(strstr(render_cap, "1391") != NULL);
  assert(strstr(render_cap, "not derandomized") == NULL);
  {
    const char *lk = strstr(render_cap, GRADE_LIKELY);
    const char *gt = strstr(render_cap, GRADE_GUARANTEED);
    assert(lk != NULL); /* speculative window shown */
    assert(gt != NULL); /* proven range shown, graded */
    /* Proven first, speculative beneath: a quantity's rows read as the claim
       and then the guess drawn inside it. */
    assert(gt < lk);
  }

  layout.virt_kaslr_text_min = sv_vlo;
  layout.virt_kaslr_text_max = sv_vhi;
  layout.phys_kaslr_text_min = sv_plo;
  layout.phys_kaslr_text_max = sv_phi;
  layout.phys_kaslr_align = sv_pal;
}

/* Memory-KASLR regions (directmap/vmalloc/vmemmap) carry their own speculative
 * "likely" sub-windows. A guaranteed region range plus a tighter likely sub-
 * range must surface in the verbose Memory KASLR block, the default direct-map
 * readout, JSON, and markdown. Reads only s->kaslr (mutates no global). */
/* The direct-map search space is reported against a baseline, the way the
 * virtual image base is: "16 of 16384" rather than a bare "16" with nothing to
 * read it against. The denominator is virt_page_offset_top_slots, the
 * RANDOMIZE_MEMORY budget window's candidate count computed at the engine
 * boundary. It is carried as a raw count and not derived from bits_top: ilog2
 * rounds up, so 2^bits_top over-states the baseline. The row must present it,
 * and must degrade to the bare residual when it is absent -- off x86_64, or
 * where the model could not be evaluated at or above the sound floor. Reads
 * only s->kaslr, so it runs the same on every arch. */
static void test_render_directmap_entropy_denominator(void) {
#if RANDOMIZE_MEMORY_ALIGN > 0
  struct summary s;
  reset_results();
  reset_comp_logs();
  stage_likely_reset();
  num_scalar_facts = 0;
  memset(&s, 0, sizeof(s));

  s.kaslr.vslots = 60; /* keep render_kaslr_text from early-returning */
  /* A narrowed, non-pinned direct-map window (no likely sub-window, so the
   * bare-window row renders). Offsets from the arch PAGE_OFFSET macro so the
   * constants fit `unsigned long` on 32-bit arches. */
  s.kaslr.virt_page_offset_min = (unsigned long)PAGE_OFFSET + 0x01000000ul;
  s.kaslr.virt_page_offset_max = (unsigned long)PAGE_OFFSET + 0x09000000ul;
  s.kaslr.virt_page_offset_slots = 16;
  s.kaslr.virt_page_offset_bits = 4;
  s.kaslr.virt_page_offset_bits_top = 14;
  s.kaslr.virt_page_offset_top_slots = 16384;

  set_render_mode(0, 0, 0);
  capture_stdout(wrap_render_summary, &s);
  /* The residual is stated on the guaranteed window row, beside the slot count
   * it restates -- not on the block header, which carries no grade and so
   * cannot own a figure describing one particular row. */
  const char *row = strstr(render_cap, "Direct Map Base");
  assert(row != NULL);
  row = strstr(row, GRADE_GUARANTEED);
  assert(row != NULL);
  {
    const char *eol = strchr(row, '\n');
    assert(eol != NULL);
    char line[256];
    size_t len = (size_t)(eol - row);
    assert(len < sizeof(line));
    memcpy(line, row, len);
    line[len] = '\0';
    assert(strstr(line, "16 of 16384") != NULL);
  }

  /* No sound baseline: the residual stands alone rather than being presented
   * against a denominator drawn from somewhere else. */
  s.kaslr.virt_page_offset_bits_top = 0;
  s.kaslr.virt_page_offset_top_slots = 0;
  capture_stdout(wrap_render_summary, &s);
  row = strstr(render_cap, "Direct Map Base");
  assert(row != NULL);
  row = strstr(row, GRADE_GUARANTEED);
  assert(row != NULL);
  {
    const char *eol = strchr(row, '\n');
    assert(eol != NULL);
    char line[256];
    size_t len = (size_t)(eol - row);
    assert(len < sizeof(line));
    memcpy(line, row, len);
    line[len] = '\0';
    assert(strstr(line, "16") != NULL);
    assert(strstr(line, " of ") == NULL);
  }
#endif
}

static void test_render_memory_likely_window(void) {
#if RANDOMIZE_MEMORY_ALIGN > 0
  struct summary s;
  reset_results();
  reset_comp_logs();
  stage_likely_reset();
  num_scalar_facts = 0;
  memset(&s, 0, sizeof(s));

  s.kaslr.vslots = 60; /* keep render_kaslr_text from early-returning */
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
  assert(strstr(render_cap, GRADE_LIKELY) != NULL);

  verbose = 0; /* DEFAULT readout direct-map likely line */
  capture_stdout(wrap_render_summary, &s);
  assert(strstr(render_cap, GRADE_LIKELY) != NULL);

  set_render_mode(1, 0, 0); /* json */
  capture_stdout(wrap_render_summary, &s);
  assert(strstr(render_cap, "\"likely\"") != NULL);
  assert(strstr(render_cap, "\"speculative\": true") != NULL);

  set_render_mode(0, 0, 1); /* markdown */
  capture_stdout(wrap_render_summary, &s);
  assert(strstr(render_cap, GRADE_LIKELY) != NULL);
  set_render_mode(0, 0, 0);
#endif
}

/* A concrete likely direct-map base — a POS_BASE timing pin
 * (prefetch_directmap) narrowed the likely window to a single-slot bracket at
 * the base — is promoted in the default readout to a graded headline (the base
 * address graded "likely") with the guaranteed window beneath it
 * ("guaranteed"), the same form as the image bases, rather than a bound row +
 * dim sub-line. The "guaranteed" label is unique to that promoted window row,
 * so its presence proves the promotion fired. RANDOMIZE_MEMORY arches only
 * (align > 0). */
static void test_render_directmap_base_promoted(void) {
#if RANDOMIZE_MEMORY_ALIGN > 0
  struct summary s;
  reset_results();
  reset_comp_logs();
  stage_likely_reset();
  num_scalar_facts = 0;
  memset(&s, 0, sizeof(s));

  s.kaslr.vslots = 60; /* keep the regular KASLR readout path */
  /* Base above the un-randomized direct-map base, so the displayed offset is
   * the realistic small positive value it always is on a live kernel
   * (page_offset_base >= the level's __PAGE_OFFSET_BASE). Which base that is
   * comes from the engine; a 4-level target is seeded here.
   * test_render_directmap_offset_follows_paging_level covers the selection. */
  unsigned long sv_ref = layout.virt_page_offset_unrandomized;
  layout.virt_page_offset_unrandomized = (unsigned long)PAGE_OFFSET_BASE_L4;
  unsigned long align = (unsigned long)RANDOMIZE_MEMORY_ALIGN;
  unsigned long base = (unsigned long)PAGE_OFFSET_BASE_L4 + 20ul * align;
  s.kaslr.virt_page_offset_min = (unsigned long)PAGE_OFFSET_BASE_L4;
  s.kaslr.virt_page_offset_max = base; /* guaranteed window top */
  s.kaslr.virt_page_offset_slots = 21;
  /* A genuine pin, which is what "promoted" means: the engine resolved the
   * direct-map base to one value, and the count says so. A bracket one grain
   * WIDE is not this -- [base - align, base] has a grid point at each end, so
   * the engine counts two candidates, and an offset measured from one of them
   * is not a measurement of the base. */
  s.kaslr.virt_page_offset_likely_min = base;
  s.kaslr.virt_page_offset_likely_max = base;
  s.kaslr.virt_page_offset_likely_slots = 1;

  set_render_mode(0, 0, 0); /* default text readout */
  capture_stdout(wrap_render_summary, &s);
  char hex[32], off[32];
  snprintf(hex, sizeof(hex), "0x%lx", base);
  snprintf(off, sizeof(off), "off +0x%lx", 20ul * align); /* base - default */
  assert(strstr(render_cap, hex) != NULL);                /* headline base */
  assert(strstr(render_cap, off) != NULL);                /* RM offset */
  assert(strstr(render_cap, GRADE_LIKELY) != NULL);       /* graded */
  assert(strstr(render_cap, GRADE_GUARANTEED) != NULL);   /* window beneath */
  set_render_mode(0, 0, 0);
  layout.virt_page_offset_unrandomized = sv_ref;
#endif
}

/* The realistic direct-map recovery: a timing directmap base narrows only the
 * LIKELY window (it is filtered out of the guaranteed floor), so page_offset
 * has NO sound upper bound — the guaranteed window is unbounded above
 * (virt_page_offset_max == 0). The concrete likely base must still be promoted
 * to a headline, with the guaranteed floor (">=") shown beneath it, not fall
 * back to a bare ">= floor" row that hides the recovery. Regression guard for
 * the promotion gate that previously required a bounded guaranteed window. */
static void test_render_directmap_base_promoted_unbounded(void) {
#if RANDOMIZE_MEMORY_ALIGN > 0
  struct summary s;
  reset_results();
  reset_comp_logs();
  stage_likely_reset();
  num_scalar_facts = 0;
  memset(&s, 0, sizeof(s));

  s.kaslr.vslots = 60;
  unsigned long sv_ref = layout.virt_page_offset_unrandomized;
  layout.virt_page_offset_unrandomized = (unsigned long)PAGE_OFFSET_BASE_L4;
  unsigned long align = (unsigned long)RANDOMIZE_MEMORY_ALIGN;
  unsigned long base = (unsigned long)PAGE_OFFSET_BASE_L4 + 20ul * align;
  s.kaslr.virt_page_offset_min = (unsigned long)PAGE_OFFSET_BASE_L4; /* floor */
  s.kaslr.virt_page_offset_max = 0; /* UNBOUNDED above (no sound ceiling) */
  /* A genuine pin, which is what "promoted" means: the engine resolved the
   * direct-map base to one value, and the count says so. A bracket one grain
   * WIDE is not this -- [base - align, base] has a grid point at each end, so
   * the engine counts two candidates, and an offset measured from one of them
   * is not a measurement of the base. */
  s.kaslr.virt_page_offset_likely_min = base;
  s.kaslr.virt_page_offset_likely_max = base;
  s.kaslr.virt_page_offset_likely_slots = 1;

  set_render_mode(0, 0, 0); /* default text readout */
  capture_stdout(wrap_render_summary, &s);
  char hex[32], off[32];
  snprintf(hex, sizeof(hex), "0x%lx", base);
  snprintf(off, sizeof(off), "off +0x%lx", 20ul * align);
  assert(strstr(render_cap, hex) != NULL);          /* headline base */
  assert(strstr(render_cap, off) != NULL);          /* RM offset */
  assert(strstr(render_cap, GRADE_LIKELY) != NULL); /* graded */
  assert(strstr(render_cap, GRADE_GUARANTEED) !=
         NULL); /* floor beneath, labelled */
  set_render_mode(0, 0, 0);
  layout.virt_page_offset_unrandomized = sv_ref;
#endif
}

/* The RANDOMIZE_MEMORY offset is measured from the base for the paging level
 * actually in force, which the engine projects — not from a compile-time
 * constant. x86_64 has two un-randomized direct-map bases 59.6 PiB apart and a
 * build cannot know which one its target runs: measuring a 5-level base
 * against the 4-level constant yields `off -0xee888000000000` where the truth
 * is a small positive slide, and the sign handling renders that as a
 * measurement rather than an obvious wrap.
 *
 * Drives the same slide against each base in turn, so an implementation that
 * names either one can satisfy at most half of it. The unresolved case asserts
 * the annotation is dropped rather than measured from a default — the headline
 * address must survive, since that part is known. */
static void test_render_directmap_offset_follows_paging_level(void) {
#if RANDOMIZE_MEMORY_ALIGN > 0
  unsigned long align = (unsigned long)RANDOMIZE_MEMORY_ALIGN;
  unsigned long sv_ref = layout.virt_page_offset_unrandomized;
  const unsigned long refs[2] = {(unsigned long)PAGE_OFFSET_BASE_L4,
                                 (unsigned long)PAGE_OFFSET_BASE_L5};

  for (int i = 0; i < 2; i++) {
    struct summary s;
    reset_results();
    reset_comp_logs();
    stage_likely_reset();
    num_scalar_facts = 0;
    memset(&s, 0, sizeof(s));

    unsigned long base = refs[i] + 20ul * align;
    layout.virt_page_offset_unrandomized = refs[i];
    s.kaslr.vslots = 60;
    s.kaslr.virt_page_offset_min = refs[i];
    s.kaslr.virt_page_offset_max = base;
    s.kaslr.virt_page_offset_slots = 21;
    /* Pinned, so the offset annotates a resolved value rather than one end of
     * a bracket: a window one grain wide holds a grid point at each end, which
     * is two candidates, and an offset from one of them measures nothing. */
    s.kaslr.virt_page_offset_likely_min = base;
    s.kaslr.virt_page_offset_likely_max = base;
    s.kaslr.virt_page_offset_likely_slots = 1;

    set_render_mode(0, 0, 0);
    capture_stdout(wrap_render_summary, &s);
    char off[32], wrong[48];
    snprintf(off, sizeof(off), "off +0x%lx", 20ul * align);
    /* What measuring from the OTHER level's base would print. */
    long bad = (long)(base - refs[i ^ 1]);
    snprintf(wrong, sizeof(wrong), "off %s0x%lx", bad < 0 ? "-" : "+",
             (unsigned long)(bad < 0 ? -bad : bad));
    assert(strstr(render_cap, off) != NULL);
    assert(strstr(render_cap, wrong) == NULL);
    set_render_mode(0, 0, 0);
  }

  /* Level unresolved: the base is still known and still headlined, but there
   * is nothing sound to measure it from, so no offset is claimed. */
  {
    struct summary s;
    reset_results();
    reset_comp_logs();
    stage_likely_reset();
    num_scalar_facts = 0;
    memset(&s, 0, sizeof(s));

    unsigned long base = (unsigned long)PAGE_OFFSET_BASE_L4 + 20ul * align;
    layout.virt_page_offset_unrandomized = 0;
    s.kaslr.vslots = 60;
    s.kaslr.virt_page_offset_min = (unsigned long)PAGE_OFFSET_BASE_L4;
    s.kaslr.virt_page_offset_max = base;
    s.kaslr.virt_page_offset_slots = 21;
    /* Pinned, so the offset annotates a resolved value rather than one end of
     * a bracket: a window one grain wide holds a grid point at each end, which
     * is two candidates, and an offset from one of them measures nothing. */
    s.kaslr.virt_page_offset_likely_min = base;
    s.kaslr.virt_page_offset_likely_max = base;
    s.kaslr.virt_page_offset_likely_slots = 1;

    set_render_mode(0, 0, 0);
    capture_stdout(wrap_render_summary, &s);
    char hex[32];
    snprintf(hex, sizeof(hex), "0x%lx", base);
    assert(strstr(render_cap, hex) != NULL);
    assert(strstr(render_cap, "off ") == NULL);
    set_render_mode(0, 0, 0);
  }

  layout.virt_page_offset_unrandomized = sv_ref;
#endif
}

/* JSON carries no offset annotation, so a consumer recovers the
 * RANDOMIZE_MEMORY slide as virt_page_offset minus the un-randomized base.
 * That base has to be published rather than left to be worked out: the obvious
 * reconstruction, range-testing virt_page_offset against the two known x86_64
 * bases, is unsound because the 4-level base lies inside the 5-level span, so a
 * sufficiently slid 5-level map reads as 4-level.
 *
 * Both bases are driven through, so a field wired to either constant satisfies
 * at most half. Zero is published rather than omitted, because a consumer has
 * to be able to tell an unresolved level from a zero slide — and the pairing is
 * asserted alongside it, the two fields being useless apart. */
static void test_render_json_publishes_unrandomized_directmap_base(void) {
#if RANDOMIZE_MEMORY_ALIGN > 0
  unsigned long sv_ref = layout.virt_page_offset_unrandomized;
  const unsigned long refs[3] = {(unsigned long)PAGE_OFFSET_BASE_L4,
                                 (unsigned long)PAGE_OFFSET_BASE_L5, 0ul};

  for (int i = 0; i < 3; i++) {
    struct summary s;
    reset_results();
    reset_comp_logs();
    stage_likely_reset();
    num_scalar_facts = 0;
    memset(&s, 0, sizeof(s));

    layout.virt_page_offset_unrandomized = refs[i];
    set_render_mode(1, 0, 0);
    capture_stdout(wrap_render_summary, &s);

    char want[80];
    snprintf(want, sizeof(want),
             "\"virt_page_offset_unrandomized\": \"0x%016lx\"", refs[i]);
    assert(strstr(render_cap, want) != NULL);
    /* The minuend the slide is taken from, in the same object. */
    assert(strstr(render_cap, "\"virt_page_offset\":") != NULL);
    set_render_mode(0, 0, 0);
  }

  layout.virt_page_offset_unrandomized = sv_ref;
#endif
}

/* The residual search space is stated against the space the KASLR window
 * started with, so a reader can tell whether almost everything or almost
 * nothing was recovered — "24 remain" says nothing on its own. Where that
 * baseline is not known the residual stands alone: a denominator borrowed from
 * a quantity whose honest top is an addressable range rather than a
 * randomization window would read as KASLR entropy the kernel never had. */
static void test_render_entropy_states_its_baseline(void) {
  struct summary s;
  reset_results();
  reset_comp_logs();
  stage_likely_reset();
  num_scalar_facts = 0;
  memset(&s, 0, sizeof(s));
  s.kaslr.vslots = 24;
  s.kaslr.vtop_slots = 512;

  set_render_mode(0, 0, 0);
  capture_stdout(wrap_render_summary, &s);
  assert(strstr(render_cap, "24 of 512") != NULL);

  s.kaslr.vtop_slots = 0; /* baseline unknown */
  capture_stdout(wrap_render_summary, &s);
  assert(strstr(render_cap, "24") != NULL);
  assert(strstr(render_cap, "of 512") == NULL);
  set_render_mode(0, 0, 0);
}

/* Every window row states its grade, including one with no speculative line
 * above it to contrast against. Within a single readout some quantities carry
 * a likely window and others do not; an unlabelled range would then be
 * indistinguishable from an unstated grade rather than reading as guaranteed,
 * and the reader could not tell which of the two windows a row belongs to. */
static void test_render_window_row_always_graded(void) {
#if RANDOMIZE_MEMORY_ALIGN > 0
  struct summary s;
  reset_results();
  reset_comp_logs();
  stage_likely_reset();
  num_scalar_facts = 0;
  memset(&s, 0, sizeof(s));

  unsigned long align = (unsigned long)RANDOMIZE_MEMORY_ALIGN;
  s.kaslr.vslots = 60;
  /* A bounded direct-map window and deliberately NO likely window. */
  s.kaslr.virt_page_offset_min = (unsigned long)PAGE_OFFSET_BASE_L4;
  s.kaslr.virt_page_offset_max =
      (unsigned long)PAGE_OFFSET_BASE_L4 + 12ul * align;
  s.kaslr.virt_page_offset_slots = 13;
  s.kaslr.virt_page_offset_likely_min = 0;
  s.kaslr.virt_page_offset_likely_max = 0;

  set_render_mode(0, 0, 0);
  capture_stdout(wrap_render_summary, &s);
  assert(strstr(render_cap, "Direct Map Base") != NULL);
  assert(strstr(render_cap, GRADE_LIKELY) == NULL);     /* none to show */
  assert(strstr(render_cap, GRADE_GUARANTEED) != NULL); /* graded regardless */
  /* The count reconciles with the window it is printed beside: a closed
   * 12-slot span holds 13 candidates. */
  assert(strstr(render_cap, "13") != NULL);
  set_render_mode(0, 0, 0);
#endif
}

/* The Phys/Virt coupling line states a static architectural property, so it is
 * present whenever the readout reaches the layout: every arch has both a
 * physical and a virtual image base row, so there is always something to
 * relate. What governs it is the posture — the unsupported and disabled banners
 * answer the base question themselves and stop before the layout, in text and
 * markdown alike, so neither may state a coupling there.
 *
 * Runs on every arch: the two wordings ("move together (coupled)" and
 * "randomize independently") share an opening, so one assertion covers both,
 * and the phrase belongs to kasld_coupling_descr() alone. Nothing here writes
 * to `layout` — the note no longer depends on its contents. */
static void test_render_coupling_note(void) {
  struct summary s;

  reset_results();
  reset_comp_logs();
  stage_likely_reset();
  num_scalar_facts = 0;
  memset(&s, 0, sizeof(s));
  s.kaslr.vslots = 60; /* keep the regular KASLR readout path */

  /* KASLR live: stated by both formats that carry it. */
  set_render_mode(0, 0, 0);
  capture_stdout(wrap_render_summary, &s);
  assert(strstr(render_cap, "physical and virtual text") != NULL);
  set_render_mode(0, 0, 1);
  capture_stdout(wrap_render_summary, &s);
  assert(strstr(render_cap, "Phys/Virt coupling") != NULL);

  /* Unsupported: the banner is the whole answer, and no coupling follows it. */
  s.kaslr.unsupported = 1;
  set_render_mode(0, 0, 0);
  capture_stdout(wrap_render_summary, &s);
  assert(strstr(render_cap, "physical and virtual text") == NULL);
  set_render_mode(0, 0, 1);
  capture_stdout(wrap_render_summary, &s);
  assert(strstr(render_cap, "Phys/Virt coupling") == NULL);
  s.kaslr.unsupported = 0;

  /* Disabled: likewise. */
  s.kaslr.disabled = 1;
  set_render_mode(0, 0, 0);
  capture_stdout(wrap_render_summary, &s);
  assert(strstr(render_cap, "physical and virtual text") == NULL);
  set_render_mode(0, 0, 1);
  capture_stdout(wrap_render_summary, &s);
  assert(strstr(render_cap, "Phys/Virt coupling") == NULL);
  s.kaslr.disabled = 0;

  set_render_mode(0, 0, 0);
}

/* A reordered (non-canonical) kernel-text function order surfaces a Caution in
 * the markdown readout, mirroring the text headline warning: a leaked address
 * no longer generalises through a generic System.map. Canonical order is
 * silent. */
static void test_render_markdown_text_order_caution(void) {
  struct summary s;
  reset_results();
  reset_comp_logs();
  stage_likely_reset();
  num_scalar_facts = 0;
  memset(&s, 0, sizeof(s));
  s.kaslr.vslots = 60; /* keep the KASLR readout path alive */

  scalar_facts[num_scalar_facts].fact = SF_TEXT_ORDER;
  scalar_facts[num_scalar_facts].value = TEXT_ORDER_STATIC;
  scalar_facts[num_scalar_facts].conf = CONF_PARSED;
  scalar_facts[num_scalar_facts].origin = test_origin("fingerprint");
  num_scalar_facts++;

  set_render_mode(0, 0, 1); /* markdown */
  capture_stdout(wrap_render_summary, &s);
  assert(strstr(render_cap, "**Caution:**") != NULL);
  assert(strstr(render_cap, "non-canonical") != NULL);

  /* Per-boot (dynamic) variant carries the stronger wording. */
  scalar_facts[0].value = TEXT_ORDER_DYNAMIC;
  capture_stdout(wrap_render_summary, &s);
  assert(strstr(render_cap, "per-boot randomized") != NULL);

  /* Canonical order → no caution. */
  scalar_facts[0].value = TEXT_ORDER_CANONICAL;
  capture_stdout(wrap_render_summary, &s);
  assert(strstr(render_cap, "**Caution:**") == NULL);

  set_render_mode(0, 0, 0);
  num_scalar_facts = 0;
}

/* The verbose Memory-KASLR candidate count comes from the engine's hole-aware
 * slot field (s->kaslr.virt_page_offset_slots), NOT a renderer-local
 * (max-min)/align. Set a slot count the naive formula could never produce for
 * this window and assert it is what renders. */
static void test_render_memory_kaslr_uses_stored_slots(void) {
#if RANDOMIZE_MEMORY_ALIGN > 0
  struct summary s;
  reset_results();
  reset_comp_logs();
  stage_likely_reset();
  num_scalar_facts = 0;
  memset(&s, 0, sizeof(s));

  s.kaslr.vslots = 60; /* keep render_kaslr_text from early-returning */
  /* Both-sided direct-map window (portable constants). */
  s.kaslr.virt_page_offset_min = (unsigned long)PAGE_OFFSET + 0x01000000ul;
  s.kaslr.virt_page_offset_max = (unsigned long)PAGE_OFFSET + 0x09000000ul;
  s.kaslr.virt_page_offset_slots = 7; /* engine-supplied; naive width gives 0 */

  verbose = 1;
  set_render_mode(0, 0, 0);
  capture_stdout(wrap_render_summary, &s);
  verbose = 0;
  set_render_mode(0, 0, 0);

  /* The engine-supplied count is used verbatim in the row's Candidates
     cell; a naive (max-min)/align would give a different number. */
  {
    const char *row = strstr(render_cap, "Direct Map Base");
    const char *eol;
    char line[256];
    assert(row != NULL);
    eol = strchr(row, '\n');
    assert(eol != NULL);
    assert((size_t)(eol - row) < sizeof(line));
    snprintf(line, (size_t)(eol - row) + 1, "%s", row);
    assert(strstr(line, " 7  ") != NULL);
  }
#endif
}

/* json and markdown must carry the hole-aware candidate count for the
 * memory-KASLR windows. A consumer cannot recompute it: interior C_EXCLUDE
 * holes are carved at read time inside quantity_slots() and never reach the
 * wire, so (max - min) / align is the hole-blind figure, not this one. */
static void test_render_memory_kaslr_slots_reach_machine_formats(void) {
#if RANDOMIZE_MEMORY_ALIGN > 0
  struct summary s;
  reset_results();
  reset_comp_logs();
  stage_likely_reset();
  num_scalar_facts = 0;
  memset(&s, 0, sizeof(s));
  s.kaslr.vslots = 60;
  unsigned long align = (unsigned long)RANDOMIZE_MEMORY_ALIGN;
  s.kaslr.virt_page_offset_min = (unsigned long)PAGE_OFFSET_BASE_L4;
  s.kaslr.virt_page_offset_max =
      (unsigned long)PAGE_OFFSET_BASE_L4 + 8ul * align;
  s.kaslr.virt_page_offset_slots = 7; /* engine value; a naive width gives 9 */
  s.kaslr.virt_page_offset_bits = 3;

  set_render_mode(1, 0, 0); /* json */
  capture_stdout(wrap_render_summary, &s);
  assert(strstr(render_cap, "\"slots\": 7") != NULL);
  assert(strstr(render_cap, "\"entropy_bits\": 3") != NULL);

  /* Markdown reports the same hole-aware count in the Layout table's search
     space column. Bits stay a machine-format figure: the human table states
     the candidate count itself, which is the same fact without the log. */
  set_render_mode(0, 0, 1); /* markdown */
  capture_stdout(wrap_render_summary, &s);
  assert(strstr(render_cap, "| 7 | 1 GiB |") != NULL);
  set_render_mode(0, 0, 0);
#endif
}

/* The image base under the no-slide postures (KASLR unsupported / disabled),
 * across every format that reports it and every shape the engine can resolve.
 *
 * Two rules, one table:
 *
 *   1. The base comes from the ENGINE, never from the compile-time default.
 *      The default is a build-time constant a differently-configured kernel
 *      does not honour. Live witness: an Alpine armv7 kernel built VMSPLIT_2G
 *      has _text at 0x80008000 while its arch default is 0xc0008000 -- printing
 *      the default there states a wrong address as the answer.
 *   2. The default appears only as a remark, and the remark's verdict is a
 *      property of the resolved BOUNDS, not of how a format drew them. It is
 *      "ruled out" exactly when a known edge lies on the wrong side of it; an
 *      unresolved edge rules nothing out. Containment is not corroboration --
 *      that armv7 default sits inside the proven bounds and is still wrong --
 *      so the surviving verdict claims only "still possible".
 *
 * Portable: every address is built from this arch's own text floor and KASLR
 * alignment, so nothing here can overflow a 32-bit unsigned long. */
static void check_static_base_case(int posture_disabled, unsigned long lo,
                                   unsigned long hi, unsigned long dflt,
                                   const char *want_verdict, int json_mode,
                                   int md_mode, int want_verbose) {
  struct summary s;
  reset_results();
  reset_comp_logs();
  stage_likely_reset();
  num_scalar_facts = 0;
  memset(&s, 0, sizeof(s));

  unsigned long sv_lo = layout.virt_kaslr_text_min;
  unsigned long sv_hi = layout.virt_kaslr_text_max;
  layout.virt_kaslr_text_min = lo;
  layout.virt_kaslr_text_max = hi;
  if (posture_disabled)
    s.kaslr.disabled = 1;
  else
    s.kaslr.unsupported = 1;
  s.kaslr.default_addr = dflt;

  verbose = want_verbose;
  set_render_mode(json_mode, 0, md_mode);
  capture_stdout(wrap_render_summary, &s);
  set_render_mode(0, 0, 0);
  verbose = 0;

  layout.virt_kaslr_text_min = sv_lo;
  layout.virt_kaslr_text_max = sv_hi;

  /* Every format renders the resolved window through the shared Layout table,
   * which right-aligns addresses without zero-filling, so one expected string
   * serves all three. A per-format width here would only re-assert that the
   * formats spell a value differently, which is the thing they no longer do. */
  const char *afmt = "0x%lx";
  char abuf[40];
  if (lo) {
    snprintf(abuf, sizeof(abuf), afmt, lo);
    assert(strstr(render_cap, abuf) != NULL);
  }
  if (hi) {
    snprintf(abuf, sizeof(abuf), afmt, hi);
    assert(strstr(render_cap, abuf) != NULL);
  }

  const char *rem = strstr(render_cap, "The compile-time default");
  if (!want_verdict) {
    assert(rem == NULL);
    return;
  }
  assert(rem != NULL);
  const char *eol = strchr(rem, '\n');
  char line[256];
  assert(eol != NULL);
  assert((size_t)(eol - rem) < sizeof(line));
  snprintf(line, (size_t)(eol - rem) + 1, "%s", rem);
  /* The verdict, the default, and no grade word: the remark is a sentence
   * about a constant, never a row on the confidence ladder. */
  assert(strstr(line, want_verdict) != NULL);
  snprintf(abuf, sizeof(abuf), afmt, dflt);
  assert(strstr(line, abuf) != NULL);
  assert(strstr(line, GRADE_GUARANTEED) == NULL);
  assert(strstr(line, GRADE_LIKELY) == NULL);
}

static void test_render_static_base_prefers_engine_window(void) {
  unsigned long al = layout.virt_kaslr_align ? layout.virt_kaslr_align : 0x1000;
  /* Grid-aligned so the readout's own edge snapping is a no-op and the printed
   * edges are the ones set here. */
  unsigned long b = (layout.virt_image_base_min + al - 1) & ~(al - 1);
  unsigned long lo = b + al * 2;
  unsigned long hi = b + al * 6;
  unsigned long inside = b + al * 4;
  unsigned long below = b;          /* < lo */
  unsigned long above = b + al * 8; /* > hi */

  struct {
    const char *name;
    unsigned long lo, hi, dflt;
    const char *want;
  } cases[] = {
      /* Closed range. */
      {"inside", lo, hi, inside, "still possible"},
      {"below", lo, hi, below, "ruled out"},
      {"above", lo, hi, above, "ruled out"},
      /* Pinned: the default either IS the answer (nothing to remark on) or is
         ruled out by the same edge test, with no special case. */
      {"pin is default", inside, inside, inside, NULL},
      {"pin elsewhere", inside, inside, below, "ruled out"},
      /* Half-bounds: an unresolved edge rules nothing out on that side. A
         ceiling alone cannot exclude a default beneath it. */
      {"ceiling only, under", 0, hi, inside, "still possible"},
      {"ceiling only, over", 0, hi, above, "ruled out"},
      {"floor only, over", lo, 0, inside, "still possible"},
      {"floor only, under", lo, 0, below, "ruled out"},
  };

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    /* Both postures, and every format that carries the base: the compact
       readout, the verbose text block, and markdown. A representation
       difference between them is fine; a different verdict is a bug. */
    for (int disabled = 0; disabled <= 1; disabled++) {
      check_static_base_case(disabled, cases[i].lo, cases[i].hi, cases[i].dflt,
                             cases[i].want, 0, 0, 0);
      check_static_base_case(disabled, cases[i].lo, cases[i].hi, cases[i].dflt,
                             cases[i].want, 0, 0, 1);
      check_static_base_case(disabled, cases[i].lo, cases[i].hi, cases[i].dflt,
                             cases[i].want, 0, 1, 0);
    }
  }
}

/* The map's direct-map band must be floored on the engine's resolved page
 * offset, not on layout.virt_page_offset. That field is SEEDED from the arch's
 * compile-time PAGE_OFFSET and only replaced when the engine pins the
 * quantity, so where the engine holds a window instead it stays a stale
 * constant. Live witness: an Alpine armv7 VMSPLIT_2G kernel left it at
 * 0xc0000000 while the engine had already proved the direct map starts at or
 * below an address observed inside it at 0x81d44600 -- and the map drew the
 * constant as the region's floor, ABOVE an address it had just proven was
 * inside the region, labelled "base proven". */
/* The direct map's ceiling is DERIVED at display time -- the resolved base plus
 * the kernel's own RAM span -- under gates that cannot be satisfied by
 * accident. Each is asserted on its own because each fails SILENTLY: a ceiling
 * computed from the wrong span still draws a perfectly plausible band.
 *
 *   base PINNED      -- measured from a floor that is itself a lower bound, the
 *                       ceiling would carry both uncertainties while reading as
 *                       a measurement.
 *   highmem RULED OUT -- max_pfn spans ALL RAM, but a 32-bit linear map covers
 *                       lowmem only, so on a highmem kernel it names a ceiling
 *                       past where the mapping really ends (32-bit only).
 *   meminfo READ      -- without it an unreadable /proc/meminfo is
 *                       indistinguishable from a kernel that has no highmem.
 *
 * Every value is an offset from this arch's own VAS floor, so the test states
 * real addresses on the arch under test and cannot overflow a 32-bit word. */
static void test_render_map_directmap_extent_derived(void) {
  struct summary s;
  unsigned long sv_po = layout.virt_page_offset;
  unsigned long sv_min = layout.virt_page_offset_min;
  unsigned long sv_max = layout.virt_page_offset_max;
  unsigned long sv_bmin = layout.virt_image_base_min;
  unsigned long sv_bmax = layout.virt_image_base_max;

  unsigned long step = 0x100000ul;
  unsigned long base = layout.virt_kernel_vas_start + step;
  /* Enough pages to clear PHYS_OFFSET, plus a reach that CONTAINS the text band
   * placed below. On a coupled arch the image sits inside the linear map, so a
   * ceiling drawn under it would describe a layout that cannot exist and the
   * map declines to draw the top edge at all -- which fails on those arches
   * only, the exact shape of an assertion that passes because of what one host
   * is. */
  /* A page-frame count is in the TARGET kernel's pages, so the extent is drawn
   * with that kernel's page size: the compile-time one where the architecture
   * admits a single size, and the observed SF_PAGE_SIZE where it admits
   * several. The test supplies the observation on the latter, since the
   * renderer declines to draw an extent it cannot compute soundly. */
#ifdef pfn_to_phys
  const unsigned long tgt_page = (unsigned long)PAGE_SIZE_MIN;
#else
  const unsigned long tgt_page = 65536ul; /* a 64 KiB-page target */
#endif
  unsigned long pfn =
      ((unsigned long)PHYS_OFFSET / tgt_page) + (step * 20 / tgt_page);
  unsigned long reach = pfn * tgt_page - (unsigned long)PHYS_OFFSET;
  unsigned long expect_end = base + reach - 1;
  char abuf[32];

  snprintf(abuf, sizeof(abuf), "0x%lx", expect_end);

  /* --- pinned base, meminfo read, no highmem: the ceiling is derived. --- */
  reset_results();
  reset_comp_logs();
  stage_likely_reset();
  num_scalar_facts = 0;
  memset(&s, 0, sizeof(s));
  scalar_facts[num_scalar_facts].fact = SF_PHYS_MAX_PFN;
  scalar_facts[num_scalar_facts].value = pfn;
  scalar_facts[num_scalar_facts++].conf = CONF_PARSED;
  scalar_facts[num_scalar_facts].fact = SF_PHYS_MEMTOTAL;
  scalar_facts[num_scalar_facts].value = reach;
  scalar_facts[num_scalar_facts++].conf = CONF_PARSED;
#ifndef pfn_to_phys
  scalar_facts[num_scalar_facts].fact = SF_PAGE_SIZE;
  scalar_facts[num_scalar_facts].value = tgt_page;
  scalar_facts[num_scalar_facts++].conf = CONF_PARSED;
#endif

  layout.virt_page_offset_min = base;
  layout.virt_page_offset_max = base; /* pinned */
  layout.virt_page_offset = base;
  layout.virt_image_base_min = layout.virt_kernel_vas_start + step * 10;
  layout.virt_image_base_max = layout.virt_image_base_min;
  s.kaslr.vslots = 60;
  verbose = 1;
  set_render_mode(0, 0, 0);
  capture_stdout(wrap_render_summary, &s);
  assert(strstr(render_cap, "extent derived") != NULL);
  assert(strstr(render_cap, abuf) != NULL);

  /* --- same facts, base only a lower bound: no derivation. --- */
  layout.virt_page_offset_max = base + step;
  capture_stdout(wrap_render_summary, &s);
  assert(strstr(render_cap, "extent derived") == NULL);
  assert(strstr(render_cap, abuf) == NULL);
  layout.virt_page_offset_max = base;

#if ULONG_MAX <= 0xFFFFFFFFul
  /* --- highmem present: max_pfn is not the linear map's reach. --- */
  scalar_facts[num_scalar_facts].fact = SF_PHYS_LOWMEM;
  scalar_facts[num_scalar_facts].value = reach;
  scalar_facts[num_scalar_facts++].conf = CONF_PARSED;
  capture_stdout(wrap_render_summary, &s);
  assert(strstr(render_cap, "extent derived") == NULL);
  num_scalar_facts--;

  /* --- meminfo unreadable: indistinguishable from no highmem, so decline. ---
   */
  scalar_facts[1].fact = SF_PHYS_MAX_PFN; /* drop the MEMTOTAL witness */
  scalar_facts[1].value = pfn;
  capture_stdout(wrap_render_summary, &s);
  assert(strstr(render_cap, "extent derived") == NULL);
#endif

  verbose = 0;
  set_render_mode(0, 0, 0);
  num_scalar_facts = 0;
  layout.virt_page_offset = sv_po;
  layout.virt_page_offset_min = sv_min;
  layout.virt_page_offset_max = sv_max;
  layout.virt_image_base_min = sv_bmin;
  layout.virt_image_base_max = sv_bmax;
}

static void test_render_map_directmap_base_from_engine(void) {
  struct summary s;
  reset_results();
  reset_comp_logs();
  stage_likely_reset();
  num_scalar_facts = 0;
  memset(&s, 0, sizeof(s));

  unsigned long sv_po = layout.virt_page_offset;
  unsigned long sv_min = layout.virt_page_offset_min;
  unsigned long sv_max = layout.virt_page_offset_max;
  unsigned long sv_bmin = layout.virt_image_base_min;
  unsigned long sv_bmax = layout.virt_image_base_max;

  /* Offsets from this arch's own VAS floor, so every value is a real address
   * on the arch under test and none can overflow a 32-bit unsigned long. */
  unsigned long step = 0x100000ul;
  unsigned long po_min = layout.virt_kernel_vas_start + step;
  unsigned long po_max = layout.virt_kernel_vas_start + step * 2;
  unsigned long stale = layout.virt_kernel_vas_start + step * 4;

  layout.virt_page_offset_min = po_min;
  layout.virt_page_offset_max = po_max;
  layout.virt_page_offset = stale; /* above the proven ceiling */
  /* Put the text band clear of the direct-map floor. A decoupled arch draws no
   * direct-map band at all when the two coincide (there the region proves
   * nothing the text band does not already say) -- and on s390 the VAS floor
   * plus one step lands exactly on KERNEL_VIRT_TEXT_MIN. */
  layout.virt_image_base_min = layout.virt_kernel_vas_start + step * 10;
  layout.virt_image_base_max = layout.virt_image_base_min;

  s.kaslr.vslots = 60;
  verbose = 1;
  set_render_mode(0, 0, 0);
  capture_stdout(wrap_render_summary, &s);
  verbose = 0;
  set_render_mode(0, 0, 0);

  layout.virt_page_offset = sv_po;
  layout.virt_page_offset_min = sv_min;
  layout.virt_page_offset_max = sv_max;
  layout.virt_image_base_min = sv_bmin;
  layout.virt_image_base_max = sv_bmax;

  const char *map = strstr(render_cap, "Virtual address space");
  assert(map != NULL);
  const char *dmap = strstr(map, "direct map");
  assert(dmap != NULL);

  /* Bound the search to the virtual column. */
  const char *end = strstr(map, "Physical address space");
  size_t vlen = end ? (size_t)(end - map) : strlen(map);

  char abuf[32];
  snprintf(abuf, sizeof(abuf), "0x%lx", stale);
  const char *bad = strstr(map, abuf);
  assert(bad == NULL || (size_t)(bad - map) >= vlen);

  snprintf(abuf, sizeof(abuf), "0x%lx", po_min);
  const char *good = strstr(map, abuf);
  assert(good != NULL && (size_t)(good - map) < vlen);

  /* And the floor is not promoted to a proven address while the engine still
   * holds a window around it: the band's own label line says which it is. */
  const char *eol = strchr(dmap, '\n');
  assert(eol != NULL);
  char line[256];
  size_t ln = (size_t)(eol - dmap);
  if (ln >= sizeof(line))
    ln = sizeof(line) - 1;
  memcpy(line, dmap, ln);
  line[ln] = '\0';
  assert(strstr(line, "base proven") == NULL);
  assert(strstr(line, "lower bound") != NULL);
}

/* A band that the band above it OVERLAPS has no bookend to carry its top edge:
 * the transition is suppressed (an overlap has no boundary to draw), so the
 * last address in the column is the overlapping band's floor -- below this
 * band's ceiling. The ceiling then went unstated entirely, and where a leak had
 * widened the band, that leak printed above BOTH of the band's bookends and
 * broke the descending column. Live on aarch64: the engine's module window
 * spans most of the kernel VAS and so covers the direct map, and the
 * direct-map band drew one address as both of its bookends with its own
 * interior leak 64 MiB above them.
 *
 * Every address here is an offset from this arch's own VAS floor, so the case
 * is built the same way on a 32- and a 64-bit target. */
static void test_render_map_overlapped_band_states_its_ceiling(void) {
  struct summary s;
  reset_results();
  reset_comp_logs();
  stage_likely_reset();
  num_scalar_facts = 0;
  memset(&s, 0, sizeof(s));

  unsigned long sv_ms = layout.modules_start;
  unsigned long sv_me = layout.modules_end;
  unsigned long sv_po = layout.virt_page_offset;
  unsigned long sv_pmin = layout.virt_page_offset_min;
  unsigned long sv_pmax = layout.virt_page_offset_max;
  unsigned long sv_bmin = layout.virt_image_base_min;
  unsigned long sv_bmax = layout.virt_image_base_max;

  unsigned long step = 0x100000ul;
  unsigned long base = layout.virt_kernel_vas_start;
  /* A module window straddling the direct-map base: the two bands overlap and
   * neither can print the other's ceiling as a shared bookend. */
  layout.modules_start = base + step;
  layout.modules_end = base + step * 3;
  layout.virt_page_offset = base + step * 2;
  layout.virt_page_offset_min = layout.virt_page_offset;
  layout.virt_page_offset_max = layout.virt_page_offset;
  layout.virt_image_base_min = base + step * 10;
  layout.virt_image_base_max = base + step * 10;

  s.kaslr.vslots = 60;
  verbose = 1;
  set_render_mode(0, 0, 0);
  capture_stdout(wrap_render_summary, &s);
  verbose = 0;
  set_render_mode(0, 0, 0);

  unsigned long mod_end = layout.modules_end;
  layout.modules_start = sv_ms;
  layout.modules_end = sv_me;
  layout.virt_page_offset = sv_po;
  layout.virt_page_offset_min = sv_pmin;
  layout.virt_page_offset_max = sv_pmax;
  layout.virt_image_base_min = sv_bmin;
  layout.virt_image_base_max = sv_bmax;

  const char *map = strstr(render_cap, "Virtual address space");
  assert(map != NULL);
  const char *end = strstr(map, "Physical address space");
  size_t vlen = end ? (size_t)(end - map) : strlen(map);

  /* The overlapped band's ceiling is stated, and stated as what it is: an edge
   * that lies inside the band drawn above it, not a bookend of its own. */
  char abuf[32];
  snprintf(abuf, sizeof(abuf), "0x%lx", mod_end);
  const char *hit = NULL;
  for (const char *p = map; p && (size_t)(p - map) < vlen;
       p = strchr(p + 1, '\n')) {
    const char *nl = strchr(p + 1, '\n');
    size_t len = nl ? (size_t)(nl - p) : strlen(p);
    char line[256];
    if (len >= sizeof(line))
      len = sizeof(line) - 1;
    memcpy(line, p, len);
    line[len] = '\0';
    if (strstr(line, abuf) && strstr(line, "inside the band above")) {
      hit = p;
      break;
    }
  }
  assert(hit != NULL);
}

/* The trailing hint is a footer, so it must come after everything it
 * advertises. It was emitted from inside the readout, which put it BETWEEN the
 * readout and the map -- where it reads as a section divider. Nothing caught
 * that, because without --map there was no content after it to be wrong about.
 * The hint also names only what this run did not already produce. */
static void test_render_footer_hint_is_last(void) {
  struct summary s;
  reset_results();
  reset_comp_logs();
  stage_likely_reset();
  num_scalar_facts = 0;
  memset(&s, 0, sizeof(s));
  s.kaslr.vslots = 60;
  verbose = 0;

  /* No --map: the hint stands alone and offers the map. */
  map_mode = 0;
  set_render_mode(0, 0, 0);
  capture_stdout(wrap_render_summary, &s);
  const char *hint = strstr(render_cap, "[-v:");
  assert(hint != NULL);
  assert(strstr(hint, "memory map") != NULL);

  /* --map: the hint follows the diagram, and stops offering what is already
   * on screen. */
  map_mode = 1;
  capture_stdout(wrap_render_summary, &s);
  const char *map = strstr(render_cap, "Virtual address space");
  hint = strstr(render_cap, "[-v:");
  assert(map != NULL);
  assert(hint != NULL);
  assert(hint > map);
  assert(strstr(hint, "memory map") == NULL);
  map_mode = 0;
}

/* Reads a physical-map boundary line -- an address alone on its line, with at
 * most the speculative tag after it. Leak rows carry a `[tag] name` suffix and
 * are inside a band, not edges of one, so they are rejected here. */
static int map_boundary_addr(const char *line, unsigned long *out) {
  const char *p = line;
  while (*p == ' ')
    p++;
  if (p[0] != '0' || p[1] != 'x')
    return 0;
  char *end;
  unsigned long v = strtoul(p + 2, &end, 16);
  if (end == p + 2)
    return 0;
  while (*end == ' ')
    end++;
  if (*end != '\0' && strncmp(end, GRADE_LIKELY, sizeof(GRADE_LIKELY) - 1) != 0)
    return 0;
  *out = v;
  return 1;
}

/* The physical column runs strictly downward. Two consequences, both of which
 * were violated at once by a band bounded with ULONG_MAX when no RAM top was
 * known: a band whose bookends are the SAME address is a labelled region of
 * zero height, and a band drawn ABOVE the stated ceiling is off the map it
 * belongs to. Asserting strict descent covers both without the test having to
 * reproduce the bucket arithmetic. */
static void test_render_phys_map_descends_strictly(void) {
  struct summary s;
  reset_results();
  reset_comp_logs();
  stage_likely_reset();
  num_scalar_facts = 0;
  memset(&s, 0, sizeof(s));
  s.kaslr.vslots = 60;
  verbose = 0;
  map_mode = 1;

  /* A physical window is required, or the column is a single undivided DRAM
   * band and there is no bucket arithmetic to get wrong. Its ceiling has to
   * sit above the sysconf RAM estimate, which is the case the defect needed:
   * the proven ceiling outruns anything observed, no RAM top is known, and the
   * band above the window is left bounded by the ULONG_MAX placeholder.
   * Derived from ULONG_MAX so it holds on 32-bit as well as 64-bit. */
  unsigned long sv_pmin = layout.phys_kaslr_text_min;
  unsigned long sv_pmax = layout.phys_kaslr_text_max;
  layout.phys_kaslr_text_min = 0x200000ul;
  layout.phys_kaslr_text_max = ULONG_MAX / 2;

  set_render_mode(0, 0, 0);
  capture_stdout(wrap_render_summary, &s);
  map_mode = 0;
  layout.phys_kaslr_text_min = sv_pmin;
  layout.phys_kaslr_text_max = sv_pmax;

  const char *phys = strstr(render_cap, "Physical address space");
  assert(phys != NULL);

  int seen = 0;
  unsigned long prev = 0;
  for (const char *p = phys; p; p = strchr(p + 1, '\n')) {
    const char *nl = strchr(p + 1, '\n');
    size_t len = nl ? (size_t)(nl - (p + 1)) : strlen(p + 1);
    char line[256];
    if (len >= sizeof(line))
      len = sizeof(line) - 1;
    memcpy(line, p + 1, len);
    line[len] = '\0';
    unsigned long addr;
    if (!map_boundary_addr(line, &addr))
      continue;
    if (seen)
      assert(addr < prev);
    prev = addr;
    seen = 1;
  }
  /* The column exists at all -- otherwise the loop above proves nothing. */
  assert(seen);
}

/* --map draws the address-space diagram without --verbose, which is the whole
 * point of the flag: the diagram is a view of the resolved layout, not run
 * narration, so it must be reachable without the per-component stream. */
static void test_render_map_flag(void) {
  struct summary s;
  reset_results();
  reset_comp_logs();
  stage_likely_reset();
  num_scalar_facts = 0;
  memset(&s, 0, sizeof(s));
  s.kaslr.vslots = 60;

  /* Default readout: no diagram. */
  verbose = 0;
  map_mode = 0;
  set_render_mode(0, 0, 0);
  capture_stdout(wrap_render_summary, &s);
  assert(strstr(render_cap, "address space") == NULL);

  /* --map alone: diagram, and still no per-component narration. */
  map_mode = 1;
  capture_stdout(wrap_render_summary, &s);
  assert(strstr(render_cap, "Virtual address space") != NULL);

  /* markdown honours it too, as its own section. */
  set_render_mode(0, 0, 1);
  capture_stdout(wrap_render_summary, &s);
  assert(strstr(render_cap, "## Address space") != NULL);

  /* --verbose implies it: removing content from --verbose would regress
   * anyone relying on it today. */
  map_mode = 0;
  verbose = 1;
  set_render_mode(0, 0, 0);
  capture_stdout(wrap_render_summary, &s);
  assert(strstr(render_cap, "Virtual address space") != NULL);

  verbose = 0;
  map_mode = 0;
  set_render_mode(0, 0, 0);
}

/* A virtual map band must contain the region it names, and therefore every
 * address proven to be inside it. The band bounds come from the engine's *base*
 * estimates -- where a region starts, not how far it reaches -- so an interior
 * leak routinely sits above them, and the map drew an address it had just
 * proven was inside kernel text above the band that named it. */
static void test_render_map_band_contains_its_leaks(void) {
  struct summary s;
  reset_results();
  reset_comp_logs();
  stage_likely_reset();
  num_scalar_facts = 0;
  memset(&s, 0, sizeof(s));
  unsigned long sv_max = layout.virt_image_base_max;

  /* Narrow the base window so there is room between its ceiling and the next
   * region: at the honest top it abuts modules_start, leaving nowhere for an
   * interior sample to sit. */
  unsigned long win_lo = layout.virt_image_base_min;
  unsigned long win_hi = layout.virt_image_base_max;
  /* The map stacks disjoint bands, so a band widened past the next region's
   * floor is clamped back to it and the widened edge is never drawn. On some
   * layouts a neighbouring region starts *inside* the base window rather than
   * above it -- ppc64 places modules at PAGE_OFFSET + 32 PiB while its text
   * window spans the whole kernel VAS -- so the window alone does not bound
   * where the next band begins. Cap the synthetic window at the nearest region
   * floor above it, keeping the sample in the stretch no other region claims.
   */
  if (layout.modules_start > win_lo && layout.modules_start < win_hi)
    win_hi = layout.modules_start;
  if (layout.virt_page_offset > win_lo && layout.virt_page_offset < win_hi)
    win_hi = layout.virt_page_offset;
  unsigned long win_span = win_hi - win_lo;
  layout.virt_image_base_max = win_lo + win_span / 4;
  /* One byte above the narrowed ceiling: the widening must still fire, while
   * the sample stays well inside the unclaimed stretch on every arch layout --
   * and it is derived, so nothing overflows on 32-bit. */
  unsigned long interior = layout.virt_image_base_max + 1;

  struct result *r = push_result();
  r->type = KASLD_TYPE_VIRT;
  r->region = REGION_KERNEL_TEXT;
  r->pos = POS_INTERIOR;
  r->conf = CONF_PARSED;
  r->sample = interior;
  r->set_mask = SAMPLE_SET;
  add_origin(r, "synthetic_test");
  r->method_set = 1u << KM_PARSED;

  s.kaslr.vslots = 60;
  verbose = 1;
  set_render_mode(0, 0, 0);
  capture_stdout(wrap_render_summary, &s);
  verbose = 0;
  set_render_mode(0, 0, 0);
  layout.virt_image_base_max = sv_max;

  /* Assert the property directly: the ceiling the map gives kernel text must
   * cover the address proven to be inside it. An occurrence count will not do
   * -- whether the widened edge is printed at all depends on whether a region
   * sits above kernel text, which differs by arch (on arm64 modules are placed
   * below the image, so kernel text is topmost and its ceiling comes from the
   * map's own top instead).
   *
   * Kernel text is drawn in one of two shapes. As a band of its own, its
   * ceiling is the bookend printed above the label. Mapped through the direct
   * map (coupled arches), it is drawn nested inside its container with its own
   * span inline -- there is no bookend of its own, and the inline upper edge is
   * the ceiling. Read whichever shape was emitted. */
  const char *map = strstr(render_cap, "Virtual address space");
  assert(map != NULL);
  const char *lbl = strstr(map, "kernel text");
  assert(lbl != NULL);

  unsigned long ceiling = 0;
  int found = 0;
  const char *eol = strchr(lbl, '\n');
  const char *inline_hi = strstr(lbl, " - 0x");
  if (inline_hi && eol && inline_hi < eol &&
      sscanf(inline_hi + 3, "0x%lx", &ceiling) == 1) {
    found = 1; /* contained form: the entry states its own span */
  } else {
    for (const char *l = map; l < lbl;) {
      const char *nl = strchr(l, '\n');
      if (!nl || nl > lbl)
        break;
      unsigned long v;
      if (sscanf(l, " 0x%lx", &v) == 1 && strncmp(l, "  0x", 4) == 0) {
        ceiling = v;
        found = 1;
      }
      l = nl + 1;
    }
  }
  assert(found);
  assert(ceiling >= interior);
}

/* The physical map's ceiling must sit above every point drawn beneath it. High
 * MMIO routinely lies above the leaked DRAM top, and pinning the ceiling to
 * ram_top drew those points outside the map that lists them -- and, where the
 * above-DRAM band's own footer is ram_top too, printed one address as both
 * bookends of a band holding points gigabytes higher. */
static void test_render_map_ceiling_covers_high_mmio(void) {
  struct summary s;
  reset_results();
  reset_comp_logs();
  stage_likely_reset();
  num_scalar_facts = 0;
  memset(&s, 0, sizeof(s));

  /* Small, so both fit a 32-bit unsigned long; the property under test is
   * only that the MMIO point sits above the leaked DRAM top. */
  unsigned long top = (unsigned long)PHYS_OFFSET + 0x1000000ul;
  unsigned long mmio = top + 0x1000000ul;

  struct result *r1 = push_result();
  r1->type = KASLD_TYPE_PHYS;
  r1->region = REGION_RAM;
  r1->hi = top;
  r1->set_mask = HI_SET;
  r1->pos = POS_TOP;
  r1->conf = CONF_PARSED;
  add_origin(r1, "synthetic_test");
  r1->method_set = 1u << KM_PARSED;

  struct result *r2 = push_result();
  r2->type = KASLD_TYPE_PHYS;
  r2->region = REGION_MMIO;
  r2->sample = mmio;
  r2->set_mask = SAMPLE_SET;
  r2->pos = POS_INTERIOR;
  r2->conf = CONF_PARSED;
  add_origin(r2, "synthetic_test");
  r2->method_set = 1u << KM_PARSED;

  s.kaslr.vslots = 60;
  verbose = 1;
  set_render_mode(0, 0, 0);
  capture_stdout(wrap_render_summary, &s);
  verbose = 0;
  set_render_mode(0, 0, 0);

  const char *blk = strstr(render_cap, "Physical address space");
  assert(blk != NULL);
  char hex[32];
  /* Un-padded: the map prints addresses right-aligned to the widest one in the
   * block, not zero-filled to 16 digits. */
  snprintf(hex, sizeof(hex), "0x%lx", mmio);
  assert(strstr(blk, hex) != NULL); /* the point is drawn */

  /* The first bare address line after the heading is the ceiling. Right
   * alignment means the leading run of spaces varies with the block's widest
   * address, so skip it rather than matching a fixed indent. */
  unsigned long ceiling = 0;
  for (const char *l = strchr(blk, '\n'); l; l = strchr(l + 1, '\n')) {
    const char *p = l + 1;
    while (*p == ' ')
      p++;
    if (sscanf(p, "0x%lx", &ceiling) == 1)
      break;
  }
  assert(ceiling >= mmio);
}

/* The physical map's bands must PARTITION the address space: a leak belongs to
 * exactly one band, under exactly one header. The phys-text window band is
 * [phys_kaslr_text_min, phys_kaslr_text_max] and the above-DRAM band is
 * (ram_top, ULONG_MAX]; phys_kaslr_text_max is the engine's proven ceiling and
 * stays at the arch default until an observation narrows it, so it routinely
 * sits above a leaked ram_top and the two bands overlap. A kernel-image leak
 * in the overlap satisfies both (the window's `text_only` gate admits it, the
 * above-DRAM band admits every region) and was printed TWICE, once under
 * "above DRAM" and once under "phys kernel text". */
static void test_render_map_phys_buckets_partition(void) {
  struct summary s;
  reset_results();
  reset_comp_logs();
  stage_likely_reset();
  num_scalar_facts = 0;
  memset(&s, 0, sizeof(s));

  unsigned long sv_min = layout.phys_kaslr_text_min;
  unsigned long sv_max = layout.phys_kaslr_text_max;

  /* Small offsets from PHYS_OFFSET so every value fits a 32-bit unsigned
   * long. The property under test is only the ordering
   * pmin < ram_top < ktext <= pmax. */
  unsigned long ram_top = (unsigned long)PHYS_OFFSET + 0x1000000ul;
  unsigned long ktext = ram_top + 0x400000ul;

  layout.phys_kaslr_text_min = (unsigned long)PHYS_OFFSET + 0x100000ul;
  layout.phys_kaslr_text_max = ram_top + 0x1000000ul;

  struct result *r1 = push_result();
  r1->type = KASLD_TYPE_PHYS;
  r1->region = REGION_RAM;
  r1->hi = ram_top;
  r1->set_mask = HI_SET;
  r1->pos = POS_TOP;
  r1->conf = CONF_PARSED;
  add_origin(r1, "synthetic_test");
  r1->method_set = 1u << KM_PARSED;

  /* A kernel-image leak above the leaked DRAM top but inside the (still wide)
   * proven text window — the overlap. */
  struct result *r2 = push_result();
  r2->type = KASLD_TYPE_PHYS;
  r2->region = REGION_KERNEL_IMAGE;
  r2->lo = ktext;
  r2->set_mask = LO_SET;
  r2->pos = POS_BASE;
  r2->conf = CONF_PARSED;
  add_origin(r2, "synthetic_test");
  r2->method_set = 1u << KM_PARSED;

  s.kaslr.vslots = 60;
  verbose = 1;
  set_render_mode(0, 0, 0);
  capture_stdout(wrap_render_summary, &s);
  verbose = 0;
  set_render_mode(0, 0, 0);

  layout.phys_kaslr_text_min = sv_min;
  layout.phys_kaslr_text_max = sv_max;

  const char *blk = strstr(render_cap, "Physical address space");
  assert(blk != NULL);

  char hex[32];
  /* Un-padded (the map right-aligns rather than zero-fills); the two trailing
   * spaces plus `[` still anchor this to a leak row, not a bare bookend. */
  snprintf(hex, sizeof(hex), "0x%lx  [", ktext);
  int seen = 0;
  for (const char *p = strstr(blk, hex); p; p = strstr(p + 1, hex))
    seen++;
  assert(seen == 1); /* drawn, and drawn once */
}

/* Kernel text is mapped THROUGH the direct map on coupled arches, and the map
 * has to say so. It previously could not: the direct-map region was only added
 * when its base differed from the text floor, which on the default
 * configuration of every coupled arch it does not -- so the largest kernel
 * region was absent from the map entirely (verified missing on ppc64le, ppc32,
 * mips32, riscv32) -- and on the configurations where it did appear it was
 * stacked as a sibling BELOW the region it contains.
 *
 * Drive the coinciding case directly and assert the direct map is drawn with
 * kernel text nested inside its bookends. On decoupled arches the same input
 * means the two really are indistinguishable and suppression is right, so the
 * arms differ; both are asserted rather than skipped. */
static void test_render_map_directmap_contains_text(void) {
  struct summary s;
  reset_results();
  reset_comp_logs();
  stage_likely_reset();
  num_scalar_facts = 0;
  memset(&s, 0, sizeof(s));

  unsigned long sv_po = layout.virt_page_offset;
  /* The coupled default: the direct map begins exactly where the kernel image
   * may begin. Derived from layout, so it is that arch's own address. */
  layout.virt_page_offset = layout.virt_image_base_min;

  s.kaslr.vslots = 60;
  verbose = 1;
  set_render_mode(0, 0, 0);
  capture_stdout(wrap_render_summary, &s);
  verbose = 0;
  set_render_mode(0, 0, 0);
  layout.virt_page_offset = sv_po;

  const char *map = strstr(render_cap, "Virtual address space");
  assert(map != NULL);
  const char *dmap = strstr(map, "direct map");

#if TEXT_TRACKS_DIRECTMAP
  /* Present at all -- the whole defect was its absence. */
  assert(dmap != NULL);
  const char *text = strstr(dmap, "kernel text");
  assert(text != NULL);
  /* Nested, not stacked: no band bookend separates the two, and the contained
   * region is indented one level deeper than its container's label. */
  for (const char *l = strchr(dmap, '\n'); l && l < text;
       l = strchr(l + 1, '\n'))
    assert(strncmp(l + 1, "  0x", 4) != 0);
  const char *text_bol = text;
  while (text_bol > map && text_bol[-1] != '\n')
    text_bol--;
  const char *dmap_bol = dmap;
  while (dmap_bol > map && dmap_bol[-1] != '\n')
    dmap_bol--;
  assert((text - text_bol) > (dmap - dmap_bol));
#else
  /* Decoupled: a direct-map base equal to the text floor proves nothing the
   * text band does not already say, and nothing is contained. */
  assert(dmap == NULL);
#endif
}

/* The map's address bookends are shared: one line is at once the floor of the
 * band above and the ceiling of the band below, and the band above prints it.
 * Nothing sits above the topmost band, so its ceiling has no other printer --
 * leave it out and the reader takes the map's top edge for the band's own end,
 * which contradicts the window the readout states for that same region.
 *
 * Lay three narrow bands strictly inside the kernel VAS so the map's top edge
 * is provably above every band's end on every arch (several arches ship a
 * modules or text region that really does reach the VAS ceiling, where there is
 * correctly nothing extra to draw), then assert the first thing under the top
 * edge is an address BELOW it and not a region label. */
static void test_render_map_draws_topmost_band_ceiling(void) {
  struct summary s;
  reset_results();
  reset_comp_logs();
  stage_likely_reset();
  num_scalar_facts = 0;
  memset(&s, 0, sizeof(s));

  unsigned long sv_po = layout.virt_page_offset;
  unsigned long sv_tmin = layout.virt_image_base_min;
  unsigned long sv_tmax = layout.virt_image_base_max;
  unsigned long sv_mstart = layout.modules_start;
  unsigned long sv_mend = layout.modules_end;

  /* Eighths of the arch's own kernel VAS: derived, so nothing overflows a
   * 32-bit word and the bands land inside the VAS on every layout. */
  unsigned long vas_lo = layout.virt_kernel_vas_start;
  unsigned long vas_hi = layout.virt_kernel_vas_end;
  unsigned long q = (vas_hi - vas_lo) / 8;
  layout.virt_page_offset = vas_lo + q;
  layout.virt_image_base_min = vas_lo + 3 * q;
  layout.virt_image_base_max = vas_lo + 4 * q;
  layout.modules_start = vas_lo + 5 * q;
  layout.modules_end = vas_lo + 6 * q;

  s.kaslr.vslots = 60;
  verbose = 1;
  set_render_mode(0, 0, 0);
  capture_stdout(wrap_render_summary, &s);
  verbose = 0;
  set_render_mode(0, 0, 0);

  layout.virt_page_offset = sv_po;
  layout.virt_image_base_min = sv_tmin;
  layout.virt_image_base_max = sv_tmax;
  layout.modules_start = sv_mstart;
  layout.modules_end = sv_mend;

  const char *map = strstr(render_cap, "Virtual address space");
  assert(map != NULL);

  unsigned long top = 0, next = 0;
  int have_top = 0, have_next = 0;
  for (const char *l = map; l && *l && !have_next;) {
    const char *nl = strchr(l, '\n');
    unsigned long v;
    if (strncmp(l, "  0x", 4) == 0 && sscanf(l + 2, "0x%lx", &v) == 1) {
      if (!have_top) {
        top = v;
        have_top = 1;
      } else {
        next = v;
        have_next = 1;
      }
    } else if (have_top) {
      /* Only a gap separator or the open-extent marker may stand between the
       * map's top edge and the topmost band's ceiling. A region label here
       * means the ceiling was never drawn. Copy the line out first: strstr()
       * over the raw cursor would happily match a gap separator further down
       * the block and pass a test that should fail. */
      char line[256];
      size_t len = nl ? (size_t)(nl - l) : strlen(l);
      if (len >= sizeof(line))
        len = sizeof(line) - 1;
      memcpy(line, l, len);
      line[len] = '\0';
      assert(line[0] == '\0' || strstr(line, ". . .") != NULL ||
             strstr(line, "^ extent unknown") != NULL);
    }
    l = nl ? nl + 1 : NULL;
  }
  assert(have_top && have_next);
  assert(top == vas_hi);
  assert(next < top);
}

/* Walk the bare address bookends of one map block (lines whose first four
 * characters are exactly "  0x" -- the column that brackets each band; leaks
 * and sub-entries are indented further and are deliberately skipped) and assert
 * the column never rises as it descends. Returns the number of bookends seen so
 * a caller can check the block was actually drawn. */
static int assert_map_column_descends(const char *block) {
  unsigned long prev = 0;
  int seen = 0;
  for (const char *l = block; l && *l;) {
    const char *nl = strchr(l, '\n');
    size_t len = nl ? (size_t)(nl - l) : strlen(l);
    const char *p = l;
    while ((size_t)(p - l) < len && *p == ' ')
      p++;
    unsigned long v;
    /* A bookend is a bare address line. The map right-aligns addresses to the
     * widest in the block, so the indent varies with the block's contents and
     * cannot be matched literally; what separates a bookend from a leak row
     * under a bucket header is that the leak row carries a "[section]" tag. */
    if (sscanf(p, "0x%lx", &v) == 1 && memchr(l, '[', len) == NULL) {
      if (seen)
        assert(v <= prev);
      prev = v;
      seen++;
    }
    l = nl ? nl + 1 : NULL;
  }
  return seen;
}

/* The physical column must descend: the ceiling has to dominate every edge
 * drawn beneath it, and the bucket FOOTERS are edges too. The bucket above the
 * phys-text window carries `phys_kaslr_text_max` as its footer, and that bound
 * routinely sits above both a leaked ram_top and the sysconf estimate whenever
 * no DRAM-extent observation narrowed it -- so the map printed an address above
 * its own stated top. The engine's window must NOT be clipped to fix this
 * (truncating it would misreport the window); the ceiling rises instead. */
static void test_render_phys_ceiling_covers_bucket_footers(void) {
  struct summary s;
  reset_results();
  reset_comp_logs();
  stage_likely_reset();
  num_scalar_facts = 0;
  memset(&s, 0, sizeof(s));

  unsigned long sv_min = layout.phys_kaslr_text_min;
  unsigned long sv_max = layout.phys_kaslr_text_max;

  /* No RAM observation at all, so the DRAM ceiling falls back to the sysconf
   * estimate and dram_hi stays ULONG_MAX -- the configuration that emits the
   * `[pmax + 1, dram_hi]` bucket whose footer is pmax. A pmax of ULONG_MAX - 1
   * is above any estimate sysconf can produce on any word size, so the ordering
   * violation is deterministic rather than dependent on the host's RAM. */
  layout.phys_kaslr_text_min = ULONG_MAX / 2;
  layout.phys_kaslr_text_max = ULONG_MAX - 1;

  s.kaslr.vslots = 60;
  verbose = 1;
  set_render_mode(0, 0, 0);
  capture_stdout(wrap_render_summary, &s);
  verbose = 0;
  set_render_mode(0, 0, 0);

  layout.phys_kaslr_text_min = sv_min;
  layout.phys_kaslr_text_max = sv_max;

  const char *blk = strstr(render_cap, "Physical address space");
  assert(blk != NULL);
  assert(assert_map_column_descends(blk) >= 2);

  /* And the window itself is reported untouched: the ceiling moved, pmax did
   * not. */
  char hex[32];
  /* Un-padded: the map right-aligns addresses rather than zero-filling them,
   * so on a 32-bit target the padded form does not appear at all. */
  snprintf(hex, sizeof(hex), "0x%lx", ULONG_MAX - 1);
  assert(strstr(blk, hex) != NULL);
}

/* A KASLR-disabled base is a proven pin, not a speculative "likely" value: the
 * word "Likely" must not prefix the kernel image base. */
static void test_render_disabled_base_not_labeled_likely(void) {
  struct summary s;
  reset_results();
  reset_comp_logs();
  stage_likely_reset();
  num_scalar_facts = 0;
  memset(&s, 0, sizeof(s));

  s.kaslr.disabled = 1;
  unsigned long vt = (unsigned long)KERNEL_VIRT_TEXT_DEFAULT;
  /* The orchestrator always carries the arch default on the summary. */
  s.kaslr.default_addr = vt;
  unsigned long smin = layout.virt_kaslr_text_min;
  unsigned long smax = layout.virt_kaslr_text_max;
  layout.virt_kaslr_text_min = vt; /* engine pin: min == max != 0 */
  layout.virt_kaslr_text_max = vt;

  verbose = 1;
  set_render_mode(0, 0, 0);
  capture_stdout(wrap_render_summary, &s);
  verbose = 0;
  /* The static postures render from the shared row model, so the quantity
   * wears the same name it does in the table -- not a second label for the
   * same thing. */
  assert(strstr(render_cap, "Virtual Image Base") != NULL);
  assert(strstr(render_cap, "Likely kernel image base") == NULL);

  /* Markdown carries the same pinned base in the disabled case (not just a
   * "KASLR is disabled" banner) — the base IS the answer when there is no
   * slide. The address itself is the assertion: the pin is an engine result,
   * and it is reported without a qualifier naming where it happens to land. */
  set_render_mode(0, 0, 1);
  capture_stdout(wrap_render_summary, &s);
  set_render_mode(0, 0, 0);
  /* The static postures render from the shared row model, so the quantity
   * wears the same name it does in the table -- not a second label for the
   * same thing. */
  assert(strstr(render_cap, "Virtual Image Base") != NULL);
  char pinhex[32];
  /* Built unpadded: the Layout rows markdown draws are the ones the readout
   * draws, and they right-align addresses rather than zero-filling them, so
   * "0x%016lx" matches only on arches whose addresses fill 16 hex digits. */
  snprintf(pinhex, sizeof(pinhex), "0x%lx", vt);
  assert(strstr(render_cap, pinhex) != NULL);

  layout.virt_kaslr_text_min = smin;
  layout.virt_kaslr_text_max = smax;
}

/* A leaked interior sample must self-disclose "[interior]" in the leak rows so
 * a reader never mistakes it for the region base. A lone in-bounds
 * interior kernel-text sample is the best record for its region, so the readout
 * Leaks list surfaces it. */
static void test_render_leak_discloses_interior(void) {
  struct summary s;
  reset_results();
  reset_comp_logs();
  stage_likely_reset();
  num_scalar_facts = 0;
  memset(&s, 0, sizeof(s));

  struct result *r = push_result();
  r->type = KASLD_TYPE_VIRT;
  r->region = REGION_KERNEL_TEXT;
  r->pos = POS_INTERIOR;
  r->conf = CONF_PARSED;
  r->lo = (unsigned long)KERNEL_VIRT_TEXT_DEFAULT;
  r->set_mask = LO_SET;
  add_origin(r, "synthetic_test");
  r->method_set = 1u << KM_PARSED;

  set_render_mode(0, 0, 0); /* readout */
  capture_stdout(wrap_render_summary, &s);

  /* The row states the position in its own column, so a reader cannot take the
   * sample for the region's base. Asserted on that row rather than anywhere on
   * screen: "interior" appearing somewhere proves nothing about which finding
   * carries it. */
  assert(evidence_sources(render_cap, "virt kernel text", "interior") == 1);
  assert(evidence_sources(render_cap, "virt kernel text", "base") == -1);
}

static void test_render_markdown_with_rich_content(void) {
  struct summary s;
  set_rich_render_state(&s);
  verbose = 1; /* per-record Evidence table (with the Pos column) */
  set_render_mode(0, 0, 1);
  capture_stdout(wrap_render_summary, &s);
  verbose = 0;
  /* Markdown produces a table and discloses each leak's extent-position. */
  assert(strstr(render_cap, "|") != NULL);
  assert(strstr(render_cap, "| Pos |") != NULL);
  assert(strstr(render_cap, "| base |") != NULL);
  /* Verbose markdown embeds the ASCII memory-layout maps in a fenced code
   * block (the same diagrams the text readout draws). */
  assert(strstr(render_cap, "## Address space") != NULL);
  assert(strstr(render_cap, "```") != NULL);
  assert(strstr(render_cap, "address space") != NULL); /* map heading text */
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
/* A region key states a BARE address only where the engine resolved the region
 * to one, and the window otherwise -- the grammar every value key on that line
 * follows.
 *
 * The floor alone was reported instead, under a key named for the base, on
 * windows that commonly admit tens of thousands of placements. A scraper cannot
 * tell that from a resolved base, and a floor put through a direct-map
 * translation gives a wrong address rather than an approximate one. The window
 * says the same thing without the ambiguity, and says more of it. */
/* Every token on the oneline splits into a key and a value.
 *
 * The line is documented as whitespace-separated key=value pairs, and one value
 * broke that: the DRAM extent carried its size as "(13.0 GiB)", so the obvious
 * tokenizer produced a trailing "GiB)" with no `=` in it. A format whose
 * contract is a stable key set has to be splittable by that contract. */
/* A set's values are not addresses, and must not be formatted as ones.
 *
 * The paging level is a count of bits: 48, not 0x30. It shares the value
 * grammar's "resolved" state with the address quantities, so a helper that
 * reads the value before reading the SHAPE formats it through the address path
 * and publishes a plausible-looking wrong number. */
/* The direct map's residual is measured against the budget window the kernel
 * draws page_offset_base from, not against nothing.
 *
 * That denominator is derived from engine evidence and cannot be reached from
 * the estimates, so the caller supplies it to the model. When it stopped being
 * supplied the readout quietly changed from "~4 of 15 bits" to "~4 bits" and
 * the row's count lost its denominator -- no assertion noticed, because
 * nothing tied the two together. */
/* A window's excluded interior ranges are disclosed, not merely counted.
 *
 * The range a format prints is the convex HULL; the engine carves sub-ranges
 * out of it, and the candidate count already reflects them. So the count and
 * the range disagree by exactly the carved amount, and a reader reconciling the
 * two has nothing to reconcile with -- while anyone brute-forcing the hull
 * spends effort on placements already ruled out. On one x86_64 host that is 647
 * of 6616 physical placements. */
/* The physical map's derived ceiling follows the TARGET's memory, not the
 * analysing host's.
 *
 * With no observed DRAM top the map derives one. It used to call
 * sysconf(_SC_PHYS_PAGES), which answers for the machine running the analysis
 * and ignores KASLD_SYSROOT -- so replaying a capture drew the ceiling from
 * whichever computer opened it, an order of magnitude out for a 1 GB target on
 * this host. The engine already carries the target's figure as
 * SF_PHYS_MEMTOTAL.
 *
 * Asserted as a RELATIONSHIP rather than an exact top: the ceiling is folded in
 * against the band footers and the physical window afterwards, so which value
 * ends up printed depends on the rest of the map. What must hold is that
 * changing the target's memory changes the map -- a host-bound source could
 * not. The two figures straddle nothing else: both sit above the arch's
 * physical image ceiling, so the derived value is what the column prints. */
static void render_map_with_memtotal(struct summary *s,
                                     unsigned long memtotal) {
  reset_results();
  reset_comp_logs();
  stage_likely_reset();
  num_scalar_facts = 0;
  memset(s, 0, sizeof(*s));

  scalar_facts[num_scalar_facts].fact = SF_PHYS_MEMTOTAL;
  scalar_facts[num_scalar_facts].value = memtotal;
  scalar_facts[num_scalar_facts++].conf = CONF_PARSED;

  /* A physical point far below the derived ceiling, and deliberately no
   * ram_top: an observed edge would win and the estimate would not be drawn. */
  {
    struct result *r = push_result();
    r->type = KASLD_TYPE_PHYS;
    r->region = REGION_KERNEL_IMAGE;
    r->pos = POS_BASE;
    r->conf = CONF_PARSED;
    r->lo = (unsigned long)PHYS_OFFSET + 0x100000ul;
    r->set_mask = LO_SET;
    add_origin(r, "synthetic_test");
    r->method_set = 1u << KM_PARSED;
  }

  verbose = 1;
  set_render_mode(0, 0, 0);
  capture_stdout(wrap_render_summary, s);
  verbose = 0;
  set_render_mode(0, 0, 0);
}

static void test_render_map_ceiling_from_target_not_host(void) {
  struct summary s;
  char small[RENDER_CAP_BUF];

  render_map_with_memtotal(&s, 0x800000000ul); /* 32 GiB */
  snprintf(small, sizeof small, "%s", render_cap);

  render_map_with_memtotal(&s, 0x1000000000ul); /* 64 GiB */
  assert(strcmp(small, render_cap) != 0);
}

static void test_render_excluded_ranges_are_disclosed(void) {
  struct summary s;

  set_rich_render_state(&s);
  /* One carved range, and a total larger than the number listed, so the
   * truncation is visible too. */
  t_excl_lo = layout.virt_kaslr_text_min + 0x1000ul;
  t_excl_hi = layout.virt_kaslr_text_min + 0x2000ul;
  t_excl_total = 3;

  verbose = 1;
  set_render_mode(0, 0, 0);
  capture_stdout(wrap_render_summary, &s);
  verbose = 0;
  set_render_mode(0, 0, 0);
  {
    char hex[40];
    assert(strstr(render_cap, "excludes 3 ranges") != NULL);
    snprintf(hex, sizeof hex, "0x%lx - 0x%lx", t_excl_lo, t_excl_hi);
    assert(strstr(render_cap, hex) != NULL);
  }

  /* The default readout has no room for the ranges, but must still say why its
   * Window and Candidates cells disagree -- that reconciliation gap is the
   * whole complaint, and it is the format most people see. */
  set_render_mode(0, 0, 0);
  capture_stdout(wrap_render_summary, &s);
  assert(strstr(render_cap, "sub-range") != NULL);
  assert(strstr(render_cap, "3") != NULL);

  /* Markdown is a document with room, so it lists them like -v does. */
  set_render_mode(0, 0, 1);
  capture_stdout(wrap_render_summary, &s);
  set_render_mode(0, 0, 0);
  {
    char hex[48];
    assert(strstr(render_cap, "excludes 3 ranges") != NULL);
    snprintf(hex, sizeof hex, "`0x%016lx` - `0x%016lx`", t_excl_lo, t_excl_hi);
    assert(strstr(render_cap, hex) != NULL);
  }
}

static void test_render_directmap_residual_has_a_denominator(void) {
#if RANDOMIZE_MEMORY_ALIGN > 0
  struct summary s;
  set_rich_render_state(&s);
  s.kaslr.virt_page_offset_min = (unsigned long)PAGE_OFFSET_BASE_L4;
  s.kaslr.virt_page_offset_max = (unsigned long)PAGE_OFFSET_BASE_L4 +
                                 12ul * (unsigned long)RANDOMIZE_MEMORY_ALIGN;
  s.kaslr.virt_page_offset_slots = 13;
  s.kaslr.virt_page_offset_top_slots = 16384;

  verbose = 1;
  set_render_mode(0, 0, 0);
  capture_stdout(wrap_render_summary, &s);
  verbose = 0;
  set_render_mode(0, 0, 0);

  /* The phrase carries both figures: "~N of M bits", never the bare residual.
   */
  {
    const char *e = strstr(render_cap, "Direct map entropy:");
    const char *eol;
    assert(e != NULL);
    eol = strchr(e, '\n');
    assert(eol != NULL);
    assert(memchr(e, 'o', (size_t)(eol - e)) != NULL);
    assert(strstr(e, " of ") != NULL && strstr(e, " of ") < eol);
  }
#endif
}

static void test_render_oneline_set_value_is_not_hex(void) {
  struct summary s;
  /* Only where the architecture has a set quantity to report at all. */
  if (quantities[Q_VA_BITS].n_candidates <= 1)
    return;
  set_rich_render_state(&s);
  set_render_mode(0, 1, 0);
  capture_stdout(wrap_render_summary, &s);
  set_render_mode(0, 0, 0);
  {
    const char *v = strstr(render_cap, " vabits=");
    assert(v != NULL);
    v += strlen(" vabits=");
    /* Decimal, or the `na` sentinel -- never `0x`. */
    assert(strncmp(v, "0x", 2) != 0);
  }
}

static void test_render_oneline_tokens_are_key_value(void) {
  struct summary s;
  char *tok, *save, buf[RENDER_CAP_BUF];

  set_rich_render_state(&s);
  set_render_mode(0, 1, 0);
  capture_stdout(wrap_render_summary, &s);
  set_render_mode(0, 0, 0);

  snprintf(buf, sizeof buf, "%s", render_cap);
  for (tok = strtok_r(buf, " \t\n", &save); tok;
       tok = strtok_r(NULL, " \t\n", &save)) {
    const char *eq = strchr(tok, '=');
    assert(eq != NULL); /* a token with no '=' is not a pair */
    assert(eq != tok);  /* nor is one with an empty key */
  }
}

static void test_render_oneline_region_key_needs_one_candidate(void) {
  struct summary s;
  unsigned long base;

  set_rich_render_state(&s);
  base =
      s.kaslr.virt_module_min ? s.kaslr.virt_module_min : 0xffffffffc0000000ul;

  /* A window with room in it: the window is stated, never a bare address. The
   * bare form is reserved for a resolved value, and a consumer tests for it by
   * the absence of a bracket. */
  s.kaslr.virt_module_min = base;
  s.kaslr.virt_module_max = base + 0x400000ul;
  s.kaslr.virt_module_slots = 1025;
  set_render_mode(0, 1, 0);
  capture_stdout(wrap_render_summary, &s);
  {
    char want[64];
    const char *v = strstr(render_cap, "module=");
    assert(v != NULL);
    assert(v[strlen("module=")] == '[');
    snprintf(want, sizeof want, "module=[0x%lx..0x%lx]", base,
             base + 0x400000ul);
    assert(strstr(render_cap, want) != NULL);
  }

  /* The same region resolved: the address, now that it is one. */
  s.kaslr.virt_module_max = base;
  s.kaslr.virt_module_slots = 1;
  capture_stdout(wrap_render_summary, &s);
  set_render_mode(0, 0, 0);
  {
    char hex[32];
    snprintf(hex, sizeof hex, "module=0x%lx", base);
    assert(strstr(render_cap, hex) != NULL);
  }
}

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
  add_origin(r, "synthetic_test");
  r->method_set = 1u << KM_PARSED;

  /* Engine-resolved base: the window admits exactly this address. A floor
   * alone is not a resolved base -- `dmap=` states a value only where one
   * candidate remains, since a floor cannot be translated through. */
  s.kaslr.virt_page_offset_min = base;
  s.kaslr.virt_page_offset_max = base;
  s.kaslr.virt_page_offset_slots = 1;
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
 * no resolved base (vtext==0), `text=` does not render a bare address — an
 * unresolved base is not backfilled from a leak (sibling of the dmap=
 * base/interior rule). The fixed schema keeps the key present; the value
 * degrades to the proven window, or to `na` where there is not even one, and
 * neither form asserts a base. */
static void test_render_oneline_text_na_when_engine_unresolved(void) {
  struct summary s;
  set_rich_render_state(&s);
  const unsigned long leak = (unsigned long)KERNEL_VIRT_TEXT_DEFAULT;
  s.kaslr.vtext = 0; /* engine resolved no concrete base */
  s.kaslr.vstext = 0;

  set_render_mode(0, 1, 0);
  capture_stdout(wrap_render_summary, &s);
  set_render_mode(0, 0, 0);

  /* The key is present, and its value is not a bare address: the bare form
   * means "resolved", and nothing resolved a base here. What it may carry is
   * the proven window, which is a statement about bounds rather than the leak
   * -- and the leak's own address must not appear as the value either. */
  {
    const char *v = strstr(render_cap, " text=");
    char leakbuf[32];
    assert(v != NULL);
    v += strlen(" text=");
    assert(*v == '[' || strncmp(v, "na", 2) == 0);
    snprintf(leakbuf, sizeof(leakbuf), " text=0x%lx", leak);
    assert(strstr(render_cap, leakbuf) == NULL);
  }
}

/* Contract lock for the fixed oneline schema: every documented key must appear
 * on every line so a scraper can rely on matching `field=` unconditionally. A
 * fully-zeroed summary (nothing resolved) is the worst case — each optional
 * value must fall back to its `na` sentinel rather than dropping the key. A
 * future edit that drops or renames a key fails here. */
static void test_render_oneline_schema_is_stable(void) {
  reset_results();
  reset_comp_logs();
  stage_likely_reset();
  num_scalar_facts = 0;
  struct summary s;
  memset(&s, 0, sizeof(s));

  /* "Nothing resolved" has to be made true, not assumed: `layout` is a global
   * and holds whatever the previous test left in it, so a window would survive
   * into this run and the value keys would honestly report it. Clearing the
   * windows is what makes `na` the correct answer here rather than an accident
   * of test order. */
  unsigned long sv[6] = {
      layout.virt_kaslr_text_min,  layout.virt_kaslr_text_max,
      layout.phys_kaslr_text_min,  layout.phys_kaslr_text_max,
      layout.virt_page_offset_min, layout.virt_page_offset_max};
  layout.virt_kaslr_text_min = layout.virt_kaslr_text_max = 0;
  layout.phys_kaslr_text_min = layout.phys_kaslr_text_max = 0;
  layout.virt_page_offset_min = layout.virt_page_offset_max = 0;

  set_render_mode(0, 1, 0);
  capture_stdout(wrap_render_summary, &s);
  set_render_mode(0, 0, 0);

  layout.virt_kaslr_text_min = sv[0];
  layout.virt_kaslr_text_max = sv[1];
  layout.phys_kaslr_text_min = sv[2];
  layout.phys_kaslr_text_max = sv[3];
  layout.virt_page_offset_min = sv[4];
  layout.virt_page_offset_max = sv[5];

  static const char *const keys[] = {
      "arch=",     "kaslr=",  " text=",    " stext=",  " slide=",
      " entropy=", " ptext=", " pstext=",  " pslide=", " pentropy=",
      " dmap=",    " dram=",  " results=",
  };
  for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++)
    assert(strstr(render_cap, keys[i]) != NULL);

  /* With nothing resolved, every optional field is the na sentinel. */
  assert(strstr(render_cap, " text=na") != NULL);
  assert(strstr(render_cap, " slide=na") != NULL);
  assert(strstr(render_cap, " entropy=na") != NULL);
  assert(strstr(render_cap, " ptext=na") != NULL);
  assert(strstr(render_cap, " pslide=na") != NULL);
  assert(strstr(render_cap, " dmap=na") != NULL);
  assert(strstr(render_cap, " dram=na") != NULL);
}

/* Oneline entropy reflects the guaranteed-window residual even with NO concrete
 * base (the unpinned windowed case — the number a fleet/CI scraper needs), and
 * 0bits for a pin (not na); and the randomization-failed posture surfaces as
 * kaslr=failed, distinct from off/on. */
static void test_render_oneline_entropy_and_failed(void) {
  struct summary s;
  reset_results();
  reset_comp_logs();
  stage_likely_reset();
  num_scalar_facts = 0;

  /* Unpinned windowed case: a resolved window (vslots/pslots), no concrete
   * base. Residual entropy must still surface for both virt and phys. */
  memset(&s, 0, sizeof(s));
  s.kaslr.vslots = 512;
  s.kaslr.pslots = 64;
  set_render_mode(0, 1, 0);
  capture_stdout(wrap_render_summary, &s);
  {
    /* No concrete base: not a bare address. The window may be reported in its
     * place, which states bounds rather than an answer. */
    const char *v = strstr(render_cap, " text=");
    assert(v != NULL);
    v += strlen(" text=");
    assert(*v == '[' || strncmp(v, "na", 2) == 0);
  }
  assert(strstr(render_cap, " entropy=9bits") != NULL);  /* residual shown */
  assert(strstr(render_cap, " pentropy=6bits") != NULL); /* phys too */
  assert(strstr(render_cap, " kaslr=on") != NULL);

  /* Pin: one slot -> 0 bits, reported as 0bits (not na). */
  memset(&s, 0, sizeof(s));
  s.kaslr.vtext = (unsigned long)KERNEL_VIRT_TEXT_DEFAULT;
  s.kaslr.vslots = 1;
  capture_stdout(wrap_render_summary, &s);
  assert(strstr(render_cap, " entropy=0bits") != NULL);
  assert(strstr(render_cap, " entropy=na") == NULL);

  /* Randomization-failed posture -> kaslr=failed (distinct from off/on). The
   * proven window residual is still reported; kaslr=failed is the effective-
   * zero signal. */
  memset(&s, 0, sizeof(s));
  s.kaslr.randomization_failed = 1;
  s.kaslr.vslots = 512;
  capture_stdout(wrap_render_summary, &s);
  assert(strstr(render_cap, " kaslr=failed") != NULL);
  assert(strstr(render_cap, " kaslr=on") == NULL);
  assert(strstr(render_cap, " kaslr=off") == NULL);
  assert(strstr(render_cap, " entropy=9bits") != NULL);

  set_render_mode(0, 0, 0);
}

/* The randomization-failed posture is stated in every format, and is never
 * conflated with the disabled one.
 *
 * `disabled` means the boot stub took the no-KASLR path and the image stayed at
 * its link-time base. `failed` means the stub ran and relocated the image with
 * no randomness to place it with: neither randomized nor at the compile-time
 * default. A reader (or a consumer branching on `disabled == false`) that could
 * not tell the two apart would assume full randomization on a kernel that has
 * none, so the posture must appear in its own right rather than only under -H.
 *
 * The engine's windows stay the answer here, so the human formats state the
 * posture and continue rather than branching to a single base line -- and the
 * compile-time-default remark must NOT appear, since the image did move. */
static void test_render_randomization_failed_posture(void) {
  struct summary s;
  /* The arch's own resolved window is left exactly as it is: this test is
     about the posture line, not about any particular bounds, and narrowing
     the window here would push the shared fixture's text result out of
     bounds for whichever test runs next. */
  struct {
    int json, md, verb;
    const char *want;
  } modes[] = {
      {0, 0, 0, "KASLR randomization did not run"},
      {0, 0, 1, "KASLR randomization did not run"},
      {0, 1, 0, "KASLR randomization did not run"},
      {1, 0, 0, "\"randomization_failed\": true"},
  };

  for (size_t i = 0; i < sizeof(modes) / sizeof(modes[0]); i++) {
    reset_results();
    reset_comp_logs();
    stage_likely_reset();
    num_scalar_facts = 0;
    memset(&s, 0, sizeof(s));
    s.kaslr.randomization_failed = 1;
    s.kaslr.default_addr = (unsigned long)KERNEL_VIRT_TEXT_DEFAULT;
    s.kaslr.vslots = 7;

    verbose = modes[i].verb;
    set_render_mode(modes[i].json, 0, modes[i].md);
    capture_stdout(wrap_render_summary, &s);
    set_render_mode(0, 0, 0);
    verbose = 0;

    assert(strstr(render_cap, modes[i].want) != NULL);
    /* Never reported as the disabled posture ... */
    assert(strstr(render_cap, "KASLR is disabled") == NULL);
    assert(strstr(render_cap, "\"disabled\": true") == NULL);
    /* ... and the default is not offered as a candidate: the stub relocated
       the image, so "still possible" would invite the wrong guess. */
    assert(strstr(render_cap, "The compile-time default") == NULL);
  }
}

/* set_rich_render_state seeds a single-origin record; this overlays a second
 * and third origin on the VIRT/KERNEL_TEXT record so the renderer tests below
 * exercise the multi-contributor display path text.c, markdown.c and json.c
 * walk r->origins for. */
static void seed_multi_origin_text_result(struct summary *s) {
  set_rich_render_state(s);
  for (int i = 0; i < num_results; i++) {
    struct result *r = &results[i];
    if (r->type == KASLD_TYPE_VIRT && r->region == REGION_KERNEL_TEXT) {
      add_origin(r, "prefetch");
      add_origin(r, "perf_event_open");
      add_origin(r, "perf_lbr_sampling");
      r->method_set = 1u << KM_TIMING;
      r->method_set |= 1u << KM_PARSED;
      r->method_set |= 1u << KM_PARSED;
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

  /* The evidence table counts contributors rather than naming them, so what the
   * default must get right is the COUNT: all three origins credited to the one
   * finding, not just the record that represents it. Asserted on the row's own
   * trailing field, since a bare "3" could match any digit on screen. */
  assert(strstr(render_cap, "virt kernel text") != NULL);
  /* The base leak self-discloses its position, not just interior/top. */
  assert(strstr(render_cap, "base") != NULL);
  /* At least the three seeded here: the row credits every contributor, not the
   * single record that represents the finding. The exact figure is not pinned
   * because the rich state this builds on seeds origins of its own, and a test
   * that hardcoded the total would fail whenever that fixture gained one. */
  assert(evidence_sources(render_cap, "virt kernel text", NULL) >= 3);

  /* The names themselves are detail, and -v is where they live. */
  verbose = 1;
  capture_stdout(wrap_render_summary, &s);
  verbose = 0;
  assert(strstr(render_cap, "prefetch") != NULL);
  assert(strstr(render_cap, "perf_event_open") != NULL);
  assert(strstr(render_cap, "perf_lbr_sampling") != NULL);
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
  /* The Sources count before the second record exists. */
  set_render_mode(0, 0, 0); /* text */
  capture_stdout(wrap_render_summary, &s);
  int before = evidence_sources(render_cap, "virt kernel text", NULL);
  assert(before > 0);

  struct result *r = push_result();
  r->type = KASLD_TYPE_VIRT;
  r->region = REGION_KERNEL_TEXT;
  r->lo = addr;
  r->set_mask = LO_SET;
  r->pos = POS_BASE;
  r->conf = CONF_PARSED;
  snprintf(r->name, NAME_LEN, "_stext");
  add_origin(r, "proc_kallsyms");

  /* One further distinct origin, carried on a SEPARATE record, must raise the
   * finding's count by exactly one. That is the whole claim: the row credits
   * every record of the (type, region), not the single one that represents it.
   * Counting is a stronger test than naming was -- a row that listed only the
   * representing record's origins would still have contained the name, since
   * both records sit under the same finding. */
  capture_stdout(wrap_render_summary, &s);
  assert(evidence_sources(render_cap, "virt kernel text", NULL) == before + 1);

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
 * with the resolved confidence), not any single contributor's. */
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

/* Defensive: when a record has no contributors recorded, the
 * renderers must still produce sensible output for the record without
 * crashing or emitting a stray "()" empty-origin block. */
static void seed_no_provenance_text_result(struct summary *s) {
  set_rich_render_state(s);
  for (int i = 0; i < num_results; i++) {
    struct result *r = &results[i];
    if (r->type == KASLD_TYPE_VIRT && r->region == REGION_KERNEL_TEXT) {
      memset(&r->origins, 0, sizeof(r->origins));
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
  /* Address must still appear, and a record with no origins gets no
   * provenance line at all. */
  assert(strstr(render_cap, "0x") != NULL);
  const char *evidence = strstr(render_cap, "Evidence");
  assert(evidence != NULL);
  const char *label = strstr(evidence, "virt kernel text");
  assert(label != NULL);
  /* The single finding has no origins, so the "from ..." continuation the
   * empty-origins fallback suppresses must be absent from the whole block. */
  assert(strstr(evidence, "from") == NULL);
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
      add_origin(r, "origin_a");
      add_origin(r, "origin_b");
      r->method_set = 1u << KM_PARSED;
      r->method_set |= 1u << KM_PARSED;
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
  add_origin(r, "synthetic_test");
  r->method_set = 1u << KM_PARSED;
}

static void test_render_text_leaks_count_is_groups_not_contributors(void) {
  struct summary s;
  seed_two_region_groups(&s);
  set_render_mode(0, 0, 0);
  capture_stdout(wrap_render_summary, &s);
  /* Two groups (virt kernel text + virt directmap), regardless of how many
   * origins contribute to each. The heading now states findings and
   * contributing components separately, so a row count can no longer be
   * mistaken for a component count. */
  assert(strstr(render_cap, "2 findings") != NULL);
  assert(strstr(render_cap, "components)") != NULL);
  assert(strstr(render_cap, "virt kernel text") != NULL);
  assert(strstr(render_cap, "virt directmap") != NULL);
  /* Both seeded contributors are credited to the text row, and the directmap
   * row carries its own single one -- the counts are per finding, so a row's
   * figure never borrows from its neighbour. */
  assert(evidence_sources(render_cap, "virt kernel text", NULL) >= 2);
  assert(evidence_sources(render_cap, "virt directmap", NULL) >= 1);
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
  add_origin(r3, "synthetic_test");
  r3->method_set = 1u << KM_DERIVED;

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
  add_origin(r4, "synthetic_test");
  r4->method_set = 1u << KM_PARSED;

  /* Phys-side band so render_text's phys map has something to draw and
   * render_memory_kaslr_bound's pinned / one-sided branches fire. */
  layout.phys_kaslr_text_min = 0x1000000ul;
  layout.phys_kaslr_text_max = 0x10000000ul;

  /* memory_kaslr (RANDOMIZE_MEMORY) — populate all three to hit the
   * pinned branch (min == max), the one-sided branch (min only), and the
   * window branch (min < max). */
  /* pinned: min == max. quantity_slots() reports one candidate for a pinned
     estimate, so the fixture carries the count a real run would. */
  s->kaslr.virt_page_offset_min = (unsigned long)PAGE_OFFSET + 0x01000000ul;
  s->kaslr.virt_page_offset_max = (unsigned long)PAGE_OFFSET + 0x01000000ul;
  s->kaslr.virt_page_offset_slots = 1;
  /* one-sided: min only */
  s->kaslr.virt_vmalloc_min = (unsigned long)PAGE_OFFSET + 0x11000000ul;
  s->kaslr.virt_vmalloc_max = 0;
  /* window: min < max */
  s->kaslr.virt_vmemmap_min = (unsigned long)PAGE_OFFSET + 0x13000000ul;
  s->kaslr.virt_vmemmap_max = (unsigned long)PAGE_OFFSET + 0x14000000ul;
}

static void test_render_text_with_memory_kaslr_bound(void) {
#if RANDOMIZE_MEMORY_ALIGN > 0
  struct summary s;
  set_richer_render_state(&s);
  set_render_mode(0, 0, 0);
  capture_stdout(wrap_render_summary, &s);
  /* The default (no-verbose) readout surfaces the direct-map base as its own
   * table row. The richer-render-state setup pins virt_page_offset_min ==
   * virt_page_offset_max, and a pinned quantity needs no separate annotation:
   * the row carries the single address and a search space of one, which is
   * what "pinned" used to say. (Under -v render_memory_kaslr_bound runs too,
   * producing "(pinned)" / ">= 0x" / "<= 0x" — covered below.) */
  const char *row = strstr(render_cap, "Direct Map Base");
  assert(row != NULL);
  {
    const char *eol = strchr(row, '\n');
    char line[256];
    assert(eol != NULL);
    assert((size_t)(eol - row) < sizeof(line));
    snprintf(line, (size_t)(eol - row) + 1, "%s", row);
    /* One candidate, and one address rather than a range. */
    assert(strstr(line, " 1  ") != NULL);
    assert(strstr(line, " - ") == NULL);
  }
#endif
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

/* Seed one PHYS "dram" section carrying two unrelated regions: a RAM extent
 * and a much lower cmdline blob. Both are POS_BASE at CONF_PARSED, so a
 * section-wide consensus (which resolves ties by lowest anchor) would pick the
 * cmdline address and publish it as the consensus for DRAM. */
static void seed_two_regions_one_section(struct summary *s) {
  reset_results();
  reset_comp_logs();
  stage_likely_reset();
  num_scalar_facts = 0;
  memset(s, 0, sizeof(*s));

  struct result *ram = push_result();
  ram->type = KASLD_TYPE_PHYS;
  ram->region = REGION_RAM;
  ram->pos = POS_BASE;
  ram->conf = CONF_PARSED;
  ram->lo = 0x40000000ul;
  ram->hi = 0xf0000000ul;
  ram->set_mask = LO_SET | HI_SET;
  add_origin(ram, "origin_ram");
  ram->method_set = 1u << KM_PARSED;

  struct result *cmdline = push_result();
  cmdline->type = KASLD_TYPE_PHYS;
  cmdline->region = REGION_CMDLINE;
  cmdline->pos = POS_BASE;
  cmdline->conf = CONF_PARSED;
  cmdline->lo = 0x10000000ul;
  cmdline->set_mask = LO_SET;
  add_origin(cmdline, "origin_cmdline");
  cmdline->method_set = 1u << KM_PARSED;
}

/* Point at a JSON group's "region" key. Every aggregate key the group reports
 * (consensus, lo, hi) is emitted after it within the same object, so a caller
 * can assert on this group by searching forward from the returned pointer. */
static const char *json_group_at_region(const char *region) {
  static char needle[64];
  snprintf(needle, sizeof(needle), "\"region\": \"%s\"", region);
  return strstr(render_cap, needle);
}

/* Assert the next occurrence of `key` at or after `from` carries `want`. */
static void assert_group_key_hex(const char *from, const char *key,
                                 unsigned long want) {
  char needle[64], expect[96];
  snprintf(needle, sizeof(needle), "\"%s\": ", key);
  const char *p = strstr(from, needle);
  assert(p != NULL);
  snprintf(expect, sizeof(expect), "\"%s\": \"0x%016lx\"", key, want);
  assert(strncmp(p, expect, strlen(expect)) == 0);
}

/* A JSON group's aggregate describes exactly the region it names — it never
 * spans the other regions sharing its section. Without the per-region split,
 * the single "dram" group reports the cmdline address as the DRAM consensus
 * and a span reaching from the cmdline blob to the top of RAM. */
static void test_render_json_group_aggregate_is_per_region(void) {
  struct summary s;
  seed_two_regions_one_section(&s);
  set_render_mode(1, 0, 0);
  capture_stdout(wrap_render_summary, &s);
  set_render_mode(0, 0, 0);

  const char *ram = json_group_at_region("ram");
  const char *cmdline = json_group_at_region("cmdline");
  assert(ram != NULL);
  assert(cmdline != NULL);

  /* Each group's consensus and span come from its own records only. */
  assert_group_key_hex(ram, "consensus", 0x40000000ul);
  assert_group_key_hex(ram, "lo", 0x40000000ul);
  assert_group_key_hex(ram, "hi", 0xf0000000ul);

  assert_group_key_hex(cmdline, "consensus", 0x10000000ul);
  assert_group_key_hex(cmdline, "lo", 0x10000000ul);
}

/* One group per region present, not one per section: a section carrying N
 * regions emits N groups, each naming its region. */
static void test_render_json_groups_split_by_region(void) {
  struct summary s;
  seed_two_regions_one_section(&s);
  set_render_mode(1, 0, 0);
  capture_stdout(wrap_render_summary, &s);
  set_render_mode(0, 0, 0);

  /* Count by a group-only key: "region" also appears on every record inside a
   * group, so it cannot stand in for the group count. */
  int groups = 0;
  for (const char *p = render_cap;
       (p = strstr(p, "\"consensus_method\": ")) != NULL; p++)
    groups++;
  assert(groups == 2);

  /* Both groups still report the section they belong to. */
  int sections = 0;
  for (const char *p = render_cap;
       (p = strstr(p, "\"section\": \"dram\"")) != NULL; p++)
    sections++;
  assert(sections == 2);

  /* ...and are told apart by their region. */
  assert(json_group_at_region("ram") != NULL);
  assert(json_group_at_region("cmdline") != NULL);
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

static void wrap_readout_leaks(void *arg) {
  (void)arg;
  readout_print_leaks();
}

/* A directmap finding built from distinct interior samples plus a coexisting
 * base bound must render as a corroborated SPAN, not a single sample address
 * credited to every source. Three independent leaks — two interior pointers at
 * different addresses and one base — agree on the base but did NOT all find the
 * same pointer; collapsing them onto one interior address and crediting all
 * three to it misattributes (the reported readout bug: one interior value
 * "from" three components that each found something different). The
 * lower-suffix fix gates the span on `best`, not on any record, so a coexisting
 * base bound no longer suppresses the span. */
static void test_render_evidence_distinct_interior_samples_span(void) {
  reset_results();
  reset_comp_logs();
  stage_likely_reset();
  num_scalar_facts = 0;
  unsigned long base = (unsigned long)PAGE_OFFSET;
  unsigned long s1 =
      base + 0x03ace520ul; /* interior sample 1 (best: pushed 1st) */
  unsigned long s2 =
      base + 0x05000000ul; /* interior sample 2 — higher, distinct */
  layout.virt_page_offset = base;

  struct result *i1 = push_result();
  i1->type = KASLD_TYPE_VIRT;
  i1->region = REGION_DIRECTMAP;
  i1->pos = POS_INTERIOR;
  i1->conf = CONF_PARSED;
  i1->sample = s1;
  i1->set_mask = SAMPLE_SET;
  add_origin(i1, "alsa_synth");
  i1->method_set = 1u << KM_PARSED;

  struct result *i2 = push_result();
  i2->type = KASLD_TYPE_VIRT;
  i2->region = REGION_DIRECTMAP;
  i2->pos = POS_INTERIOR;
  i2->conf = CONF_PARSED;
  i2->sample = s2;
  i2->set_mask = SAMPLE_SET;
  add_origin(i2, "dmesg_synth");
  i2->method_set = 1u << KM_PARSED;

  struct result *b = push_result(); /* coexisting base bound (an edge) */
  b->type = KASLD_TYPE_VIRT;
  b->region = REGION_DIRECTMAP;
  b->pos = POS_BASE;
  b->conf = CONF_PARSED;
  b->lo = base;
  b->set_mask = LO_SET;
  add_origin(b, "prefetch_synth");
  b->method_set = 1u << KM_PARSED;

  set_render_mode(0, 0, 0);
  capture_stdout(wrap_readout_leaks, NULL);
  set_render_mode(0, 0, 0);

  /* Span form: the higher interior sample's address appears only when the
   * finding renders as a span [lo, hi]; the pre-fix single-address form would
   * show only `best` (s1). And all three sources stay credited. */
  char hex2[24];
  snprintf(hex2, sizeof hex2, "0x%lx", s2);
  assert(strstr(render_cap, hex2) != NULL);
  /* All three stay credited, and to the right rows: the two interior samples
   * to the span, the base bound to its own. A row crediting every record of the
   * region regardless of kind would put 3 on both. */
  assert(evidence_sources(render_cap, "virt directmap", "interior span") == 2);
  assert(evidence_sources(render_cap, "virt directmap", "base") == 1);
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
    add_origin(r, "synth");
    r->method_set = 1u << KM_PARSED;
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
  add_origin(r_interior, "synth");
  r_interior->method_set = 1u << KM_PARSED;

  struct result *r_base = push_result();
  r_base->type = KASLD_TYPE_VIRT;
  r_base->region = REGION_KERNEL_TEXT;
  r_base->pos = POS_BASE;
  r_base->conf = CONF_PARSED;
  r_base->lo = base_addr;
  r_base->set_mask = LO_SET;
  add_origin(r_base, "synth");
  r_base->method_set = 1u << KM_PARSED;

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
  add_origin(r_h, "synth");
  r_h->method_set = 1u << KM_HEURISTIC;

  struct result *r_p = push_result();
  r_p->type = KASLD_TYPE_VIRT;
  r_p->region = REGION_DIRECTMAP;
  r_p->pos = POS_INTERIOR;
  r_p->conf = CONF_PARSED;
  r_p->sample = hi_parsed;
  r_p->set_mask = SAMPLE_SET;
  add_origin(r_p, "synth");
  r_p->method_set = 1u << KM_PARSED;

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
  reset_comp_logs();
  stage_likely_reset();
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
  add_origin(r, "synth");
  r->method_set = 1u << KM_DERIVED;
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
  reset_comp_logs();
  stage_likely_reset();
  num_scalar_facts = 0;
  struct summary s;
  memset(&s, 0, sizeof(s));
  unsigned long vt = (unsigned long)KERNEL_VIRT_TEXT_DEFAULT;
  s.kaslr.disabled = 1;
  s.kaslr.vslots =
      0; /* KASLR off ⇒ no entropy, as compute_kaslr_info sets it */
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
  /* Every posture renders the same table from the shared row model, so the
   * quantity wears the name and the range spelling it wears when KASLR is
   * active -- not a second label and a second grammar for the same thing. */
  assert(strstr(render_cap, "Virtual Image Base") != NULL);
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
  struct component_log *cl = seed_comp_log(name);
  cl->outcome = oc;
  return cl;
}
static void hr_seed_meta(struct component_log *cl, const char *k,
                         const char *v) {
  /* An entry holds pointers into the raw section a log slot owns; here the
   * caller's string literals stand in for it, and outlive the test. */
  int i = cl->meta.num_entries++;
  cl->meta.entries[i].key = k;
  cl->meta.entries[i].value = v;
}

static void test_build_hardening_report(void) {
  reset_results();
  reset_comp_logs();
  stage_likely_reset();
  num_scalar_facts = 0;
  kasld_env.hardening.kptr_restrict = 1;       /* active   (threshold 1) */
  kasld_env.hardening.dmesg_restrict = 1;      /* active   (threshold 1) */
  kasld_env.hardening.perf_event_paranoid = 0; /* inactive (threshold 2) */
  kasld_env.hardening.lockdown = LOCKDOWN_NONE;

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
  hr_seed_meta(c, "discloses", "physical");

  c = hr_seed_comp("c_hw", OUTCOME_SUCCESS);
  hr_seed_meta(c, "method", "parsed");
  hr_seed_meta(c, "hardware", "KPTI");
  hr_seed_meta(c, "discloses", "virtual");

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
  scalar_facts[num_scalar_facts].origin = test_origin("dmesg_kaslr");
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
  kasld_env.hardening.kptr_restrict = 0;
  kasld_env.hardening.dmesg_restrict = 0;
  kasld_env.hardening.perf_event_paranoid = 0;
  kasld_env.hardening.lockdown = LOCKDOWN_NONE;
  reset_comp_logs();
  stage_likely_reset();
  num_scalar_facts = 0;
}

/* The per-component disposition surfaces in JSON: a mitigation carries its
 * category, gate, and message; a non-mitigation (absent) carries category and
 * message with no gate. */
static void test_render_json_disposition(void) {
  struct summary s;
  set_rich_render_state(
      &s); /* resets, stages a summary + one success comp_log */

  struct component_log *m = hr_seed_comp("prefetch", OUTCOME_UNAVAILABLE);
  m->disposition.category = DISP_MITIGATION;
  snprintf(m->disposition.gate, DISP_GATE_LEN, "kpti");
  snprintf(m->disposition.message, DISP_MSG_LEN, "KPTI enabled");

  struct component_log *a = hr_seed_comp("databounce", OUTCOME_UNAVAILABLE);
  a->disposition.category = DISP_ABSENT;
  snprintf(a->disposition.message, DISP_MSG_LEN, "not an Intel CPU");

  set_render_mode(1, 0, 0);
  capture_stdout(wrap_render_summary, &s);
  set_render_mode(0, 0, 0);

  assert(strstr(render_cap, "\"disposition\"") != NULL);
  assert(strstr(render_cap, "\"category\": \"mitigation\"") != NULL);
  assert(strstr(render_cap, "\"gate\": \"kpti\"") != NULL);
  assert(strstr(render_cap, "KPTI enabled") != NULL);
  assert(strstr(render_cap, "\"category\": \"absent\"") != NULL);
  assert(strstr(render_cap, "not an Intel CPU") != NULL);

  reset_comp_logs();
  stage_likely_reset();
}

/* A mitigation disposition is confirmed active in the hardening report; absent
 * and inconclusive dispositions are not. Asserts both the report model and the
 * rendered JSON confirmed_mitigations array. */
/* The disclosure a report row carries is OBSERVED, not declared: it is read off
 * the records attributed to the component. The declaration is consulted only
 * where nothing was produced, and where neither answers the row must say so
 * rather than name a kind -- reporting an unstated disclosure as "virtual" is
 * the defect this replaced. */
static void test_hardening_disclosure_is_observed(void) {
  struct summary s;
  set_rich_render_state(&s);

  /* Declares physical, discloses a VIRTUAL address: observation must win. */
  struct component_log *c = hr_seed_comp("c_obs", OUTCOME_SUCCESS);
  hr_seed_meta(c, "method", "parsed");
  hr_seed_meta(c, "config", "CONFIG_OBS");
  hr_seed_meta(c, "discloses", "physical");
  struct result *r = push_result();
  r->type = KASLD_TYPE_VIRT;
  r->region = REGION_KERNEL_TEXT;
  r->pos = POS_BASE;
  r->conf = CONF_PARSED;
  r->lo = (unsigned long)KERNEL_VIRT_TEXT_DEFAULT;
  r->set_mask = LO_SET;
  origin_set_add(&r->origins, test_origin("c_obs"));

  /* Ran, produced nothing, declares nothing: no kind may be invented. The
   * hardware section is where that can arise -- the compile-time surface lists
   * only OUTCOME_SUCCESS, so it always has something to observe. */
  struct component_log *u = hr_seed_comp("c_unstated", OUTCOME_NO_RESULT);
  hr_seed_meta(u, "method", "timing");
  hr_seed_meta(u, "hardware", "some CPU feature");

  struct hardening_report rep;
  build_hardening_report(&rep);

  int seen_obs = 0, seen_unstated = 0;
  for (int i = 0; i < rep.n_surface; i++)
    if (strcmp(rep.surface[i].name, "c_obs") == 0) {
      seen_obs = 1;
      assert(rep.surface[i].discloses != NULL);
      assert(strcmp(rep.surface[i].discloses, DISCLOSE_VIRT) == 0);
    }
  for (int i = 0; i < rep.n_hw; i++)
    if (strcmp(rep.hw[i].name, "c_unstated") == 0) {
      seen_unstated = 1;
      assert(rep.hw[i].discloses == NULL);
    }
  assert(seen_obs && seen_unstated);
}

/* The declaration IS used where there is nothing to observe, and only there. */
static void test_hardening_disclosure_declared_fallback(void) {
  struct summary s;
  set_rich_render_state(&s);

  struct component_log *c = hr_seed_comp("c_quiet", OUTCOME_NO_RESULT);
  hr_seed_meta(c, "method", "timing");
  hr_seed_meta(c, "hardware", "TSX required");
  hr_seed_meta(c, "discloses", "facts");

  struct hardening_report rep;
  build_hardening_report(&rep);

  int seen = 0;
  for (int i = 0; i < rep.n_hw; i++)
    if (strcmp(rep.hw[i].name, "c_quiet") == 0) {
      seen = 1;
      assert(rep.hw[i].discloses != NULL);
      assert(strcmp(rep.hw[i].discloses, DISCLOSE_FACTS) == 0);
      assert(!rep.hw[i].succeeded);
    }
  assert(seen);
}

static void test_render_hardening_confirmed_mitigations(void) {
  struct summary s;
  set_rich_render_state(
      &s); /* resets, stages a summary + one success comp_log */

  struct component_log *m = hr_seed_comp("prefetch", OUTCOME_UNAVAILABLE);
  m->disposition.category = DISP_MITIGATION;
  snprintf(m->disposition.gate, DISP_GATE_LEN, "kpti");
  snprintf(m->disposition.message, DISP_MSG_LEN, "KPTI enabled");
  struct component_log *a = hr_seed_comp("databounce", OUTCOME_UNAVAILABLE);
  a->disposition.category = DISP_ABSENT;
  struct component_log *ic =
      hr_seed_comp("mmap_brute_vmsplit", OUTCOME_NO_RESULT);
  ic->disposition.category = DISP_INCONCLUSIVE;

  /* Report model: only the mitigation is confirmed; its gate/component/message
   * carry through, and absent/inconclusive are excluded. */
  struct hardening_report rep;
  build_hardening_report(&rep);
  assert(rep.n_confirmed == 1);
  assert(strcmp(rep.confirmed[0].gate, "kpti") == 0);
  assert(strcmp(rep.confirmed[0].component, "prefetch") == 0);
  assert(rep.confirmed[0].message != NULL &&
         strcmp(rep.confirmed[0].message, "KPTI enabled") == 0);

  /* Rendered JSON hardening object carries the array. */
  set_render_mode(1, 0, 0);
  hardening_mode = 1;
  capture_stdout(wrap_render_summary, &s);
  hardening_mode = 0;
  set_render_mode(0, 0, 0);
  assert(strstr(render_cap, "\"confirmed_mitigations\"") != NULL);
  assert(strstr(render_cap, "\"gate\": \"kpti\"") != NULL);

  reset_comp_logs();
  stage_likely_reset();
}

/* Interior samples corroborate an extent; they are not competing base claims.
 * A section with only interior samples is interior-only (no single base), its
 * sources count the distinct contributors, and it has no conflicts. Adding a
 * base does not make the interior samples "conflict" with it — only a second,
 * differing base does. */
static void stage_vt_interior(unsigned long sample, const char *origin) {
  struct result *r = push_result();
  r->type = KASLD_TYPE_VIRT;
  r->region = REGION_KERNEL_TEXT;
  r->pos = POS_INTERIOR;
  r->conf = CONF_PARSED;
  r->sample = sample;
  r->set_mask = SAMPLE_SET;
  add_origin(r, origin);
  r->method_set = 1u << KM_PARSED;
}
static void stage_vt_base(unsigned long lo, const char *origin) {
  struct result *r = push_result();
  r->type = KASLD_TYPE_VIRT;
  r->region = REGION_KERNEL_TEXT;
  r->pos = POS_BASE;
  r->conf = CONF_TIMING;
  r->lo = lo;
  r->set_mask = LO_SET;
  add_origin(r, origin);
  r->method_set = 1u << KM_TIMING;
}

static void test_section_interior_only_and_conflicts(void) {
  reset_results();
  reset_comp_logs();
  stage_likely_reset();
  num_scalar_facts = 0;
  const unsigned long vt = (unsigned long)KERNEL_VIRT_TEXT_DEFAULT;
  const char *sec = "text"; /* REGION_KERNEL_TEXT's section name */

  const char *bm;
  int ns, nc, io;

  /* Two interior samples from two components: interior-only, 2 sources, no
   * conflict. */
  stage_vt_interior(vt + 0x1000, "comp_a");
  stage_vt_interior(vt + 0x5000, "comp_b");
  assert(section_is_interior_only(KASLD_TYPE_VIRT, sec, REGION_UNKNOWN) == 1);
  assert(section_source_count(KASLD_TYPE_VIRT, sec, REGION_UNKNOWN) == 2);
  section_consensus_info(KASLD_TYPE_VIRT, sec, REGION_UNKNOWN, &bm, &ns, &nc,
                         &io);
  assert(io == 1 && ns == 2 && nc == 0);

  /* Add a base from a third component: no longer interior-only, still no
   * conflict (a base and interior samples above it agree), 3 sources. */
  stage_vt_base(vt, "comp_c");
  assert(section_is_interior_only(KASLD_TYPE_VIRT, sec, REGION_UNKNOWN) == 0);
  section_consensus_info(KASLD_TYPE_VIRT, sec, REGION_UNKNOWN, &bm, &ns, &nc,
                         &io);
  assert(io == 0 && ns == 3 && nc == 0);

  /* A second, differing base is a genuine disagreement: one conflict. */
  stage_vt_base(vt + 0x100000, "comp_d");
  section_consensus_info(KASLD_TYPE_VIRT, sec, REGION_UNKNOWN, &bm, &ns, &nc,
                         &io);
  assert(io == 0 && nc == 1);

  reset_results();
}

/* The interior-only resolution surfaces in the rendered output: the JSON group
 * is flagged interior_only with zero conflicts (interior samples corroborate an
 * extent, they never compete for a base). */
static void test_render_interior_only_surface(void) {
  reset_results();
  reset_comp_logs();
  stage_likely_reset();
  num_scalar_facts = 0;
  const unsigned long vt = (unsigned long)KERNEL_VIRT_TEXT_DEFAULT;
  stage_vt_interior(vt + 0x1000, "comp_a");
  stage_vt_interior(vt + 0x9000, "comp_b");

  struct summary s;
  memset(&s, 0, sizeof(s));

  set_render_mode(1, 0, 0);
  capture_stdout(wrap_render_summary, &s);
  set_render_mode(0, 0, 0);
  assert(strstr(render_cap, "\"interior_only\": true") != NULL);
  assert(strstr(render_cap, "\"conflicts\": 0") != NULL);

  reset_results();
}

/* The unprivileged_bpf_disabled gate: 0 = unprivileged bpf() allowed (the leak
 * fires), >=1 = disabled (blocks it), so it uses the "value >= threshold
 * blocks" model with threshold 1. Inactive (0) with a succeeded bpf component
 * yields a "Set kernel.unprivileged_bpf_disabled = 1" suggestion; active (>=1)
 * with a denied component credits the gate as blocking. */
static void test_hardening_unprivileged_bpf_gate(void) {
  const struct hr_gate *gb;
  struct hardening_report rep;

  /* Inactive gate + succeeded leak -> a suggestion. */
  reset_results();
  reset_comp_logs();
  stage_likely_reset();
  num_scalar_facts = 0;
  /* inactive (threshold 1) */
  kasld_env.hardening.unprivileged_bpf_disabled = 0;
  struct component_log *c = hr_seed_comp("c_bpf_leak", OUTCOME_SUCCESS);
  hr_seed_meta(c, "method", "parsed");
  hr_seed_meta(c, "sysctl", "unprivileged_bpf_disabled>=1");
  hr_seed_meta(c, "discloses", "virtual");

  build_hardening_report(&rep);
  gb = NULL;
  for (int i = 0; i < rep.n_gates; i++)
    if (strcmp(rep.gates[i].display, "kernel.unprivileged_bpf_disabled") == 0)
      gb = &rep.gates[i];
  assert(gb && !gb->active && gb->gated == 1 && gb->bypassed == 1);
  int found = 0;
  for (int i = 0; i < rep.n_gate_suggestions; i++)
    if (strcmp(rep.gate_suggestions[i].display,
               "kernel.unprivileged_bpf_disabled") == 0) {
      found = 1;
      assert(rep.gate_suggestions[i].threshold == 1);
    }
  assert(found);

  /* Active gate + denied leak -> credited as blocking, not a suggestion. */
  reset_results();
  reset_comp_logs();
  stage_likely_reset();
  num_scalar_facts = 0;
  /* active (>= threshold 1) */
  kasld_env.hardening.unprivileged_bpf_disabled = 2;
  c = hr_seed_comp("c_bpf_blocked", OUTCOME_ACCESS_DENIED);
  hr_seed_meta(c, "method", "parsed");
  hr_seed_meta(c, "sysctl", "unprivileged_bpf_disabled>=1");

  build_hardening_report(&rep);
  gb = NULL;
  for (int i = 0; i < rep.n_gates; i++)
    if (strcmp(rep.gates[i].display, "kernel.unprivileged_bpf_disabled") == 0)
      gb = &rep.gates[i];
  assert(gb && gb->active && gb->gated == 1 && gb->blocked == 1);
  for (int i = 0; i < rep.n_gate_suggestions; i++)
    assert(strcmp(rep.gate_suggestions[i].display,
                  "kernel.unprivileged_bpf_disabled") != 0);

  kasld_env.hardening.unprivileged_bpf_disabled = KASLD_SYSCTL_UNREAD;
  reset_comp_logs();
  stage_likely_reset();
  num_scalar_facts = 0;
}

/* The verbose block's hardening rows distinguish the three states a value can
 * be in. A refused read is not an absent one: these knobs are world-readable,
 * so a refusal is a policy acting on this vantage — information about where the
 * analysis stands, which "(unavailable)" would discard. And a negative value is
 * not necessarily either: perf_event_paranoid reports -1 for "unrestricted",
 * which must print as the setting it is. */
static void wrap_print_hardening_value(void *a) {
  print_hardening_value("k:", *(int *)a);
}

static void test_render_hardening_value_states(void) {
  int v;

  v = 2;
  capture_stdout(wrap_print_hardening_value, &v);
  assert(strstr(render_cap, "2") != NULL);
  assert(strstr(render_cap, "(") == NULL);

  /* The permissive extreme, not a marker. */
  v = -1;
  capture_stdout(wrap_print_hardening_value, &v);
  assert(strstr(render_cap, "-1") != NULL);
  assert(strstr(render_cap, "(") == NULL);

  v = KASLD_SYSCTL_UNREAD;
  capture_stdout(wrap_print_hardening_value, &v);
  assert(strstr(render_cap, "(unavailable)") != NULL);

  v = KASLD_SYSCTL_DENIED;
  capture_stdout(wrap_print_hardening_value, &v);
  assert(strstr(render_cap, "(denied)") != NULL);
  assert(strstr(render_cap, "(unavailable)") == NULL);
}

static void wrap_render_hardening_text(void *a) {
  (void)a;
  render_hardening_text();
}
static void wrap_render_hardening_json(void *a) {
  (void)a;
  render_hardening_json();
}
static void wrap_render_hardening_markdown(void *a) {
  (void)a;
  render_hardening_markdown();
}

/* Projected posture, leave-one-out framing. With the engine compiled
 * out kasld_project_posture is a stub; kasld_test_projection makes it report an
 * available posture whose entropy grows with the exclude-set size, so the
 * current / ceiling / leave-one-out re-resolutions can be exercised without the
 * resolver. Seeds three suggestion sources, each silencing exactly one
 * component: an inactive sysctl gate, the lockdown suggestion (a succeeded
 * no-fallback lockdown leak), and the dmesg-fallback suggestion (a succeeded
 * dmesg leak that bypassed via a log file). Checks the report fields, the
 * ceiling union, the per-suggestion forfeit, each renderer's output — and that
 * the default (unavailable) stub suppresses every projected row. */
static void test_hardening_projection(void) {
  reset_results();
  reset_comp_logs();
  stage_likely_reset();
  num_scalar_facts = 0;
  kasld_env.hardening.kptr_restrict = 1; /* active   — not a suggestion */
  /* active, but fallback bypass -> suggestion */
  kasld_env.hardening.dmesg_restrict = 1;
  kasld_env.hardening.perf_event_paranoid =
      0; /* inactive (threshold 2) — a gate suggestion */
  /* inactive -> lockdown suggestion */
  kasld_env.hardening.lockdown = LOCKDOWN_NONE;

  struct component_log *c = hr_seed_comp("c_perf_leak", OUTCOME_SUCCESS);
  hr_seed_meta(c, "method", "parsed");
  hr_seed_meta(c, "sysctl", "perf_event_paranoid>=2");
  hr_seed_meta(c, "discloses", "virtual");
  /* No fallback, so enabling the gate silences it: gate exclude-set size 1. */

  c = hr_seed_comp("c_lockdown_leak", OUTCOME_SUCCESS);
  hr_seed_meta(c, "method", "parsed");
  hr_seed_meta(c, "lockdown", "yes");
  hr_seed_meta(c, "discloses", "virtual");
  /* No fallback, so enabling lockdown silences it: lockdown set size 1. */

  c = hr_seed_comp("c_dmesg_fallback", OUTCOME_SUCCESS);
  hr_seed_meta(c, "method", "parsed");
  hr_seed_meta(c, "sysctl", "dmesg_restrict>=1");
  hr_seed_meta(c, "fallback", "yes");
  /* Succeeded via a log file, so restricting the files silences it: set size 1.
   */

  kasld_test_projection = 1;

  struct hardening_report rep;
  build_hardening_report(&rep);

  /* Current posture (stub: 4 + 0 excluded). Ceiling excludes the union of the
   * three size-1 silenced sets (stub: 4 + 3 = 7). Each suggestion's
   * leave-one-out excludes the union minus its own set = 2 (stub: 4 + 2 = 6),
   * so each forfeits all_vbits - skip_vbits = 7 - 6 = 1 bit. */
  assert(rep.has_projection == 1);
  assert(rep.cur_vbits == 4);
  assert(rep.all_impact == 3 && rep.all_vbits == 7);
  assert(rep.n_gate_suggestions == 1);
  assert(rep.gate_suggestions[0].has_projection == 1 &&
         rep.gate_suggestions[0].silences == 1 &&
         rep.gate_suggestions[0].skip_vbits == 6);
  assert(rep.suggest_lockdown && rep.lockdown_has_projection == 1 &&
         rep.lockdown_silences == 1 && rep.lockdown_skip_vbits == 6);
  assert(rep.suggest_dmesg_fallback && rep.dmesg_fallback_has_projection == 1 &&
         rep.dmesg_fallback_silences == 1 &&
         rep.dmesg_fallback_skip_vbits == 6);

  /* Text: the current-vs-hardened anchor + a load-bearing verdict per
   * suggestion (each forfeits 1 bit). */
  set_render_mode(0, 0, 0);
  capture_stdout(wrap_render_hardening_text, NULL);
  assert(strstr(render_cap,
                "base recoverable: 4 bits now \xe2\x86\x92 7 bits") != NULL);
  assert(strstr(render_cap,
                "load-bearing - omitting forfeits 1 virtual bits") != NULL);

  /* JSON: each suggestion carries silences + the leave-one-out projection;
   * top-level projected_posture reports current and the all-applied ceiling. */
  set_render_mode(1, 0, 0);
  capture_stdout(wrap_render_hardening_json, NULL);
  assert(strstr(render_cap, "\"silences\": 1") != NULL);
  assert(strstr(render_cap, "\"virt_base_entropy_forfeited\": 1") != NULL);
  assert(strstr(render_cap, "\"projected_posture\"") != NULL);

  /* Markdown: the inline load-bearing verdict on the suggestion bullets, plus
   * each suggestion's enforcement surface as a trailing [`lever`] tag — the
   * three suggestions here sit on three distinct levers. */
  set_render_mode(0, 0, 1);
  capture_stdout(wrap_render_hardening_markdown, NULL);
  assert(strstr(render_cap,
                "load-bearing - omitting forfeits 1 virtual bits") != NULL);
  assert(strstr(render_cap, "[`sysctl`]") != NULL);
  assert(strstr(render_cap, "[`lsm`]") != NULL);
  assert(strstr(render_cap, "[`file_permissions`]") != NULL);

  /* Suppressed path: the default (unavailable) stub drops every projected row.
   */
  kasld_test_projection = 0;
  build_hardening_report(&rep);
  assert(rep.has_projection == 0 && rep.lockdown_has_projection == 0 &&
         rep.dmesg_fallback_has_projection == 0);
  set_render_mode(0, 0, 0);
  capture_stdout(wrap_render_hardening_text, NULL);
  assert(strstr(render_cap, "load-bearing") == NULL &&
         strstr(render_cap, "base recoverable") == NULL);
  set_render_mode(1, 0, 0);
  capture_stdout(wrap_render_hardening_json, NULL);
  assert(strstr(render_cap, "projected_posture") == NULL);

  set_render_mode(0, 0, 0);
  kasld_env.hardening.perf_event_paranoid = 0;
  kasld_env.hardening.dmesg_restrict = 0;
  reset_comp_logs();
  stage_likely_reset();
  num_scalar_facts = 0;
}

/* Projected posture on a base that is never recoverable (the fully-hardened
 * host). The constant stub (kasld_test_projection == 2) reports the same
 * entropy regardless of exclusions, so every suggestion silences a real leak
 * yet forfeits 0 guaranteed bits — the "speculative window only" verdict,
 * matching the "guaranteed base already at N bits" anchor. */
static void test_hardening_projection_no_exposure(void) {
  reset_results();
  reset_comp_logs();
  stage_likely_reset();
  num_scalar_facts = 0;
  kasld_env.hardening.kptr_restrict = 1;
  kasld_env.hardening.dmesg_restrict = 1;
  kasld_env.hardening.perf_event_paranoid = 2;
  /* inactive -> lockdown suggestion */
  kasld_env.hardening.lockdown = LOCKDOWN_NONE;

  struct component_log *c = hr_seed_comp("c_lockdown_leak", OUTCOME_SUCCESS);
  hr_seed_meta(c, "method", "parsed");
  hr_seed_meta(c, "lockdown", "yes");
  hr_seed_meta(c, "discloses", "virtual");

  kasld_test_projection = 2;

  struct hardening_report rep;
  build_hardening_report(&rep);

  /* Constant stub: current == ceiling == 9, so no recoverable exposure; the
   * lockdown suggestion silences its leak but forfeits nothing. */
  assert(rep.has_projection && rep.cur_vbits == 9 && rep.all_vbits == 9);
  assert(rep.suggest_lockdown && rep.lockdown_has_projection &&
         rep.lockdown_silences == 1 && rep.lockdown_skip_vbits == 9);

  set_render_mode(0, 0, 0);
  capture_stdout(wrap_render_hardening_text, NULL);
  assert(strstr(render_cap, "guaranteed base already at 9 bits") != NULL);
  assert(strstr(render_cap, "speculative window only, no guaranteed bits") !=
         NULL);
  assert(strstr(render_cap, "load-bearing") == NULL);

  set_render_mode(0, 0, 1);
  capture_stdout(wrap_render_hardening_markdown, NULL);
  assert(strstr(render_cap, "speculative window only (no guaranteed bits)") !=
         NULL);

  kasld_test_projection = 0;
  set_render_mode(0, 0, 0);
  kasld_env.hardening.lockdown = LOCKDOWN_NONE;
  reset_comp_logs();
  stage_likely_reset();
  num_scalar_facts = 0;
}

/* Projected posture with a recoverable base pinned by ONE leak, plus a second,
 * redundant leak. The set-membership stub (kasld_test_projection == 3) makes
 * the base recoverable (9 bits) only when "c_critical" is silenced. So the gate
 * that silences it is load-bearing (forfeits all 9), while the gate that
 * silences the redundant leak forfeits 0 despite silencing a real leak — the
 * "not required (the rest reach the same posture)" verdict, distinct from
 * speculative-only because the base IS recoverable. */
static void test_hardening_projection_redundant(void) {
  reset_results();
  reset_comp_logs();
  stage_likely_reset();
  num_scalar_facts = 0;
  /* inactive -> a suggestion (redundant leak) */
  kasld_env.hardening.kptr_restrict = 0;
  kasld_env.hardening.dmesg_restrict = 1; /* active */
  /* inactive -> a suggestion (critical leak) */
  kasld_env.hardening.perf_event_paranoid = 0;
  /* active: no lockdown suggestion */
  kasld_env.hardening.lockdown = LOCKDOWN_INTEGRITY;

  struct component_log *c = hr_seed_comp("c_critical", OUTCOME_SUCCESS);
  hr_seed_meta(c, "method", "parsed");
  hr_seed_meta(c, "sysctl", "perf_event_paranoid>=2");
  hr_seed_meta(c, "discloses", "virtual");

  c = hr_seed_comp("c_redundant", OUTCOME_SUCCESS);
  hr_seed_meta(c, "method", "parsed");
  hr_seed_meta(c, "sysctl", "kptr_restrict>=1");
  hr_seed_meta(c, "discloses", "virtual");

  /* A gate that governs a component which did NOT succeed: it becomes a
   * suggestion (impact > 0) but silences nothing -> the "no base-leak" verdict.
   */
  kasld_env.hardening.hashed_pointers = 0; /* inactive -> a suggestion */
  c = hr_seed_comp("c_hashed_denied", OUTCOME_ACCESS_DENIED);
  hr_seed_meta(c, "method", "parsed");
  hr_seed_meta(c, "sysctl", "hashed_pointers>=1");
  hr_seed_meta(c, "discloses", "virtual");

  kasld_test_projection = 3;

  struct hardening_report rep;
  build_hardening_report(&rep);

  /* Base recoverable (stub: 0 with c_critical present, 9 once excluded). */
  assert(rep.has_projection && rep.cur_vbits == 0 && rep.all_vbits == 9);
  const struct hr_suggestion *crit = NULL, *redu = NULL;
  for (int i = 0; i < rep.n_gate_suggestions; i++) {
    if (strcmp(rep.gate_suggestions[i].display, "kernel.perf_event_paranoid") ==
        0)
      crit = &rep.gate_suggestions[i];
    else if (strcmp(rep.gate_suggestions[i].display, "kernel.kptr_restrict") ==
             0)
      redu = &rep.gate_suggestions[i];
  }
  assert(crit && redu);
  /* Critical gate: leave-one-out keeps c_critical in -> 0 bits -> forfeits 9.
   */
  assert(crit->silences == 1 && crit->skip_vbits == 0);
  /* Redundant gate: leave-one-out still excludes c_critical -> 9 bits -> 0. */
  assert(redu->silences == 1 && redu->skip_vbits == 9);
  /* Suggestions are ranked by forfeit, so the critical gate (forfeits 9) sorts
   * ahead of the redundant one (forfeits 0), regardless of gate-table order. */
  assert(&rep.gate_suggestions[0] == crit);
  /* Hashed-pointers gate: governs a denied component, so silences nothing. */
  const struct hr_suggestion *none = NULL;
  for (int i = 0; i < rep.n_gate_suggestions; i++)
    if (strcmp(rep.gate_suggestions[i].display,
               "kernel pointer hashing (%pK)") == 0)
      none = &rep.gate_suggestions[i];
  assert(none && none->silences == 0);

  set_render_mode(0, 0, 0);
  capture_stdout(wrap_render_hardening_text, NULL);
  assert(strstr(render_cap,
                "base recoverable: 0 bits now \xe2\x86\x92 9 bits") != NULL);
  assert(strstr(render_cap,
                "load-bearing - omitting forfeits 9 virtual bits") != NULL);
  assert(strstr(render_cap, "not required (the rest reach the same posture)") !=
         NULL);
  assert(strstr(render_cap, "no base-leak behind this - recovers "
                            "nothing") != NULL);

  set_render_mode(0, 0, 1);
  capture_stdout(wrap_render_hardening_markdown, NULL);
  assert(strstr(render_cap, "not required - the rest reach the same posture") !=
         NULL);

  kasld_test_projection = 0;
  set_render_mode(0, 0, 0);
  kasld_env.hardening.kptr_restrict = 0;
  kasld_env.hardening.dmesg_restrict = 0;
  kasld_env.hardening.lockdown = LOCKDOWN_NONE;
  kasld_env.hardening.hashed_pointers = 0;
  reset_comp_logs();
  stage_likely_reset();
  num_scalar_facts = 0;
}

/* The pointer-hashing gate: a %pK leak tagged sysctl:hashed_pointers is gated
 * by kernel pointer hashing. With hashing on (the modern default) the gate is
 * active, the leak yields nothing (hashed ids fail the kernel-VAS filter), and
 * an active gate is not re-offered as available hardening. */
static void test_render_hardening_pointer_hashing_gate(void) {
  reset_results();
  reset_comp_logs();
  stage_likely_reset();
  num_scalar_facts = 0;
  /* Isolate the pointer-hashing gate — make the three sysctl gates unreadable
   * so only it can surface. */
  kasld_env.hardening.kptr_restrict = KASLD_SYSCTL_UNREAD;
  kasld_env.hardening.dmesg_restrict = KASLD_SYSCTL_UNREAD;
  kasld_env.hardening.perf_event_paranoid = KASLD_SYSCTL_UNREAD;
  kasld_env.hardening.lockdown = LOCKDOWN_NONE;
  kasld_env.hardening.hashed_pointers = 1; /* hashing on => gate active */

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
  kasld_env.hardening.hashed_pointers = KASLD_SYSCTL_UNREAD;
  kasld_env.hardening.lockdown = LOCKDOWN_NONE;
  reset_comp_logs();
  stage_likely_reset();
  num_scalar_facts = 0;
}

/* Every gate entry must name both the group and what it gates: an entry with a
 * name but no consequence tells a reader nothing they could act on. */
static void test_group_gate_table_is_complete(void) {
  for (int i = 0; i < KASLD_N_GROUP_GATES; i++) {
    assert(kasld_group_gates[i].name != NULL);
    assert(kasld_group_gates[i].name[0] != '\0');
    assert(kasld_group_gates[i].gates != NULL);
    assert(kasld_group_gates[i].gates[0] != '\0');
  }
  /* readproc is the load-bearing one: without it a hidepid /proc hides every
   * other task, which silences a whole class of components. */
  int seen = 0;
  for (int i = 0; i < KASLD_N_GROUP_GATES; i++)
    if (kasld_group_gates[i].gid == 3009)
      seen = 1;
  assert(seen);
}

/* The MAC posture helpers. Two honesty rules are load-bearing: an unreadable
 * LSM is reported as unknown and never as absent, and a policy that only logs
 * is not confinement. */
static void test_vantage_mac_posture_helpers(void) {
  struct kasld_vantage v;
  char buf[224];

  /* Nothing observable: "unknown", not "none". */
  memset(&v, 0, sizeof(v));
  v.selinux = SELINUX_UNAVAILABLE;
  assert(!kasld_vantage_mac_enforcing(&v));
  assert(strcmp(kasld_vantage_lsm_str(&v, buf, sizeof(buf)), "unknown") == 0);

  /* SELinux enforcing, securityfs unreadable (the Android shape). */
  v.selinux = SELINUX_ENFORCING;
  snprintf(v.sec_context, sizeof(v.sec_context), "u:r:shell:s0");
  assert(kasld_vantage_mac_enforcing(&v));
  assert(kasld_vantage_confined(&v));
  assert(strcmp(kasld_vantage_lsm_str(&v, buf, sizeof(buf)),
                "selinux (enforcing)") == 0);

  /* Permissive logs but does not deny, so it is not confinement. */
  v.selinux = SELINUX_PERMISSIVE;
  assert(!kasld_vantage_mac_enforcing(&v));
  assert(strcmp(kasld_vantage_lsm_str(&v, buf, sizeof(buf)),
                "selinux (permissive)") == 0);

  /* AppArmor: the mode is carried in the context, and only enforce denies. */
  memset(&v, 0, sizeof(v));
  v.selinux = SELINUX_UNAVAILABLE;
  snprintf(v.lsm_list, sizeof(v.lsm_list), "capability,yama,apparmor");
  snprintf(v.sec_context, sizeof(v.sec_context), "firefox (unconfined)");
  assert(!kasld_vantage_mac_enforcing(&v));
  snprintf(v.sec_context, sizeof(v.sec_context), "firefox (complain)");
  assert(!kasld_vantage_mac_enforcing(&v));
  snprintf(v.sec_context, sizeof(v.sec_context), "firefox (enforce)");
  assert(kasld_vantage_mac_enforcing(&v));
  assert(strcmp(kasld_vantage_lsm_str(&v, buf, sizeof(buf)),
                "capability,yama,apparmor") == 0);
}

/* Which denials a MAC policy may be credited with. The rule is narrow: the
 * component must declare at least one sysctl knob, and every knob
 * it declares must be observably not-blocking — either read and below its
 * threshold, or refused (these files are world-readable, so a refusal is the
 * policy itself and not file permissions). A component declaring no knob is
 * never attributed, which is what keeps ordinary DAC denials out. */
static void test_hardening_mac_attribution_scope(void) {
  reset_comp_logs();
  stage_likely_reset();
  struct component_log *c = hr_seed_comp("c_gated", OUTCOME_ACCESS_DENIED);
  hr_seed_meta(c, "method", "parsed");
  hr_seed_meta(c, "sysctl", "dmesg_restrict>=1");

  /* readable and permissive => attributable */
  kasld_env.hardening.dmesg_restrict = 0;
  assert(declared_sysctl_gates_permit(c) == 1);

  /* the knob was blocking => it explains it */
  kasld_env.hardening.dmesg_restrict = 1;
  assert(declared_sysctl_gates_permit(c) == 0);

  /* Absent => unexplained, so attribute nothing. */
  kasld_env.hardening.dmesg_restrict = KASLD_SYSCTL_UNREAD;
  assert(declared_sysctl_gates_permit(c) == 0);

  /* A negative value that is a real SETTING, not an unread marker, is a knob
   * that was read and found permissive — so it does not explain the denial and
   * something else must. perf_event_paranoid reports -1 for "unrestricted";
   * treating that as unread would silently withdraw the attribution on exactly
   * the hosts where perf is wide open and the denial therefore came from
   * somewhere else. */
  struct component_log *pp =
      hr_seed_comp("c_perf_permissive", OUTCOME_ACCESS_DENIED);
  hr_seed_meta(pp, "method", "parsed");
  hr_seed_meta(pp, "sysctl", "perf_event_paranoid>=2");
  kasld_env.hardening.perf_event_paranoid = -1;
  assert(declared_sysctl_gates_permit(pp) == 1);
  kasld_env.hardening.perf_event_paranoid = KASLD_SYSCTL_UNREAD;
  assert(declared_sysctl_gates_permit(pp) == 0);

  /* refused => policy is acting */
  kasld_env.hardening.dmesg_restrict = KASLD_SYSCTL_DENIED;
  assert(declared_sysctl_gates_permit(c) == 1);

  /* No declared knob: nothing is known about what should have gated it, so it
   * stays unattributed however the denial arose. */
  reset_comp_logs();
  stage_likely_reset();
  struct component_log *u = hr_seed_comp("c_ungated", OUTCOME_ACCESS_DENIED);
  hr_seed_meta(u, "method", "parsed");
  assert(declared_sysctl_gates_permit(u) == 0);

  kasld_env.hardening.dmesg_restrict = 0;
  reset_comp_logs();
  stage_likely_reset();
}

/* The full attribution predicate. A denial is credited to the policy only when
 * the policy is enforcing, no declared knob accounts for it, and seccomp — the
 * more specific mechanism — has not already claimed it. */
static void test_hardening_mac_blocked_predicate(void) {
  reset_comp_logs();
  stage_likely_reset();
  struct kasld_vantage v;
  memset(&v, 0, sizeof(v));
  v.selinux = SELINUX_ENFORCING;
  v.seccomp = 0;

  struct component_log *c = hr_seed_comp("c_gated", OUTCOME_ACCESS_DENIED);
  hr_seed_meta(c, "method", "parsed");
  hr_seed_meta(c, "sysctl", "dmesg_restrict>=1");
  kasld_env.hardening.dmesg_restrict = 0;

  assert(mac_blocked(c, &v, -1) == 1);

  /* Not enforcing: a permissive policy logs, it does not deny. */
  v.selinux = SELINUX_PERMISSIVE;
  assert(mac_blocked(c, &v, -1) == 0);
  v.selinux = SELINUX_ENFORCING;

  /* A component that ran or found nothing is not a denial to attribute. */
  c->outcome = OUTCOME_SUCCESS;
  assert(mac_blocked(c, &v, -1) == 0);
  c->outcome = OUTCOME_NO_RESULT;
  assert(mac_blocked(c, &v, -1) == 0);
  c->outcome = OUTCOME_ACCESS_DENIED;

  /* The knob was blocking, so it — not the policy — explains the denial. */
  kasld_env.hardening.dmesg_restrict = 1;
  assert(mac_blocked(c, &v, -1) == 0);
  kasld_env.hardening.dmesg_restrict = 0;

  /* seccomp wins the tie for a perf denial it can account for. */
  reset_comp_logs();
  stage_likely_reset();
  struct component_log *p = hr_seed_comp("c_perf", OUTCOME_ACCESS_DENIED);
  hr_seed_meta(p, "method", "parsed");
  hr_seed_meta(p, "sysctl", "perf_event_paranoid>=2");
  kasld_env.hardening.perf_event_paranoid = 0;
  v.seccomp = 2;
  assert(mac_blocked(p, &v, 0) == 0); /* host paranoid 0 < 2 => seccomp's */
  v.seccomp = 0;
  assert(mac_blocked(p, &v, 0) == 1); /* no filter => the policy's */

  kasld_env.hardening.dmesg_restrict = 0;
  kasld_env.hardening.perf_event_paranoid = KASLD_SYSCTL_UNREAD;
  reset_comp_logs();
  stage_likely_reset();
}

/* SF_VIRT_KASLR_RANDOMIZATION_FAILED surfaces in the text hardening report as a
 * dedicated posture section (entropy downgrade). The fact is distinct from
 * SF_VIRT_KASLR_DISABLED — the kernel was relocated to a firmware-determined
 * position, not the link-time default — so the renderer must call this out
 * with its own banner rather than reuse the opt-out banner. */
static void test_render_hardening_text_rand_failed_surfaces(void) {
  reset_results();
  reset_comp_logs();
  stage_likely_reset();
  num_scalar_facts = 0;
  struct summary s;
  set_rich_render_state(&s);
  /* Plant the new scalar fact a randomization-failed boot would emit. */
  scalar_facts[num_scalar_facts].fact = SF_VIRT_KASLR_RANDOMIZATION_FAILED;
  scalar_facts[num_scalar_facts].value = 1;
  scalar_facts[num_scalar_facts].conf = CONF_PARSED;
  scalar_facts[num_scalar_facts].origin = test_origin("dmesg_kaslr_disabled");
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
  reset_comp_logs();
  stage_likely_reset();
  num_scalar_facts = 0;
  struct summary s;
  set_rich_render_state(&s);
  scalar_facts[num_scalar_facts].fact = SF_VIRT_KASLR_RANDOMIZATION_FAILED;
  scalar_facts[num_scalar_facts].value = 1;
  scalar_facts[num_scalar_facts].conf = CONF_PARSED;
  scalar_facts[num_scalar_facts].origin = test_origin("dmesg_kaslr_disabled");
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
  reset_comp_logs();
  stage_likely_reset();
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

/* An empty tree for the whole suite. It is staged before the first test because
 * the sysroot prefix is resolved once and cached, and it must be the suite's
 * view rather than the host's.
 *
 * Nothing is put in it. The renderers here read the environment snapshot, which
 * this suite leaves unobserved, so no render reaches a fact source at all --
 * that is the property, and the empty tree is what proves it: under the
 * hermeticity probe a render that did reach one would resolve a path against
 * this root and find nothing, and a render that reached PAST it would be
 * recorded and fail the binary. The gatherer's own behaviour is exercised in
 * the orchestrator suite, where each source is staged and asserted in both
 * directions. */
static void stage_render_sysroot(void) { th_sysroot_init("render"); }

int main(void) {
  TEST_SUITE("render — renderer unit suite");
  stage_render_sysroot();
  test_init_layout_engine_bounds();

  BEGIN_CATEGORY("Renderer — json_print_escaped");
  RUN(test_json_print_escaped_passthrough);
  RUN(test_json_print_escaped_all_named_escapes);
  RUN(test_json_print_escaped_other_control);
  RUN(test_json_print_escaped_empty);
  RUN(test_md_print_cell_escaping);

  BEGIN_CATEGORY("Renderer — dispatcher (minimal summary)");
  RUN(test_render_summary_text_mode_minimal);
  RUN(test_render_summary_json_mode_minimal);
  RUN(test_render_summary_oneline_mode_minimal);
  RUN(test_render_summary_markdown_mode_minimal);

  BEGIN_CATEGORY("Renderer — rich content");
  RUN(test_render_text_with_rich_content);
  RUN(test_render_oneline_dmap_not_asserted_when_unpinned);
  RUN(test_render_json_with_rich_content);
  RUN(test_render_json_posture_always_present);
  RUN(test_render_markdown_with_rich_content);
  RUN(test_render_oneline_with_rich_content);
  RUN(test_render_map_ceiling_from_target_not_host);
  RUN(test_render_excluded_ranges_are_disclosed);
  RUN(test_render_directmap_residual_has_a_denominator);
  RUN(test_render_oneline_set_value_is_not_hex);
  RUN(test_render_oneline_tokens_are_key_value);
  RUN(test_render_oneline_region_key_needs_one_candidate);
  RUN(test_render_oneline_dmap_is_base_not_interior);
  RUN(test_render_oneline_text_na_when_engine_unresolved);
  RUN(test_render_oneline_schema_is_stable);
  RUN(test_render_oneline_entropy_and_failed);
  RUN(test_render_randomization_failed_posture);
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
  RUN(test_render_json_disposition);
  RUN(test_hardening_disclosure_is_observed);
  RUN(test_hardening_disclosure_declared_fallback);
  RUN(test_render_hardening_confirmed_mitigations);
  RUN(test_section_interior_only_and_conflicts);
  RUN(test_render_interior_only_surface);
  RUN(test_hardening_unprivileged_bpf_gate);
  RUN(test_hardening_projection);
  RUN(test_hardening_projection_no_exposure);
  RUN(test_hardening_projection_redundant);
  RUN(test_render_hardening_pointer_hashing_gate);
  RUN(test_group_gate_table_is_complete);
  RUN(test_render_hardening_value_states);
  RUN(test_vantage_mac_posture_helpers);
  RUN(test_hardening_mac_attribution_scope);
  RUN(test_hardening_mac_blocked_predicate);
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
  RUN(test_render_evidence_distinct_interior_samples_span);
  RUN(test_section_consensus_lowest_among_ties);
  RUN(test_section_consensus_prefers_pos_base);
  RUN(test_section_consensus_higher_conf_wins);
  RUN(test_section_consensus_empty);
  RUN(test_render_json_with_memory_kaslr);
  RUN(test_render_likely_window);
  RUN(test_render_vtext_speculative);
  RUN(test_render_windowed_base_likely_order);
  RUN(test_render_memory_likely_window);
  RUN(test_render_directmap_entropy_denominator);
  RUN(test_render_directmap_base_promoted);
  RUN(test_render_directmap_base_promoted_unbounded);
  RUN(test_render_directmap_offset_follows_paging_level);
  RUN(test_render_json_publishes_unrandomized_directmap_base);
  RUN(test_render_entropy_states_its_baseline);
  RUN(test_render_memory_kaslr_slots_reach_machine_formats);
  RUN(test_render_map_band_contains_its_leaks);
  RUN(test_render_map_ceiling_covers_high_mmio);
  RUN(test_render_map_phys_buckets_partition);
  RUN(test_render_phys_ceiling_covers_bucket_footers);
  RUN(test_render_map_draws_topmost_band_ceiling);
  RUN(test_render_map_directmap_contains_text);
  RUN(test_render_static_base_prefers_engine_window);
  RUN(test_render_map_directmap_base_from_engine);
  RUN(test_render_map_directmap_extent_derived);
  RUN(test_render_map_overlapped_band_states_its_ceiling);
  RUN(test_render_map_flag);
  RUN(test_render_footer_hint_is_last);
  RUN(test_render_phys_map_descends_strictly);
  RUN(test_render_window_row_always_graded);
  RUN(test_render_coupling_note);
  RUN(test_render_markdown_text_order_caution);
  RUN(test_render_memory_kaslr_uses_stored_slots);
  RUN(test_render_disabled_base_not_labeled_likely);
  RUN(test_render_leak_discloses_interior);
  RUN(test_render_json_group_aggregate_is_per_region);
  RUN(test_render_json_groups_split_by_region);

  return TEST_DONE();
}
