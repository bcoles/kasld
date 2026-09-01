// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Unit tests for the orchestrator internals: the result model (parser, merge
// pass, select_anchor, result_in_bounds), compute_kaslr_info, the
// engine->layout projection (engine_sync_authoritative), region_info, and the
// renderers. Compiled via `make check` as a single TU: the sources under test
// are #included directly below, with -DKASLD_TESTING, so their static helpers
// (json_print_escaped, render_summary, section_consensus, etc.) are reachable
// without exporting them. main() and the live engine run are compiled out.
// ---
// <bcoles@gmail.com>

#define _POSIX_C_SOURCE 200809L
#ifndef KASLD_TESTING
#define KASLD_TESTING /* Makefile passes -DKASLD_TESTING; this is the          \
                         fallback. */
#endif

#include "../src/environment.c"
/* The orchestrator is compiled into this test, so every static it does not
 * happen to call is unused here. Suppressed at the include rather than by
 * tagging the definitions: they are production code, and the property is a
 * fact about this translation unit, not about them. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wunused-variable"
#include "../src/capture.c"
#include "../src/discard.c"
#include "../src/meta.c"
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
#include "../src/render.c"
#include "../src/render/hardening.c"
#include "../src/render/json.c"
#include "../src/render/markdown.c"
#include "../src/report.c"

#include "../src/render/oneline.c"
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#include "../src/render/text.c"
#pragma GCC diagnostic pop
#include "test_harness.h"
#include "test_orch_common.h"
#include "test_po_access.h"
#include "test_sysroot.h"

#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

/* =========================================================================
 * Helpers
 * ========================================================================= */

/* capture_result takes the producing component's discovery slot, the way
 * run_component supplies it; register the name so provenance resolves back to
 * it the way a real run's does. */
static int parse_line(const char *line, const char *method,
                      const char *origin) {
  return capture_result(line, method, test_origin(origin));
}

/* =========================================================================
 * Portable fixture addresses
 *
 * These suites run on every cross target via tests/test-cross — 32- and
 * 64-bit, big- and little-endian. A hardcoded x86_64 kernel address (e.g.
 * 0xffffffff81000000) overflows a 32-bit `unsigned long` and falls outside
 * other arches' parse-time VAS windows, so fixtures derive their addresses
 * from the current arch's own layout constants. This mirrors the idiom the
 * section_consensus tests already use (PAGE_OFFSET / KERNEL_VIRT_TEXT_DEFAULT
 * plus a byte offset).
 * ========================================================================= */

/* Kernel-text base for the current arch. Never truncates; kernel-image
 * regions are VAS-open so the parser admits it everywhere. */
#define FX_TEXT ((unsigned long)KERNEL_VIRT_TEXT_DEFAULT)

/* A virtual address inside `region`'s parse-time VAS window (the range
 * capture_result() validates against) on the current arch. VAS-open and
 * runtime-derived regions report a {0, ULONG_MAX} or {0, 0} static window;
 * for those any kernel address is admitted, so fall back to the text base. */
static unsigned long fx_region_addr(enum kasld_region region) {
  unsigned long lo = region_info[region].static_vas.lo;
  unsigned long hi = region_info[region].static_vas.hi;
  if (lo == 0 && (hi == 0 || hi == ULONG_MAX))
    return FX_TEXT;
  unsigned long a = lo + 0x123456ul; /* a little above the window floor */
  return a <= hi ? a : lo;
}

/* =========================================================================
 * result_init
 * ========================================================================= */
static void test_result_init_zeroes_everything(void) {
  struct result r;
  memset(&r, 0xAA, sizeof(r));
  result_init(&r);
  assert(r.type == KASLD_TYPE_UNKNOWN);
  assert(r.region == REGION_UNKNOWN);
  assert(r.set_mask == 0);
  assert(r.pos == POS_UNKNOWN);
  assert(r.conf == CONF_UNKNOWN);
  assert(origin_set_count(&r.origins) == 0);
  assert(r.name[0] == '\0');
  assert(!HAS_LO(&r) && !HAS_HI(&r) && !HAS_SAMPLE(&r) && !HAS_BASE_ALIGN(&r));
}

/* =========================================================================
 * Parser
 * ========================================================================= */
static void test_parse_base_record(void) {
  reset_results();
  int ok =
      parse_line("P initrd pos=base conf=parsed lo=0x33000000 hi=0x333fffff",
                 "parsed", "proc-iomem");
  assert(ok == 1);
  assert(num_results == 1);
  struct result *r = &results[0];
  assert(r->type == KASLD_TYPE_PHYS);
  assert(r->region == REGION_INITRD);
  assert(r->pos == POS_BASE);
  assert(r->conf == CONF_PARSED);
  assert(HAS_LO(r) && HAS_HI(r));
  assert(r->lo == 0x33000000ul);
  assert(r->hi == 0x333ffffful);
  assert(origin_set_count(&r->origins) == 1);
  assert(strcmp(first_origin(r), "proc-iomem") == 0);
}

static void test_parse_interior_sample(void) {
  reset_results();
  unsigned long vaddr = fx_region_addr(REGION_VMALLOC);
  char line[160];
  snprintf(line, sizeof(line),
           "V vmalloc pos=interior conf=heuristic sample=0x%lx", vaddr);
  assert(parse_line(line, "heuristic", "comp") == 1);
  struct result *r = &results[0];
  assert(r->type == KASLD_TYPE_VIRT);
  assert(r->region == REGION_VMALLOC);
  assert(r->pos == POS_INTERIOR);
  assert(HAS_SAMPLE(r) && !HAS_LO(r) && !HAS_HI(r));
  assert(r->sample == vaddr);
}

static void test_parse_pos_extent(void) {
  reset_results();
  /* kasld_result_extent's wire form: a [lo,hi] member of a complete RAM map
   * (a covering). Must parse to POS_EXTENT with both edges set — the map rules
   * read lo+hi, and floor rules (which require pos=base) must NOT treat lo as
   * the DRAM floor. The orchestrator routes POS_EXTENT records to coverings[],
   * out of the cross-source merge. */
  int ok =
      parse_line("P ram pos=extent conf=parsed lo=0x10000000 hi=0x1fffffff",
                 "parsed", "sysfs_memory_blocks");
  assert(ok == 1);
  struct result *r = &results[0];
  assert(r->type == KASLD_TYPE_PHYS);
  assert(r->region == REGION_RAM);
  assert(r->pos == POS_EXTENT);
  assert(HAS_LO(r) && HAS_HI(r));
  assert(r->lo == 0x10000000ul);
  assert(r->hi == 0x1ffffffful);
}

static void test_parse_extent_requires_both_edges(void) {
  reset_results();
  /* A covering member is a closed extent; a half-open pos=extent is rejected.
   */
  assert(parse_line("P ram pos=extent conf=parsed lo=0x10000000", NULL, NULL) ==
         0);
  assert(parse_line("P ram pos=extent conf=parsed hi=0x1fffffff", NULL, NULL) ==
         0);
}

static void test_parse_named_record(void) {
  reset_results();
  assert(parse_line("V kernel_image:commit_creds pos=interior conf=parsed "
                    "sample=0x1000",
                    "parsed", "kallsyms") == 1);
  struct result *r = &results[0];
  assert(strcmp(r->name, "commit_creds") == 0);
  assert(r->region == REGION_KERNEL_IMAGE);
}

static void test_parse_name_with_colons(void) {
  reset_results();
  assert(parse_line("P pci_mmio:0000:00:14.0 pos=base conf=parsed "
                    "lo=0xfe000000 hi=0xfeffffff",
                    "parsed", "sysfs") == 1);
  struct result *r = &results[0];
  assert(r->region == REGION_PCI_MMIO);
  assert(strcmp(r->name, "0000:00:14.0") == 0);
}

static void test_parse_sz_normalizes_to_hi(void) {
  reset_results();
  assert(parse_line("P initrd pos=base conf=parsed lo=0x100000 sz=0x10000",
                    "parsed", "x") == 1);
  struct result *r = &results[0];
  assert(HAS_LO(r) && HAS_HI(r));
  assert(r->lo == 0x100000ul);
  assert(r->hi == 0x10ffffu);
}

static void test_parse_rejects_unknown_key(void) {
  reset_results();
  assert(parse_line("V kernel_text pos=base conf=parsed lo=0x1000 "
                    "bogus=0x1",
                    NULL, NULL) == 0);
  assert(num_results == 0);
}

static void test_parse_rejects_missing_pos(void) {
  reset_results();
  assert(parse_line("V kernel_text conf=parsed lo=0x1000", NULL, NULL) == 0);
}

static void test_parse_rejects_missing_conf(void) {
  reset_results();
  assert(parse_line("V kernel_text pos=base lo=0x1000", NULL, NULL) == 0);
}

static void test_parse_rejects_pos_base_without_lo(void) {
  reset_results();
  assert(parse_line("V kernel_text pos=base conf=parsed sample=0x1000", NULL,
                    NULL) == 0);
}

static void test_parse_rejects_pos_top_without_hi(void) {
  reset_results();
  assert(parse_line("P ram pos=top conf=parsed lo=0x1000", NULL, NULL) == 0);
}

static void test_parse_rejects_lo_above_hi(void) {
  reset_results();
  assert(parse_line("V kernel_text pos=base conf=parsed lo=0x2000 hi=0x1000",
                    NULL, NULL) == 0);
}

static void test_parse_rejects_sample_outside_extent(void) {
  reset_results();
  assert(parse_line(
             "P initrd pos=base conf=parsed lo=0x1000 hi=0x2000 sample=0x3000",
             NULL, NULL) == 0);
}

static void test_parse_rejects_sz_overflow(void) {
  reset_results();
  /* lo at the top of the arch's address space so lo + sz - 1 overflows. */
  char line[96];
  snprintf(line, sizeof(line), "P ram pos=base conf=parsed lo=0x%lx sz=0x2",
           ULONG_MAX);
  assert(parse_line(line, NULL, NULL) == 0);
}

static void test_parse_rejects_non_power_of_two_base_align(void) {
  reset_results();
  assert(parse_line("V kernel_text pos=base conf=parsed lo=0x1000 "
                    "base_align=0x3",
                    NULL, NULL) == 0);
}

static void test_parse_accepts_power_of_two_base_align(void) {
  reset_results();
  assert(parse_line("V kernel_text pos=base conf=parsed lo=0x1000 "
                    "base_align=0x200000",
                    NULL, NULL) == 1);
  assert(HAS_BASE_ALIGN(&results[0]));
  assert(results[0].base_align == 0x200000ul);
}

static void test_parse_genuine_zero_lo(void) {
  reset_results();
  assert(parse_line("P ram pos=base conf=parsed lo=0x0", NULL, NULL) == 1);
  struct result *r = &results[0];
  assert(HAS_LO(r));
  assert(r->lo == 0);
}

/* =========================================================================
 * result_in_bounds
 * ========================================================================= */
static void test_result_in_bounds_rejects_region_unknown(void) {
  struct result r;
  result_init(&r);
  r.region = REGION_UNKNOWN;
  assert(result_in_bounds(&r, &layout) == 0);
}

static void test_result_in_bounds_open_vas_accepts_anything(void) {
  struct result r;
  result_init(&r);
  r.region = REGION_RAM;
  r.lo = 0x12345678;
  r.set_mask = LO_SET;
  assert(result_in_bounds(&r, &layout) == 1);
}

static void test_result_in_bounds_no_set_bits_passes(void) {
  struct result r;
  result_init(&r);
  r.region = REGION_RAM;
  assert(result_in_bounds(&r, &layout) == 1);
}

/* =========================================================================
 * select_anchor
 * ========================================================================= */
static void test_select_anchor_prefers_no_name(void) {
  reset_results();
  struct result *named = push_result();
  named->type = KASLD_TYPE_VIRT;
  named->region = REGION_KERNEL_IMAGE;
  snprintf(named->name, NAME_LEN, "commit_creds");
  named->pos = POS_INTERIOR;
  named->conf = CONF_PARSED;
  named->sample = (FX_TEXT + 0x234000ul);
  named->set_mask = SAMPLE_SET;

  struct result *anchor = push_result();
  anchor->type = KASLD_TYPE_VIRT;
  anchor->region = REGION_KERNEL_IMAGE;
  anchor->pos = POS_BASE;
  anchor->conf = CONF_HEURISTIC;
  anchor->lo = FX_TEXT;
  anchor->set_mask = LO_SET;

  const struct result *picked =
      select_anchor(KASLD_TYPE_VIRT, REGION_KERNEL_IMAGE);
  assert(picked == anchor);
}

static void test_select_anchor_falls_back_to_named(void) {
  reset_results();
  struct result *named = push_result();
  named->type = KASLD_TYPE_VIRT;
  named->region = REGION_KERNEL_IMAGE;
  snprintf(named->name, NAME_LEN, "commit_creds");
  named->pos = POS_INTERIOR;
  named->conf = CONF_PARSED;
  named->sample = (FX_TEXT + 0x234000ul);
  named->set_mask = SAMPLE_SET;

  const struct result *picked =
      select_anchor(KASLD_TYPE_VIRT, REGION_KERNEL_IMAGE);
  assert(picked == named);
}

static void test_select_anchor_returns_null_on_miss(void) {
  reset_results();
  const struct result *picked =
      select_anchor(KASLD_TYPE_VIRT, REGION_KERNEL_IMAGE);
  assert(picked == NULL);
}

/* =========================================================================
 * Merge pass
 * ========================================================================= */
static void test_merge_collapses_same_key(void) {
  reset_results();
  struct result *base = push_result();
  base->type = KASLD_TYPE_PHYS;
  base->region = REGION_INITRD;
  base->pos = POS_BASE;
  base->conf = CONF_PARSED;
  base->lo = 0x33000000;
  base->set_mask = LO_SET;
  add_origin(base, "proc-iomem");

  struct result *top = push_result();
  top->type = KASLD_TYPE_PHYS;
  top->region = REGION_INITRD;
  top->pos = POS_TOP;
  top->conf = CONF_PARSED;
  top->hi = 0x333fffff;
  top->set_mask = HI_SET;
  add_origin(top, "dmesg");

  merge_results();
  assert(num_results == 1);
  struct result *r = &results[0];
  assert(HAS_LO(r) && HAS_HI(r));
  assert(r->lo == 0x33000000ul && r->hi == 0x333ffffful);
  assert(origin_set_count(&r->origins) == 2);
}

static void test_merge_keeps_conflicting_records(void) {
  reset_results();
  struct result *a = push_result();
  a->type = KASLD_TYPE_PHYS;
  a->region = REGION_INITRD;
  a->pos = POS_BASE;
  a->conf = CONF_PARSED;
  a->lo = 0x100000;
  a->hi = 0x1fffff;
  a->set_mask = LO_SET | HI_SET;
  add_origin(a, "source-a");

  struct result *b = push_result();
  b->type = KASLD_TYPE_PHYS;
  b->region = REGION_INITRD;
  b->pos = POS_BASE;
  b->conf = CONF_PARSED;
  b->lo = 0x500000;
  b->hi = 0x5fffff;
  b->set_mask = LO_SET | HI_SET;
  add_origin(b, "source-b");

  int before = num_results;
  merge_results();
  assert(num_results == before);
}

static void test_merge_does_not_cross_types(void) {
  reset_results();
  struct result *p = push_result();
  p->type = KASLD_TYPE_PHYS;
  p->region = REGION_INITRD;
  p->pos = POS_BASE;
  p->conf = CONF_PARSED;
  p->lo = 0x33000000;
  p->set_mask = LO_SET;

  struct result *v = push_result();
  v->type = KASLD_TYPE_VIRT;
  v->region = REGION_INITRD;
  v->pos = POS_BASE;
  v->conf = CONF_DERIVED;
  v->lo = (unsigned long)PAGE_OFFSET + 0x33000000ul;
  v->set_mask = LO_SET;

  merge_results();
  assert(num_results == 2);
}

/* A sample OUTSIDE an extent is a distinct witness (different instance of
 * the region), not a refinement that should be clamped onto the extent's
 * edge. sample_bound_clamp_conflict in merge_results refuses to merge
 * sample-vs-bound pairs that would force clamp_sample() to rewrite the
 * sample address — silently shifting an observation to fit a bound was a
 * data-loss bug exposed by ppc64-no-KASLR. */
static void test_merge_keeps_sample_outside_extent_separate(void) {
  reset_results();
  struct result *a = push_result();
  a->type = KASLD_TYPE_PHYS;
  a->region = REGION_INITRD;
  a->pos = POS_BASE;
  a->conf = CONF_PARSED;
  a->lo = 0x1000;
  a->hi = 0x1fff;
  a->set_mask = LO_SET | HI_SET;

  struct result *b = push_result();
  b->type = KASLD_TYPE_PHYS;
  b->region = REGION_INITRD;
  b->pos = POS_INTERIOR;
  b->conf = CONF_HEURISTIC;
  b->sample = 0x500; /* below the extent's lo */
  b->set_mask = SAMPLE_SET;

  merge_results();
  assert(num_results == 2);
}

/* A sample INSIDE an extent legitimately refines it — that merge should
 * still happen. */
static void test_merge_sample_inside_extent_collapses(void) {
  reset_results();
  struct result *a = push_result();
  a->type = KASLD_TYPE_PHYS;
  a->region = REGION_INITRD;
  a->pos = POS_BASE;
  a->conf = CONF_PARSED;
  a->lo = 0x1000;
  a->hi = 0x1fff;
  a->set_mask = LO_SET | HI_SET;

  struct result *b = push_result();
  b->type = KASLD_TYPE_PHYS;
  b->region = REGION_INITRD;
  b->pos = POS_INTERIOR;
  b->conf = CONF_HEURISTIC;
  b->sample = 0x1500; /* inside [0x1000, 0x1fff] */
  b->set_mask = SAMPLE_SET;

  merge_results();
  assert(num_results == 1);
  struct result *r = &results[0];
  assert(HAS_SAMPLE(r));
  assert(r->sample == 0x1500);
}

/* Two LO-only POS_BASE records at different addresses are independent
 * point witnesses (not refinements of a single range). Same rationale as
 * sample-conflict: silently collapsing them via max(lo) would discard the
 * lower one — exposed on ppc64-no-KASLR where sysfs_devicetree_memory and
 * sysfs_memory_blocks legitimately emit different directmap-base
 * witnesses. */
static void test_merge_keeps_lo_only_witnesses_separate(void) {
  reset_results();
  struct result *a = push_result();
  a->type = KASLD_TYPE_VIRT;
  a->region = REGION_DIRECTMAP;
  a->pos = POS_BASE;
  a->conf = CONF_PARSED;
  a->lo = (unsigned long)PAGE_OFFSET;
  a->set_mask = LO_SET;
  add_origin(a, "source-a");

  struct result *b = push_result();
  b->type = KASLD_TYPE_VIRT;
  b->region = REGION_DIRECTMAP;
  b->pos = POS_BASE;
  b->conf = CONF_PARSED;
  b->lo = (unsigned long)PAGE_OFFSET + 0x10000000ul;
  b->set_mask = LO_SET;
  add_origin(b, "source-b");

  merge_results();
  assert(num_results == 2);
  /* Origin attribution is preserved (no cross-witness merging). */
  assert(strcmp(first_origin(&results[0]), "source-a") == 0);
  assert(strcmp(first_origin(&results[1]), "source-b") == 0);
}

static void test_merge_picks_highest_conf_sample(void) {
  reset_results();
  /* Same-key contributors where only one has SAMPLE_SET: the sample
   * survives, the other contributes nothing sample-wise.
   *
   * Both at the same confidence, deliberately. What this exercises is the
   * sample-owner and pos handling; giving the bound-only record a WEAKER
   * confidence would instead exercise conf_edge_conflict, which refuses the
   * merge precisely because the merged record would publish that record's `lo`
   * at the sample contributor's stronger tier. That case has its own test. */
  struct result *no_sample = push_result();
  no_sample->type = KASLD_TYPE_VIRT;
  no_sample->region = REGION_KERNEL_IMAGE;
  no_sample->pos = POS_BASE;
  no_sample->conf = CONF_PARSED;
  no_sample->lo = FX_TEXT;
  no_sample->set_mask = LO_SET;

  struct result *sample = push_result();
  sample->type = KASLD_TYPE_VIRT;
  sample->region = REGION_KERNEL_IMAGE;
  sample->pos = POS_INTERIOR;
  sample->conf = CONF_PARSED;
  sample->sample = (FX_TEXT + 0x222222ul);
  sample->set_mask = SAMPLE_SET;

  merge_results();
  assert(num_results == 1);
  struct result *r = &results[0];
  assert(HAS_LO(r) && r->lo == FX_TEXT);
  assert(HAS_SAMPLE(r) && r->sample == (FX_TEXT + 0x222222ul));
  /* pos must NOT downgrade to POS_INTERIOR when the surviving sample's
   * contributor was POS_INTERIOR but the merged record retains a POS_BASE
   * claim from another contributor. Skipping this assertion let a real
   * regression land: text_pin_from_observation gates on POS_BASE and silently
   * skipped merged records whose pos had been overwritten. */
  assert(r->pos == POS_BASE);
}

/* Inverse seed order of the above: POS_INTERIOR record is the merge seed,
 * a later POS_BASE contributor must promote the merged record's pos.
 * Without the promote branch in merge_into the result stays POS_INTERIOR
 * and downstream text_pin_from_observation never fires. */
static void test_merge_promotes_pos_to_base_from_later_contributor(void) {
  reset_results();
  struct result *sample = push_result();
  sample->type = KASLD_TYPE_VIRT;
  sample->region = REGION_KERNEL_IMAGE;
  sample->pos = POS_INTERIOR;
  sample->conf = CONF_PARSED;
  sample->sample = (FX_TEXT + 0x333333ul);
  sample->set_mask = SAMPLE_SET;

  /* Same confidence as the seed: this test is about the pos-promotion branch.
   * A weaker contributor supplying `lo` is refused by conf_edge_conflict, since
   * the merged record would carry that bound at the seed's stronger tier. */
  struct result *base = push_result();
  base->type = KASLD_TYPE_VIRT;
  base->region = REGION_KERNEL_IMAGE;
  base->pos = POS_BASE;
  base->conf = CONF_PARSED;
  base->lo = FX_TEXT;
  base->set_mask = LO_SET;

  merge_results();
  assert(num_results == 1);
  struct result *r = &results[0];
  assert(r->pos == POS_BASE);
  assert(HAS_LO(r) && r->lo == FX_TEXT);
  assert(HAS_SAMPLE(r) && r->sample == (FX_TEXT + 0x333333ul));
}

static void test_merge_samples_conflict_kept_separate(void) {
  /* Per the regression-fix to merge_results: two interior samples at
   * different addresses with the same merge key are treated as a conflict
   * (they're almost always different instances of the region — two swiotlb
   * buffers, two initrd witnesses). Both records must survive. */
  reset_results();
  struct result *a = push_result();
  a->type = KASLD_TYPE_PHYS;
  a->region = REGION_SWIOTLB;
  a->pos = POS_INTERIOR;
  a->conf = CONF_PARSED;
  a->sample = 0xbbed0000;
  a->set_mask = SAMPLE_SET;

  struct result *b = push_result();
  b->type = KASLD_TYPE_PHYS;
  b->region = REGION_SWIOTLB;
  b->pos = POS_INTERIOR;
  b->conf = CONF_PARSED;
  b->sample = 0xbfed0000;
  b->set_mask = SAMPLE_SET;

  merge_results();
  assert(num_results == 2);
}

/* A weaker record must not tighten a stronger one. merge_into takes the
 * tightest edge from any contributor and the strongest confidence across all of
 * them; without conf_edge_conflict the two come from different contributors and
 * the merged record publishes a heuristic edge at the inferred tier, where the
 * engine's sound floor admits it. This is the shape mmap_brute_vmsplit emits on
 * every arch where TASK_SIZE is not PAGE_OFFSET: a measured bound plus a
 * stride-rounded guess strictly inside it. */
static void test_merge_weaker_tightening_edge_kept_separate(void) {
  reset_results();
  struct result *a = push_result();
  a->type = KASLD_TYPE_VIRT;
  a->region = REGION_PAGE_OFFSET;
  a->pos = POS_BASE;
  a->conf = CONF_INFERRED; /* the measurement */
  a->lo = 0x7f000000ul;
  a->hi = 0xc0000000ul;
  a->set_mask = LO_SET | HI_SET;

  struct result *b = push_result();
  b->type = KASLD_TYPE_VIRT;
  b->region = REGION_PAGE_OFFSET;
  b->pos = POS_BASE;
  b->conf = CONF_HEURISTIC; /* the guess, tighter than what was measured */
  b->lo = 0x80000000ul;
  b->set_mask = LO_SET;

  merge_results();
  assert(num_results == 2);
  /* The measured edge survives intact on its own record, still inferred. */
  int seen_measured = 0, seen_guess = 0;
  for (int i = 0; i < num_results; i++) {
    if (results[i].conf == CONF_INFERRED && results[i].lo == 0x7f000000ul)
      seen_measured = 1;
    if (results[i].conf == CONF_HEURISTIC && results[i].lo == 0x80000000ul)
      seen_guess = 1;
  }
  assert(seen_measured && seen_guess);
}

/* ...but a weaker record that merely AGREES still merges. That is the
 * corroboration the merge exists for, and the consensus-source counting the
 * renderers do depends on those collapsing. Nothing tightens here, so there is
 * no edge to publish above its tier. */
static void test_merge_weaker_agreeing_still_merges(void) {
  reset_results();
  struct result *a = push_result();
  a->type = KASLD_TYPE_VIRT;
  a->region = REGION_KERNEL_TEXT;
  a->pos = POS_BASE;
  a->conf = CONF_PARSED;
  a->lo = 0xc0300000ul;
  a->set_mask = LO_SET;

  struct result *b = push_result();
  b->type = KASLD_TYPE_VIRT;
  b->region = REGION_KERNEL_TEXT;
  b->pos = POS_BASE;
  b->conf = CONF_DERIVED;
  b->lo = 0xc0300000ul;
  b->set_mask = LO_SET;

  merge_results();
  assert(num_results == 1);
  assert(results[0].conf == CONF_PARSED);
  assert(results[0].lo == 0xc0300000ul);
}

/* =========================================================================
 * conf_weight
 * ========================================================================= */
static void test_conf_weight_ordering(void) {
  assert(conf_weight(CONF_PARSED) > conf_weight(CONF_DERIVED));
  assert(conf_weight(CONF_DERIVED) > conf_weight(CONF_INFERRED));
  assert(conf_weight(CONF_INFERRED) > conf_weight(CONF_HEURISTIC));
  assert(conf_weight(CONF_HEURISTIC) > conf_weight(CONF_TIMING));
  assert(conf_weight(CONF_TIMING) > conf_weight(CONF_BRUTE));
  assert(conf_weight(CONF_BRUTE) > conf_weight(CONF_UNKNOWN));
}

/* =========================================================================
 * anchor_addr
 * ========================================================================= */
static void test_anchor_addr_base(void) {
  struct result r;
  result_init(&r);
  r.pos = POS_BASE;
  r.lo = 0x1000;
  r.set_mask = LO_SET;
  assert(anchor_addr(&r) == 0x1000);
}

static void test_anchor_addr_interior_sample(void) {
  struct result r;
  result_init(&r);
  r.pos = POS_INTERIOR;
  r.sample = 0x2000;
  r.set_mask = SAMPLE_SET;
  assert(anchor_addr(&r) == 0x2000);
}

static void test_anchor_addr_null(void) { assert(anchor_addr(NULL) == 0); }

/* =========================================================================
 * ilog2
 * ========================================================================= */
static void test_ilog2_power_of_two(void) {
  assert(ilog2(1) == 0);
  assert(ilog2(2) == 1);
  assert(ilog2(4) == 2);
  assert(ilog2(1024) == 10);
}

static void test_ilog2_zero(void) { assert(ilog2(0) == 0); }

/* ilog2 returns CEIL(log2(N)) for non-power-of-2 inputs so the displayed
 * "residual entropy" reflects the attacker's worst-case brute-force work
 * (13 candidates = 4 bits of attempts, not 3). */
static void test_ilog2_non_power_of_two_rounds_up(void) {
  assert(ilog2(3) == 2);   /* log2(3) ~ 1.58  -> ceil 2 */
  assert(ilog2(5) == 3);   /* log2(5) ~ 2.32  -> ceil 3 */
  assert(ilog2(13) == 4);  /* log2(13) ~ 3.7  -> ceil 4 (the directmap case) */
  assert(ilog2(127) == 7); /* log2(127) ~ 6.99 -> ceil 7 (phys-slots case) */
  assert(ilog2(471) == 9); /* log2(471) ~ 8.88 -> ceil 9 (vtext-slots case) */
  assert(ilog2(1023) == 10); /* one below 1024 -> ceil 10 */
}

/* =========================================================================
 * compute_kaslr_info fallback chain
 * ========================================================================= */
static void test_compute_kaslr_info_uses_kernel_image_anchor(void) {
  reset_results();
  struct result *r = push_result();
  r->type = KASLD_TYPE_VIRT;
  r->region = REGION_KERNEL_IMAGE;
  r->pos = POS_BASE;
  r->conf = CONF_PARSED;
  r->lo = layout.virt_kaslr_text_min + layout.virt_kaslr_align;
  r->set_mask = LO_SET;

  struct summary s = {0};
  compute_kaslr_info(&s, NULL, NULL, NULL);
  assert(s.kaslr.vtext == layout.virt_kaslr_text_min + layout.virt_kaslr_align);
}

/* The engine's resolutions reach the summary as PARAMETERS, so a build that
 * does not link the engine can still drive the paths that consume them.
 *
 * A pinned guaranteed estimate wins over the raw anchor scan: the scan reads
 * results[] and is blind to the verdicts, so the engine's pin is what decides.
 */
static void test_compute_kaslr_info_engine_pin_overrides_raw_anchor(void) {
  struct engine auth;
  memset(&auth, 0, sizeof(auth));

  unsigned long raw = layout.virt_kaslr_text_min + layout.virt_kaslr_align;
  unsigned long pinned =
      layout.virt_kaslr_text_min + 2 * layout.virt_kaslr_align;

  reset_results();
  struct result *r = push_result();
  r->type = KASLD_TYPE_VIRT;
  r->region = REGION_KERNEL_IMAGE;
  r->pos = POS_BASE;
  r->conf = CONF_PARSED;
  r->lo = raw;
  r->set_mask = LO_SET;

  /* No snapshot: the raw pick stands, as the tests above already pin. */
  struct summary s = {0};
  compute_kaslr_info(&s, NULL, NULL, NULL);
  assert(s.kaslr.vtext == raw);

  /* With a snapshot holding a sound pin, that pin is authoritative. */
  auth.est[Q_VIRT_IMAGE_BASE].lo = pinned;
  auth.est[Q_VIRT_IMAGE_BASE].hi = pinned;
  memset(&s, 0, sizeof(s));
  compute_kaslr_info(&s, &auth, NULL, NULL);
  assert(s.kaslr.vtext == pinned);
}

/* The LIKELY snapshot's own consumers: the speculative window is clamped into
 * the guaranteed one and reported only where it is strictly tighter, so a
 * likely window narrower than the arch bracket must surface, and one no
 * tighter must not. */
/* The singular rendered direct-map base follows the LIKELY resolution wherever
 * the sound one stopped at a window rather than a value. It is a
 * best-single-answer field, and the alternative to a likely value is not a
 * sounder one -- it is the compile-time seed, the analysing build's split
 * presented as the target's.
 *
 * Reachable only since the resolutions became parameters; before that the whole
 * branch was compiled out of this build, and disabling it changed no test.
 *
 * The estimates are built through the quantity's own top and narrowed with a
 * constraint, never by assigning .lo/.hi: Q_PAGE_OFFSET's lattice is declared
 * in the quantity table and a test that writes the fields has hard-coded an
 * answer it never asked for.
 */
static void test_compute_kaslr_info_directmap_base_follows_likely(void) {
  const struct quantity_def *qd = &quantities[Q_PAGE_OFFSET];
  struct engine auth;
  struct engine_resolution likely;
  unsigned long pinned = 0, g_lo = 0, g_hi = 0;

  reset_results();
  memset(&auth, 0, sizeof(auth));
  memset(&likely, 0, sizeof(likely));

  /* Guaranteed side: the quantity's honest top. On most arches that is a
   * window -- the state the fallback exists for. On five (loongarch64, mips32,
   * mips64, ppc64, riscv32) PAGE_OFFSET_MIN == PAGE_OFFSET_MAX, so the top is
   * already a value.
   *
   * Both are asserted rather than one skipped. Returning early on the pinned
   * arches would leave this reporting PASS on five of twelve targets while
   * checking nothing, which is the failure the test exists to catch, one level
   * up. */
  qd->init_top(&auth.est[Q_PAGE_OFFSET]);
  quantity_window(Q_PAGE_OFFSET, &auth.est[Q_PAGE_OFFSET], &g_lo, &g_hi);
  int auth_pinned =
      quantity_pinned(Q_PAGE_OFFSET, &auth.est[Q_PAGE_OFFSET], &pinned);

  unsigned long before = layout.virt_page_offset;

  /* Likely side: the same top, narrowed to one admissible value. */
  qd->init_top(&likely.est[Q_PAGE_OFFSET]);
  struct constraint c;
  memset(&c, 0, sizeof(c));
  c.q = Q_PAGE_OFFSET;
  c.op = C_EQUALS;
  /* Non-zero: the branch under test refuses a zero base (po_likely != 0), and
   * s390's direct map starts at 0, so the window FLOOR is not a usable pin
   * there. The ceiling is admissible on every arch and never zero. */
  unsigned long pin_want = g_lo ? g_lo : g_hi;
  assert(pin_want != 0);
  c.value = pin_want;
  c.conf = CONF_PARSED;
  c.id = 1;
  estimate_meet(&likely.est[Q_PAGE_OFFSET], qd, &c);
  /* The fixture is asserted, not assumed: a meet that failed to pin would make
   * every assertion below vacuous. */
  assert(quantity_pinned(Q_PAGE_OFFSET, &likely.est[Q_PAGE_OFFSET], &pinned));
  assert(pinned == pin_want);

  /* Seeded to a value no branch here produces, so an assertion can only hold
   * because the code did what it was meant to. Without it the field already
   * equals the expected value on some arches and this passes against a
   * disabled block -- which is how the first version survived every mutation.
   *
   * Offset from the expected value rather than a fixed 0: s390's direct map
   * starts at 0, so a zero sentinel IS the expected value there. */
  layout.virt_page_offset = pin_want + 1;
  struct summary s = {0};
  compute_kaslr_info(&s, &auth, &likely, NULL);
  if (auth_pinned) {
    /* The sound resolution already answered, so the speculative one must not
     * overwrite it -- the whole fallback is gated on the guaranteed side NOT
     * having a value. */
    assert(layout.virt_page_offset == pin_want + 1);
  } else {
    assert(layout.virt_page_offset == pin_want);
  }

  /* A likely WINDOW is not a single answer, so nothing is taken from it. This
   * is what stops the branch above being satisfied by "copy the likely floor
   * unconditionally". Only meaningful where the top is a window; where it is a
   * pin there is no window to offer and the case above already covers it. */
  if (!auth_pinned) {
    memset(&likely, 0, sizeof(likely));
    qd->init_top(&likely.est[Q_PAGE_OFFSET]);
    layout.virt_page_offset = pin_want + 1;
    memset(&s, 0, sizeof(s));
    compute_kaslr_info(&s, &auth, &likely, NULL);
#if !TEXT_TRACKS_DIRECTMAP
    /* Coupled arches have a second fallback (the proven floor) that
     * legitimately moves the field here; decoupled ones do not. */
    assert(layout.virt_page_offset == pin_want + 1);
#endif
  }

  layout.virt_page_offset = before;
}

static void test_compute_kaslr_info_likely_window_reaches_the_model(void) {
  struct engine auth;
  struct engine_resolution likely;
  unsigned long lo = layout.virt_kaslr_text_min + layout.virt_kaslr_align;
  unsigned long hi = layout.virt_kaslr_text_min + 3 * layout.virt_kaslr_align;

  if (layout.virt_kaslr_text_max <= hi)
    return; /* arch bracket too narrow to hold a strictly tighter sub-window */

  reset_results();
  memset(&auth, 0, sizeof(auth));
  memset(&likely, 0, sizeof(likely));
  auth.est[Q_VIRT_IMAGE_BASE].lo = layout.virt_kaslr_text_min;
  auth.est[Q_VIRT_IMAGE_BASE].hi = layout.virt_kaslr_text_max;

  /* Asserted on the report model, which is where the likely window lives: the
   * summary never carried it usefully and no longer carries it at all. The
   * claim is unchanged -- a speculative window appears only when one was
   * resolved, and lies inside the proven one. */
  {
    struct summary s = {0};
    struct kasld_report rep;
    const struct kasld_report_quantity *it;

    /* No likely snapshot: nothing speculative is reported. */
    compute_kaslr_info(&s, &auth, NULL, &rep);
    it = kasld_report_find(&rep, Q_VIRT_IMAGE_BASE);
    assert(it != NULL);
    assert(!kasld_report_likely_is_tighter(it));

    /* A strictly tighter likely window surfaces, clamped into the guaranteed
     * one. */
    likely.est[Q_VIRT_IMAGE_BASE].lo = lo;
    likely.est[Q_VIRT_IMAGE_BASE].hi = hi;
    memset(&s, 0, sizeof(s));
    compute_kaslr_info(&s, &auth, &likely, &rep);
    it = kasld_report_find(&rep, Q_VIRT_IMAGE_BASE);
    assert(it != NULL);
    assert(kasld_report_likely_is_tighter(it));
    assert(it->likely.has_lo && it->likely.lo >= it->guaranteed.lo);
    assert(it->likely.has_hi && it->likely.hi <= it->guaranteed.hi);
  }
}

static void test_compute_kaslr_info_falls_back_to_kernel_text(void) {
  reset_results();
  struct result *r = push_result();
  r->type = KASLD_TYPE_VIRT;
  r->region = REGION_KERNEL_TEXT;
  r->pos = POS_BASE;
  r->conf = CONF_PARSED;
  r->lo = layout.virt_kaslr_text_min + 2 * layout.virt_kaslr_align;
  r->set_mask = LO_SET;

  struct summary s = {0};
  compute_kaslr_info(&s, NULL, NULL, NULL);
  /* A KERNEL_TEXT (_stext) fallback resolves vtext to the image base, i.e. down
   * by the head gap (STEXT_OFFSET): 0 on most arches, nonzero on arm64
   * (0x10000) and loongarch64 (0x20000). */
  unsigned long stext =
      layout.virt_kaslr_text_min + 2 * layout.virt_kaslr_align;
  assert(s.kaslr.vtext == kasld_image_base_from(stext, 1));
}

/* =========================================================================
 * Round-trip: emit via helper → parse → struct equality
 * ========================================================================= */

/* Capture helper output by redirecting stdout to a pipe. Returns the line
 * the helper emitted (without trailing newline). Caller passes a buffer. */
static int capture_helper(int (*emit)(void), char *buf, size_t buflen) {
  int pipefd[2];
  if (pipe(pipefd) != 0)
    return -1;
  int saved_stdout = dup(fileno(stdout));
  fflush(stdout);
  dup2(pipefd[1], fileno(stdout));
  close(pipefd[1]);
  int ok = emit();
  fflush(stdout);
  dup2(saved_stdout, fileno(stdout));
  close(saved_stdout);
  ssize_t n = read(pipefd[0], buf, buflen - 1);
  close(pipefd[0]);
  if (n < 0)
    return -1;
  buf[n] = '\0';
  /* Strip trailing newline for parser. */
  if (n > 0 && buf[n - 1] == '\n')
    buf[n - 1] = '\0';
  return ok;
}

static int emit_base_helper(void) {
  return kasld_result_base(KASLD_TYPE_VIRT, REGION_KERNEL_TEXT, FX_TEXT,
                           "test_sym", CONF_PARSED);
}
static int emit_range_helper(void) {
  return kasld_result_range(KASLD_TYPE_PHYS, REGION_INITRD, 0x33000000ul,
                            0x333ffffful, NULL, CONF_PARSED);
}
static int emit_top_helper(void) {
  return kasld_result_top(KASLD_TYPE_PHYS, REGION_RAM, 0xf0000000ul, NULL,
                          CONF_PARSED);
}
static int emit_sample_helper(void) {
  return kasld_result_sample(KASLD_TYPE_VIRT, REGION_VMALLOC,
                             fx_region_addr(REGION_VMALLOC), NULL,
                             CONF_HEURISTIC);
}
static int emit_sized_helper(void) {
  return kasld_result_sized(KASLD_TYPE_PHYS, REGION_INITRD, 0x100000ul,
                            0x10000ul, NULL, CONF_PARSED);
}

static void test_roundtrip_base(void) {
  char buf[512];
  reset_results();
  assert(capture_helper(emit_base_helper, buf, sizeof(buf)) == 1);
  assert(capture_result(buf, "parsed", test_origin("test")) == 1);
  struct result *r = &results[0];
  assert(r->type == KASLD_TYPE_VIRT);
  assert(r->region == REGION_KERNEL_TEXT);
  assert(strcmp(r->name, "test_sym") == 0);
  assert(r->pos == POS_BASE);
  assert(r->conf == CONF_PARSED);
  assert(HAS_LO(r) && r->lo == FX_TEXT);
}

static void test_roundtrip_range(void) {
  char buf[512];
  reset_results();
  assert(capture_helper(emit_range_helper, buf, sizeof(buf)) == 1);
  assert(capture_result(buf, "parsed", test_origin("test")) == 1);
  struct result *r = &results[0];
  assert(r->type == KASLD_TYPE_PHYS);
  assert(r->region == REGION_INITRD);
  assert(r->name[0] == '\0');
  assert(HAS_LO(r) && r->lo == 0x33000000ul);
  assert(HAS_HI(r) && r->hi == 0x333ffffful);
}

static void test_roundtrip_top(void) {
  char buf[512];
  reset_results();
  assert(capture_helper(emit_top_helper, buf, sizeof(buf)) == 1);
  assert(capture_result(buf, "parsed", test_origin("test")) == 1);
  struct result *r = &results[0];
  assert(r->type == KASLD_TYPE_PHYS);
  assert(r->region == REGION_RAM);
  assert(r->pos == POS_TOP);
  assert(!HAS_LO(r) && HAS_HI(r));
  assert(r->hi == 0xf0000000ul);
}

static void test_roundtrip_sample(void) {
  char buf[512];
  reset_results();
  assert(capture_helper(emit_sample_helper, buf, sizeof(buf)) == 1);
  assert(capture_result(buf, "heuristic", test_origin("test")) == 1);
  struct result *r = &results[0];
  assert(r->type == KASLD_TYPE_VIRT);
  assert(r->region == REGION_VMALLOC);
  assert(r->pos == POS_INTERIOR);
  assert(r->conf == CONF_HEURISTIC);
  assert(HAS_SAMPLE(r) && r->sample == fx_region_addr(REGION_VMALLOC));
}

static void test_roundtrip_sized(void) {
  char buf[512];
  reset_results();
  assert(capture_helper(emit_sized_helper, buf, sizeof(buf)) == 1);
  assert(capture_result(buf, "parsed", test_origin("test")) == 1);
  struct result *r = &results[0];
  assert(HAS_LO(r) && HAS_HI(r));
  assert(r->lo == 0x100000ul);
  assert(r->hi == 0x10ffffu); /* lo + sz - 1 */
}

static int emit_mitigation_helper(void) {
  return kasld_disp_mitigation("kpti", "KPTI enabled");
}
static int emit_absent_helper(void) {
  return kasld_disp_absent("not an Intel CPU");
}
static int emit_inconclusive_helper(void) {
  return kasld_disp_inconclusive("noisy");
}
static int emit_mitigation_nogate_helper(void) {
  /* A mitigation with no gate is a bug: the emitter must print nothing. */
  kasld_disposition(DISP_MITIGATION, NULL, "should not emit");
  return 0;
}

/* An `R` disposition line is parsed onto the per-component log (always, not
 * only under --verbose) and tags no address record; the typed emitters return
 * the exit code the category implies and round-trip through the parser;
 * malformed dispositions leave the category at DISP_NONE; a wire result line
 * tags a record and leaves the disposition empty. */
static void test_disposition_capture(void) {
  int saved_v = verbose;
  verbose = 0;
  char buf[512];
  struct component_log cl;
  /* A component's identity is its slot in the discovery table. These cases
   * exercise the line parser, which records the slot without resolving it to a
   * name, and each starts from a cleared log — so one slot serves for all of
   * them. */
  const int slot = 0;

  /* mitigation: emitter returns UNAVAILABLE and the gate round-trips. */
  assert(capture_helper(emit_mitigation_helper, buf, sizeof(buf)) ==
         KASLD_EXIT_UNAVAILABLE);
  assert(strcmp(buf, "R cat=mitigation gate=kpti msg=\"KPTI enabled\"") == 0);
  memset(&cl, 0, sizeof(cl));
  assert(handle_component_line(&cl, "timing", slot, buf, strlen(buf)) == 0);
  assert(cl.disposition.category == DISP_MITIGATION);
  assert(strcmp(cl.disposition.gate, "kpti") == 0);
  assert(strcmp(cl.disposition.message, "KPTI enabled") == 0);

  /* absent: UNAVAILABLE, no gate. */
  assert(capture_helper(emit_absent_helper, buf, sizeof(buf)) ==
         KASLD_EXIT_UNAVAILABLE);
  memset(&cl, 0, sizeof(cl));
  handle_component_line(&cl, "timing", slot, buf, strlen(buf));
  assert(cl.disposition.category == DISP_ABSENT);
  assert(cl.disposition.gate[0] == '\0');
  assert(strcmp(cl.disposition.message, "not an Intel CPU") == 0);

  /* inconclusive: exit 0. */
  assert(capture_helper(emit_inconclusive_helper, buf, sizeof(buf)) == 0);
  memset(&cl, 0, sizeof(cl));
  handle_component_line(&cl, "timing", slot, buf, strlen(buf));
  assert(cl.disposition.category == DISP_INCONCLUSIVE);

  /* mitigation with no gate: emitter prints nothing (bug), and a hand-built
   * gate-less mitigation line parses to DISP_NONE rather than a bogus claim. */
  assert(capture_helper(emit_mitigation_nogate_helper, buf, sizeof(buf)) == 0);
  assert(buf[0] == '\0');
  memset(&cl, 0, sizeof(cl));
  const char *nogate = "R cat=mitigation msg=\"x\"";
  handle_component_line(&cl, "timing", slot, nogate, strlen(nogate));
  assert(cl.disposition.category == DISP_NONE);

  /* Unknown category is dropped. */
  memset(&cl, 0, sizeof(cl));
  const char *bogus = "R cat=bogus msg=\"x\"";
  handle_component_line(&cl, "timing", slot, bogus, strlen(bogus));
  assert(cl.disposition.category == DISP_NONE);

  /* A `gate=`/`cat=` substring inside the quoted message is not mistaken for a
   * field: fields come from parsed keys, so message text supplies none. */
  memset(&cl, 0, sizeof(cl));
  const char *tricky = "R cat=absent msg=\"weird cat=x gate=y text\"";
  handle_component_line(&cl, "timing", slot, tricky, strlen(tricky));
  assert(cl.disposition.category == DISP_ABSENT);
  assert(cl.disposition.gate[0] == '\0');
  assert(strcmp(cl.disposition.message, "weird cat=x gate=y text") == 0);

  /* A wire result line tags a record and leaves the disposition empty. */
  reset_results();
  memset(&cl, 0, sizeof(cl));
  assert(capture_helper(emit_base_helper, buf, sizeof(buf)) == 1);
  assert(handle_component_line(&cl, "parsed", slot, buf, strlen(buf)) == 1);
  assert(cl.disposition.category == DISP_NONE);

  verbose = saved_v;
}

/* The disposition parser commits only a record it has fully validated, and is
 * as strict about its key set as the address and scalar parsers are about
 * theirs. kasld_disposition() cannot emit any of the lines below, and
 * check-component-output stops a component hand-writing one — so these hold the
 * parser to its own contract rather than relying on either of those. */
static void test_disposition_rejects_malformed(void) {
  int saved_v = verbose;
  verbose = 0;
  const int slot = 0;
  struct component_log cl;

  /* A rejected line leaves an established record untouched. Components are
   * contracted to emit at most one R line; the captured record does not depend
   * on every component honouring that. */
  memset(&cl, 0, sizeof(cl));
  const char *good = "R cat=mitigation gate=kpti msg=\"KPTI active\"";
  handle_component_line(&cl, "timing", slot, good, strlen(good));
  assert(cl.disposition.category == DISP_MITIGATION);
  const char *junk = "R garbage with no category at all";
  handle_component_line(&cl, "timing", slot, junk, strlen(junk));
  assert(cl.disposition.category == DISP_MITIGATION); /* survived */
  assert(strcmp(cl.disposition.gate, "kpti") == 0);

  /* Each of these rejects the whole line. `cat` is read from a parsed key, so
   * neither a message body nor a key merely ending in "cat" can supply one. */
  static const char *const bad[] = {
      "R xcat=mitigation gate=kpti msg=\"m\"",  /* key ending in "cat" */
      "R gate=x msg=\"see cat=absent detail\"", /* category only in prose */
      "R cat=absent bogus=1 msg=\"m\"",         /* unknown key */
      "R cat=absent cat=disabled",              /* repeated key */
      "R cat=absent msg=\"unterminated",        /* no closing quote */
      "R cat=absent msg=bare",                  /* message not quoted */
      "R cat=mitigation gate= msg=\"m\"",       /* gate naming nothing */
      "R cat=absent extra",                     /* bare token, not key=value */
  };
  for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
    memset(&cl, 0, sizeof(cl));
    handle_component_line(&cl, "timing", slot, bad[i], strlen(bad[i]));
    assert(cl.disposition.category == DISP_NONE);
  }

  /* Over-length gate and message reject rather than truncate — the same
   * no-silent-narrowing rule the region/name parser follows. */
  char big[MAX_LINE_LEN];
  memset(&cl, 0, sizeof(cl));
  int n = snprintf(big, sizeof(big), "R cat=mitigation gate=");
  memset(big + n, 'G', DISP_GATE_LEN);
  big[n + DISP_GATE_LEN] = '\0';
  handle_component_line(&cl, "timing", slot, big, strlen(big));
  assert(cl.disposition.category == DISP_NONE);

  memset(&cl, 0, sizeof(cl));
  n = snprintf(big, sizeof(big), "R cat=absent msg=\"");
  memset(big + n, 'M', DISP_MSG_LEN);
  big[n + DISP_MSG_LEN] = '"';
  big[n + DISP_MSG_LEN + 1] = '\0';
  handle_component_line(&cl, "timing", slot, big, strlen(big));
  assert(cl.disposition.category == DISP_NONE);

  /* Well-formed records still parse, including a message carrying text that
   * looks like other fields, and fields given in either order. */
  memset(&cl, 0, sizeof(cl));
  const char *tricky = "R cat=absent msg=\"weird cat=x gate=y text\"";
  handle_component_line(&cl, "timing", slot, tricky, strlen(tricky));
  assert(cl.disposition.category == DISP_ABSENT);
  assert(cl.disposition.gate[0] == '\0');
  assert(strcmp(cl.disposition.message, "weird cat=x gate=y text") == 0);

  memset(&cl, 0, sizeof(cl));
  const char *reordered = "R msg=\"m\" gate=kpti cat=mitigation";
  handle_component_line(&cl, "timing", slot, reordered, strlen(reordered));
  assert(cl.disposition.category == DISP_MITIGATION);
  assert(strcmp(cl.disposition.gate, "kpti") == 0);
  assert(strcmp(cl.disposition.message, "m") == 0);

  verbose = saved_v;
}

/* =========================================================================
 * CONF_UNKNOWN rejection at helpers
 * ========================================================================= */
static int emit_with_conf_unknown_base(void) {
  return kasld_result_base(KASLD_TYPE_VIRT, REGION_KERNEL_TEXT, FX_TEXT, NULL,
                           CONF_UNKNOWN);
}
static int emit_with_conf_unknown_sample(void) {
  return kasld_result_sample(KASLD_TYPE_PHYS, REGION_RAM, 0x1000, NULL,
                             CONF_UNKNOWN);
}

static int emit_with_invalid_type(void) {
  return kasld_result_base(KASLD_TYPE_UNKNOWN, REGION_KERNEL_TEXT, FX_TEXT,
                           NULL, CONF_PARSED);
}

static int emit_with_region_unknown(void) {
  return kasld_result_base(KASLD_TYPE_VIRT, REGION_UNKNOWN, 0x1000, NULL,
                           CONF_PARSED);
}

static void test_helpers_reject_conf_unknown(void) {
  char buf[512];
  /* Redirect stderr to /dev/null so the warning doesn't pollute test output. */
  int saved = dup(fileno(stderr));
  FILE *devnull = fopen("/dev/null", "w");
  dup2(fileno(devnull), fileno(stderr));

  /* All five helpers must reject CONF_UNKNOWN. */
  assert(capture_helper(emit_with_conf_unknown_base, buf, sizeof(buf)) == 0);
  assert(buf[0] == '\0'); /* no wire output */
  assert(capture_helper(emit_with_conf_unknown_sample, buf, sizeof(buf)) == 0);
  assert(buf[0] == '\0');

  /* Same for invalid type and REGION_UNKNOWN. */
  assert(capture_helper(emit_with_invalid_type, buf, sizeof(buf)) == 0);
  assert(buf[0] == '\0');
  assert(capture_helper(emit_with_region_unknown, buf, sizeof(buf)) == 0);
  assert(buf[0] == '\0');

  dup2(saved, fileno(stderr));
  close(saved);
  fclose(devnull);
}

/* =========================================================================
 * Provenance dedup + full retention (the cap no longer binds)
 * ========================================================================= */
static void test_merge_dedups_provenance(void) {
  reset_results();
  /* Three base contributors at the SAME lo (so lo_only_conflict permits
   * merging) but with one origin duplicated. After merge the duplicate
   * origin must appear only once. Use HAS_LO records (not HAS_SAMPLE) so
   * samples_conflict doesn't prevent merging. */
  for (int i = 0; i < 3; i++) {
    struct result *r = push_result();
    r->type = KASLD_TYPE_VIRT;
    r->region = REGION_KERNEL_IMAGE;
    r->pos = POS_BASE;
    r->conf = CONF_HEURISTIC;
    r->lo = FX_TEXT;
    r->set_mask = LO_SET;
    add_origin(r, i == 1 ? "src-b" : "src-a");
    r->method_set = 1u << KM_HEURISTIC;
  }
  merge_results();
  assert(num_results == 1);
  struct result *r = &results[0];
  /* "src-a" appears twice in the contributors but only once in the merged
   * origin list. */
  assert(origin_set_count(&r->origins) == 2);
  assert(origin_set_has(&r->origins, test_origin("src-a")));
  assert(origin_set_has(&r->origins, test_origin("src-b")));
}

static void test_merge_keeps_all_contributors(void) {
  reset_results();
  /* Many distinct-origin contributors at the same lo. Provenance is a bitset
   * over the whole discovery table, so the merged record keeps every one and no
   * contributor count below MAX_COMPONENTS can truncate. */
  const int n = 40;
  for (int i = 0; i < n; i++) {
    struct result *r = push_result();
    r->type = KASLD_TYPE_VIRT;
    r->region = REGION_KERNEL_IMAGE;
    r->pos = POS_BASE;
    r->conf = CONF_HEURISTIC;
    r->lo = FX_TEXT; /* same lo so lo_only_conflict permits merge */
    r->set_mask = LO_SET;
    char nm[32];
    snprintf(nm, sizeof(nm), "src-%d", i);
    add_origin(r, nm);
  }
  merge_results();

  assert(num_results == 1);
  assert(origin_set_count(&results[0].origins) ==
         n); /* all kept, none truncated */
}

/* =========================================================================
 * Phys/virt linkage: P and V records with same region+name stay separate
 * ========================================================================= */
static void test_phys_virt_linkage_stays_two_records(void) {
  reset_results();
  /* P initrd extent */
  struct result *p = push_result();
  p->type = KASLD_TYPE_PHYS;
  p->region = REGION_INITRD;
  p->pos = POS_BASE;
  p->conf = CONF_PARSED;
  p->lo = 0x33000000;
  p->hi = 0x333fffff;
  p->set_mask = LO_SET | HI_SET;

  /* V initrd extent — same region+name as the P extent above, different type.
   * This fixture exercises the merge invariant (PHYS and VIRT of the same
   * region+name must not collapse). No in-tree component currently emits
   * VIRT/REGION_INITRD via a directmap projection — components project to
   * REGION_DIRECTMAP — but a direct virt leak of the initrd region (e.g. a
   * kernel-logged initrd virt) would still land here. */
  struct result *v = push_result();
  v->type = KASLD_TYPE_VIRT;
  v->region = REGION_INITRD;
  v->pos = POS_BASE;
  v->conf = CONF_DERIVED;
  v->lo = (unsigned long)PAGE_OFFSET + 0x33000000ul;
  v->hi = (unsigned long)PAGE_OFFSET + 0x333ffffful;
  v->set_mask = LO_SET | HI_SET;

  merge_results();
  /* Must stay two records — type discriminates. */
  assert(num_results == 2);
  /* select_anchor returns the right one per type. */
  const struct result *picked_p = select_anchor(KASLD_TYPE_PHYS, REGION_INITRD);
  const struct result *picked_v = select_anchor(KASLD_TYPE_VIRT, REGION_INITRD);
  assert(picked_p && picked_p->type == KASLD_TYPE_PHYS);
  assert(picked_v && picked_v->type == KASLD_TYPE_VIRT);
}

/* =========================================================================
 * Layout-sensitive result_in_bounds: derive_vas re-evaluates each call
 * ========================================================================= */
static void test_result_in_bounds_layout_sensitive(void) {
  /* REGION_PAGE_OFFSET deliberately uses ARCH-default kernel VAS bounds
   * (compile-time constants), NOT layout.virt_kernel_vas_start — using the
   * runtime layout would create a circular dependency where a virt_page_offset
   * record gets rejected because earlier inference (based on different
   * records) tightened the bound above it.
   *
   * To exercise the layout-sensitive code path, we'd need a region with
   * derive_vas non-NULL whose bounds depend on layout. None currently exist
   * (all derive_vas regions were removed in favour of static bounds to avoid
   * the circular dependency). When such a region is added in the future,
   * extend this test to exercise it. For now, verify that result_in_bounds
   * accepts a valid record under default layout (smoke test). */
  struct result r;
  result_init(&r);
  r.type = KASLD_TYPE_VIRT;
  r.region = REGION_PAGE_OFFSET;
  r.pos = POS_BASE;
  r.conf = CONF_PARSED;
  r.lo = (unsigned long)
      PAGE_OFFSET; /* arch-default virt_page_offset is always valid */
  r.set_mask = LO_SET;
  assert(result_in_bounds(&r, &layout) == 1);
}

/* =========================================================================
 * Synthesized result: a producer constructs one via result_init()
 * ========================================================================= */
static void test_synthesized_result_sets_fields_correctly(void) {
  reset_results();
  /* Simulate what a derived-result-emitting component does. */
  struct result *r = &results[num_results++];
  result_init(r);
  r->type = KASLD_TYPE_VIRT;
  r->region = REGION_INITRD;
  /* name stays "" — canonical region anchor */
  r->pos = POS_BASE;
  r->conf = CONF_DERIVED;
  r->lo = (unsigned long)PAGE_OFFSET + 0x33000000ul;
  r->hi = (unsigned long)PAGE_OFFSET + 0x333ffffful;
  r->set_mask = LO_SET | HI_SET;
  add_origin(r, "inference:my_plugin");
  r->method_set = 1u << KM_DERIVED;

  /* Round-trip through result_in_bounds and select_anchor. */
  assert(result_in_bounds(r, &layout) == 1);
  const struct result *picked = select_anchor(KASLD_TYPE_VIRT, REGION_INITRD);
  assert(picked == r);
  /* set_mask correctly reflects what was set. */
  assert(HAS_LO(picked) && HAS_HI(picked));
  assert(!HAS_SAMPLE(picked) && !HAS_BASE_ALIGN(picked));
}

/* =========================================================================
 * compute_kaslr_info: all-NULL anchor case
 * ========================================================================= */

static void test_compute_kaslr_info_no_anchors_yields_zero_vtext(void) {
  reset_results();
  struct summary s = {0};
  compute_kaslr_info(&s, NULL, NULL, NULL);
  /* No anchors → vtext=0; the slot/entropy fields are still populated from
   * the layout, but vtext itself is the "no information" sentinel. */
  assert(s.kaslr.vtext == 0);
}

/* =========================================================================
 * is_phys_dram_region predicate
 *
 * Used by dram_bound, dram_ceiling, meminfo_phys_ceiling, phys_virt_synth,
 * directmap_page_offset_bounds, riscv64_non_efi_phys_base. Misclassifying
 * a kernel-image region as not-DRAM (the regression we hit) silently
 * excludes critical leaks from the inference chain.
 * ========================================================================= */
static void test_is_phys_dram_region_includes_ram_landmarks(void) {
  assert(is_phys_dram_region(REGION_RAM));
  assert(is_phys_dram_region(REGION_DMA));
  assert(is_phys_dram_region(REGION_DMA32));
  assert(is_phys_dram_region(REGION_INITRD));
  assert(is_phys_dram_region(REGION_RESERVED_MEM));
  assert(is_phys_dram_region(REGION_SWIOTLB));
  assert(is_phys_dram_region(REGION_VMCOREINFO));
  assert(is_phys_dram_region(REGION_CRASHKERNEL));
  assert(is_phys_dram_region(REGION_PMEM));
  assert(is_phys_dram_region(REGION_ACPI_TABLE));
  assert(is_phys_dram_region(REGION_ACPI_NVS));
  assert(is_phys_dram_region(REGION_NUMA_NODE));
}

static void test_is_phys_dram_region_includes_kernel_image(void) {
  /* The kernel is loaded into physical RAM, so its phys leaks live in
   * DRAM. The regression that triggered the virt_page_offset-derivation hunt
   * was caused by this predicate excluding kernel_image regions. */
  assert(is_phys_dram_region(REGION_KERNEL_TEXT));
  assert(is_phys_dram_region(REGION_KERNEL_DATA));
  assert(is_phys_dram_region(REGION_KERNEL_BSS));
  assert(is_phys_dram_region(REGION_KERNEL_IMAGE));
  /* The EFI loader's resident kernel image is DRAM-resident — distinct from
   * EFI_MEMMAP (a descriptor) which is excluded below. */
  assert(is_phys_dram_region(REGION_EFI_LOADER_IMAGE));
}

static void test_is_phys_dram_region_excludes_non_dram(void) {
  /* MMIO is physical but not DRAM. */
  assert(!is_phys_dram_region(REGION_MMIO));
  assert(!is_phys_dram_region(REGION_PCI_MMIO));
  /* EFI_MEMMAP is structurally a descriptor, not necessarily DRAM-resident. */
  assert(!is_phys_dram_region(REGION_EFI_MEMMAP));
  /* Virtual-only abstract regions. */
  assert(!is_phys_dram_region(REGION_DIRECTMAP));
  assert(!is_phys_dram_region(REGION_PAGE_OFFSET));
  assert(!is_phys_dram_region(REGION_VMALLOC));
  assert(!is_phys_dram_region(REGION_VMEMMAP));
  assert(!is_phys_dram_region(REGION_MODULE));
  assert(!is_phys_dram_region(REGION_MODULE_BAND));
  /* Sentinel. */
  assert(!is_phys_dram_region(REGION_UNKNOWN));
}

/* =========================================================================
 * result_in_bounds: PHYS records in kernel-image regions
 *
 * Kernel-image regions (KERNEL_TEXT, KERNEL_DATA, KERNEL_BSS, KERNEL_IMAGE)
 * legitimately carry PHYS leaks (the kernel is loaded into RAM). The
 * regression hunt found that virt-only static_vas for these regions
 * rejected every PHYS leak — costing us the kernel_bss:cr3 record that
 * was needed to derive virt_page_offset via phys_virt_synth.
 * ========================================================================= */
static void test_result_in_bounds_accepts_phys_kernel_image(void) {
  struct result r;
  result_init(&r);
  r.type = KASLD_TYPE_PHYS;
  /* A physical kernel-image leak at a plausible load address (kept within
   * 32-bit so the fixture is valid on 32-bit arches too). */
  r.sample = 0x19446000ul;
  r.set_mask = SAMPLE_SET;

  /* All four kernel-image regions must accept a phys sample. */
  r.region = REGION_KERNEL_TEXT;
  assert(result_in_bounds(&r, &layout) == 1);
  r.region = REGION_KERNEL_DATA;
  assert(result_in_bounds(&r, &layout) == 1);
  r.region = REGION_KERNEL_BSS;
  assert(result_in_bounds(&r, &layout) == 1);
  r.region = REGION_KERNEL_IMAGE;
  assert(result_in_bounds(&r, &layout) == 1);
}

/* =========================================================================
 * derive_vas_page_offset uses arch constants, not runtime layout
 *
 * PAGE_OFFSET is itself a layout field; validating PAGE_OFFSET records
 * against the runtime layout.virt_kernel_vas_start creates a circular
 * dependency where a virt_page_offset record gets rejected because earlier
 * inference (based on different records) tightened the bound above it.
 * Verify the check is layout-independent.
 * ========================================================================= */
static void test_page_offset_in_bounds_independent_of_runtime_layout(void) {
  struct result r;
  result_init(&r);
  r.type = KASLD_TYPE_VIRT;
  r.region = REGION_PAGE_OFFSET;
  /* A virt_page_offset value at the arch floor. */
  r.lo = (unsigned long)PAGE_OFFSET;
  r.set_mask = LO_SET;

  /* Default layout: accepts. */
  assert(result_in_bounds(&r, &layout) == 1);

  /* Construct a synthetic layout with virt_kernel_vas_start TIGHTENED far
   * above the record. If derive_vas_page_offset read
   * layout.virt_kernel_vas_start, the record would be rejected. With
   * arch-constant validation, it stays accepted. */
  struct kasld_layout tight = layout;
  /* Midpoint between the record's address and the top of the address space —
   * well above the record on every word size (a fixed 1<<40 shift overflows a
   * 32-bit unsigned long). */
  tight.virt_kernel_vas_start =
      (unsigned long)PAGE_OFFSET + (ULONG_MAX - (unsigned long)PAGE_OFFSET) / 2;
  assert(result_in_bounds(&r, &tight) == 1);
}

/* =========================================================================
 * select_anchor skips out-of-bounds records
 *
 * If a record is rendered out-of-bounds by inference-tightened layout,
 * select_anchor must not return it. Verifies the select_anchor →
 * result_in_bounds gating wired correctly.
 * ========================================================================= */
static void test_select_anchor_skips_out_of_bounds(void) {
  reset_results();
  /* A record in a region whose VAS is static and bounded, with an
   * address outside that VAS. */
  struct result *r = push_result();
  r->type = KASLD_TYPE_VIRT;
  r->region = REGION_VMALLOC; /* has static_vas = {KERNEL_VIRT_VAS_START,
                                 KERNEL_VIRT_VAS_END} */
  r->pos = POS_BASE;
  r->conf = CONF_PARSED;
  /* An address just outside the region's VAS window for the current arch.
   * Prefer one above the ceiling (some arches put the floor at 0, so
   * "below the floor" is not always available). */
  {
    unsigned long vlo = region_info[REGION_VMALLOC].static_vas.lo;
    unsigned long vhi = region_info[REGION_VMALLOC].static_vas.hi;
    r->lo = (vhi < ULONG_MAX) ? vhi + 1 : vlo - 1;
  }
  r->set_mask = LO_SET;

  assert(result_in_bounds(r, &layout) == 0);
  /* select_anchor must skip it. */
  assert(select_anchor(KASLD_TYPE_VIRT, REGION_VMALLOC) == NULL);
}

/* =========================================================================
 * Post-merge sample clamp on upper bound
 *
 * test_merge_sample_clamped_to_extent covers clamping up to lo. This
 * covers the symmetric clamping down to hi.
 * ========================================================================= */
/* Symmetric to test_merge_keeps_sample_outside_extent_separate: a sample
 * above the extent's hi is a distinct witness, not a refinement. */
static void test_merge_keeps_sample_above_hi_separate(void) {
  reset_results();
  struct result *base = push_result();
  base->type = KASLD_TYPE_PHYS;
  base->region = REGION_INITRD;
  base->pos = POS_BASE;
  base->conf = CONF_PARSED;
  base->lo = 0x1000;
  base->hi = 0x1fff;
  base->set_mask = LO_SET | HI_SET;

  struct result *sample = push_result();
  sample->type = KASLD_TYPE_PHYS;
  sample->region = REGION_INITRD;
  sample->pos = POS_INTERIOR;
  sample->conf = CONF_HEURISTIC;
  sample->sample = 0x5000; /* ABOVE hi */
  sample->set_mask = SAMPLE_SET;

  merge_results();
  assert(num_results == 2);
}

/* =========================================================================
 * Multi-pass convergence: merge is idempotent on its own output
 *
 * The spec requires merge_results to run at each convergence pass so
 * that newly-emitted derived results merge before the next pass reads
 * them. The invariant is that running merge twice produces the same
 * result as running it once (idempotence).
 * ========================================================================= */
static void test_merge_is_idempotent(void) {
  reset_results();
  /* Four contributors to a single (PHYS, RAM) record at the same lo so
   * lo_only_conflict permits merging. */
  for (int i = 0; i < 4; i++) {
    struct result *r = push_result();
    r->type = KASLD_TYPE_PHYS;
    r->region = REGION_RAM;
    r->pos = POS_BASE;
    r->conf = CONF_PARSED;
    r->lo = 0x1000ul;
    r->set_mask = LO_SET;
    char nm[32];
    snprintf(nm, sizeof(nm), "src-%d", i);
    add_origin(r, nm);
  }
  merge_results();
  assert(num_results == 1);
  unsigned long lo_after_first = results[0].lo;
  uint32_t mask_after_first = results[0].set_mask;
  int prov_after_first = origin_set_count(&results[0].origins);

  /* Run again — must be a no-op. */
  merge_results();
  assert(num_results == 1);
  assert(results[0].lo == lo_after_first);
  assert(results[0].set_mask == mask_after_first);
  assert(origin_set_count(&results[0].origins) == prov_after_first);
}

/* =========================================================================
 * Merge: capture order is irrelevant
 *
 * results[] arrives in component completion order, which the worker pool
 * makes vary between runs. merge_results() opens by sorting into a canonical
 * content order so the merged set is a pure function of the record SET.
 *
 * The scenario below is the one that makes this load-bearing rather than
 * cosmetic: the refusal predicates are NOT transitive. A record carrying no
 * sample is sample-compatible with every other, so an unsorted pass could
 * anchor a group on it and admit a candidate that the canonically-first
 * record would have refused — a different grouping from the same evidence.
 * ========================================================================= */
static void seed_merge_permutation(const int *order, int n) {
  reset_results();
  for (int k = 0; k < n; k++) {
    struct result *r = push_result();
    r->type = KASLD_TYPE_PHYS;
    r->region = REGION_RAM;
    r->conf = CONF_PARSED;
    switch (order[k]) {
    case 0: /* bare bound, no sample: compatible with both samples below */
      r->pos = POS_BASE;
      r->lo = 0x1000ul;
      r->set_mask = LO_SET;
      add_origin(r, "src-bound");
      break;
    case 1: /* sample witness A */
      r->pos = POS_INTERIOR;
      r->sample = 0x2000ul;
      r->set_mask = SAMPLE_SET;
      add_origin(r, "src-sample-a");
      break;
    default: /* sample witness B — conflicts with A, not with the bound */
      r->pos = POS_INTERIOR;
      r->sample = 0x3000ul;
      r->set_mask = SAMPLE_SET;
      add_origin(r, "src-sample-b");
      break;
    }
  }
  merge_results();
}

static void test_merge_is_capture_order_independent(void) {
  const int forward[3] = {0, 1, 2};
  const int reverse[3] = {2, 1, 0};
  const int middle[3] = {1, 0, 2};

  seed_merge_permutation(forward, 3);
  int n_ref = num_results;
  struct result ref[3];
  assert(n_ref <= (int)(sizeof(ref) / sizeof(ref[0])));
  for (int i = 0; i < n_ref; i++)
    ref[i] = results[i];

  const int *perms[2] = {reverse, middle};
  for (int p = 0; p < 2; p++) {
    seed_merge_permutation(perms[p], 3);
    assert(num_results == n_ref);
    for (int i = 0; i < n_ref; i++) {
      /* Same records, in the same slots — not merely the same set. */
      assert(results[i].type == ref[i].type);
      assert(results[i].region == ref[i].region);
      assert(results[i].pos == ref[i].pos);
      assert(results[i].conf == ref[i].conf);
      assert(results[i].set_mask == ref[i].set_mask);
      assert(results[i].lo == ref[i].lo);
      assert(results[i].hi == ref[i].hi);
      assert(results[i].sample == ref[i].sample);
      assert(memcmp(&results[i].origins, &ref[i].origins,
                    sizeof(ref[i].origins)) == 0);
    }
  }
}

/* =========================================================================
 * Parser: key order is irrelevant
 *
 * Spec rule: tail keys may appear in any order. The two-stage parser
 * collects all keys before sz→hi normalization, so `sz` before `lo` must
 * work the same as `lo` before `sz`.
 * ========================================================================= */
static void test_parse_key_order_independent(void) {
  reset_results();
  /* Canonical order. */
  assert(parse_line("P initrd pos=base conf=parsed lo=0x100000 hi=0x1fffff",
                    NULL, NULL) == 1);
  struct result a = results[0];

  reset_results();
  /* Permuted order. */
  assert(parse_line("P initrd hi=0x1fffff lo=0x100000 conf=parsed pos=base",
                    NULL, NULL) == 1);
  struct result b = results[0];

  assert(a.lo == b.lo);
  assert(a.hi == b.hi);
  assert(a.pos == b.pos);
  assert(a.conf == b.conf);
  assert(a.set_mask == b.set_mask);
}

static void test_parse_sz_before_lo_normalizes(void) {
  /* Critical: sz needs lo to compute hi. If the parser were streaming, sz
   * before lo would fail (lo unknown yet). The two-stage design must
   * collect both keys before normalizing. */
  reset_results();
  assert(parse_line("P initrd pos=base conf=parsed sz=0x10000 lo=0x100000",
                    NULL, NULL) == 1);
  assert(num_results == 1);
  assert(HAS_LO(&results[0]) && HAS_HI(&results[0]));
  assert(results[0].lo == 0x100000ul);
  assert(results[0].hi == 0x10ffffu); /* lo + sz - 1 */
}

/* =========================================================================
 * Merge: base_align LCM-of-powers-of-two (= max)
 *
 * The spec restricts base_align to powers of two so the merge rule
 * simplifies to max() (no LCM overflow risk).
 * ========================================================================= */
static void test_merge_base_align_takes_max(void) {
  reset_results();
  struct result *a = push_result();
  a->type = KASLD_TYPE_VIRT;
  a->region = REGION_KERNEL_TEXT;
  a->pos = POS_BASE;
  a->conf = CONF_PARSED;
  a->lo = FX_TEXT;
  a->base_align = 0x1000; /* 4 KiB */
  a->set_mask = LO_SET | BASE_ALIGN_SET;

  struct result *b = push_result();
  b->type = KASLD_TYPE_VIRT;
  b->region = REGION_KERNEL_TEXT;
  b->pos = POS_BASE;
  b->conf = CONF_PARSED;
  b->lo = FX_TEXT;
  b->base_align = 0x200000; /* 2 MiB */
  b->set_mask = LO_SET | BASE_ALIGN_SET;

  merge_results();
  assert(num_results == 1);
  assert(HAS_BASE_ALIGN(&results[0]));
  /* LCM of powers of two = max. Merged record carries the stricter
   * (larger) alignment claim. */
  assert(results[0].base_align == 0x200000);
}

static void test_merge_base_align_propagates_from_either_contributor(void) {
  reset_results();
  /* One contributor with base_align, one without. The set bit must
   * propagate. */
  struct result *a = push_result();
  a->type = KASLD_TYPE_VIRT;
  a->region = REGION_KERNEL_TEXT;
  a->pos = POS_BASE;
  a->conf = CONF_PARSED;
  a->lo = FX_TEXT;
  a->set_mask = LO_SET;

  struct result *b = push_result();
  b->type = KASLD_TYPE_VIRT;
  b->region = REGION_KERNEL_TEXT;
  b->pos = POS_BASE;
  b->conf = CONF_PARSED;
  b->lo = FX_TEXT;
  b->base_align = 0x200000;
  b->set_mask = LO_SET | BASE_ALIGN_SET;

  merge_results();
  assert(num_results == 1);
  assert(HAS_BASE_ALIGN(&results[0]));
  assert(results[0].base_align == 0x200000);
}

/* =========================================================================
 * region_info: every region has a non-empty wire_name and a section_name
 *
 * The render layer reads region_info[r->region].section_name and the
 * parser reads region_info[].wire_name. A NULL wire_name would skip
 * the region in the parser's linear scan; a NULL section_name would
 * crash the renderer.
 * ========================================================================= */
static void test_region_info_table_completeness(void) {
  for (int i = 1; i < REGION__COUNT; i++) {
    assert(region_info[i].wire_name != NULL);
    assert(region_info[i].wire_name[0] != '\0');
    assert(region_info[i].section_name != NULL);
    /* wire_name in region_info must match the wire-token table in api.h. */
    assert(strcmp(region_info[i].wire_name, kasld_region_wire_table[i]) == 0);
  }
}

static void test_region_info_static_vas_or_derive_vas_set(void) {
  /* Every non-UNKNOWN region must provide a VAS resolver: either
   * derive_vas non-NULL, or static_vas with a meaningful range. An
   * all-zero VAS is the "no constraint" form (open VAS) — explicitly
   * checked by result_in_bounds. Any region with neither yields no
   * validation, which would silently accept any address. */
  for (int i = 1; i < REGION__COUNT; i++) {
    const struct region_info *ri = &region_info[i];
    int has_derive = (ri->derive_vas != NULL);
    int has_static = (ri->static_vas.lo != 0 || ri->static_vas.hi != 0);
    /* Either derive_vas or static_vas must be set (or, for fully
     * open regions, both .lo and .hi being literal zero is rejected
     * by the open-VAS short-circuit — that's deliberate, so this
     * assertion just guards against accidental all-zero entries
     * paired with a NULL derive_vas, which would silently accept
     * any address with no recorded intent). */
    assert(has_derive || has_static);
  }
}

/* =========================================================================
 * compute_kaslr_info: decoupled_note flag
 *
 * On decoupled arches (x86_64, arm64, riscv64, s390), when phys leaks
 * exist but no virt text leak does, decoupled_note must be set so the
 * summary clarifies that physical leaks don't reveal virtual text.
 * ========================================================================= */
#if !TEXT_TRACKS_DIRECTMAP
static void test_compute_kaslr_info_sets_decoupled_note(void) {
  reset_results();
  /* PHYS leak in a DRAM region, no VIRT text leak. */
  struct result *r = push_result();
  r->type = KASLD_TYPE_PHYS;
  r->region = REGION_RAM;
  r->pos = POS_BASE;
  r->conf = CONF_PARSED;
  r->lo = 0x100000;
  r->set_mask = LO_SET;

  struct summary s = {0};
  compute_kaslr_info(&s, NULL, NULL, NULL);
  assert(s.kaslr.vtext == 0);    /* no virt anchor */
  assert(s.decoupled_note == 1); /* note must be set */
}

static void test_compute_kaslr_info_no_note_when_vtext_present(void) {
  reset_results();
  /* Both phys landmark AND virt text — no decoupling-explanation needed. */
  struct result *p = push_result();
  p->type = KASLD_TYPE_PHYS;
  p->region = REGION_RAM;
  p->pos = POS_BASE;
  p->conf = CONF_PARSED;
  p->lo = 0x100000;
  p->set_mask = LO_SET;

  struct result *v = push_result();
  v->type = KASLD_TYPE_VIRT;
  v->region = REGION_KERNEL_IMAGE;
  v->pos = POS_BASE;
  v->conf = CONF_PARSED;
  v->lo = layout.virt_kaslr_text_min + layout.virt_kaslr_align;
  v->set_mask = LO_SET;

  struct summary s = {0};
  compute_kaslr_info(&s, NULL, NULL, NULL);
  assert(s.kaslr.vtext != 0);
  assert(s.decoupled_note == 0);
}

static void test_compute_kaslr_info_no_note_without_phys_landmark(void) {
  reset_results();
  /* No phys leaks at all — note shouldn't fire (there's nothing to
   * explain). */
  struct summary s = {0};
  compute_kaslr_info(&s, NULL, NULL, NULL);
  assert(s.decoupled_note == 0);
}
#endif /* !TEXT_TRACKS_DIRECTMAP */

/* =========================================================================
 * Main
 * ========================================================================= */

/* Contract test for engine_sync_authoritative(): the engine->layout
 * projection. This is the bug class that twice leaked into the renderer — the
 * sync silently failing to write a field, so the diagram disagreed with the
 * inferred range. Build a synthetic resolved engine and assert EVERY edge it is
 * responsible for lands where compute_kaslr_info()/render expect it.
 *
 * Crucially pins kaslr_base_* == kernel_base_* == Q_VIRT_IMAGE_BASE: those must
 * stay equal post-resolution (the "kernel text" band vs the reported "Inferred
 * text range"), which is the exact invariant the original bug violated. */
static void test_engine_sync_projects_all_fields(void) {
  struct engine e;
  memset(&e, 0, sizeof(e));

  /* Synthetic resolved windows — distinct, recognizable values per quantity so
   * a mis-wired field (writing the wrong source) is caught, not just a missing
   * write. */
  e.est[Q_VIRT_IMAGE_BASE].lo = FX_TEXT;
  e.est[Q_VIRT_IMAGE_BASE].hi = (FX_TEXT + 0x0e000000ul);
  e.est[Q_VIRT_KASLR_ALIGN].lo = 0x200000ul;
  /* Build Q_PAGE_OFFSET through the quantity's own top and narrow it with a
   * constraint rather than assigning .lo / .hi, so the fixture states a window
   * and lets the lattice decide how to hold it. */
  unsigned long fx_po_lo = 0, fx_po_hi = 0;
  {
    const struct quantity_def *qd = &quantities[Q_PAGE_OFFSET];
    struct estimate *po = &e.est[Q_PAGE_OFFSET];
    unsigned long t_lo = 0, t_hi = 0;
    qd->init_top(po);
    quantity_window(Q_PAGE_OFFSET, po, &t_lo, &t_hi);
    /* Lift the floor so the projected window is narrower than the top — a
     * field that is never written would otherwise still compare equal. On a
     * decoupled arch the assertion below also wants the base ABOVE the
     * compile-time default, which is what that branch is about. */
#if !TEXT_TRACKS_DIRECTMAP
    unsigned long want_floor = (unsigned long)PAGE_OFFSET + 1;
#else
    unsigned long want_floor = t_lo + 1;
#endif
    if (t_lo < t_hi) {
      struct constraint c;
      memset(&c, 0, sizeof(c));
      c.q = Q_PAGE_OFFSET;
      c.op = C_LOWER_BOUND;
      c.value = want_floor;
      c.conf = CONF_PARSED;
      c.id = 1;
      estimate_meet(po, qd, &c);
    }
    quantity_window(Q_PAGE_OFFSET, po, &fx_po_lo, &fx_po_hi);
  }
  e.est[Q_PHYS_IMAGE_BASE].lo = 0x4000000ul;
  e.est[Q_PHYS_IMAGE_BASE].hi = 0x3c000000ul;
  e.est[Q_PHYS_KASLR_ALIGN].lo = 0x200000ul;
  e.est[Q_VMALLOC_BASE].lo = (unsigned long)PAGE_OFFSET + 0x11000000ul;
  e.est[Q_VMALLOC_BASE].lo_binding = 1;
  e.est[Q_VMALLOC_BASE].hi = (unsigned long)PAGE_OFFSET + 0x12000000ul;
  e.est[Q_VMALLOC_BASE].hi_binding = 1;
  e.est[Q_VMEMMAP_BASE].lo = (unsigned long)PAGE_OFFSET + 0x13000000ul;
  e.est[Q_VMEMMAP_BASE].lo_binding = 1;
  e.est[Q_VMEMMAP_BASE].hi = (unsigned long)PAGE_OFFSET + 0x14000000ul;
  e.est[Q_VMEMMAP_BASE].hi_binding = 1;

  /* The VAS floor must survive the sync untouched (second renderer bug). */
  unsigned long vas_floor_before = layout.virt_kernel_vas_start;

  /* Start the targets at poison so a missing write is visibly wrong. */
  layout.virt_kaslr_text_min = layout.virt_kaslr_text_max = 0;
  layout.virt_image_base_min = layout.virt_image_base_max = 0;
  layout.virt_kaslr_align = 0;
  layout.virt_page_offset_min = layout.virt_page_offset_max = 0;
  layout.virt_vmalloc_base_min = layout.virt_vmalloc_base_max = 0;
  layout.virt_vmemmap_base_min = layout.virt_vmemmap_base_max = 0;

  engine_sync_authoritative(&e);

  /* Virtual text window projects onto BOTH the KASLR window and the kernel
   * image-placement range, and they must be identical (the renderer bug). */
  assert(layout.virt_kaslr_text_min == FX_TEXT);
  assert(layout.virt_kaslr_text_max == (FX_TEXT + 0x0e000000ul));
  assert(layout.virt_image_base_min == layout.virt_kaslr_text_min);
  assert(layout.virt_image_base_max == layout.virt_kaslr_text_max);
  assert(layout.virt_kaslr_align == 0x200000ul);

  assert(layout.virt_page_offset_min == fx_po_lo);
  assert(layout.virt_page_offset_max == fx_po_hi);

  assert(layout.virt_vmalloc_base_min ==
         (unsigned long)PAGE_OFFSET + 0x11000000ul);
  assert(layout.virt_vmalloc_base_max ==
         (unsigned long)PAGE_OFFSET + 0x12000000ul);
  assert(layout.virt_vmemmap_base_min ==
         (unsigned long)PAGE_OFFSET + 0x13000000ul);
  assert(layout.virt_vmemmap_base_max ==
         (unsigned long)PAGE_OFFSET + 0x14000000ul);

#if !TEXT_TRACKS_DIRECTMAP
  /* Direct-map base moves to the proven lower bound (the fixture lifts the
   * floor above the lowest admissible base), but the VAS floor must NOT — only
   * layout.virt_page_offset, never virt_kernel_vas_start, which was the second
   * renderer bug. */
  assert(fx_po_lo > (unsigned long)PAGE_OFFSET);
  assert(layout.virt_page_offset == fx_po_lo);
  assert(layout.phys_kaslr_text_min == 0x4000000ul);
  assert(layout.phys_kaslr_text_max == 0x3c000000ul);
  assert(layout.phys_kaslr_align == 0x200000ul);
#endif
  assert(layout.virt_kernel_vas_start == vas_floor_before);
}

/* Contract test for the candidate COUNTS engine_sync_authoritative() projects.
 * Separate from the edge test above because a count answers a different
 * question than a window edge: not "did the field get written" but "was it
 * counted at the resolved alignment, over evidence at the sound floor, with
 * interior holes removed".
 *
 * Those three are independent, and each has a wrong answer that a window
 * assertion cannot see -- counting at PAGE_SIZE rather than the resolved
 * KASLR granularity, ignoring the constraint set so interior holes survive, or
 * carving at CONF_BRUTE so a heuristic claim narrows the GUARANTEED window.
 * The fixture is built so all three land on different totals and one exact
 * assertion separates them. */
static void test_engine_sync_projects_slot_counts(void) {
  struct engine e;
  memset(&e, 0, sizeof(e));

  e.est[Q_VIRT_IMAGE_BASE].lo = FX_TEXT;
  e.est[Q_VIRT_IMAGE_BASE].hi = FX_TEXT + 0x0e000000ul;
  e.est[Q_VIRT_KASLR_ALIGN].lo = 0x200000ul;
  e.est[Q_PHYS_IMAGE_BASE].lo = 0x4000000ul;
  e.est[Q_PHYS_IMAGE_BASE].hi = 0x3c000000ul;
  e.est[Q_PHYS_KASLR_ALIGN].lo = 0x200000ul;
  e.est[Q_VMALLOC_BASE].lo = (unsigned long)PAGE_OFFSET + 0x11000000ul;
  e.est[Q_VMALLOC_BASE].lo_binding = 1;
  e.est[Q_VMALLOC_BASE].hi = (unsigned long)PAGE_OFFSET + 0x12000000ul;
  e.est[Q_VMALLOC_BASE].hi_binding = 1;

  /* A proven hole over one aligned candidate. Excluding a single point rather
   * than a span is what shows up in the total: splitting a range removes the
   * excluded candidate but the new range contributes its own floor, so a
   * point exclude nets exactly -1 while a span nets its own width. */
  e.constraints[0].q = Q_VIRT_IMAGE_BASE;
  e.constraints[0].op = C_EXCLUDE;
  e.constraints[0].value = FX_TEXT + 0x02000000ul;
  e.constraints[0].value2 = FX_TEXT + 0x02000000ul;
  e.constraints[0].conf = CONF_PARSED;
  e.constraints[0].id = 1;

  /* A heuristic hole below the sound floor: the guaranteed count must ignore
   * it. Deliberately wide -- a below-floor hole that happened to leave the
   * total unchanged would make the assertion pass for the wrong reason. */
  e.constraints[1].q = Q_VIRT_IMAGE_BASE;
  e.constraints[1].op = C_EXCLUDE;
  e.constraints[1].value = FX_TEXT + 0x04000000ul;
  e.constraints[1].value2 = FX_TEXT + 0x06000000ul - 1;
  e.constraints[1].conf = CONF_HEURISTIC;
  e.constraints[1].id = 2;
  e.n_constraints = 2;

  layout.virt_kaslr_align = 0;
  layout.virt_kaslr_slots = 0;
  layout.phys_kaslr_slots = 0;
  layout.virt_vmalloc_slots = 0;

  engine_sync_authoritative(&e);

  /* 0x0e000000 of window at 2 MiB granularity is 112 whole strides plus the
   * floor itself, less the one proven hole. Counting at PAGE_SIZE, dropping
   * the constraint set, or carving at CONF_BRUTE each lands elsewhere. */
  assert(layout.virt_kaslr_align == 0x200000ul);
  assert(layout.virt_kaslr_slots == 112);

  /* Taken on every arch, not only the decoupled ones that resolve a separate
   * phys window: 0x38000000 at the same granularity, no holes. The align a
   * coupled arch mirrors from the virt side is the same 2 MiB. */
  assert(layout.phys_kaslr_slots == 449);

#if RANDOMIZE_MEMORY_ALIGN
  /* Memory KASLR moves the direct map, vmalloc and vmemmap bases on a coarser
   * pitch than the image base: 16 MiB of window at that pitch is the floor and
   * nothing above it. */
  assert(layout.virt_vmalloc_slots == 0x1000000ul / RANDOMIZE_MEMORY_ALIGN + 1);
#else
  /* No memory KASLR here, so no pitch to count on. */
  assert(layout.virt_vmalloc_slots == 0);
#endif
}

/* engine_sync_authoritative selects the un-randomized direct-map base from the
 * paging level the engine resolved, so the rendered RANDOMIZE_MEMORY offset is
 * measured from the base the target kernel actually slid away from.
 *
 * The two bases are 59.6 PiB apart, and the level is knowable at run time but
 * never at build time, so naming either one in the source is wrong on the
 * other. Driving both levels through one projection is what a fixed constant
 * cannot satisfy. Asserting against PAGE_OFFSET_BASE_L4/_L5 also holds the arch
 * header and the paging-level table to the same pair of addresses, which are
 * separate definitions of the same upstream constants.
 *
 * The unresolved case is the one that decides what an unknown level costs: no
 * base, so downstream states no offset rather than measuring from a default. */
static void test_engine_sync_selects_directmap_base_by_level(void) {
#if RANDOMIZE_MEMORY_ALIGN > 0
  const struct quantity_def *qd = &quantities[Q_VA_BITS];
  const struct {
    unsigned long bits;
    unsigned long base;
  } want[2] = {{48ul, (unsigned long)PAGE_OFFSET_BASE_L4},
               {57ul, (unsigned long)PAGE_OFFSET_BASE_L5}};

  for (int i = 0; i < 2; i++) {
    struct engine e;
    memset(&e, 0, sizeof(e));
    qd->init_top(&e.est[Q_VA_BITS]);

    struct constraint c;
    memset(&c, 0, sizeof(c));
    c.q = Q_VA_BITS;
    c.op = C_EQUALS;
    c.value = want[i].bits;
    c.conf = CONF_PARSED;
    c.id = 1;
    estimate_meet(&e.est[Q_VA_BITS], qd, &c);

    layout.virt_page_offset_unrandomized = 0;
    engine_sync_authoritative(&e);
    assert(layout.virt_page_offset_unrandomized == want[i].base);
  }

  /* Every candidate still live: the level is not resolved, so no base. */
  {
    struct engine e;
    memset(&e, 0, sizeof(e));
    qd->init_top(&e.est[Q_VA_BITS]);

    layout.virt_page_offset_unrandomized = 0;
    engine_sync_authoritative(&e);
    assert(layout.virt_page_offset_unrandomized == 0);
  }
#endif
}

/* discard_project_engine(): the engine records what it discarded in its own
 * state, and this carries it to the ledger. Every bug found in this function so
 * far was a MISCLASSIFICATION rather than a miscount, so the assertions are on
 * which reason and which source, not only on the total.
 *
 * Two of them are pinned here because both shipped in a draft and both would
 * have made the ledger lie in the reassuring direction -- reporting healthy
 * runs as lossy:
 *
 *   - An observation can be invalid because a verdict removed it, or because it
 *     sits below the run's confidence floor. Only the first is a discard. The
 *     second is the two-window design working, and counting it would report the
 *     floor gate itself as evidence loss on every floored run.
 *   - conflicts[] holds constraint IDS, not constraints, so the emitting rule
 *     comes from a lookup in the constraint store. Reading an origin off the id
 *     array yields garbage.
 */
static void test_discard_project_engine_classifies_correctly(void) {
  static struct engine e;
  memset(&e, 0, sizeof(e));
  kasld_discard_reset();

  /* Three observations, populated directly: this file links the orchestrator
   * and the engine's pure layers, not evidence.c, and the projection reads the
   * set rather than caring how it was filled. */
  const uint32_t curated_id = 11, floored_id = 22, kept_id = 33;
  const uint32_t ids[3] = {curated_id, floored_id, kept_id};
  for (int i = 0; i < 3; i++) {
    struct observation *o = &e.ev.obs[i];
    memset(o, 0, sizeof(*o));
    o->id = ids[i];
    o->value_kind = OBS_ADDRESS;
    o->type = o->eff_type = KASLD_TYPE_VIRT;
    o->region = o->eff_region = REGION_KERNEL_TEXT;
    o->pos = POS_BASE;
    o->set_mask = LO_SET;
    o->lo = 0x1000ul * (unsigned long)(i + 1);
    o->conf = (ids[i] == floored_id) ? CONF_HEURISTIC : CONF_PARSED;
    /* Only the survivor stays valid. The first was removed by the verdict
     * below; the second is invalid because it sits under the floor, which no
     * verdict targets. */
    o->valid = (ids[i] == kept_id);
  }
  e.ev.n_obs = 3;

  struct verdict *v = &e.ev.verdicts[0];
  memset(v, 0, sizeof(*v));
  v->observation_id = curated_id;
  v->kind = V_INVALID;
  snprintf(v->origin, ORIGIN_LEN, "%s", "text_cluster_filter");
  e.ev.n_verdicts = 1;

  /* One engine cap, and one rejected constraint whose origin must be resolved
   * through the constraint store rather than read off the id. */
  e.saturation = ENGINE_SAT_VERDICTS_FULL;
  e.constraints[0].id = 4242;
  snprintf(e.constraints[0].origin, ORIGIN_LEN, "%s", "some_bound_rule");
  e.n_constraints = 1;
  e.conflicts[Q_VIRT_IMAGE_BASE][0] = 4242;
  e.n_conflicts[Q_VIRT_IMAGE_BASE] = 1;

  discard_project_engine(&e);

  /* Exactly three: the curated observation, the cap, the conflict. The
   * floor-gated observation is NOT among them, and neither is the survivor. */
  assert(kasld_discard_total() == 3);
  assert(kasld_discard_count() == 3);

  int saw_curated = 0, saw_capacity = 0, saw_conflict = 0;
  for (int i = 0; i < kasld_discard_count(); i++) {
    const struct kasld_discard *d = kasld_discard_at(i);
    assert(d);
    switch (d->reason) {
    case DISCARD_CURATED:
      /* Attributed to the rule that ruled, not to the observation. */
      assert(strcmp(d->source, "text_cluster_filter") == 0);
      assert(d->count == 1);
      saw_curated++;
      break;
    case DISCARD_CAPACITY:
      assert(strcmp(d->source, DSRC_VERDICTS) == 0);
      saw_capacity++;
      break;
    case DISCARD_CONFLICT:
      /* Resolved through the store: the id 4242 names some_bound_rule. */
      assert(strcmp(d->source, "some_bound_rule") == 0);
      saw_conflict++;
      break;
    default:
      assert(0 && "projection produced a reason it cannot source");
    }
  }
  assert(saw_curated == 1 && saw_capacity == 1 && saw_conflict == 1);

  kasld_discard_reset();
}

/* A conflict whose constraint is no longer in the store is still counted, under
 * an empty source. The ledger's job is that the discard is visible even when
 * its provenance is not -- dropping it would make the store's size decide how
 * much loss the run admits to. */
static void test_discard_project_engine_conflict_without_constraint(void) {
  static struct engine e;
  memset(&e, 0, sizeof(e));
  kasld_discard_reset();

  e.n_constraints = 0; /* the id below resolves to nothing */
  e.conflicts[Q_PAGE_OFFSET][0] = 999;
  e.n_conflicts[Q_PAGE_OFFSET] = 1;

  discard_project_engine(&e);

  assert(kasld_discard_total() == 1);
  assert(kasld_discard_count() == 1);
  assert(kasld_discard_at(0)->reason == DISCARD_CONFLICT);
  assert(kasld_discard_at(0)->source[0] == '\0');

  kasld_discard_reset();
}

/* engine_sync_authoritative tightens layout.modules_start/end from observed
 * VIRT/REGION_MODULE_BAND addresses (when inside the validation union),
 * so the rendered band reflects the actual runtime module range rather than
 * the wide validation window. */
static void test_engine_sync_anchors_module_band_to_observations(void) {
  struct engine e;
  memset(&e, 0, sizeof(e));

  /* Pick addresses inside the arch's static MODULES_* union. Two
   * observations form a [lo, hi] band a few MiB wide. */
  unsigned long obs_lo = (unsigned long)MODULES_START + 0x1000ul;
  unsigned long obs_hi = (unsigned long)MODULES_START + 0x100000ul;
  if (obs_hi > (unsigned long)MODULES_END)
    obs_hi = (unsigned long)MODULES_END;

  struct observation o1;
  memset(&o1, 0, sizeof(o1));
  o1.id = 1;
  o1.valid = 1;
  o1.value_kind = OBS_ADDRESS;
  o1.eff_type = KASLD_TYPE_VIRT;
  o1.eff_region = REGION_MODULE_BAND;
  o1.pos = POS_INTERIOR;
  o1.sample = obs_lo;
  o1.set_mask = SAMPLE_SET;
  o1.conf = CONF_PARSED;
  e.ev.obs[e.ev.n_obs++] = o1;

  struct observation o2 = o1;
  o2.id = 2;
  o2.sample = obs_hi;
  e.ev.obs[e.ev.n_obs++] = o2;

  /* Seed the resolved estimates: just enough for the rest of sync. */
  e.est[Q_VIRT_IMAGE_BASE].lo = layout.virt_kaslr_text_min;
  e.est[Q_VIRT_IMAGE_BASE].hi = layout.virt_kaslr_text_max;

  /* Static modules_start/end (the validation union) as the pre-sync value. */
  layout.modules_start = MODULES_START;
  layout.modules_end = MODULES_END;

  engine_sync_authoritative(&e);

  /* Tightened to observed range — diagram reflects real runtime band. */
  assert(layout.modules_start == obs_lo);
  assert(layout.modules_end == obs_hi);
}

/* An out-of-union module observation must never be adopted as the rendered
 * band. This holds on every arch: static-module arches keep the validation
 * window; text-relative arches (riscv64/s390) project the band onto the
 * resolved text window. Neither commits to the bogus single point. */
static void test_engine_sync_module_band_rejects_out_of_union(void) {
  struct engine e;
  memset(&e, 0, sizeof(e));

  struct observation o;
  memset(&o, 0, sizeof(o));
  o.id = 1;
  o.valid = 1;
  o.value_kind = OBS_ADDRESS;
  o.eff_type = KASLD_TYPE_VIRT;
  o.eff_region = REGION_MODULE_BAND;
  o.pos = POS_INTERIOR;
  /* Just below the union floor — out of the validation union on every arch
   * (module unions never start at 0). A fixed sentinel like ULONG_MAX is not
   * portable: on some arches MODULES_END == ULONG_MAX, so ~0ul would be a
   * legitimate in-union address. */
  unsigned long oob = (unsigned long)MODULES_START - 0x1000ul;
  o.sample = oob;
  o.set_mask = SAMPLE_SET;
  o.conf = CONF_PARSED;
  e.ev.obs[e.ev.n_obs++] = o;

  e.est[Q_VIRT_IMAGE_BASE].lo = layout.virt_kaslr_text_min;
  e.est[Q_VIRT_IMAGE_BASE].hi = layout.virt_kaslr_text_max;

  layout.modules_start = MODULES_START;
  layout.modules_end = MODULES_END;

  engine_sync_authoritative(&e);

  /* The bogus sample is not adopted, and the band stays well-ordered. */
  assert(layout.modules_start != oob);
  assert(layout.modules_end != oob);
  assert(layout.modules_start <= layout.modules_end);
}

/* A projected module band must never collapse. On MODULES_RELATIVE_TO_TEXT
 * arches the band is derived by subtracting from the resolved text window; with
 * nothing yet proven the window sits at its honest top, and on an arch whose
 * IMAGE_BASE_OFFSET equals that floor (s390) both subtractions saturate and the
 * projection degenerates to start == end == 0. Adopting that publishes a pin at
 * an address nothing was proven about -- the map drew `modules (pinned)` at 0
 * -- and hands region_info a validation range that rejects every real module
 * leak. Sync must reject a degenerate projection and keep the static band.
 *
 * Live on every arch: static-module arches assert their union stays intact,
 * text-relative arches assert the projection is well-formed. */
static void test_engine_sync_module_band_never_degenerate(void) {
  struct engine e;
  memset(&e, 0, sizeof(e));

  /* The honest top of Q_VIRT_IMAGE_BASE: the state before any evidence lands.
   * Derived from the arch's own widened window so it is exact on every arch and
   * cannot overflow a 32-bit word. */
  e.est[Q_VIRT_IMAGE_BASE].lo = (unsigned long)KASLR_VIRT_TEXT_MIN_WIDE;
  e.est[Q_VIRT_IMAGE_BASE].hi = (unsigned long)KASLR_VIRT_TEXT_MAX_WIDE;

  layout.modules_start = MODULES_START;
  layout.modules_end = MODULES_END;

  engine_sync_authoritative(&e);

  /* Non-empty and well-ordered: a band that starts where it ends is a pin
   * claim, and 0/0 is a pin claim about nothing. */
  assert(layout.modules_end > layout.modules_start);
}

/* Where the arch defines its module band as a delta from PAGE_OFFSET, the band
 * must follow the PAGE_OFFSET the engine resolves, not the one this binary was
 * compiled against. arm32 picks PAGE_OFFSET by VMSPLIT, so on a kernel built
 * with a 2 GiB split the compile-time band sits a full gigabyte above the real
 * one -- the map drew modules inside the stretch it labels user space, and
 * region_info, which validates module addresses against the same band, threw
 * away every genuine module leak that kernel produced.
 *
 * Both shapes of engine knowledge are asserted, because they differ in kind:
 * a pin gives the exact band; a window that has merely excluded the
 * compile-time value gives the union over that window -- wider, still
 * containing the truth, and never the disproved compile-time placement. */
static void test_engine_sync_module_band_follows_page_offset(void) {
  struct engine e;
  unsigned long sv_po = layout.virt_page_offset;

  /* A split the architecture actually admits, and where it offers more than
   * one, not the compile-time default. An invented address cannot serve here:
   * where the architecture fixes the linear-map base, pinning to anything but
   * that value empties the estimate instead of moving it. */
  unsigned long moved = po_admissible(1);

  memset(&e, 0, sizeof(e));
  e.est[Q_VIRT_IMAGE_BASE].lo = layout.virt_kaslr_text_min;
  e.est[Q_VIRT_IMAGE_BASE].hi = layout.virt_kaslr_text_max;
  po_set(&e.est[Q_PAGE_OFFSET], moved, moved); /* pinned: the split is proven */

  layout.modules_start = MODULES_START;
  layout.modules_end = MODULES_END;
  engine_sync_authoritative(&e);

#if MODULES_RELATIVE_TO_PAGE_OFFSET
  /* The projected floor is the relation's own value, NOT clamped up to
   * KERNEL_VIRT_VAS_START. Arches that carve the module band out of vmalloc
   * put it below PAGE_OFFSET, and on those KERNEL_VIRT_VAS_START *is*
   * PAGE_OFFSET -- clamping there would collapse the band and reject every
   * genuine module leak. Only a wrapped floor is rejected, and `moved` sits
   * well inside the address space, so the relation cannot wrap here whether it
   * adds to PAGE_OFFSET or subtracts from it. */
  unsigned long want_lo = MODULES_START_FOR(moved);
  unsigned long want_hi = MODULES_END_FOR(moved);
  assert(kasld_module_band_floor_sane(moved, want_lo)); /* no wrap here */
  assert(want_hi > want_lo);
  assert(layout.modules_start == want_lo);
  assert(layout.modules_end == want_hi);
  /* It really moved off the compile-time placement — only askable of an arch
   * whose split can move. Where exactly one value is admissible the band IS
   * the compile-time one, and reproducing it faithfully is the property. */
  if (po_is_fixed()) {
    assert(layout.modules_start == (unsigned long)MODULES_START);
    assert(layout.modules_end == (unsigned long)MODULES_END);
  } else {
    assert(layout.modules_start != (unsigned long)MODULES_START ||
           layout.modules_end != (unsigned long)MODULES_END);
  }

  if (!po_is_fixed()) {

    /* Unpinned, but the compile-time PAGE_OFFSET is excluded: the band inherits
     * the window's uncertainty as width rather than being drawn as located. */
    unsigned long win_hi = po_admissible(1);
    unsigned long win_lo = po_admissible(2);
    memset(&e, 0, sizeof(e));
    e.est[Q_VIRT_IMAGE_BASE].lo = layout.virt_kaslr_text_min;
    e.est[Q_VIRT_IMAGE_BASE].hi = layout.virt_kaslr_text_max;
    po_set(&e.est[Q_PAGE_OFFSET], win_lo, win_hi);
    layout.modules_start = MODULES_START;
    layout.modules_end = MODULES_END;
    engine_sync_authoritative(&e);
    /* Contains the band for every PAGE_OFFSET the window still admits. */
    assert(layout.modules_start <= want_lo);
    assert(layout.modules_end >= MODULES_END_FOR(win_hi));
    assert(layout.modules_end > layout.modules_start);
  }
#elif !MODULES_RELATIVE_TO_TEXT
  /* A fixed band does not move with the linear map, and must not be touched. */
  assert(layout.modules_start == (unsigned long)MODULES_START);
  assert(layout.modules_end == (unsigned long)MODULES_END);
#endif

  layout.virt_page_offset = sv_po;
  layout.modules_start = MODULES_START;
  layout.modules_end = MODULES_END;
}

/* =========================================================================
 * Progress bar
 *
 * The bar only draws when stderr is a TTY, so a live run is the only place it
 * is ever seen — and every defect in it (a stale tail left by a narrower
 * frame, an in-flight counter that could only count down) built cleanly and
 * passed every architecture. These drive progress_paint() and the in-flight
 * accounting directly and read back what was written.
 * ========================================================================= */

/* Redirect stderr to a tmpfile for the duration of `fn`, then read what was
 * written into `buf`. Mirrors capture_stdout() in test_render.c; a tmpfile
 * rather than a pipe so a frame can never block on a full pipe buffer.
 * Single-threaded (matches the harness). */
static void capture_stderr(void (*fn)(void), char *buf, size_t buflen) {
  fflush(stderr);
  int saved = dup(fileno(stderr));
  FILE *tmp = tmpfile();
  assert(saved >= 0 && tmp != NULL);
  fflush(stderr);
  dup2(fileno(tmp), fileno(stderr));
  fn();
  fflush(stderr);
  /* Restore stderr BEFORE reading so the harness can report a failure. */
  dup2(saved, fileno(stderr));
  close(saved);
  rewind(tmp);
  size_t n = fread(buf, 1, buflen - 1, tmp);
  buf[n] = '\0';
  fclose(tmp);
}

/* Replay a byte stream onto a single terminal line: '\r' homes the cursor,
 * printable bytes overwrite at the cursor, CSI escapes (colour) consume no
 * columns. Returns the visible width, trailing blanks trimmed — i.e. exactly
 * what a reader would see, which is the property the bar's own width
 * bookkeeping has to match. */
static size_t replay_tty_line(const char *in, char *out, size_t outsz) {
  size_t cur = 0, len = 0;
  memset(out, ' ', outsz);
  for (const char *p = in; *p; p++) {
    if (*p == '\033') { /* CSI: ESC [ params final */
      if (p[1] != '[')
        continue;
      p += 2;
      while (*p && !(*p >= '@' && *p <= '~'))
        p++;
      if (!*p)
        break;
      continue;
    }
    if (*p == '\r' || *p == '\n') {
      cur = 0;
      continue;
    }
    if (cur < outsz - 1) {
      out[cur++] = *p;
      if (cur > len)
        len = cur;
    }
  }
  while (len > 0 && out[len - 1] == ' ')
    len--;
  out[len] = '\0';
  return len;
}

static int pb_wide_width, pb_narrow_width;

/* A frame with an in-flight figure is wider than one without. */
static void pb_paint_wide_then_narrow(void) {
  progress_paint(5, 10, 3);
  pb_wide_width = progress_width;
  progress_paint(6, 10, 0);
  pb_narrow_width = progress_width;
}

/* \r rewinds the cursor but clears nothing, so a frame narrower than the one
 * it replaces leaves the old frame's tail on screen; progress_erase() then
 * blanks only the NEW (shorter) width and the tail survives the bar. The frame
 * has to blank the difference itself, so that the recorded progress_width is
 * always the full extent of what is visible. */
static void test_progress_paint_no_stale_tail(void) {
  char raw[1024], line[256];
  progress_width = 0;
  progress_live = 0;
  clock_gettime(CLOCK_MONOTONIC, &progress_start);

  capture_stderr(pb_paint_wide_then_narrow, raw, sizeof(raw));

  /* The premise: the second frame really is the narrower one. */
  assert(pb_wide_width > pb_narrow_width);
  size_t visible = replay_tty_line(raw, line, sizeof(line));
  /* What is on screen is what the bar thinks it drew — no stale tail beyond
   * the width progress_erase() will blank. */
  assert(visible == (size_t)pb_narrow_width);
  /* And the surviving text is the new frame, not a splice of both. */
  assert(strstr(line, "running") == NULL);
  assert(line[0] == '[');
}

/* The in-flight count is claimed by progress_enter_component() and released by
 * progress_update(). progress_update() runs on EVERY path, including the
 * sequential phases that never touch the worker pool, so the claim has to sit
 * beside the call rather than beside the pool slot — otherwise the sequential
 * phase releases what it never claimed, the count floors at zero and stays
 * there for the rest of the run. */
static void test_progress_inflight_balances(void) {
  int sv_quiet = quiet;
  int sv_done = progress_done, sv_painted = progress_painted;
  int sv_total = progress_total;

  /* Isolate the accounting: quiet returns progress_update() immediately after
   * the count, so the assertions hold whether or not stderr is a TTY. */
  quiet = 1;
  progress_inflight = 0;
  progress_done = 0;
  progress_painted = 0;
  progress_total = 8;

  /* Parallel phase: two components claimed at once, both reaped. */
  progress_enter_component();
  progress_enter_component();
  assert(progress_inflight == 2);
  progress_update();
  assert(progress_inflight == 1);
  progress_update();
  assert(progress_inflight == 0);

  /* Sequential phase: claim and release strictly alternating. The claim must
   * register here too, and the pair must return to zero. */
  for (int i = 0; i < 3; i++) {
    progress_enter_component();
    assert(progress_inflight == 1);
    progress_update();
    assert(progress_inflight == 0);
  }

  /* An unmatched release never drives the count negative. */
  progress_update();
  assert(progress_inflight == 0);
  assert(progress_done == 6);

  quiet = sv_quiet;
  progress_done = sv_done;
  progress_painted = sv_painted;
  progress_total = sv_total;
}

/* The discard ledger aggregates by (reason, source), keeps a truthful total
 * past its own cap, and says when the breakdown stopped being complete.
 *
 * The cap matters more than it looks: the ledger exists so a run cannot quietly
 * lose evidence, and a ledger that quietly lost ENTRIES would reproduce that
 * failure one level up. So the total counts every recorded item whether or not
 * a slot was free, and truncation is stated rather than inferred from a
 * suspiciously round number of kinds. */
static void test_discard_ledger_aggregates_and_reports_truncation(void) {
  kasld_discard_reset();
  assert(kasld_discard_count() == 0);
  assert(kasld_discard_total() == 0);
  assert(!kasld_discard_truncated());

  /* Same (reason, source) folds into one entry with a count. */
  kasld_discard_record(DISCARD_PARSE, "alpha");
  kasld_discard_record(DISCARD_PARSE, "alpha");
  kasld_discard_record(DISCARD_PARSE, "alpha");
  assert(kasld_discard_count() == 1);
  assert(kasld_discard_total() == 3);
  assert(kasld_discard_at(0)->count == 3);
  assert(kasld_discard_at(0)->reason == DISCARD_PARSE);

  /* Same source, different reason is a different entry -- the pair is the key,
   * not either half. */
  kasld_discard_record(DISCARD_BOUNDS, "alpha");
  assert(kasld_discard_count() == 2);

  /* A NULL source is legal and distinct from a named one. */
  kasld_discard_record(DISCARD_CURATED, NULL);
  assert(kasld_discard_count() == 3);
  assert(kasld_discard_at(2)->source[0] == '\0');

  /* Out-of-range indices report absence rather than reading past the array. */
  assert(kasld_discard_at(-1) == NULL);
  assert(kasld_discard_at(kasld_discard_count()) == NULL);

  /* Fill past the cap with distinct pairs. */
  for (int i = 0; i < MAX_DISCARDS + 8; i++) {
    char src[ORIGIN_LEN];
    snprintf(src, sizeof(src), "src%d", i);
    kasld_discard_record(DISCARD_CAPACITY, src);
  }
  assert(kasld_discard_count() == MAX_DISCARDS);
  assert(kasld_discard_truncated());
  /* The breakdown stopped growing; the total did not. */
  assert(kasld_discard_total() == 3 + 1 + 1 + (unsigned)(MAX_DISCARDS + 8));

  /* An out-of-range reason is refused rather than indexed with. */
  unsigned int before = kasld_discard_total();
  kasld_discard_record(DISCARD__COUNT, "bogus");
  assert(kasld_discard_total() == before);

  /* Every reason has a wire name, and they are distinct. */
  for (int a = 0; a < DISCARD__COUNT; a++) {
    const char *na = kasld_discard_reason_name((enum kasld_discard_reason)a);
    assert(na && *na && strcmp(na, "unknown") != 0);
    for (int b = a + 1; b < DISCARD__COUNT; b++)
      assert(strcmp(na, kasld_discard_reason_name(
                            (enum kasld_discard_reason)b)) != 0);
  }

  kasld_discard_reset();
  assert(kasld_discard_count() == 0 && kasld_discard_total() == 0 &&
         !kasld_discard_truncated());
}

/* =========================================================================
 * Vantage gathering
 *
 * kasld_gather_vantage() turns a dozen filesystem sources into the confinement
 * picture every renderer reports. Until these tests it was constrained by
 * nothing: the function could be replaced by a memset and the suite passed. The
 * vantage tests that existed filled the struct by hand and asserted on the
 * FORMATTERS -- a different seam, which would pass just as well against a
 * gatherer that never set a field.
 *
 * So these assert on the struct, and in both directions per source. The
 * negative direction alone is what the suite already had by accident, and it is
 * the direction a broken gatherer satisfies for free.
 *
 * The identity fields (uid/euid/gid/groups) come from the same staged status
 * file as the rest, so they are asserted here too. They are asserted against
 * ids DERIVED from the live ones, so a gatherer answering from
 * getuid()/getgroups() -- which no staging can reach -- fails here on any host,
 * rather than passing on the ones whose real identity happens to match a
 * fixture.
 * ========================================================================= */

/* A /proc/self/status carrying the fields the gatherer reads, in the kernel's
 * own layout (tab after the colon, hex capability masks, the identity ids in
 * real/effective/saved/fs order). */
#define TH_STATUS_BODY                                                         \
  "Name:\tkasld\n"                                                             \
  "Uid:\t2000\t2000\t2000\t2000\n"                                             \
  "Gid:\t2000\t2000\t2000\t2000\n"                                             \
  "Groups:\t1007 3009 3012 \n"                                                 \
  "Seccomp:\t2\n"                                                              \
  "NoNewPrivs:\t1\n"                                                           \
  "CapEff:\t000001ffffffffff\n"                                                \
  "CapBnd:\t0000003fffffffff\n"

static void test_vantage_container_absent_then_present(void) {
  struct kasld_vantage v;

  /* Nothing staged: not a container, and every oracle unreadable. */
  th_sysroot_clear();
  kasld_gather_vantage(&v);
  assert(v.container == NULL);
  for (int i = 0; i < KASLD_N_ORACLES; i++)
    assert(v.oracle_readable[i] == 0);

  /* The docker marker is an empty file -- its existence is the signal. */
  th_sysroot_clear();
  th_sysroot_write("/.dockerenv", NULL);
  kasld_gather_vantage(&v);
  assert(v.container != NULL && strcmp(v.container, "docker") == 0);

  th_sysroot_clear();
  th_sysroot_write("/run/.containerenv", NULL);
  kasld_gather_vantage(&v);
  assert(v.container != NULL && strcmp(v.container, "podman") == 0);

  /* No marker file, but a cgroup naming the runtime. */
  th_sysroot_clear();
  th_sysroot_write("/proc/self/cgroup", "0::/kubepods/besteffort/podabc\n");
  kasld_gather_vantage(&v);
  assert(v.container != NULL && strcmp(v.container, "kubernetes") == 0);

  /* /proc/1/cgroup is consulted when /proc/self/cgroup says nothing. */
  th_sysroot_clear();
  th_sysroot_write("/proc/self/cgroup", "0::/\n");
  th_sysroot_write("/proc/1/cgroup", "0::/lxc/ct1\n");
  kasld_gather_vantage(&v);
  assert(v.container != NULL && strcmp(v.container, "lxc") == 0);

  th_sysroot_clear();
}

/* detect_container() calls its order deliberate: marker files before cgroup
 * contents, most-specific runtime first. An order asserted only by a comment is
 * the kind that changes without anyone deciding to change it, so stage a
 * disagreement and pin which side wins. */
static void test_vantage_container_precedence(void) {
  struct kasld_vantage v;

  /* Marker file vs a cgroup naming something else: the file wins. */
  th_sysroot_clear();
  th_sysroot_write("/.dockerenv", NULL);
  th_sysroot_write("/proc/self/cgroup", "0::/kubepods/besteffort/podabc\n");
  kasld_gather_vantage(&v);
  assert(v.container != NULL && strcmp(v.container, "docker") == 0);

  /* Within the cgroup scan, kubepods outranks a docker substring -- a
   * kubernetes pod's cgroup path routinely contains both. */
  th_sysroot_clear();
  th_sysroot_write("/proc/self/cgroup", "0::/kubepods/docker-abc.scope\n");
  kasld_gather_vantage(&v);
  assert(v.container != NULL && strcmp(v.container, "kubernetes") == 0);

  th_sysroot_clear();
}

static void test_vantage_status_fields_absent_then_present(void) {
  struct kasld_vantage v;

  /* No /proc/self/status: unknown, not "none". The distinction is the whole
   * point of the -1 sentinel -- a reader must be able to tell an unreadable
   * source from a permissive one. */
  th_sysroot_clear();
  kasld_gather_vantage(&v);
  assert(v.seccomp == -1);
  assert(v.no_new_privs == -1);
  assert(v.have_caps == 0);

  th_sysroot_clear();
  th_sysroot_write("/proc/self/status", TH_STATUS_BODY);
  kasld_gather_vantage(&v);
  assert(v.seccomp == 2); /* filter mode */
  assert(v.no_new_privs == 1);
  assert(v.have_caps == 1);
  assert(v.cap_eff == 0x000001ffffffffffULL); /* hex, not decimal */
  assert(v.cap_bnd == 0x0000003fffffffffULL);
  assert(v.have_ids == 1);
  assert(v.uid == 2000 && v.euid == 2000);
  assert(v.gid == 2000 && v.egid == 2000);
  assert(v.ngroups == 3 && v.groups[0] == 1007 && v.groups[2] == 3012);

  /* CapEff present, CapBnd missing: caps are still valid, the bounding set
   * reads 0 rather than the file being discarded whole. */
  th_sysroot_clear();
  th_sysroot_write("/proc/self/status", "CapEff:\t00000000000000ff\n");
  kasld_gather_vantage(&v);
  assert(v.have_caps == 1);
  assert(v.cap_eff == 0xffULL);
  assert(v.cap_bnd == 0);

  th_sysroot_clear();
}

/* The identity comes out of the staged tree, never out of the running process.
 *
 * The staged ids are derived from the live ones, so they cannot coincide with
 * them on any host: a gatherer that fell back to getuid()/getgroups() fails
 * here wherever it runs, instead of passing on the machines whose real identity
 * happens to match a hardcoded fixture. */
static void test_vantage_identity_is_staged_not_live(void) {
  struct kasld_vantage v;
  char body[256];
  unsigned long live_uid = (unsigned long)getuid();
  unsigned long live_gid = (unsigned long)getgid();

  snprintf(body, sizeof(body),
           "Uid:\t%lu\t%lu\t%lu\t%lu\n"
           "Gid:\t%lu\t%lu\t%lu\t%lu\n"
           "Groups:\t3009 3012 \n",
           live_uid + 1, live_uid + 2, live_uid + 1, live_uid + 1, live_gid + 3,
           live_gid + 4, live_gid + 3, live_gid + 3);

  th_sysroot_clear();
  th_sysroot_write("/proc/self/status", body);
  kasld_gather_vantage(&v);
  assert(v.have_ids == 1);
  assert(v.uid == live_uid + 1 && v.euid == live_uid + 2);
  assert(v.gid == live_gid + 3 && v.egid == live_gid + 4);
  assert(v.ngroups == 2 && v.groups[0] == 3009 && v.groups[1] == 3012);
  assert(!v.groups_truncated);

  /* A status file with no identity in it: unknown, and still not the live ids.
   * The other fields it does carry are unaffected. */
  th_sysroot_clear();
  th_sysroot_write("/proc/self/status", "Seccomp:\t2\n");
  kasld_gather_vantage(&v);
  assert(v.have_ids == 0);
  assert(v.ngroups == -1);
  assert(v.seccomp == 2);

  /* A malformed id line yields no identity rather than half of one: the
   * effective id is what several gates are actually checked against, so a
   * record naming a real uid beside a missing euid would be worse than none. */
  th_sysroot_clear();
  th_sysroot_write("/proc/self/status", "Uid:\t7\nGid:\tnotanumber\n");
  kasld_gather_vantage(&v);
  assert(v.have_ids == 0);

  /* No status file at all under a sysroot: unknown. 0 is a real uid, so the
   * absence has to be carried by have_ids and not by a value in the field. */
  th_sysroot_clear();
  kasld_gather_vantage(&v);
  assert(v.have_ids == 0);
  assert(v.ngroups == -1);

  th_sysroot_clear();
}

/* Group naming, resolved when the vantage is taken. The tree being analysed is
 * the authority, so an offline replay names ITS groups; the gate table covers
 * the ids kasld knows gate one of its own sources, which is the set a tree with
 * an empty /etc/group cannot name -- the Android shape. Neither source knowing
 * an id is not an error: the number alone is what the kernel checks.
 *
 * Driven over a staged tree, never the host's own /etc/group: the ids in the
 * gate table are Android's, and whether a given machine happens to use one of
 * them for something else is not a property of the code under test. gid 1001 is
 * staged deliberately, because it is also AID_RADIO -- the one id where the two
 * sources disagree, and so the only one that can show which wins. */
static void test_vantage_group_names(void) {
  struct kasld_vantage v;

  th_sysroot_clear();
  th_sysroot_write("/proc/self/status", "Uid:\t0\t0\t0\t0\n"
                                        "Gid:\t0\t0\t0\t0\n"
                                        "Groups:\t1001 3009 4242424 \n");
  /* 1001 collides with AID_RADIO on purpose; 3009 is left out so the gate
   * table has something to answer for. */
  th_sysroot_write("/etc/group", "root:x:0:\n"
                                 "staff:x:1001:\n"
                                 "operators:x:1500:alice,bob\n");
  kasld_gather_vantage(&v);
  assert(v.ngroups == 3);
  /* Both sources name 1001. The analysed tree is the authority, so its name
   * must be the answer and the table's must not surface. */
  assert(strcmp(kasld_group_name(&v, 0), "staff") == 0);
  /* An id the tree does not name falls back to the gate table. */
  assert(strcmp(kasld_group_name(&v, 1), "readproc") == 0);
  /* An id neither source knows resolves to nothing rather than to a guess. */
  assert(kasld_group_name(&v, 2) == NULL);
  /* Nothing is named beyond the membership. */
  assert(kasld_group_name(&v, 3) == NULL);

  /* No group database at all: the gate table still names what it knows, and
   * the rest report by number. This is the Android shape, where /etc/group
   * exists but is empty. */
  th_sysroot_clear();
  th_sysroot_write("/proc/self/status", "Uid:\t0\t0\t0\t0\n"
                                        "Gid:\t0\t0\t0\t0\n"
                                        "Groups:\t1001 3012 \n");
  kasld_gather_vantage(&v);
  assert(strcmp(kasld_group_name(&v, 0), "radio") == 0);
  assert(strcmp(kasld_group_name(&v, 1), "readtracefs") == 0);

  th_sysroot_clear();
}

/* A refused read of a hardening source is not an absent one. Every source read
 * through the environment module is world-readable, so EACCES/EPERM there is a
 * policy withholding it — and under a MAC policy a denied path can fail lookup
 * exactly as a missing one does, leaving errno as the only thing that tells
 * them apart. The advisor acts on the difference: a denial it can attribute to
 * policy versus one it must leave unexplained.
 *
 * Asserted on the decision itself rather than through a mode-0000 file, which
 * would answer differently for a root test runner and prove nothing there. */
static void test_unread_marker_separates_denial_from_absence(void) {
  errno = EACCES;
  assert(unread_marker() == KASLD_SYSCTL_DENIED);
  errno = EPERM;
  assert(unread_marker() == KASLD_SYSCTL_DENIED);

  errno = ENOENT;
  assert(unread_marker() == KASLD_SYSCTL_UNREAD);
  errno = 0;
  assert(unread_marker() == KASLD_SYSCTL_UNREAD);

  /* Both are unknown to a reader asking only whether a value was observed. */
  assert(!kasld_hardening_known(KASLD_SYSCTL_DENIED));
  assert(!kasld_hardening_known(KASLD_SYSCTL_UNREAD));
}

/* An environment nobody took reads as unobserved, never as unhardened. Zeroed
 * storage would say the opposite in two fields at once -- SELINUX_PERMISSIVE
 * and LOCKDOWN_NONE are both 0 -- and "could not look" presented as "nothing
 * there" is the direction that licenses a wrong conclusion. */
static void test_environment_defaults_to_unknown(void) {
  const struct kasld_environment fresh = KASLD_ENV_UNKNOWN;

  assert(!kasld_hardening_known(fresh.hardening.kptr_restrict));
  assert(!kasld_hardening_known(fresh.hardening.dmesg_restrict));
  assert(!kasld_hardening_known(fresh.hardening.perf_event_paranoid));
  assert(!kasld_hardening_known(fresh.hardening.unprivileged_bpf_disabled));
  assert(!kasld_hardening_known(fresh.hardening.panic_on_oops));
  assert(!kasld_hardening_known(fresh.hardening.hashed_pointers));
  assert(fresh.hardening.lockdown == LOCKDOWN_UNAVAILABLE);
  /* -1 is a real setting for perf_event_paranoid ("unrestricted"), so the
   * unread marker must not be it -- otherwise the most permissive value the
   * kernel reports would be indistinguishable from never having looked. */
  assert(kasld_hardening_known(-1));

  assert(fresh.vantage.seccomp == -1);
  assert(fresh.vantage.no_new_privs == -1);
  assert(fresh.vantage.selinux == SELINUX_UNAVAILABLE);
  assert(fresh.vantage.ngroups == -1);
  assert(fresh.vantage.have_ids == 0);
  assert(fresh.vantage.have_caps == 0);
  assert(fresh.vantage.container == NULL);
  /* The two that would invert: an unobserved environment must not read as
   * MAC-free or as confined. */
  assert(!kasld_vantage_mac_enforcing(&fresh.vantage));
  assert(!kasld_vantage_confined(&fresh.vantage));
}

/* A membership longer than the report keeps is reported as truncated, not as a
 * short list: which groups are held is the point of the field, and a silently
 * dropped one is a gate the reader cannot account for. */
static void test_vantage_groups_over_cap(void) {
  struct kasld_vantage v;
  char body[1024];
  int n = snprintf(body, sizeof(body),
                   "Uid:\t0\t0\t0\t0\n"
                   "Gid:\t0\t0\t0\t0\n"
                   "Groups:\t");
  for (int i = 0; i < KASLD_N_GROUPS + 6; i++)
    n += snprintf(body + n, sizeof(body) - (size_t)n, "%d ", 100 + i);
  snprintf(body + n, sizeof(body) - (size_t)n, "\n");

  th_sysroot_clear();
  th_sysroot_write("/proc/self/status", body);
  kasld_gather_vantage(&v);
  assert(v.ngroups == KASLD_N_GROUPS);
  assert(v.groups_truncated == 1);
  assert(v.groups[0] == 100);
  assert(v.groups[KASLD_N_GROUPS - 1] ==
         (unsigned long)(100 + KASLD_N_GROUPS - 1));

  /* Exactly the cap is not truncation. */
  n = snprintf(body, sizeof(body),
               "Uid:\t0\t0\t0\t0\n"
               "Gid:\t0\t0\t0\t0\n"
               "Groups:\t");
  for (int i = 0; i < KASLD_N_GROUPS; i++)
    n += snprintf(body + n, sizeof(body) - (size_t)n, "%d ", 100 + i);
  snprintf(body + n, sizeof(body) - (size_t)n, "\n");

  th_sysroot_clear();
  th_sysroot_write("/proc/self/status", body);
  kasld_gather_vantage(&v);
  assert(v.ngroups == KASLD_N_GROUPS);
  assert(v.groups_truncated == 0);

  th_sysroot_clear();
}

static void test_vantage_mac_absent_then_present(void) {
  struct kasld_vantage v;

  /* Unreadable securityfs is UNKNOWN, never "no LSM": the list is unreachable
   * under some policies, and reporting that as unconfined would invert the
   * finding. */
  th_sysroot_clear();
  kasld_gather_vantage(&v);
  assert(v.lsm_list[0] == '\0');
  assert(v.sec_context[0] == '\0');
  assert(v.selinux == SELINUX_UNAVAILABLE);

  th_sysroot_clear();
  th_sysroot_write("/sys/kernel/security/lsm",
                   "lockdown,capability,yama,apparmor\n");
  th_sysroot_write("/proc/self/attr/current", "u:r:shell:s0\n");
  th_sysroot_write("/sys/fs/selinux/enforce", "1\n");
  kasld_gather_vantage(&v);
  assert(strcmp(v.lsm_list, "lockdown,capability,yama,apparmor") == 0);
  assert(strcmp(v.sec_context, "u:r:shell:s0") == 0);
  assert(v.selinux == SELINUX_ENFORCING);
  assert(kasld_vantage_mac_enforcing(&v));

  /* Present but permissive: readable, and not enforcing. A source that exists
   * and says "off" is a different answer from one that is missing. */
  th_sysroot_clear();
  th_sysroot_write("/sys/fs/selinux/enforce", "0\n");
  kasld_gather_vantage(&v);
  assert(v.selinux == SELINUX_PERMISSIVE);
  assert(!kasld_vantage_mac_enforcing(&v));

  th_sysroot_clear();
}

/* The oracle probes are the readable-source row of every report. Each is staged
 * on its own so a gatherer that filled the array from a single probe -- or off
 * by one against the table -- fails rather than averaging out.
 *
 * Staged by the path the gatherer resolved, not by the table's template: two
 * entries carry the kernel release, and a test staging the template would
 * probe one file and assert on another. */
static void test_vantage_oracle_readable_each_path(void) {
  struct kasld_vantage v;
  char probed[KASLD_N_ORACLES][KASLD_ORACLE_PATH_MAX];

  th_sysroot_clear();
  kasld_gather_vantage(&v);
  for (int i = 0; i < KASLD_N_ORACLES; i++)
    snprintf(probed[i], sizeof probed[i], "%s", v.oracle_path[i]);

  for (int i = 0; i < KASLD_N_ORACLES; i++) {
    th_sysroot_clear();
    th_sysroot_write(probed[i], "x\n");
    kasld_gather_vantage(&v);
    for (int j = 0; j < KASLD_N_ORACLES; j++)
      assert(v.oracle_readable[j] == (i == j));
  }

  /* All of them at once, so "exactly one readable" cannot be what passes. */
  th_sysroot_clear();
  for (int i = 0; i < KASLD_N_ORACLES; i++)
    th_sysroot_write(probed[i], "x\n");
  kasld_gather_vantage(&v);
  for (int i = 0; i < KASLD_N_ORACLES; i++)
    assert(v.oracle_readable[i] == 1);

  th_sysroot_clear();
}

/* A release-suffixed oracle is probed as the file it is, and the path the
 * report names is the one that was opened.
 *
 * The release is staged rather than taken from this host, so the assertion
 * cannot pass because the host's own release happens to appear. The staged
 * value collides with nothing: no real kernel is called this. */
static void test_vantage_oracle_release_suffixed_paths(void) {
  struct kasld_vantage v;
  const char *release = "9.9.9-kasld-test";
  struct kasld_environment saved = kasld_env;
  int checked = 0;
  char staged[KASLD_ORACLE_PATH_MAX];

  kasld_env.have_uts = 1;
  snprintf(kasld_env.uts.release, sizeof kasld_env.uts.release, "%s", release);

  th_sysroot_clear();
  kasld_gather_vantage(&v);
  for (int i = 0; i < KASLD_N_ORACLES; i++) {
    if (!kasld_oracles[i].release_suffixed) {
      /* An unsuffixed entry must not acquire the release. */
      assert(strstr(v.oracle_path[i], release) == NULL);
      assert(strcmp(v.oracle_path[i], kasld_oracles[i].path) == 0);
      continue;
    }
    snprintf(staged, sizeof staged, "%s%s", kasld_oracles[i].path, release);
    assert(strcmp(v.oracle_path[i], staged) == 0);
    checked++;

    /* Readable only when the suffixed file is the one staged: a gatherer
     * probing the bare template would read the wrong path. */
    th_sysroot_clear();
    th_sysroot_write(kasld_oracles[i].path, "x\n");
    kasld_gather_vantage(&v);
    assert(v.oracle_readable[i] == 0);

    th_sysroot_clear();
    th_sysroot_write(staged, "x\n");
    kasld_gather_vantage(&v);
    assert(v.oracle_readable[i] == 1);
  }
  assert(checked == 2);

  th_sysroot_clear();
  kasld_env = saved;
}

/* The removal half of the privilege-gaining environment guard. The detection
 * half is not exercisable here: this process gained no privilege at exec, and
 * making one that did needs a set-uid install.
 *
 * A synthetic prefix is used rather than the real KASLD_ one. Dropping that
 * prefix in-process would take the staged KASLD_SYSROOT with it and send every
 * later test to the live host — which is the hazard, not an inconvenience. */
static void test_env_drop_prefix_removes_only_the_prefix(void) {
  setenv("KASLDTEST_ALPHA", "1", 1);
  setenv("KASLDTEST_BETA", "2", 1);
  setenv("KASLDTESTNOUNDERSCORE", "keep", 1);
  setenv("PATH_KASLDTEST_MIDDLE", "keep", 1);

  assert(getenv("KASLDTEST_ALPHA") != NULL);
  assert(getenv("PATH") != NULL);

  kasld_env_drop_prefix("KASLDTEST_");

  /* Every name carrying the prefix goes, including one no read site knows
   * about — the property that keeps a variable added later covered. */
  assert(getenv("KASLDTEST_ALPHA") == NULL);
  assert(getenv("KASLDTEST_BETA") == NULL);

  /* A name merely beginning with the same letters, or carrying them in the
   * middle, is not the prefix and stays. */
  assert(getenv("KASLDTESTNOUNDERSCORE") != NULL);
  assert(getenv("PATH_KASLDTEST_MIDDLE") != NULL);

  /* Unrelated entries survive, the staged sysroot among them, and the block is
   * still a well-formed environment that setenv and getenv work over. */
  assert(getenv("PATH") != NULL);
  assert(getenv("KASLD_SYSROOT") != NULL);
  setenv("KASLDTEST_GAMMA", "3", 1);
  assert(getenv("KASLDTEST_GAMMA") != NULL);

  kasld_env_drop_prefix("KASLDTEST_");
  assert(getenv("KASLDTEST_GAMMA") == NULL);
  assert(getenv("KASLDTESTNOUNDERSCORE") != NULL);
}

/* An ordinary run must not lose its environment: the constructor has already
 * run by the time any test does, and it must have changed nothing. */
static void test_unprivileged_exec_keeps_its_environment(void) {
  assert(kasld_exec_gained_privilege() == 0);
  assert(getenv("PATH") != NULL);
  assert(getenv("KASLD_SYSROOT") != NULL);
}

int main(void) {
  th_sysroot_init("kasld");
  TEST_SUITE("test_kasld");
  test_init_layout_engine_bounds();

  BEGIN_CATEGORY("Result model");
  RUN(test_result_init_zeroes_everything);
  RUN(test_anchor_addr_base);
  RUN(test_anchor_addr_interior_sample);
  RUN(test_anchor_addr_null);
  RUN(test_synthesized_result_sets_fields_correctly);

  BEGIN_CATEGORY("Wire parser");
  RUN(test_parse_base_record);
  RUN(test_parse_interior_sample);
  RUN(test_parse_pos_extent);
  RUN(test_parse_extent_requires_both_edges);
  RUN(test_parse_named_record);
  RUN(test_parse_name_with_colons);
  RUN(test_parse_sz_normalizes_to_hi);
  RUN(test_parse_rejects_unknown_key);
  RUN(test_parse_rejects_missing_pos);
  RUN(test_parse_rejects_missing_conf);
  RUN(test_parse_rejects_pos_base_without_lo);
  RUN(test_parse_rejects_pos_top_without_hi);
  RUN(test_parse_rejects_lo_above_hi);
  RUN(test_parse_rejects_sample_outside_extent);
  RUN(test_parse_rejects_sz_overflow);
  RUN(test_parse_rejects_non_power_of_two_base_align);
  RUN(test_parse_accepts_power_of_two_base_align);
  RUN(test_parse_genuine_zero_lo);
  RUN(test_parse_key_order_independent);
  RUN(test_parse_sz_before_lo_normalizes);

  BEGIN_CATEGORY("Emit-helper round-trip");
  RUN(test_roundtrip_base);
  RUN(test_roundtrip_range);
  RUN(test_roundtrip_top);
  RUN(test_roundtrip_sample);
  RUN(test_roundtrip_sized);
  RUN(test_disposition_capture);
  RUN(test_disposition_rejects_malformed);
  RUN(test_helpers_reject_conf_unknown);

  BEGIN_CATEGORY("result_in_bounds");
  RUN(test_result_in_bounds_rejects_region_unknown);
  RUN(test_result_in_bounds_open_vas_accepts_anything);
  RUN(test_result_in_bounds_no_set_bits_passes);
  RUN(test_result_in_bounds_layout_sensitive);
  RUN(test_result_in_bounds_accepts_phys_kernel_image);
  RUN(test_page_offset_in_bounds_independent_of_runtime_layout);

  BEGIN_CATEGORY("select_anchor");
  RUN(test_select_anchor_prefers_no_name);
  RUN(test_select_anchor_falls_back_to_named);
  RUN(test_select_anchor_returns_null_on_miss);
  RUN(test_select_anchor_skips_out_of_bounds);

  BEGIN_CATEGORY("Merge pass");
  RUN(test_merge_collapses_same_key);
  RUN(test_merge_keeps_conflicting_records);
  RUN(test_merge_does_not_cross_types);
  RUN(test_merge_keeps_sample_outside_extent_separate);
  RUN(test_merge_sample_inside_extent_collapses);
  RUN(test_merge_keeps_lo_only_witnesses_separate);
  RUN(test_merge_keeps_sample_above_hi_separate);
  RUN(test_merge_picks_highest_conf_sample);
  RUN(test_merge_promotes_pos_to_base_from_later_contributor);
  RUN(test_merge_samples_conflict_kept_separate);
  RUN(test_merge_weaker_tightening_edge_kept_separate);
  RUN(test_merge_weaker_agreeing_still_merges);
  RUN(test_merge_dedups_provenance);
  RUN(test_merge_keeps_all_contributors);
  RUN(test_merge_is_idempotent);
  RUN(test_merge_is_capture_order_independent);
  RUN(test_merge_base_align_takes_max);
  RUN(test_merge_base_align_propagates_from_either_contributor);
  RUN(test_phys_virt_linkage_stays_two_records);

  BEGIN_CATEGORY("Confidence & ilog2");
  RUN(test_conf_weight_ordering);
  RUN(test_ilog2_power_of_two);
  RUN(test_ilog2_zero);
  RUN(test_ilog2_non_power_of_two_rounds_up);

  BEGIN_CATEGORY("Region info");
  RUN(test_is_phys_dram_region_includes_ram_landmarks);
  RUN(test_is_phys_dram_region_includes_kernel_image);
  RUN(test_is_phys_dram_region_excludes_non_dram);
  RUN(test_region_info_table_completeness);
  RUN(test_region_info_static_vas_or_derive_vas_set);

  BEGIN_CATEGORY("compute_kaslr_info");
  RUN(test_compute_kaslr_info_uses_kernel_image_anchor);
  RUN(test_compute_kaslr_info_engine_pin_overrides_raw_anchor);
  RUN(test_compute_kaslr_info_likely_window_reaches_the_model);
  RUN(test_compute_kaslr_info_directmap_base_follows_likely);
  RUN(test_compute_kaslr_info_falls_back_to_kernel_text);
  RUN(test_compute_kaslr_info_no_anchors_yields_zero_vtext);
#if !TEXT_TRACKS_DIRECTMAP
  RUN(test_compute_kaslr_info_sets_decoupled_note);
  RUN(test_compute_kaslr_info_no_note_when_vtext_present);
  RUN(test_compute_kaslr_info_no_note_without_phys_landmark);
#endif

  BEGIN_CATEGORY("Progress bar");
  RUN(test_progress_paint_no_stale_tail);
  RUN(test_progress_inflight_balances);

  BEGIN_CATEGORY("engine_sync_authoritative");
  RUN(test_engine_sync_projects_all_fields);
  RUN(test_vantage_container_absent_then_present);
  RUN(test_vantage_container_precedence);
  RUN(test_vantage_status_fields_absent_then_present);
  RUN(test_vantage_identity_is_staged_not_live);
  RUN(test_vantage_groups_over_cap);
  RUN(test_vantage_group_names);
  RUN(test_unread_marker_separates_denial_from_absence);
  RUN(test_environment_defaults_to_unknown);
  RUN(test_env_drop_prefix_removes_only_the_prefix);
  RUN(test_unprivileged_exec_keeps_its_environment);
  RUN(test_vantage_mac_absent_then_present);
  RUN(test_vantage_oracle_readable_each_path);
  RUN(test_vantage_oracle_release_suffixed_paths);
  RUN(test_discard_ledger_aggregates_and_reports_truncation);
  RUN(test_discard_project_engine_classifies_correctly);
  RUN(test_discard_project_engine_conflict_without_constraint);
  RUN(test_engine_sync_projects_slot_counts);
  RUN(test_engine_sync_selects_directmap_base_by_level);
  RUN(test_engine_sync_anchors_module_band_to_observations);
  RUN(test_engine_sync_module_band_rejects_out_of_union);
  RUN(test_engine_sync_module_band_never_degenerate);
  RUN(test_engine_sync_module_band_follows_page_offset);

  th_sysroot_fini();
  return TEST_DONE();
}
