// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Unit tests for the orchestrator internals: the result model (parser, merge
// pass, select_anchor, result_in_bounds), compute_kaslr_info, the
// engine->layout projection (engine_sync_authoritative), region_info, and the
// renderers. Compiled via `make check`, which includes orchestrator.c,
// region_info.c, render.c, and each src/render/*.c with -DKASLD_TESTING so the
// renderer's static helpers (json_print_escaped, render_summary,
// section_consensus, etc.) are reachable as a single TU. main() and the live
// engine run are compiled out.
// ---
// <bcoles@gmail.com>

#define _POSIX_C_SOURCE 200809L
#ifndef KASLD_TESTING
#define KASLD_TESTING /* Makefile passes -DKASLD_TESTING; this is the          \
                         fallback. */
#endif

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

/* =========================================================================
 * Helpers
 * ========================================================================= */

static int parse_line(const char *line, const char *method,
                      const char *origin) {
  return capture_result(line, method, origin);
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
  assert(r.provenance_count == 0);
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
  assert(r->provenance_count == 1);
  assert(strcmp(r->origins[0], "proc-iomem") == 0);
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
  base->provenance_count = 1;
  snprintf(base->origins[0], ORIGIN_LEN, "proc-iomem");

  struct result *top = push_result();
  top->type = KASLD_TYPE_PHYS;
  top->region = REGION_INITRD;
  top->pos = POS_TOP;
  top->conf = CONF_PARSED;
  top->hi = 0x333fffff;
  top->set_mask = HI_SET;
  top->provenance_count = 1;
  snprintf(top->origins[0], ORIGIN_LEN, "dmesg");

  merge_results();
  assert(num_results == 1);
  struct result *r = &results[0];
  assert(HAS_LO(r) && HAS_HI(r));
  assert(r->lo == 0x33000000ul && r->hi == 0x333ffffful);
  assert(r->provenance_count == 2);
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
  a->provenance_count = 1;
  snprintf(a->origins[0], ORIGIN_LEN, "source-a");

  struct result *b = push_result();
  b->type = KASLD_TYPE_PHYS;
  b->region = REGION_INITRD;
  b->pos = POS_BASE;
  b->conf = CONF_PARSED;
  b->lo = 0x500000;
  b->hi = 0x5fffff;
  b->set_mask = LO_SET | HI_SET;
  b->provenance_count = 1;
  snprintf(b->origins[0], ORIGIN_LEN, "source-b");

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
  a->provenance_count = 1;
  snprintf(a->origins[0], ORIGIN_LEN, "source-a");

  struct result *b = push_result();
  b->type = KASLD_TYPE_VIRT;
  b->region = REGION_DIRECTMAP;
  b->pos = POS_BASE;
  b->conf = CONF_PARSED;
  b->lo = (unsigned long)PAGE_OFFSET + 0x10000000ul;
  b->set_mask = LO_SET;
  b->provenance_count = 1;
  snprintf(b->origins[0], ORIGIN_LEN, "source-b");

  merge_results();
  assert(num_results == 2);
  /* Origin attribution is preserved (no cross-witness merging). */
  assert(strcmp(results[0].origins[0], "source-a") == 0);
  assert(strcmp(results[1].origins[0], "source-b") == 0);
}

static void test_merge_picks_highest_conf_sample(void) {
  reset_results();
  /* Same-key contributors where only one has SAMPLE_SET: the sample
   * survives, the other contributes nothing sample-wise. */
  struct result *no_sample = push_result();
  no_sample->type = KASLD_TYPE_VIRT;
  no_sample->region = REGION_KERNEL_IMAGE;
  no_sample->pos = POS_BASE;
  no_sample->conf = CONF_HEURISTIC;
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

  struct result *base = push_result();
  base->type = KASLD_TYPE_VIRT;
  base->region = REGION_KERNEL_IMAGE;
  base->pos = POS_BASE;
  base->conf = CONF_TIMING;
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
  compute_kaslr_info(&s);
  assert(s.kaslr.vtext == layout.virt_kaslr_text_min + layout.virt_kaslr_align);
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
  compute_kaslr_info(&s);
  assert(s.kaslr.vtext ==
         layout.virt_kaslr_text_min + 2 * layout.virt_kaslr_align);
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
  assert(capture_result(buf, "parsed", "test") == 1);
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
  assert(capture_result(buf, "parsed", "test") == 1);
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
  assert(capture_result(buf, "parsed", "test") == 1);
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
  assert(capture_result(buf, "heuristic", "test") == 1);
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
  assert(capture_result(buf, "parsed", "test") == 1);
  struct result *r = &results[0];
  assert(HAS_LO(r) && HAS_HI(r));
  assert(r->lo == 0x100000ul);
  assert(r->hi == 0x10ffffu); /* lo + sz - 1 */
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
    r->provenance_count = 1;
    snprintf(r->origins[0], ORIGIN_LEN, "%s", i == 1 ? "src-b" : "src-a");
    r->method_set = 1u << KM_HEURISTIC;
  }
  merge_results();
  assert(num_results == 1);
  struct result *r = &results[0];
  /* "src-a" appears twice in the contributors but only once in the merged
   * origin list. */
  assert(r->provenance_count == 2);
  int seen_a = 0, seen_b = 0;
  for (int i = 0; i < r->provenance_count; i++) {
    if (strcmp(r->origins[i], "src-a") == 0)
      seen_a++;
    if (strcmp(r->origins[i], "src-b") == 0)
      seen_b++;
  }
  assert(seen_a == 1 && seen_b == 1);
}

static void test_merge_keeps_all_contributors(void) {
  reset_results();
  /* Many distinct-origin contributors at the same lo. Provenance is sized to
   * the structural max (MAX_COMPONENTS), so the merged record keeps every one:
   * the cap can no longer bind at any realistic contributor count (here well
   * above the old cap of 8, well under MAX_COMPONENTS). */
  const int n = 40;
  for (int i = 0; i < n; i++) {
    struct result *r = push_result();
    r->type = KASLD_TYPE_VIRT;
    r->region = REGION_KERNEL_IMAGE;
    r->pos = POS_BASE;
    r->conf = CONF_HEURISTIC;
    r->lo = FX_TEXT; /* same lo so lo_only_conflict permits merge */
    r->set_mask = LO_SET;
    r->provenance_count = 1;
    snprintf(r->origins[0], ORIGIN_LEN, "src-%d", i);
  }
  merge_results();

  assert(num_results == 1);
  assert(results[0].provenance_count == n); /* all kept, none truncated */
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
  snprintf(r->origins[0], ORIGIN_LEN, "inference:my_plugin");
  r->method_set = 1u << KM_DERIVED;
  r->provenance_count = 1;

  /* Round-trip through result_in_bounds and select_anchor. */
  assert(result_in_bounds(r, &layout) == 1);
  const struct result *picked = select_anchor(KASLD_TYPE_VIRT, REGION_INITRD);
  assert(picked == r);
  /* set_mask correctly reflects what was set. */
  assert(HAS_LO(picked) && HAS_HI(picked));
  assert(!HAS_SAMPLE(picked) && !HAS_BASE_ALIGN(picked));
}

/* =========================================================================
 * compute_kaslr_info: derive_*_anchor terminal case and all-NULL
 * ========================================================================= */
#ifdef DATA_OFFSET
static void test_compute_kaslr_info_derives_from_kernel_data(void) {
  reset_results();
  /* No KERNEL_IMAGE or KERNEL_TEXT anchor — only KERNEL_DATA with HAS_LO.
   * derive_vtext_from_data must fire. */
  struct result *r = push_result();
  r->type = KASLD_TYPE_VIRT;
  r->region = REGION_KERNEL_DATA;
  r->pos = POS_BASE;
  r->conf = CONF_PARSED;
  unsigned long sdata = layout.virt_kaslr_text_min +
                        (unsigned long)DATA_OFFSET + layout.virt_kaslr_align;
  r->lo = sdata;
  r->set_mask = LO_SET;

  struct summary s = {0};
  compute_kaslr_info(&s);
  assert(s.kaslr.vtext == sdata - (unsigned long)DATA_OFFSET);
}
#endif

static void test_compute_kaslr_info_no_anchors_yields_zero_vtext(void) {
  reset_results();
  struct summary s = {0};
  compute_kaslr_info(&s);
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
  assert(!is_phys_dram_region(REGION_MODULE_REGION));
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
    r->provenance_count = 1;
    snprintf(r->origins[0], ORIGIN_LEN, "src-%d", i);
  }
  merge_results();
  assert(num_results == 1);
  unsigned long lo_after_first = results[0].lo;
  uint32_t mask_after_first = results[0].set_mask;
  uint8_t prov_after_first = results[0].provenance_count;

  /* Run again — must be a no-op. */
  merge_results();
  assert(num_results == 1);
  assert(results[0].lo == lo_after_first);
  assert(results[0].set_mask == mask_after_first);
  assert(results[0].provenance_count == prov_after_first);
}

/* =========================================================================
 * Parser: key order is irrelevant
 *
 * Spec rule: tail keys may appear in any order. The two-stage parser
 * collects all keys before sz→hi normalisation, so `sz` before `lo` must
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
   * collect both keys before normalising. */
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
  compute_kaslr_info(&s);
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
  compute_kaslr_info(&s);
  assert(s.kaslr.vtext != 0);
  assert(s.decoupled_note == 0);
}

static void test_compute_kaslr_info_no_note_without_phys_landmark(void) {
  reset_results();
  /* No phys leaks at all — note shouldn't fire (there's nothing to
   * explain). */
  struct summary s = {0};
  compute_kaslr_info(&s);
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
 * Crucially pins kaslr_base_* == kernel_base_* == Q_VIRT_TEXT_BASE: those must
 * stay equal post-resolution (the "kernel text" band vs the reported "Inferred
 * text range"), which is the exact invariant the original bug violated. */
static void test_engine_sync_projects_all_fields(void) {
  struct engine e;
  memset(&e, 0, sizeof(e));

  /* Synthetic resolved windows — distinct, recognisable values per quantity so
   * a mis-wired field (writing the wrong source) is caught, not just a missing
   * write. */
  e.est[Q_VIRT_TEXT_BASE].lo = FX_TEXT;
  e.est[Q_VIRT_TEXT_BASE].hi = (FX_TEXT + 0x0e000000ul);
  e.est[Q_KASLR_ALIGN].lo = 0x200000ul;
  e.est[Q_PAGE_OFFSET].lo = (unsigned long)PAGE_OFFSET + 0x10000000ul;
  e.est[Q_PAGE_OFFSET].hi = (unsigned long)PAGE_OFFSET + 0x30000000ul;
  e.est[Q_PHYS_TEXT_BASE].lo = 0x4000000ul;
  e.est[Q_PHYS_TEXT_BASE].hi = 0x3c000000ul;
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
  layout.virt_kernel_text_min = layout.virt_kernel_text_max = 0;
  layout.virt_kaslr_align = 0;
  layout.virt_page_offset_min = layout.virt_page_offset_max = 0;
  layout.virt_vmalloc_base_min = layout.virt_vmalloc_base_max = 0;
  layout.virt_vmemmap_base_min = layout.virt_vmemmap_base_max = 0;

  engine_sync_authoritative(&e);

  /* Virtual text window projects onto BOTH the KASLR window and the kernel
   * image-placement range, and they must be identical (the renderer bug). */
  assert(layout.virt_kaslr_text_min == FX_TEXT);
  assert(layout.virt_kaslr_text_max == (FX_TEXT + 0x0e000000ul));
  assert(layout.virt_kernel_text_min == layout.virt_kaslr_text_min);
  assert(layout.virt_kernel_text_max == layout.virt_kaslr_text_max);
  assert(layout.virt_kaslr_align == 0x200000ul);

  assert(layout.virt_page_offset_min ==
         (unsigned long)PAGE_OFFSET + 0x10000000ul);
  assert(layout.virt_page_offset_max ==
         (unsigned long)PAGE_OFFSET + 0x30000000ul);

  assert(layout.virt_vmalloc_base_min ==
         (unsigned long)PAGE_OFFSET + 0x11000000ul);
  assert(layout.virt_vmalloc_base_max ==
         (unsigned long)PAGE_OFFSET + 0x12000000ul);
  assert(layout.virt_vmemmap_base_min ==
         (unsigned long)PAGE_OFFSET + 0x13000000ul);
  assert(layout.virt_vmemmap_base_max ==
         (unsigned long)PAGE_OFFSET + 0x14000000ul);

#if !TEXT_TRACKS_DIRECTMAP
  /* Direct-map base moves to the proven lower bound (we set lo > PAGE_OFFSET),
   * but the VAS floor must NOT (only layout.virt_page_offset, never
   * virt_kernel_vas_start — the second renderer bug). */
  assert(layout.virt_page_offset == (unsigned long)PAGE_OFFSET + 0x10000000ul);
  assert(layout.phys_kaslr_text_min == 0x4000000ul);
  assert(layout.phys_kaslr_text_max == 0x3c000000ul);
  assert(layout.phys_kaslr_align == 0x200000ul);
#endif
  assert(layout.virt_kernel_vas_start == vas_floor_before);
}

/* engine_sync_authoritative tightens layout.modules_start/end from observed
 * VIRT/REGION_MODULE_REGION addresses (when inside the validation union),
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
  o1.eff_region = REGION_MODULE_REGION;
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
  e.est[Q_VIRT_TEXT_BASE].lo = layout.virt_kaslr_text_min;
  e.est[Q_VIRT_TEXT_BASE].hi = layout.virt_kaslr_text_max;

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
  o.eff_region = REGION_MODULE_REGION;
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

  e.est[Q_VIRT_TEXT_BASE].lo = layout.virt_kaslr_text_min;
  e.est[Q_VIRT_TEXT_BASE].hi = layout.virt_kaslr_text_max;

  layout.modules_start = MODULES_START;
  layout.modules_end = MODULES_END;

  engine_sync_authoritative(&e);

  /* The bogus sample is not adopted, and the band stays well-ordered. */
  assert(layout.modules_start != oob);
  assert(layout.modules_end != oob);
  assert(layout.modules_start <= layout.modules_end);
}
int main(void) {
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
  RUN(test_merge_dedups_provenance);
  RUN(test_merge_keeps_all_contributors);
  RUN(test_merge_is_idempotent);
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
  RUN(test_compute_kaslr_info_falls_back_to_kernel_text);
  RUN(test_compute_kaslr_info_no_anchors_yields_zero_vtext);
#ifdef DATA_OFFSET
  RUN(test_compute_kaslr_info_derives_from_kernel_data);
#endif
#if !TEXT_TRACKS_DIRECTMAP
  RUN(test_compute_kaslr_info_sets_decoupled_note);
  RUN(test_compute_kaslr_info_no_note_when_vtext_present);
  RUN(test_compute_kaslr_info_no_note_without_phys_landmark);
#endif

  BEGIN_CATEGORY("engine_sync_authoritative");
  RUN(test_engine_sync_projects_all_fields);
  RUN(test_engine_sync_anchors_module_band_to_observations);
  RUN(test_engine_sync_module_band_rejects_out_of_union);

  return TEST_DONE();
}
