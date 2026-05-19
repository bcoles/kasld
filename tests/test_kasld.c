// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Unit tests for the new result model: parser, merge pass, select_anchor,
// result_in_bounds, helpers. Compiled via `make test`, which includes
// orchestrator.c with -DKASLD_TESTING so static helpers are accessible.
// ---
// <bcoles@gmail.com>

#define _POSIX_C_SOURCE 200809L
#define KASLD_TESTING

#include "../src/orchestrator.c"
#include "../src/region_info.c"
#include "../src/render.c"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static int test_count;
static int pass_count;

#define RUN(t)                                                                 \
  do {                                                                         \
    test_count++;                                                              \
    fprintf(stderr, "[run ] %s\n", #t);                                        \
    t();                                                                       \
    pass_count++;                                                              \
    fprintf(stderr, "[ ok ] %s\n", #t);                                        \
  } while (0)

/* =========================================================================
 * Helpers
 * ========================================================================= */
static void reset_results(void) {
  num_results = 0;
  for (int i = 0; i < MAX_RESULTS; i++)
    result_init(&results[i]);
}

static struct result *push_result(void) {
  struct result *r = &results[num_results++];
  result_init(r);
  return r;
}

static int parse_line(const char *line, const char *method,
                      const char *origin) {
  return capture_result(line, method, origin);
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
  assert(parse_line("V vmalloc pos=interior conf=heuristic "
                    "sample=0xffffc90000123456",
                    "heuristic", "comp") == 1);
  struct result *r = &results[0];
  assert(r->type == KASLD_TYPE_VIRT);
  assert(r->region == REGION_VMALLOC);
  assert(r->pos == POS_INTERIOR);
  assert(HAS_SAMPLE(r) && !HAS_LO(r) && !HAS_HI(r));
  assert(r->sample == 0xffffc90000123456ul);
}

static void test_parse_named_record(void) {
  reset_results();
  assert(parse_line("V kernel_image:commit_creds pos=interior conf=parsed "
                    "sample=0xffffffff81234000",
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
  assert(parse_line("V kernel_text pos=base conf=parsed lo=0xffffffff81000000 "
                    "bogus=0x1",
                    NULL, NULL) == 0);
  assert(num_results == 0);
}

static void test_parse_rejects_missing_pos(void) {
  reset_results();
  assert(parse_line("V kernel_text conf=parsed lo=0xffffffff81000000", NULL,
                    NULL) == 0);
}

static void test_parse_rejects_missing_conf(void) {
  reset_results();
  assert(parse_line("V kernel_text pos=base lo=0xffffffff81000000", NULL,
                    NULL) == 0);
}

static void test_parse_rejects_pos_base_without_lo(void) {
  reset_results();
  assert(
      parse_line("V kernel_text pos=base conf=parsed sample=0xffffffff81234000",
                 NULL, NULL) == 0);
}

static void test_parse_rejects_pos_top_without_hi(void) {
  reset_results();
  assert(parse_line("P ram pos=top conf=parsed lo=0x1000", NULL, NULL) == 0);
}

static void test_parse_rejects_lo_above_hi(void) {
  reset_results();
  assert(parse_line("V kernel_text pos=base conf=parsed lo=0xffffffff90000000 "
                    "hi=0xffffffff80000000",
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
  assert(parse_line("P ram pos=base conf=parsed lo=0xffffffffffffffff sz=0x2",
                    NULL, NULL) == 0);
}

static void test_parse_rejects_non_power_of_two_base_align(void) {
  reset_results();
  assert(parse_line("V kernel_text pos=base conf=parsed lo=0xffffffff81000000 "
                    "base_align=0x3",
                    NULL, NULL) == 0);
}

static void test_parse_accepts_power_of_two_base_align(void) {
  reset_results();
  assert(parse_line("V kernel_text pos=base conf=parsed lo=0xffffffff81000000 "
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
  named->sample = 0xffffffff81234000ul;
  named->set_mask = SAMPLE_SET;

  struct result *anchor = push_result();
  anchor->type = KASLD_TYPE_VIRT;
  anchor->region = REGION_KERNEL_IMAGE;
  anchor->pos = POS_BASE;
  anchor->conf = CONF_HEURISTIC;
  anchor->lo = 0xffffffff81000000ul;
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
  named->sample = 0xffffffff81234000ul;
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
  v->lo = 0xffff888033000000ul;
  v->set_mask = LO_SET;

  merge_results();
  assert(num_results == 2);
}

static void test_merge_sample_clamped_to_extent(void) {
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
  b->sample = 0x500;
  b->set_mask = SAMPLE_SET;

  merge_results();
  assert(num_results == 1);
  struct result *r = &results[0];
  assert(HAS_SAMPLE(r));
  assert(r->sample == 0x1000);
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
  no_sample->lo = 0xffffffff81000000ul;
  no_sample->set_mask = LO_SET;

  struct result *sample = push_result();
  sample->type = KASLD_TYPE_VIRT;
  sample->region = REGION_KERNEL_IMAGE;
  sample->pos = POS_INTERIOR;
  sample->conf = CONF_PARSED;
  sample->sample = 0xffffffff81222222ul;
  sample->set_mask = SAMPLE_SET;

  merge_results();
  assert(num_results == 1);
  struct result *r = &results[0];
  assert(HAS_LO(r) && r->lo == 0xffffffff81000000ul);
  assert(HAS_SAMPLE(r) && r->sample == 0xffffffff81222222ul);
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
 * Adjust for page offset
 * ========================================================================= */
static void test_adjust_noop(void) {
  unsigned long saved = layout.page_offset;
  adjust_for_page_offset(layout.page_offset);
  assert(layout.page_offset == saved);
}

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
  r->lo = layout.kaslr_base_min + layout.kaslr_align;
  r->set_mask = LO_SET;

  struct summary s = {0};
  compute_kaslr_info(&s);
  assert(s.kaslr.vtext == layout.kaslr_base_min + layout.kaslr_align);
}

static void test_compute_kaslr_info_falls_back_to_kernel_text(void) {
  reset_results();
  struct result *r = push_result();
  r->type = KASLD_TYPE_VIRT;
  r->region = REGION_KERNEL_TEXT;
  r->pos = POS_BASE;
  r->conf = CONF_PARSED;
  r->lo = layout.kaslr_base_min + 2 * layout.kaslr_align;
  r->set_mask = LO_SET;

  struct summary s = {0};
  compute_kaslr_info(&s);
  assert(s.kaslr.vtext == layout.kaslr_base_min + 2 * layout.kaslr_align);
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
  return kasld_result_base(KASLD_TYPE_VIRT, REGION_KERNEL_TEXT,
                           0xffffffff81000000ul, "test_sym", CONF_PARSED);
}
static int emit_range_helper(void) {
  return kasld_result_range(KASLD_TYPE_PHYS, REGION_INITRD, 0x33000000ul,
                            0x333ffffful, NULL, CONF_PARSED);
}
static int emit_top_helper(void) {
  return kasld_result_top(KASLD_TYPE_PHYS, REGION_RAM, 0x100000000ul, NULL,
                          CONF_PARSED);
}
static int emit_sample_helper(void) {
  return kasld_result_sample(KASLD_TYPE_VIRT, REGION_VMALLOC,
                             0xffffc90000123456ul, NULL, CONF_HEURISTIC);
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
  assert(HAS_LO(r) && r->lo == 0xffffffff81000000ul);
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
  assert(r->hi == 0x100000000ul);
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
  assert(HAS_SAMPLE(r) && r->sample == 0xffffc90000123456ul);
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
  return kasld_result_base(KASLD_TYPE_VIRT, REGION_KERNEL_TEXT,
                           0xffffffff81000000ul, NULL, CONF_UNKNOWN);
}
static int emit_with_conf_unknown_sample(void) {
  return kasld_result_sample(KASLD_TYPE_PHYS, REGION_RAM, 0x1000, NULL,
                             CONF_UNKNOWN);
}

static int emit_with_invalid_type(void) {
  return kasld_result_base(KASLD_TYPE_UNKNOWN, REGION_KERNEL_TEXT,
                           0xffffffff81000000ul, NULL, CONF_PARSED);
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
 * Provenance dedup + MAX_PROVENANCE truncation
 * ========================================================================= */
static void test_merge_dedups_provenance(void) {
  reset_results();
  /* Three base contributors with consistent lo values (so they merge) but
   * one origin duplicated. After merge the duplicate origin must appear
   * only once. Use HAS_LO records (not HAS_SAMPLE) so samples_conflict
   * doesn't prevent merging. */
  for (int i = 0; i < 3; i++) {
    struct result *r = push_result();
    r->type = KASLD_TYPE_VIRT;
    r->region = REGION_KERNEL_IMAGE;
    r->pos = POS_BASE;
    r->conf = CONF_HEURISTIC;
    r->lo = 0xffffffff81000000ul + i * 0x10;
    r->set_mask = LO_SET;
    r->provenance_count = 1;
    snprintf(r->origins[0], ORIGIN_LEN, "%s", i == 1 ? "src-b" : "src-a");
    snprintf(r->methods[0], METHOD_LEN, "heuristic");
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

static void test_merge_caps_at_max_provenance(void) {
  reset_results();
  /* MAX_PROVENANCE + 2 contributors with distinct origins. Merge must keep
   * the first MAX_PROVENANCE and drop the rest. */
  int saved = dup(fileno(stderr));
  FILE *devnull = fopen("/dev/null", "w");
  dup2(fileno(devnull), fileno(stderr));

  for (int i = 0; i < MAX_PROVENANCE + 2; i++) {
    struct result *r = push_result();
    r->type = KASLD_TYPE_VIRT;
    r->region = REGION_KERNEL_IMAGE;
    r->pos = POS_BASE;
    r->conf = CONF_HEURISTIC;
    r->lo = 0xffffffff81000000ul + i * 0x10;
    r->set_mask = LO_SET;
    r->provenance_count = 1;
    snprintf(r->origins[0], ORIGIN_LEN, "src-%d", i);
  }
  merge_results();

  dup2(saved, fileno(stderr));
  close(saved);
  fclose(devnull);

  assert(num_results == 1);
  assert(results[0].provenance_count == MAX_PROVENANCE);
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

  /* V initrd extent derived via phys_to_virt — same region+name, different
   * type. */
  struct result *v = push_result();
  v->type = KASLD_TYPE_VIRT;
  v->region = REGION_INITRD;
  v->pos = POS_BASE;
  v->conf = CONF_DERIVED;
  v->lo = 0xffff888033000000ul;
  v->hi = 0xffff8880333ffffful;
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
   * (compile-time constants), NOT layout.kernel_vas_start — using the
   * runtime layout would create a circular dependency where a page_offset
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
  r.lo =
      (unsigned long)PAGE_OFFSET; /* arch-default page_offset is always valid */
  r.set_mask = LO_SET;
  assert(result_in_bounds(&r, &layout) == 1);
}

/* =========================================================================
 * Synthesized result: inference plugin constructs via result_init()
 * ========================================================================= */
static void test_synthesized_result_sets_fields_correctly(void) {
  reset_results();
  /* Simulate what a derived-result-emitting inference plugin does. */
  struct result *r = &results[num_results++];
  result_init(r);
  r->type = KASLD_TYPE_VIRT;
  r->region = REGION_INITRD;
  /* name stays "" — canonical region anchor */
  r->pos = POS_BASE;
  r->conf = CONF_DERIVED;
  r->lo = 0xffff888033000000ul;
  r->hi = 0xffff8880333ffffful;
  r->set_mask = LO_SET | HI_SET;
  snprintf(r->origins[0], ORIGIN_LEN, "inference:my_plugin");
  snprintf(r->methods[0], METHOD_LEN, "derived");
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
  unsigned long sdata =
      layout.kaslr_base_min + (unsigned long)DATA_OFFSET + layout.kaslr_align;
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
 * Inference plugin integration: structured-input test
 * ========================================================================= */
static void test_inference_phase_runs_against_structured_input(void) {
  /* Set up a minimal scenario and run the POST_COLLECTION inference phase.
   * The goal is to exercise the inference-phase machinery against new-model
   * results without depending on any single plugin's specific output (which
   * varies per arch). We just verify the phase runs without crashing and
   * doesn't widen the bounds. */
  reset_results();
  struct result *r = push_result();
  r->type = KASLD_TYPE_PHYS;
  r->region = REGION_RAM;
  r->pos = POS_TOP;
  r->conf = CONF_PARSED;
  r->hi = 0x100000000ul;
  r->set_mask = HI_SET;

  /* Snapshot the bounds before. */
  unsigned long text_min_before = g_ctx.text_base_min;
  unsigned long text_max_before = g_ctx.text_base_max;

  /* run_inference_phase iterates all registered plugins for the phase.
   * Plugins may tighten ctx bounds; they must not widen. */
  run_inference_phase(&g_ctx, KASLD_INFER_PHASE_POST_COLLECTION);

  assert(g_ctx.text_base_min >= text_min_before);
  assert(g_ctx.text_base_max <= text_max_before);
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
   * DRAM. The regression that triggered the page_offset-derivation hunt
   * was caused by this predicate excluding kernel_image regions. */
  assert(is_phys_dram_region(REGION_KERNEL_TEXT));
  assert(is_phys_dram_region(REGION_KERNEL_DATA));
  assert(is_phys_dram_region(REGION_KERNEL_BSS));
  assert(is_phys_dram_region(REGION_KERNEL_IMAGE));
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
 * was needed to derive page_offset via phys_virt_synth.
 * ========================================================================= */
static void test_result_in_bounds_accepts_phys_kernel_image(void) {
  struct result r;
  result_init(&r);
  r.type = KASLD_TYPE_PHYS;
  /* A physical kernel-image leak at ~4.4 GiB (typical kernel load
   * address on a system with phys KASLR). */
  r.sample = 0x119446000ul;
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
 * against the runtime layout.kernel_vas_start creates a circular
 * dependency where a page_offset record gets rejected because earlier
 * inference (based on different records) tightened the bound above it.
 * Verify the check is layout-independent.
 * ========================================================================= */
static void test_page_offset_in_bounds_independent_of_runtime_layout(void) {
  struct result r;
  result_init(&r);
  r.type = KASLD_TYPE_VIRT;
  r.region = REGION_PAGE_OFFSET;
  /* A page_offset value at the arch floor. */
  r.lo = (unsigned long)PAGE_OFFSET;
  r.set_mask = LO_SET;

  /* Default layout: accepts. */
  assert(result_in_bounds(&r, &layout) == 1);

  /* Construct a synthetic layout with kernel_vas_start TIGHTENED far
   * above the record. If derive_vas_page_offset read layout.kernel_vas_start,
   * the record would be rejected. With arch-constant validation, it
   * stays accepted. */
  struct kasld_layout tight = layout;
  tight.kernel_vas_start = (unsigned long)PAGE_OFFSET + (1ul << 40);
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
  r->region =
      REGION_VMALLOC; /* has static_vas = {KERNEL_VAS_START, KERNEL_VAS_END} */
  r->pos = POS_BASE;
  r->conf = CONF_PARSED;
  r->lo = 0x1000; /* far below KERNEL_VAS_START */
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
static void test_merge_sample_clamped_to_hi(void) {
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
  assert(num_results == 1);
  struct result *r = &results[0];
  assert(HAS_SAMPLE(r));
  assert(r->sample == 0x1fff); /* clamped down to hi */
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
  /* Four contributors to a single (PHYS, RAM) record. */
  for (int i = 0; i < 4; i++) {
    struct result *r = push_result();
    r->type = KASLD_TYPE_PHYS;
    r->region = REGION_RAM;
    r->pos = POS_BASE;
    r->conf = CONF_PARSED;
    r->lo = 0x1000ul + i * 0x10;
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
  a->lo = 0xffffffff81000000ul;
  a->base_align = 0x1000; /* 4 KiB */
  a->set_mask = LO_SET | BASE_ALIGN_SET;

  struct result *b = push_result();
  b->type = KASLD_TYPE_VIRT;
  b->region = REGION_KERNEL_TEXT;
  b->pos = POS_BASE;
  b->conf = CONF_PARSED;
  b->lo = 0xffffffff81000000ul;
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
  a->lo = 0xffffffff81000000ul;
  a->set_mask = LO_SET;

  struct result *b = push_result();
  b->type = KASLD_TYPE_VIRT;
  b->region = REGION_KERNEL_TEXT;
  b->pos = POS_BASE;
  b->conf = CONF_PARSED;
  b->lo = 0xffffffff81000000ul;
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
    /* wire_name in region_info must match the wire-token table in kasld.h. */
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
#if PHYS_VIRT_DECOUPLED
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
  v->lo = layout.kaslr_base_min + layout.kaslr_align;
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
#endif /* PHYS_VIRT_DECOUPLED */

/* =========================================================================
 * Convergence loop
 *
 * run_post_collection_inference() re-runs POST_COLLECTION until no bound
 * changes (capped at MAX_INFERENCE_PASSES). The change-detection itself
 * lives in snap_bounds() + bounds_changed(); if either misses a field, a
 * plugin that tightens it would not trigger a re-pass for plugins that
 * depend on that field. Both helpers are static — these tests catch
 * silent regressions where a new ctx field is added but the snapshot
 * isn't extended.
 * ========================================================================= */
static void test_bounds_snap_captures_all_tracked_fields(void) {
  struct bounds_snap snap;
  snap_bounds(&snap);
  assert(!bounds_changed(&snap));

  /* Mutate each tracked bound in turn; bounds_changed must flag every one.
   * Restoring after each check keeps the test independent of g_ctx state. */
#define CHECK_FIELD(field)                                                     \
  do {                                                                         \
    unsigned long _saved = g_ctx.field;                                        \
    g_ctx.field = _saved ^ 0x1ul;                                              \
    assert(bounds_changed(&snap));                                             \
    g_ctx.field = _saved;                                                      \
    assert(!bounds_changed(&snap));                                            \
  } while (0)

  CHECK_FIELD(text_base_min);
  CHECK_FIELD(text_base_max);
  CHECK_FIELD(page_offset_min);
  CHECK_FIELD(page_offset_max);
  CHECK_FIELD(phys_base_min);
  CHECK_FIELD(phys_base_max);
  CHECK_FIELD(vmalloc_base_min);
  CHECK_FIELD(vmalloc_base_max);
  CHECK_FIELD(vmemmap_base_min);
  CHECK_FIELD(vmemmap_base_max);
#undef CHECK_FIELD
}

static void test_bounds_changed_false_on_stable_snapshot(void) {
  /* Snapshot, do nothing, expect stable. The convergence loop relies on
   * this returning 0 to terminate. */
  struct bounds_snap snap;
  snap_bounds(&snap);
  assert(!bounds_changed(&snap));
  /* Re-snap immediately; still stable. */
  struct bounds_snap snap2;
  snap_bounds(&snap2);
  assert(!bounds_changed(&snap2));
}

static void test_post_collection_inference_converges(void) {
  /* End-to-end smoke: drive the full convergence loop with structured
   * input and assert it (a) terminates and (b) leaves bounds in the
   * tighten-only invariant. We don't depend on any specific plugin
   * tightening any specific bound — the assertion is the meta-invariant. */
  reset_results();

  /* Plant one record per kind that POST_COLLECTION plugins commonly read. */
  struct result *p = push_result();
  p->type = KASLD_TYPE_PHYS;
  p->region = REGION_RAM;
  p->pos = POS_BASE;
  p->conf = CONF_PARSED;
  p->lo = 0x100000ul;
  p->hi = 0x100000000ul;
  p->set_mask = LO_SET | HI_SET;
  snprintf(p->origins[0], ORIGIN_LEN, "test_converge");
  p->provenance_count = 1;

  struct bounds_snap before;
  snap_bounds(&before);

  unsigned long text_min_before = g_ctx.text_base_min;
  unsigned long text_max_before = g_ctx.text_base_max;
  unsigned long po_min_before = g_ctx.page_offset_min;
  unsigned long po_max_before = g_ctx.page_offset_max;
  unsigned long phys_min_before = g_ctx.phys_base_min;
  unsigned long phys_max_before = g_ctx.phys_base_max;

  /* Drive the full loop. If the convergence guard or the change detector
   * is broken, this either spins past MAX_INFERENCE_PASSES (and returns
   * with non-monotone bounds) or asserts inside a plugin. */
  run_post_collection_inference();

  /* Tighten-only invariant: every bound moved inward or stayed put. */
  assert(g_ctx.text_base_min >= text_min_before);
  assert(g_ctx.text_base_max <= text_max_before);
  assert(g_ctx.page_offset_min >= po_min_before);
  assert(g_ctx.page_offset_max <= po_max_before);
  assert(g_ctx.phys_base_min >= phys_min_before);
  assert(g_ctx.phys_base_max <= phys_max_before);

  /* After convergence, an immediate re-run must be a no-op — bounds are
   * already at the fixed point. This is the property the loop guarantees
   * and the property production code relies on (merge_results idempotence
   * + monotone tightening). */
  struct bounds_snap after;
  snap_bounds(&after);
  run_inference_phase(&g_ctx, KASLD_INFER_PHASE_POST_COLLECTION);
  assert(!bounds_changed(&after));
}

/* =========================================================================
 * Tighten-only invariant enforcement
 *
 * run_inference_phase() snapshots ctx bounds before each plugin and reverts
 * any plugin that widens a bound (lo decreased OR hi increased). These tests
 * cover the helper functions directly — first_widened_bound() must catch
 * every tracked field, and restore_ctx_bounds() must reset all fields
 * atomically. Together they keep the convergence loop's monotonicity
 * guarantee from depending on plugin discipline alone.
 * ========================================================================= */
static void test_first_widened_bound_detects_each_field(void) {
  struct ctx_bounds before;
  snap_ctx_bounds(&g_ctx, &before);
  assert(first_widened_bound(&before, &g_ctx) == NULL);

  /* Widen each field in turn and confirm it's reported by name. Reset
   * after each check so subsequent assertions see a clean baseline. */
#define WIDEN_LO(field, name)                                                  \
  do {                                                                         \
    unsigned long saved = g_ctx.field;                                         \
    g_ctx.field = (saved > 0) ? saved - 1 : 0;                                 \
    if (saved > 0) {                                                           \
      const char *w = first_widened_bound(&before, &g_ctx);                    \
      assert(w && strcmp(w, name) == 0);                                       \
    }                                                                          \
    g_ctx.field = saved;                                                       \
  } while (0)
#define WIDEN_HI(field, name)                                                  \
  do {                                                                         \
    unsigned long saved = g_ctx.field;                                         \
    g_ctx.field = (saved < ULONG_MAX) ? saved + 1 : ULONG_MAX;                 \
    if (saved < ULONG_MAX) {                                                   \
      const char *w = first_widened_bound(&before, &g_ctx);                    \
      assert(w && strcmp(w, name) == 0);                                       \
    }                                                                          \
    g_ctx.field = saved;                                                       \
  } while (0)

  WIDEN_LO(text_base_min, "text_base_min");
  WIDEN_HI(text_base_max, "text_base_max");
  WIDEN_LO(page_offset_min, "page_offset_min");
  WIDEN_HI(page_offset_max, "page_offset_max");
  WIDEN_LO(phys_base_min, "phys_base_min");
  WIDEN_HI(phys_base_max, "phys_base_max");
  WIDEN_LO(vmalloc_base_min, "vmalloc_base_min");
  WIDEN_HI(vmalloc_base_max, "vmalloc_base_max");
  WIDEN_LO(vmemmap_base_min, "vmemmap_base_min");
  WIDEN_HI(vmemmap_base_max, "vmemmap_base_max");
#undef WIDEN_LO
#undef WIDEN_HI

  /* Tightening (lo increases or hi decreases) must NOT be flagged. */
  unsigned long saved = g_ctx.text_base_min;
  if (g_ctx.text_base_min < ULONG_MAX)
    g_ctx.text_base_min = saved + 1;
  assert(first_widened_bound(&before, &g_ctx) == NULL);
  g_ctx.text_base_min = saved;
}

static void test_restore_ctx_bounds_resets_all_fields(void) {
  struct ctx_bounds snap;
  snap_ctx_bounds(&g_ctx, &snap);

  /* Mutate every field in both directions; restore must put them all back. */
  g_ctx.text_base_min = 0xdeadbeefu;
  g_ctx.text_base_max = 0xdeadbeefu;
  g_ctx.page_offset_min = 0xcafef00du;
  g_ctx.page_offset_max = 0xcafef00du;
  g_ctx.phys_base_min = 0x1234u;
  g_ctx.phys_base_max = 0x5678u;
  g_ctx.vmalloc_base_min = 0xabcdu;
  g_ctx.vmalloc_base_max = 0xef01u;
  g_ctx.vmemmap_base_min = 0x2345u;
  g_ctx.vmemmap_base_max = 0x6789u;

  restore_ctx_bounds(&g_ctx, &snap);

  assert(g_ctx.text_base_min == snap.text_min);
  assert(g_ctx.text_base_max == snap.text_max);
  assert(g_ctx.page_offset_min == snap.po_min);
  assert(g_ctx.page_offset_max == snap.po_max);
  assert(g_ctx.phys_base_min == snap.phys_min);
  assert(g_ctx.phys_base_max == snap.phys_max);
  assert(g_ctx.vmalloc_base_min == snap.vmalloc_min);
  assert(g_ctx.vmalloc_base_max == snap.vmalloc_max);
  assert(g_ctx.vmemmap_base_min == snap.vmemmap_min);
  assert(g_ctx.vmemmap_base_max == snap.vmemmap_max);
}

/* =========================================================================
 * Bound-tightening inference plugins
 *
 * Each test plants a minimal scenario and confirms the named plugin
 * tightens the right ctx bound. Plugins are exercised via
 * run_inference_phase(), which enforces the tighten-only invariant — a
 * regression that widens a bound would also surface as a failed
 * assertion here.
 * ========================================================================= */

static void test_range_tighten_from_interior_caps_text_max(void) {
  reset_results();
  /* Save then restore g_ctx bounds for isolation from other tests. */
  unsigned long saved_v = g_ctx.text_base_max;
  unsigned long saved_p = g_ctx.phys_base_max;
  g_ctx.text_base_max = layout.kaslr_base_max;
  g_ctx.phys_base_max =
      layout.phys_kaslr_base_max ? layout.phys_kaslr_base_max : ULONG_MAX;

  /* Virt: an interior sample at kernel_base_min + 0x100000 caps
   * text_base_max to that sample. */
  unsigned long v_sample = layout.kaslr_base_min + 0x100000ul;
  struct result *vr = push_result();
  vr->type = KASLD_TYPE_VIRT;
  vr->region = REGION_KERNEL_IMAGE;
  vr->pos = POS_INTERIOR;
  vr->conf = CONF_PARSED;
  vr->sample = v_sample;
  vr->set_mask = SAMPLE_SET;

  run_inference_phase(&g_ctx, KASLD_INFER_PHASE_POST_COLLECTION);

  assert(g_ctx.text_base_max <= v_sample);

  g_ctx.text_base_max = saved_v;
  g_ctx.phys_base_max = saved_p;
}

static void test_base_align_cross_validate_raises_align(void) {
  reset_results();
  unsigned long saved_align = layout.kaslr_align;
  unsigned long stricter = layout.kaslr_align * 2;
  if (stricter == 0)
    stricter = 0x400000ul; /* fallback for kaslr-disabled */

  struct result *r = push_result();
  r->type = KASLD_TYPE_VIRT;
  r->region = REGION_KERNEL_TEXT;
  r->pos = POS_BASE;
  r->conf = CONF_PARSED;
  r->lo = layout.kaslr_base_min;
  r->base_align = stricter;
  r->set_mask = LO_SET | BASE_ALIGN_SET;

  run_inference_phase(&g_ctx, KASLD_INFER_PHASE_LAYOUT_ADJUST);

  assert(layout.kaslr_align >= stricter);

  layout.kaslr_align = saved_align;
}

static void test_mmio_floor_phys_ceiling_tightens(void) {
#if PHYS_VIRT_DECOUPLED
  reset_results();
  unsigned long saved = g_ctx.phys_base_max;
  g_ctx.phys_base_max = ULONG_MAX;

  /* DRAM at 0x100000..0x80000000, MMIO at 0xc0000000 → ceiling = c0000000-1 */
  struct result *d = push_result();
  d->type = KASLD_TYPE_PHYS;
  d->region = REGION_RAM;
  d->pos = POS_BASE;
  d->conf = CONF_PARSED;
  d->lo = 0x100000ul;
  d->hi = 0x80000000ul;
  d->set_mask = LO_SET | HI_SET;

  struct result *m = push_result();
  m->type = KASLD_TYPE_PHYS;
  m->region = REGION_MMIO;
  m->pos = POS_BASE;
  m->conf = CONF_PARSED;
  m->lo = 0xc0000000ul;
  m->hi = 0xfebfffffful;
  m->set_mask = LO_SET | HI_SET;

  run_inference_phase(&g_ctx, KASLD_INFER_PHASE_POST_COLLECTION);

  assert(g_ctx.phys_base_max <= 0xc0000000ul - 1);

  g_ctx.phys_base_max = saved;
#endif
}

static void test_phys_hole_filter_drops_max_into_dram(void) {
#if PHYS_VIRT_DECOUPLED
  reset_results();
  unsigned long saved = g_ctx.phys_base_max;
  /* Set the ceiling INTO the PCI hole between two DRAM ranges, then
   * verify the plugin drops it to the top of the lower DRAM range. */
  g_ctx.phys_base_max = 0xd0000000ul; /* in the hole */

  struct result *lo = push_result();
  lo->type = KASLD_TYPE_PHYS;
  lo->region = REGION_RAM;
  lo->pos = POS_BASE;
  lo->conf = CONF_PARSED;
  lo->lo = 0x100000ul;
  lo->hi = 0xbfffffffful;
  lo->set_mask = LO_SET | HI_SET;

  struct result *hi = push_result();
  hi->type = KASLD_TYPE_PHYS;
  hi->region = REGION_RAM;
  hi->pos = POS_BASE;
  hi->conf = CONF_PARSED;
  hi->lo = 0x100000000ul;
  hi->hi = 0x33ffffffful;
  hi->set_mask = LO_SET | HI_SET;

  run_inference_phase(&g_ctx, KASLD_INFER_PHASE_POST_COLLECTION);

  /* Ceiling should drop to lo extent's hi (= 0xbfffffffful) — that's the
   * highest DRAM extent strictly below the original ceiling. */
  assert(g_ctx.phys_base_max <= 0xbfffffffful);

  g_ctx.phys_base_max = saved;
#endif
}

/* =========================================================================
 * Main
 * ========================================================================= */

/* Initialise g_ctx and g_arch_params the same way orchestrator's main() does.
 * Required because tests link against inference plugin objects (so the
 * KASLD_REGISTER_INFERENCE section is non-empty and run_inference_phase
 * actually fires plugins) — and plugins dereference ctx->arch / ctx->layout.
 * Under KASLD_TESTING the orchestrator's main() is excluded, so we do the
 * one-time pointer wiring here. */
static void test_init_g_ctx(void) {
  g_arch_params.kaslr_base_min = layout.kaslr_base_min;
  g_arch_params.kaslr_base_max = layout.kaslr_base_max;
  g_arch_params.kaslr_align = layout.kaslr_align;
  g_arch_params.phys_kaslr_base_min = layout.phys_kaslr_base_min;
  g_arch_params.phys_kaslr_base_max = layout.phys_kaslr_base_max;
  g_arch_params.phys_kaslr_align = layout.phys_kaslr_align;
  g_arch_params.phys_virt_decoupled = PHYS_VIRT_DECOUPLED;
  g_arch_params.phys_offset = PHYS_OFFSET;
  g_arch_params.page_offset = PAGE_OFFSET;
  g_arch_params.text_offset = TEXT_OFFSET;
  g_ctx.results = results;
  g_ctx.result_count = 0;
  g_ctx.text_base_min = layout.kaslr_base_min;
  g_ctx.text_base_max = layout.kaslr_base_max;
  g_ctx.page_offset_min = layout.kernel_vas_start;
  g_ctx.page_offset_max = layout.kernel_vas_end;
  g_ctx.phys_base_min = layout.phys_kaslr_base_min;
  g_ctx.phys_base_max = layout.phys_kaslr_base_max;
  g_ctx.vmalloc_base_min = 0;
  g_ctx.vmalloc_base_max = ULONG_MAX;
  g_ctx.vmemmap_base_min = 0;
  g_ctx.vmemmap_base_max = ULONG_MAX;
  g_ctx.arch = &g_arch_params;
  g_ctx.layout = &layout;
}

int main(void) {
  test_init_g_ctx();

  RUN(test_result_init_zeroes_everything);

  RUN(test_parse_base_record);
  RUN(test_parse_interior_sample);
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

  RUN(test_result_in_bounds_rejects_region_unknown);
  RUN(test_result_in_bounds_open_vas_accepts_anything);
  RUN(test_result_in_bounds_no_set_bits_passes);

  RUN(test_select_anchor_prefers_no_name);
  RUN(test_select_anchor_falls_back_to_named);
  RUN(test_select_anchor_returns_null_on_miss);

  RUN(test_merge_collapses_same_key);
  RUN(test_merge_keeps_conflicting_records);
  RUN(test_merge_does_not_cross_types);
  RUN(test_merge_sample_clamped_to_extent);
  RUN(test_merge_picks_highest_conf_sample);
  RUN(test_merge_samples_conflict_kept_separate);

  RUN(test_conf_weight_ordering);

  RUN(test_anchor_addr_base);
  RUN(test_anchor_addr_interior_sample);
  RUN(test_anchor_addr_null);

  RUN(test_adjust_noop);

  RUN(test_ilog2_power_of_two);
  RUN(test_ilog2_zero);

  RUN(test_compute_kaslr_info_uses_kernel_image_anchor);
  RUN(test_compute_kaslr_info_falls_back_to_kernel_text);
  RUN(test_compute_kaslr_info_no_anchors_yields_zero_vtext);
#ifdef DATA_OFFSET
  RUN(test_compute_kaslr_info_derives_from_kernel_data);
#endif

  RUN(test_roundtrip_base);
  RUN(test_roundtrip_range);
  RUN(test_roundtrip_top);
  RUN(test_roundtrip_sample);
  RUN(test_roundtrip_sized);

  RUN(test_helpers_reject_conf_unknown);

  RUN(test_merge_dedups_provenance);
  RUN(test_merge_caps_at_max_provenance);

  RUN(test_phys_virt_linkage_stays_two_records);

  RUN(test_result_in_bounds_layout_sensitive);

  RUN(test_synthesized_result_sets_fields_correctly);

  RUN(test_inference_phase_runs_against_structured_input);

  RUN(test_is_phys_dram_region_includes_ram_landmarks);
  RUN(test_is_phys_dram_region_includes_kernel_image);
  RUN(test_is_phys_dram_region_excludes_non_dram);

  RUN(test_result_in_bounds_accepts_phys_kernel_image);

  RUN(test_page_offset_in_bounds_independent_of_runtime_layout);

  RUN(test_select_anchor_skips_out_of_bounds);

  RUN(test_merge_sample_clamped_to_hi);

  RUN(test_merge_is_idempotent);

  RUN(test_parse_key_order_independent);
  RUN(test_parse_sz_before_lo_normalizes);

  RUN(test_merge_base_align_takes_max);
  RUN(test_merge_base_align_propagates_from_either_contributor);

  RUN(test_region_info_table_completeness);
  RUN(test_region_info_static_vas_or_derive_vas_set);

#if PHYS_VIRT_DECOUPLED
  RUN(test_compute_kaslr_info_sets_decoupled_note);
  RUN(test_compute_kaslr_info_no_note_when_vtext_present);
  RUN(test_compute_kaslr_info_no_note_without_phys_landmark);
#endif

  RUN(test_bounds_snap_captures_all_tracked_fields);
  RUN(test_bounds_changed_false_on_stable_snapshot);
  RUN(test_post_collection_inference_converges);
  RUN(test_first_widened_bound_detects_each_field);
  RUN(test_restore_ctx_bounds_resets_all_fields);

  RUN(test_range_tighten_from_interior_caps_text_max);
  RUN(test_base_align_cross_validate_raises_align);
  RUN(test_mmio_floor_phys_ceiling_tightens);
  RUN(test_phys_hole_filter_drops_max_into_dram);

  fprintf(stderr, "\n%d/%d tests passed\n", pass_count, test_count);
  return (pass_count == test_count) ? 0 : 1;
}
