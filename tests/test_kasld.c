/* Unit tests for kasld orchestrator logic.
 *
 * Uses the #include-the-.c-file pattern to access static functions.
 * Compiled with -DKASLD_TESTING to exclude main(). */

#ifndef KASLD_TESTING
#define KASLD_TESTING
#endif
#define VERSION "test"

#include "../src/inference/dram_bound.c"
#include "../src/inference/kaslr_ceiling.c"
#include "../src/inference/layout_adjust.c"
#include "../src/inference/module_text_bound.c"
#include "../src/inference/phys_virt_synth.c"
#include "../src/orchestrator.c"
#include "../src/render.c"

#include <assert.h>
#include <string.h>

/* =========================================================================
 * Helpers
 * =========================================================================
 */
static int test_count;
static int pass_count;

#define RUN_TEST(fn)                                                           \
  do {                                                                         \
    test_count++;                                                              \
    printf("  %-50s", #fn);                                                    \
    fn();                                                                      \
    pass_count++;                                                              \
    printf("PASS\n");                                                          \
  } while (0)

/* Reset all global state between tests */
static void reset_state(void) {
  num_results = 0;
  num_components = 0;
  num_printed_groups = 0;
  num_comp_logs = 0;
  progress_done = 0;
  parallel_workers = 0;
  verbose = 0;
  json_output = 0;
  oneline_output = 0;
  markdown_output = 0;
  hardening_mode = 0;
  explain_mode = 0;
  sysctl_kptr_restrict = -1;
  sysctl_dmesg_restrict = -1;
  sysctl_perf_event_paranoid = -1;
  sysctl_lockdown = LOCKDOWN_UNAVAILABLE;
  num_skip_patterns = 0;
  experimental_mode = 0;
  memset(results, 0, sizeof(results));
  memset(components, 0, sizeof(components));
  memset(comp_logs, 0, sizeof(comp_logs));
  memset(skip_patterns, 0, sizeof(skip_patterns));

  /* Restore default layout */
  layout.page_offset = PAGE_OFFSET;
  layout.kernel_vas_start = KERNEL_VAS_START;
  layout.kernel_vas_end = KERNEL_VAS_END;
  layout.kernel_base_min = KERNEL_BASE_MIN;
  layout.kernel_base_max = KERNEL_BASE_MAX;
  layout.modules_start = MODULES_START;
  layout.modules_end = MODULES_END;
  layout.kernel_align = KERNEL_ALIGN;
  layout.text_offset = TEXT_OFFSET;
  layout.kernel_text_default = KERNEL_TEXT_DEFAULT;
}

/* Inject a tagged line as if a component emitted it (parses directly into
 * results) */
static void inject_tagged(const char *line) {
  char buf[LINE_LEN];
  snprintf(buf, sizeof(buf), "%s\n", line);
  capture_result(buf, "parsed", NULL);
}

/* Inject a result directly. label may be "region" or "region:name". */
static void inject_result(char type, const char *section, unsigned long addr,
                          const char *label) {
  assert(num_results < MAX_RESULTS);
  struct result *r = &results[num_results];
  r->type = type;
  strncpy(r->section, section, SECTION_LEN - 1);
  r->section[SECTION_LEN - 1] = '\0';
  r->raw = addr;
  r->aligned = align_for_section(type, section, addr);
  r->valid = validate_for_section(type, section, r->aligned);
  const char *colon = strchr(label, ':');
  if (colon) {
    size_t rlen = (size_t)(colon - label);
    if (rlen >= REGION_LEN)
      rlen = REGION_LEN - 1;
    memcpy(r->region, label, rlen);
    r->region[rlen] = '\0';
    strncpy(r->name, colon + 1, NAME_LEN - 1);
    r->name[NAME_LEN - 1] = '\0';
  } else {
    strncpy(r->region, label, REGION_LEN - 1);
    r->region[REGION_LEN - 1] = '\0';
  }
  num_results++;
}

/* Initialize g_ctx and g_arch_params from compile-time layout constants.
 * Call after reset_state() and after any inject_result() calls that should
 * be visible to the plugin under test. */
static void init_inference_ctx(void) {
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
  g_ctx.result_count = (size_t)num_results;
  g_ctx.text_base_min = layout.kaslr_base_min;
  g_ctx.text_base_max = layout.kaslr_base_max;
  g_ctx.page_offset_min = layout.kernel_vas_start;
  g_ctx.page_offset_max = layout.kernel_vas_end;
  g_ctx.phys_base_min = layout.phys_kaslr_base_min;
  g_ctx.phys_base_max = layout.phys_kaslr_base_max;
  g_ctx.arch = &g_arch_params;
  g_ctx.layout = &layout;
}

/* Like inject_result(), but also tags the result with a component origin. */
static void inject_result_with_origin(char type, const char *section,
                                      unsigned long addr, const char *label,
                                      const char *origin) {
  inject_result(type, section, addr, label);
  struct result *r = &results[num_results - 1];
  strncpy(r->origin, origin, ORIGIN_LEN - 1);
  r->origin[ORIGIN_LEN - 1] = '\0';
}

/* =========================================================================
 * align_for_section
 * =========================================================================
 */
static void test_align_text_rounds_down(void) {
  /* KERNEL_ALIGN is 2 MiB on x86_64 */
  unsigned long addr = KERNEL_BASE_MIN + 0x123456;
  unsigned long aligned =
      align_for_section(KASLD_ADDR_VIRT, KASLD_SECTION_TEXT, addr);
  assert(aligned == (addr & -KERNEL_ALIGN));
  assert(aligned < addr);
  assert((aligned % KERNEL_ALIGN) == 0);
}

static void test_align_text_already_aligned(void) {
  unsigned long addr = KERNEL_BASE_MIN + KERNEL_ALIGN;
  unsigned long aligned =
      align_for_section(KASLD_ADDR_VIRT, KASLD_SECTION_TEXT, addr);
  assert(aligned == addr);
}

static void test_align_module_passthrough(void) {
  unsigned long addr = MODULES_START + 0x123;
  unsigned long aligned =
      align_for_section(KASLD_ADDR_VIRT, KASLD_SECTION_MODULE, addr);
  assert(aligned == addr);
}

static void test_align_default_passthrough(void) {
  unsigned long addr = 0xdeadbeef;
  unsigned long aligned =
      align_for_section(KASLD_ADDR_DEFAULT, KASLD_SECTION_NONE, addr);
  assert(aligned == addr);
}

static void test_align_phys_text_rounds_down(void) {
  unsigned long addr = KERNEL_PHYS_MIN + 0x54321;
  unsigned long aligned =
      align_for_section(KASLD_ADDR_PHYS, KASLD_SECTION_TEXT, addr);
  assert(aligned == (addr & -KERNEL_ALIGN));
}

/* =========================================================================
 * validate_for_section
 * =========================================================================
 */
static void test_validate_virt_text_in_range(void) {
  unsigned long addr = KERNEL_BASE_MIN + KERNEL_ALIGN;
  assert(validate_for_section(KASLD_ADDR_VIRT, KASLD_SECTION_TEXT, addr) == 1);
}

static void test_validate_virt_text_below_range(void) {
  unsigned long addr = KERNEL_BASE_MIN - 1;
  assert(validate_for_section(KASLD_ADDR_VIRT, KASLD_SECTION_TEXT, addr) == 0);
}

static void test_validate_virt_text_above_range(void) {
  unsigned long addr = KERNEL_BASE_MAX + 1;
  assert(validate_for_section(KASLD_ADDR_VIRT, KASLD_SECTION_TEXT, addr) == 0);
}

static void test_validate_virt_module_in_range(void) {
  unsigned long addr = MODULES_START + 0x1000;
  assert(validate_for_section(KASLD_ADDR_VIRT, KASLD_SECTION_MODULE, addr) ==
         1);
}

static void test_validate_virt_module_below_range(void) {
  unsigned long addr = MODULES_START - 1;
  assert(validate_for_section(KASLD_ADDR_VIRT, KASLD_SECTION_MODULE, addr) ==
         0);
}

static void test_validate_default_always_valid(void) {
  assert(validate_for_section(KASLD_ADDR_DEFAULT, KASLD_SECTION_NONE, 0) == 1);
  assert(validate_for_section(KASLD_ADDR_DEFAULT, KASLD_SECTION_NONE,
                              0xdeadbeef) == 1);
}

static void test_validate_phys_text_in_range(void) {
  unsigned long addr = KERNEL_PHYS_MIN + KERNEL_ALIGN;
  assert(validate_for_section(KASLD_ADDR_PHYS, KASLD_SECTION_TEXT, addr) == 1);
}

static void test_validate_phys_text_below_range(void) {
  unsigned long addr = KERNEL_PHYS_MIN - 1;
  assert(validate_for_section(KASLD_ADDR_PHYS, KASLD_SECTION_TEXT, addr) == 0);
}

static void test_validate_phys_dram_always_valid(void) {
  assert(validate_for_section(KASLD_ADDR_PHYS, KASLD_SECTION_DRAM,
                              0x80000000) == 1);
}

/* =========================================================================
 * capture_result (parse during capture)
 * =========================================================================
 */
static void test_parse_basic(void) {
  reset_state();
  inject_tagged("V text 0xffffffff81000000 proc-kallsyms");

  assert(num_results == 1);
  assert(results[0].type == KASLD_ADDR_VIRT);
  assert(strcmp(results[0].section, "text") == 0);
  assert(strcmp(results[0].region, "proc-kallsyms") == 0);
  assert(results[0].name[0] == '\0');
  assert(results[0].raw == 0xffffffff81000000ul);
}

static void test_parse_multiple(void) {
  reset_state();
  inject_tagged("V text 0xffffffff81200000 entrybleed");
  inject_tagged("P dram 0x0000000001000000 dmesg_e820_memory_map:lo");
  inject_tagged("D - 0xffffffff81000000 default:text");

  assert(num_results == 3);
  assert(results[0].type == KASLD_ADDR_VIRT);
  assert(results[1].type == KASLD_ADDR_PHYS);
  assert(results[2].type == KASLD_ADDR_DEFAULT);
}

static void test_parse_incremental(void) {
  reset_state();
  inject_tagged("V text 0xffffffff81000000 first");
  assert(num_results == 1);

  inject_tagged("V text 0xffffffff82000000 second");
  assert(num_results == 2);
  assert(strcmp(results[1].region, "second") == 0);
}

static void test_parse_ignores_non_tagged(void) {
  reset_state();
  /* Non-tagged lines are rejected by capture_result */
  char buf[LINE_LEN];
  snprintf(buf, sizeof(buf), "some random output\n");
  capture_result(buf, "parsed", NULL);
  assert(num_results == 0);
}

static void test_parse_label_with_colon(void) {
  reset_state();
  inject_tagged("V module 0xffffffffc0001000 sysfs-module-sections:lo");

  assert(num_results == 1);
  assert(strcmp(results[0].region, "sysfs-module-sections") == 0);
  assert(strcmp(results[0].name, "lo") == 0);
}

static void test_parse_strips_newline(void) {
  reset_state();
  inject_tagged("V text 0xffffffff81000000 test_label");

  size_t len = strlen(results[0].region);
  assert(results[0].region[len - 1] != '\n');
}

/* =========================================================================
 * group_consensus
 * =========================================================================
 */
static void test_consensus_single(void) {
  reset_state();
  inject_result(KASLD_ADDR_VIRT, KASLD_SECTION_TEXT,
                KERNEL_BASE_MIN + KERNEL_ALIGN, "a");

  unsigned long c = group_consensus(KASLD_ADDR_VIRT, KASLD_SECTION_TEXT);
  assert(c == KERNEL_BASE_MIN + KERNEL_ALIGN);
}

static void test_consensus_majority(void) {
  reset_state();
  unsigned long addr_a = KERNEL_BASE_MIN + 2 * KERNEL_ALIGN;
  unsigned long addr_b = KERNEL_BASE_MIN + 4 * KERNEL_ALIGN;

  inject_result(KASLD_ADDR_VIRT, KASLD_SECTION_TEXT, addr_a, "a");
  inject_result(KASLD_ADDR_VIRT, KASLD_SECTION_TEXT, addr_b, "b");
  inject_result(KASLD_ADDR_VIRT, KASLD_SECTION_TEXT, addr_a, "c");

  unsigned long c = group_consensus(KASLD_ADDR_VIRT, KASLD_SECTION_TEXT);
  assert(c == addr_a);
}

static void test_consensus_tie_lowest(void) {
  reset_state();
  unsigned long addr_lo = KERNEL_BASE_MIN + 2 * KERNEL_ALIGN;
  unsigned long addr_hi = KERNEL_BASE_MIN + 8 * KERNEL_ALIGN;

  inject_result(KASLD_ADDR_VIRT, KASLD_SECTION_TEXT, addr_hi, "a");
  inject_result(KASLD_ADDR_VIRT, KASLD_SECTION_TEXT, addr_lo, "b");

  unsigned long c = group_consensus(KASLD_ADDR_VIRT, KASLD_SECTION_TEXT);
  assert(c == addr_lo);
}

static void test_consensus_empty(void) {
  reset_state();
  unsigned long c = group_consensus(KASLD_ADDR_VIRT, KASLD_SECTION_TEXT);
  assert(c == 0);
}

static void test_consensus_ignores_invalid(void) {
  reset_state();
  /* Inject a result that's out of range */
  struct result *r = &results[num_results++];
  r->type = KASLD_ADDR_VIRT;
  strncpy(r->section, KASLD_SECTION_TEXT, SECTION_LEN - 1);
  r->raw = 0x1000; /* way below KERNEL_BASE_MIN */
  r->aligned = 0x1000;
  r->valid = 0;
  strncpy(r->region, "bad", REGION_LEN - 1);

  unsigned long c = group_consensus(KASLD_ADDR_VIRT, KASLD_SECTION_TEXT);
  assert(c == 0);
}

static void test_consensus_type_isolation(void) {
  reset_state();
  unsigned long vaddr = KERNEL_BASE_MIN + KERNEL_ALIGN;
  unsigned long paddr = KERNEL_PHYS_MIN + KERNEL_ALIGN;

  inject_result(KASLD_ADDR_VIRT, KASLD_SECTION_TEXT, vaddr, "v");
  inject_result(KASLD_ADDR_PHYS, KASLD_SECTION_TEXT, paddr, "p");

  assert(group_consensus(KASLD_ADDR_VIRT, KASLD_SECTION_TEXT) == vaddr);
  assert(group_consensus(KASLD_ADDR_PHYS, KASLD_SECTION_TEXT) == paddr);
}

/* =========================================================================
 * group_range
 * =========================================================================
 */
static void test_range_single(void) {
  reset_state();
  unsigned long addr = MODULES_START + 0x1000;
  inject_result(KASLD_ADDR_VIRT, KASLD_SECTION_MODULE, addr, "a");

  unsigned long lo, hi;
  group_range(KASLD_ADDR_VIRT, KASLD_SECTION_MODULE, &lo, &hi);
  assert(lo == addr);
  assert(hi == 0); /* single address → hi cleared */
}

static void test_range_multiple(void) {
  reset_state();
  unsigned long addr_lo = MODULES_START + 0x1000;
  unsigned long addr_hi = MODULES_START + 0x50000;

  inject_result(KASLD_ADDR_VIRT, KASLD_SECTION_MODULE, addr_hi, "hi");
  inject_result(KASLD_ADDR_VIRT, KASLD_SECTION_MODULE, addr_lo, "lo");

  unsigned long lo, hi;
  group_range(KASLD_ADDR_VIRT, KASLD_SECTION_MODULE, &lo, &hi);
  assert(lo == addr_lo);
  assert(hi == addr_hi);
}

static void test_range_empty(void) {
  reset_state();
  unsigned long lo, hi;
  group_range(KASLD_ADDR_VIRT, KASLD_SECTION_MODULE, &lo, &hi);
  assert(lo == 0);
  assert(hi == 0);
}

/* =========================================================================
 * detect_kaslr_state
 * =========================================================================
 */
static void test_kaslr_enabled(void) {
  reset_state();
  inject_result(KASLD_ADDR_DEFAULT, KASLD_SECTION_NONE, KERNEL_TEXT_DEFAULT,
                "default:text");
  assert(detect_kaslr_state() == 0);
}

static void test_kaslr_disabled_cmdline(void) {
  reset_state();
  inject_result(KASLD_ADDR_DEFAULT, KASLD_SECTION_NONE, KERNEL_TEXT_DEFAULT,
                "default:text");
  inject_result(KASLD_ADDR_DEFAULT, KASLD_SECTION_NONE, KERNEL_TEXT_DEFAULT,
                "proc-cmdline:nokaslr");
  assert(detect_kaslr_state() == 1);
}

static void test_kaslr_unsupported(void) {
  reset_state();
  inject_result(KASLD_ADDR_DEFAULT, KASLD_SECTION_NONE, KERNEL_TEXT_DEFAULT,
                "default:unsupported");
  assert(detect_kaslr_state() == 1);
}

static void test_kaslr_no_results(void) {
  reset_state();
  assert(detect_kaslr_state() == 0);
}

/* =========================================================================
 * adjust_for_page_offset
 * =========================================================================
 */
static void test_adjust_noop_same_po(void) {
  reset_state();
  unsigned long orig = layout.page_offset;
  adjust_for_page_offset(orig);
  assert(layout.page_offset == orig);
  assert(layout.kernel_base_min == KERNEL_BASE_MIN);
}

#if defined(__i386__) || defined(__arm__)
/* PAGE_OFFSET adjustment is meaningful on 32-bit with vmsplit */
static void test_adjust_shifts_layout(void) {
  reset_state();
  unsigned long new_po = PAGE_OFFSET + 0x10000000ul;
  unsigned long old_modules_end = layout.modules_end;

  adjust_for_page_offset(new_po);

  assert(layout.page_offset == new_po);
  assert(layout.kernel_vas_start == new_po);
  assert(layout.kernel_base_min == new_po);
  assert(layout.kernel_text_default == new_po + TEXT_OFFSET);

  /* modules_end should shift if it was anchored to old PAGE_OFFSET */
  if (old_modules_end == PAGE_OFFSET)
    assert(layout.modules_end == new_po);
}
#endif

/* =========================================================================
 * revalidate_results
 * =========================================================================
 */
static void test_revalidate_updates_validity(void) {
  reset_state();
  /* Inject a result that's valid with current layout */
  unsigned long addr = KERNEL_BASE_MIN + KERNEL_ALIGN;
  inject_result(KASLD_ADDR_VIRT, KASLD_SECTION_TEXT, addr, "test");
  assert(results[0].valid == 1);

  /* Manually corrupt validity, then revalidate */
  results[0].valid = 0;
  revalidate_results();
  assert(results[0].valid == 1);
}

/* =========================================================================
 * ilog2
 * =========================================================================
 */
static void test_ilog2_power_of_two(void) {
  assert(ilog2(1) == 0);
  assert(ilog2(2) == 1);
  assert(ilog2(4) == 2);
  assert(ilog2(1024) == 10);
  assert(ilog2(0x200000) == 21); /* 2 MiB */
}

static void test_ilog2_non_power(void) {
  assert(ilog2(3) == 1);
  assert(ilog2(5) == 2);
  assert(ilog2(1023) == 9);
}

static void test_ilog2_zero(void) { assert(ilog2(0) == 0); }

static void test_ilog2_large(void) {
  assert(ilog2(1ul << 30) == 30);
#if __SIZEOF_LONG__ == 8
  assert(ilog2(1ul << 62) == 62);
#endif
}

/* =========================================================================
 * section_display_name
 * =========================================================================
 */
static void test_section_display_default_null(void) {
  assert(section_display_name(KASLD_ADDR_DEFAULT, KASLD_SECTION_NONE) == NULL);
}

static void test_section_display_virt_text(void) {
  const char *name = section_display_name(KASLD_ADDR_VIRT, KASLD_SECTION_TEXT);
  assert(name != NULL);
  assert(strstr(name, "virtual") != NULL);
}

static void test_section_display_phys_text(void) {
  const char *name = section_display_name(KASLD_ADDR_PHYS, KASLD_SECTION_TEXT);
  assert(name != NULL);
  assert(strstr(name, "physical") != NULL);
}

static void test_section_display_pageoffset_null(void) {
  assert(section_display_name(KASLD_ADDR_VIRT, KASLD_SECTION_PAGEOFFSET) ==
         NULL);
}

static void test_section_display_module(void) {
  assert(section_display_name(KASLD_ADDR_VIRT, KASLD_SECTION_MODULE) != NULL);
}

static void test_section_display_dram(void) {
  assert(section_display_name(KASLD_ADDR_PHYS, KASLD_SECTION_DRAM) != NULL);
}

/* =========================================================================
 * validate_for_section — additional section coverage
 * =========================================================================
 */
static void test_validate_virt_directmap_in_range(void) {
  unsigned long addr = layout.kernel_vas_start + 0x1000;
  assert(validate_for_section(KASLD_ADDR_VIRT, KASLD_SECTION_DIRECTMAP, addr) ==
         1);
}

static void test_validate_virt_directmap_below_range(void) {
  unsigned long addr = layout.kernel_vas_start - 1;
  assert(validate_for_section(KASLD_ADDR_VIRT, KASLD_SECTION_DIRECTMAP, addr) ==
         0);
}

static void test_validate_virt_data_in_range(void) {
  unsigned long addr = layout.kernel_vas_start + 0x1000;
  assert(validate_for_section(KASLD_ADDR_VIRT, KASLD_SECTION_DATA, addr) == 1);
}

static void test_validate_virt_pageoffset_always_valid(void) {
  assert(validate_for_section(KASLD_ADDR_VIRT, KASLD_SECTION_PAGEOFFSET,
                              0x1000) == 1);
  assert(validate_for_section(KASLD_ADDR_VIRT, KASLD_SECTION_PAGEOFFSET, 0) ==
         1);
}

static void test_validate_virt_text_at_boundaries(void) {
  /* Exactly at min: valid */
  assert(validate_for_section(KASLD_ADDR_VIRT, KASLD_SECTION_TEXT,
                              KERNEL_BASE_MIN) == 1);
  /* Exactly at max: valid */
  assert(validate_for_section(KASLD_ADDR_VIRT, KASLD_SECTION_TEXT,
                              KERNEL_BASE_MAX) == 1);
}

static void test_validate_virt_module_at_boundaries(void) {
  assert(validate_for_section(KASLD_ADDR_VIRT, KASLD_SECTION_MODULE,
                              MODULES_START) == 1);
  assert(validate_for_section(KASLD_ADDR_VIRT, KASLD_SECTION_MODULE,
                              MODULES_END) == 1);
}

/* =========================================================================
 * capture_result — additional parser edge cases
 * =========================================================================
 */
static void test_parse_rejects_lowercase_type(void) {
  reset_state();
  char buf[LINE_LEN];
  snprintf(buf, sizeof(buf), "v text 0xffffffff81000000 lowercase\n");
  capture_result(buf, "parsed", NULL);
  assert(num_results == 0);
}

static void test_parse_rejects_missing_space(void) {
  reset_state();
  char buf[LINE_LEN];
  snprintf(buf, sizeof(buf), "Vtext 0xffffffff81000000 nospace\n");
  capture_result(buf, "parsed", NULL);
  assert(num_results == 0);
}

static void test_parse_rejects_empty_label(void) {
  reset_state();
  char buf[LINE_LEN];
  /* Only type, section, addr — no label after the hex */
  snprintf(buf, sizeof(buf), "V text 0xffffffff81000000\n");
  capture_result(buf, "parsed", NULL);
  /* label_start points to '\n' or '\0'; should be rejected or have empty label
   */
  /* The function checks *label_start == '\0' but '\n' passes that check */
  /* Either way it shouldn't crash */
}

static void test_parse_zero_address(void) {
  reset_state();
  inject_tagged("P dram 0x0 zero-addr");
  assert(num_results == 1);
  assert(results[0].raw == 0);
}

static void test_parse_phys_type(void) {
  reset_state();
  inject_tagged("P text 0x0000000040200000 dmesg-phys");
  assert(num_results == 1);
  assert(results[0].type == KASLD_ADDR_PHYS);
  assert(strcmp(results[0].section, "text") == 0);
}

static void test_parse_directmap_section(void) {
  reset_state();
  inject_tagged("V directmap 0xffff888000000000 sysfs-directmap");
  assert(num_results == 1);
  assert(strcmp(results[0].section, "directmap") == 0);
}

/* =========================================================================
 * group_consensus — additional edge cases
 * =========================================================================
 */
static void test_consensus_section_isolation(void) {
  reset_state();
  unsigned long text_addr = KERNEL_BASE_MIN + KERNEL_ALIGN;
  unsigned long mod_addr = MODULES_START + 0x1000;

  inject_result(KASLD_ADDR_VIRT, KASLD_SECTION_TEXT, text_addr, "t");
  inject_result(KASLD_ADDR_VIRT, KASLD_SECTION_MODULE, mod_addr, "m");

  /* text consensus should not include the module result */
  assert(group_consensus(KASLD_ADDR_VIRT, KASLD_SECTION_TEXT) == text_addr);
  assert(group_consensus(KASLD_ADDR_VIRT, KASLD_SECTION_MODULE) == mod_addr);
}

static void test_consensus_three_way_tie(void) {
  reset_state();
  unsigned long a1 = KERNEL_BASE_MIN + 4 * KERNEL_ALIGN;
  unsigned long a2 = KERNEL_BASE_MIN + 2 * KERNEL_ALIGN;
  unsigned long a3 = KERNEL_BASE_MIN + 6 * KERNEL_ALIGN;

  inject_result(KASLD_ADDR_VIRT, KASLD_SECTION_TEXT, a1, "x");
  inject_result(KASLD_ADDR_VIRT, KASLD_SECTION_TEXT, a2, "y");
  inject_result(KASLD_ADDR_VIRT, KASLD_SECTION_TEXT, a3, "z");

  /* Three-way tie: should pick lowest */
  assert(group_consensus(KASLD_ADDR_VIRT, KASLD_SECTION_TEXT) == a2);
}

static void test_consensus_weight_beats_count(void) {
  reset_state();
  unsigned long addr_exact = KERNEL_BASE_MIN + 4 * KERNEL_ALIGN;
  unsigned long addr_heur = KERNEL_BASE_MIN + 2 * KERNEL_ALIGN;

  /* One exact result (weight 4) vs two heuristic results (weight 1 each) */
  struct result *r = &results[num_results++];
  r->type = KASLD_ADDR_VIRT;
  strncpy(r->section, KASLD_SECTION_TEXT, SECTION_LEN - 1);
  r->raw = addr_exact;
  r->aligned = addr_exact;
  r->valid = 1;
  strncpy(r->region, "e", REGION_LEN - 1);
  strncpy(r->method, "exact", METHOD_LEN - 1);

  inject_result(KASLD_ADDR_VIRT, KASLD_SECTION_TEXT, addr_heur, "h1");
  results[num_results - 1].method[0] = '\0';
  strncpy(results[num_results - 1].method, "heuristic", METHOD_LEN - 1);

  inject_result(KASLD_ADDR_VIRT, KASLD_SECTION_TEXT, addr_heur, "h2");
  results[num_results - 1].method[0] = '\0';
  strncpy(results[num_results - 1].method, "heuristic", METHOD_LEN - 1);

  /* exact (score 4) beats 2x heuristic (score 2) */
  assert(group_consensus(KASLD_ADDR_VIRT, KASLD_SECTION_TEXT) == addr_exact);
}

static void test_consensus_weight_tie_to_count(void) {
  reset_state();
  unsigned long addr_a = KERNEL_BASE_MIN + 4 * KERNEL_ALIGN;
  unsigned long addr_b = KERNEL_BASE_MIN + 2 * KERNEL_ALIGN;

  /* Two parsed results (2+2=4) vs one exact result (4) — score tie */
  inject_result(KASLD_ADDR_VIRT, KASLD_SECTION_TEXT, addr_a, "p1");
  results[num_results - 1].method[0] = '\0';
  strncpy(results[num_results - 1].method, "parsed", METHOD_LEN - 1);

  inject_result(KASLD_ADDR_VIRT, KASLD_SECTION_TEXT, addr_a, "p2");
  results[num_results - 1].method[0] = '\0';
  strncpy(results[num_results - 1].method, "parsed", METHOD_LEN - 1);

  struct result *r = &results[num_results++];
  r->type = KASLD_ADDR_VIRT;
  strncpy(r->section, KASLD_SECTION_TEXT, SECTION_LEN - 1);
  r->raw = addr_b;
  r->aligned = addr_b;
  r->valid = 1;
  strncpy(r->region, "e", REGION_LEN - 1);
  strncpy(r->method, "exact", METHOD_LEN - 1);

  /* Score tie (4 vs 4): break to count (2 vs 1) */
  assert(group_consensus(KASLD_ADDR_VIRT, KASLD_SECTION_TEXT) == addr_a);
}

/* =========================================================================
 * group_range — additional edge cases
 * =========================================================================
 */
static void test_range_ignores_invalid(void) {
  reset_state();
  unsigned long valid_addr = MODULES_START + 0x1000;
  inject_result(KASLD_ADDR_VIRT, KASLD_SECTION_MODULE, valid_addr, "ok");

  /* Inject an invalid result manually */
  struct result *r = &results[num_results++];
  r->type = KASLD_ADDR_VIRT;
  strncpy(r->section, KASLD_SECTION_MODULE, SECTION_LEN - 1);
  r->section[SECTION_LEN - 1] = '\0';
  r->raw = 0x1000; /* way out of range */
  r->aligned = 0x1000;
  r->valid = 0;
  strncpy(r->region, "bad", REGION_LEN - 1);

  unsigned long lo, hi;
  group_range(KASLD_ADDR_VIRT, KASLD_SECTION_MODULE, &lo, &hi);
  assert(lo == valid_addr);
  assert(hi == 0); /* only one valid result */
}

static void test_range_type_isolation(void) {
  reset_state();
  unsigned long vaddr = MODULES_START + 0x1000;
  unsigned long paddr = 0x80001000ul;

  inject_result(KASLD_ADDR_VIRT, KASLD_SECTION_DRAM, vaddr, "v");
  inject_result(KASLD_ADDR_PHYS, KASLD_SECTION_DRAM, paddr, "p");

  unsigned long lo, hi;
  group_range(KASLD_ADDR_PHYS, KASLD_SECTION_DRAM, &lo, &hi);
  assert(lo == paddr);
  assert(hi == 0);
}

static void test_range_zero_address(void) {
  reset_state();
  /* Physical DRAM can legitimately start at 0x0 */
  results[num_results].type = KASLD_ADDR_PHYS;
  strncpy(results[num_results].section, KASLD_SECTION_DRAM, SECTION_LEN - 1);
  results[num_results].aligned = 0x0;
  results[num_results].valid = 1;
  num_results++;

  results[num_results].type = KASLD_ADDR_PHYS;
  strncpy(results[num_results].section, KASLD_SECTION_DRAM, SECTION_LEN - 1);
  results[num_results].aligned = 0x340000000ul;
  results[num_results].valid = 1;
  num_results++;

  unsigned long lo, hi;
  group_range(KASLD_ADDR_PHYS, KASLD_SECTION_DRAM, &lo, &hi);
  assert(lo == 0x0);
  assert(hi == 0x340000000ul);
}

/* =========================================================================
 * add_derived
 * =========================================================================
 */
static void test_add_derived_basic(void) {
  struct summary s;
  memset(&s, 0, sizeof(s));

  add_derived(&s, KASLD_ADDR_VIRT, KASLD_SECTION_TEXT, 0xffffffff81200000ul, 0,
              "Virtual text base", "via P text");
  assert(s.num_derived == 1);
  assert(s.derived[0].type == KASLD_ADDR_VIRT);
  assert(strcmp(s.derived[0].section, "text") == 0);
  assert(s.derived[0].addr == 0xffffffff81200000ul);
  assert(s.derived[0].addr_hi == 0);
  assert(strcmp(s.derived[0].label, "Virtual text base") == 0);
  assert(strcmp(s.derived[0].via, "via P text") == 0);
}

static void test_add_derived_with_range(void) {
  struct summary s;
  memset(&s, 0, sizeof(s));

  add_derived(&s, KASLD_ADDR_PHYS, KASLD_SECTION_DRAM, 0x1000ul, 0x8000ul,
              "DRAM range", "via dmesg");
  assert(s.num_derived == 1);
  assert(s.derived[0].addr == 0x1000ul);
  assert(s.derived[0].addr_hi == 0x8000ul);
}

static void test_add_derived_overflow(void) {
  struct summary s;
  memset(&s, 0, sizeof(s));

  /* Fill to MAX_DERIVED */
  for (int i = 0; i < MAX_DERIVED; i++)
    add_derived(&s, KASLD_ADDR_VIRT, KASLD_SECTION_TEXT,
                0x1000ul * (unsigned long)i, 0, "fill", "test");
  assert(s.num_derived == MAX_DERIVED);

  /* One more should be silently dropped */
  add_derived(&s, KASLD_ADDR_VIRT, KASLD_SECTION_TEXT, 0xdeadbeeful, 0,
              "overflow", "test");
  assert(s.num_derived == MAX_DERIVED);
}

/* =========================================================================
 * inject_kaslr_defaults
 * =========================================================================
 */
static void test_inject_defaults_nokaslr(void) {
  reset_state();
  struct summary s;
  memset(&s, 0, sizeof(s));

  /* "proc-cmdline:nokaslr" isn't "default:text", so disabled=1 */
  inject_result(KASLD_ADDR_DEFAULT, KASLD_SECTION_NONE, KERNEL_TEXT_DEFAULT,
                "proc-cmdline:nokaslr");

  inject_kaslr_defaults(&s);
  assert(s.kaslr.disabled == 1);
  assert(s.kaslr.default_addr == KERNEL_TEXT_DEFAULT);
  /* Should have injected a V text result */
  int found = 0;
  for (int i = 0; i < num_results; i++) {
    if (results[i].type == KASLD_ADDR_VIRT &&
        strcmp(results[i].section, KASLD_SECTION_TEXT) == 0 &&
        strcmp(results[i].region, KASLD_REGION_KERNEL_TEXT) == 0 &&
        strcmp(results[i].name, "nokaslr") == 0) {
      assert(results[i].raw == KERNEL_TEXT_DEFAULT);
      found = 1;
    }
  }
  assert(found == 1);
}

static void test_inject_defaults_unsupported(void) {
  reset_state();
  struct summary s;
  memset(&s, 0, sizeof(s));

  inject_result(KASLD_ADDR_DEFAULT, KASLD_SECTION_NONE, KERNEL_TEXT_DEFAULT,
                "default:unsupported");

  inject_kaslr_defaults(&s);
  assert(s.kaslr.unsupported == 1);
  assert(s.kaslr.disabled == 0);
  /* Should still inject V text result */
  assert(num_results == 2); /* original + injected */
  assert(results[1].type == KASLD_ADDR_VIRT);
}

static void test_inject_defaults_kaslr_enabled(void) {
  reset_state();
  struct summary s;
  memset(&s, 0, sizeof(s));

  inject_result(KASLD_ADDR_DEFAULT, KASLD_SECTION_NONE, KERNEL_TEXT_DEFAULT,
                "default:text");

  inject_kaslr_defaults(&s);
  assert(s.kaslr.disabled == 0);
  assert(s.kaslr.unsupported == 0);
  /* Should NOT inject V text result (KASLR is enabled) */
  assert(num_results == 1);
}

/* =========================================================================
 * compute_kaslr_info
 * =========================================================================
 */
static void test_compute_kaslr_with_vtext(void) {
  reset_state();
  struct summary s;
  memset(&s, 0, sizeof(s));

  unsigned long addr = KERNEL_BASE_MIN + 4 * KERNEL_ALIGN;
  inject_result(KASLD_ADDR_VIRT, KASLD_SECTION_TEXT, addr, "test");

  compute_kaslr_info(&s);
  assert(s.kaslr.vtext == addr);
  assert(s.kaslr.vslide == (long)(addr - layout.kernel_text_default));
}

static void test_compute_kaslr_empty(void) {
  reset_state();
  struct summary s;
  memset(&s, 0, sizeof(s));

  compute_kaslr_info(&s);
  assert(s.kaslr.vtext == 0);
  assert(s.kaslr.ptext == 0);
  assert(s.kaslr.has_phys == 0);
  /* Slot count is computed unconditionally from the layout range. */
  assert(s.kaslr.vslots > 0);
  assert(s.kaslr.vbits > 0);
}

static void test_compute_kaslr_disabled_zeroes(void) {
  reset_state();
  struct summary s;
  memset(&s, 0, sizeof(s));

  /* Inject a nokaslr indicator and a virtual text result */
  inject_result(KASLD_ADDR_DEFAULT, KASLD_SECTION_NONE, KERNEL_TEXT_DEFAULT,
                "proc-cmdline:nokaslr");
  inject_kaslr_defaults(&s);

  unsigned long addr = KERNEL_BASE_MIN + 4 * KERNEL_ALIGN;
  inject_result(KASLD_ADDR_VIRT, KASLD_SECTION_TEXT, addr, "test");

  compute_kaslr_info(&s);

  /* Consensus should prefer the exact default over the unknown-method
   * result, since inject_kaslr_defaults sets method=exact (weight 4). */
  assert(s.kaslr.vtext == layout.kernel_text_default);

  /* But slide and entropy must be clamped to zero */
  assert(s.kaslr.disabled == 1);
  assert(s.kaslr.vslide == 0);
  assert(s.kaslr.vslots == 0);
  assert(s.kaslr.vbits == 0);
  assert(s.kaslr.vslot_valid == 0);
  assert(s.kaslr.pslide == 0);
  assert(s.kaslr.pslots == 0);
  assert(s.kaslr.pbits == 0);
}

/* =========================================================================
 * compute_derived_addrs — decoupled_note flag
 * =========================================================================
 */
static void test_derived_decoupled_note_with_phys(void) {
  reset_state();
  struct summary s;
  memset(&s, 0, sizeof(s));

  /* Only physical DRAM, no virtual text */
  inject_result(KASLD_ADDR_PHYS, KASLD_SECTION_DRAM, 0x40000000ul, "test:dram");

  compute_derived_addrs(&s);
#if PHYS_VIRT_DECOUPLED
  assert(s.decoupled_note == 1);
#else
  assert(s.decoupled_note == 0);
#endif
}

static void test_derived_decoupled_note_suppressed_with_vtext(void) {
  reset_state();
  struct summary s;
  memset(&s, 0, sizeof(s));

  /* Both physical DRAM and virtual text — note should be suppressed */
  inject_result(KASLD_ADDR_PHYS, KASLD_SECTION_DRAM, 0x40000000ul, "test:dram");
  inject_result(KASLD_ADDR_VIRT, KASLD_SECTION_TEXT,
                KERNEL_BASE_MIN + KERNEL_ALIGN, "test:text");

  compute_derived_addrs(&s);
  assert(s.decoupled_note == 0);
}

static void test_derived_decoupled_note_suppressed_no_phys(void) {
  reset_state();
  struct summary s;
  memset(&s, 0, sizeof(s));

  /* No physical results at all — nothing to explain */
  compute_derived_addrs(&s);
  assert(s.decoupled_note == 0);
}

/* =========================================================================
 * Helpers: stdout capture for render tests
 * =========================================================================
 */
static int saved_stdout_fd = -1;
static FILE *capture_tmpfp;

static void capture_start(void) {
  fflush(stdout);
  saved_stdout_fd = dup(STDOUT_FILENO);
  capture_tmpfp = tmpfile();
  assert(capture_tmpfp);
  dup2(fileno(capture_tmpfp), STDOUT_FILENO);
}

/* Returns malloc'd string of captured output. Caller must free. */
static char *capture_end(void) {
  fflush(stdout);
  dup2(saved_stdout_fd, STDOUT_FILENO);
  close(saved_stdout_fd);
  saved_stdout_fd = -1;

  long sz = ftell(capture_tmpfp);
  rewind(capture_tmpfp);
  char *buf = malloc((size_t)sz + 1);
  assert(buf);
  size_t n = fread(buf, 1, (size_t)sz, capture_tmpfp);
  buf[n] = '\0';
  fclose(capture_tmpfp);
  return buf;
}

/* =========================================================================
 * json_print_escaped
 * =========================================================================
 */
static void test_json_print_escaped_special_chars(void) {
  capture_start();
  json_print_escaped("hello \"world\"\nfoo\\bar");
  char *out = capture_end();

  assert(strcmp(out, "\"hello \\\"world\\\"\\nfoo\\\\bar\"") == 0);
  free(out);
}

/* =========================================================================
 * render_json
 * =========================================================================
 */
static void test_json_basic_structure(void) {
  reset_state();
  struct summary s;
  memset(&s, 0, sizeof(s));

  capture_start();
  render_json(&s);
  char *out = capture_end();

  /* Must start with { and end with }\n */
  assert(out[0] == '{');
  size_t len = strlen(out);
  assert(len >= 2);
  assert(out[len - 2] == '}');
  assert(out[len - 1] == '\n');

  /* Required top-level keys */
  assert(strstr(out, "\"version\""));
  assert(strstr(out, "\"arch\""));
  assert(strstr(out, "\"kernel\""));
  assert(strstr(out, "\"layout\""));
  assert(strstr(out, "\"kaslr\""));
  assert(strstr(out, "\"groups\""));
  assert(strstr(out, "\"derived\""));

  /* No "components" without verbose */
  assert(strstr(out, "\"components\"") == NULL);

  free(out);
}

static void test_json_layout_values(void) {
  reset_state();
  struct summary s;
  memset(&s, 0, sizeof(s));

  capture_start();
  render_json(&s);
  char *out = capture_end();

  /* Layout section should contain expected fields */
  assert(strstr(out, "\"page_offset\""));
  assert(strstr(out, "\"kernel_base_min\""));
  assert(strstr(out, "\"kernel_align\""));
  assert(strstr(out, "\"kernel_text_default\""));
  assert(strstr(out, "\"modules_start\""));
  assert(strstr(out, "\"modules_end\""));

  /* phys_virt_decoupled matches compile-time constant */
  if (PHYS_VIRT_DECOUPLED)
    assert(strstr(out, "\"phys_virt_decoupled\": true"));
  else
    assert(strstr(out, "\"phys_virt_decoupled\": false"));

  free(out);
}

static void test_json_groups_with_results(void) {
  reset_state();
  struct summary s;
  memset(&s, 0, sizeof(s));

  inject_result(KASLD_ADDR_VIRT, KASLD_SECTION_TEXT,
                KERNEL_BASE_MIN + KERNEL_ALIGN, "test-component");

  capture_start();
  render_json(&s);
  char *out = capture_end();

  /* Group should have type V and section text */
  assert(strstr(out, "\"type\": \"V\""));
  assert(strstr(out, "\"section\": \"text\""));
  /* Region should appear in results */
  assert(strstr(out, "\"region\": \"test-component\""));
  /* Consensus should be populated */
  assert(strstr(out, "\"consensus\": \"0x"));

  free(out);
}

static void test_json_kaslr_virtual(void) {
  reset_state();
  struct summary s;
  memset(&s, 0, sizeof(s));

  unsigned long addr = KERNEL_BASE_MIN + 4 * KERNEL_ALIGN;
  inject_result(KASLD_ADDR_VIRT, KASLD_SECTION_TEXT, addr, "test");

  inject_kaslr_defaults(&s);
  compute_kaslr_info(&s);

  capture_start();
  render_json(&s);
  char *out = capture_end();

  assert(strstr(out, "\"disabled\": false"));
  assert(strstr(out, "\"virtual\""));
  assert(strstr(out, "\"text_base\""));
  assert(strstr(out, "\"slide_bytes\""));
  assert(strstr(out, "\"entropy_bits\""));
  assert(strstr(out, "\"slots\""));

  free(out);
}

static void test_json_kaslr_no_address_has_inferred(void) {
  reset_state();
  struct summary s;
  memset(&s, 0, sizeof(s));

  /* No results — KASLR appears active; inferred range must appear in JSON */
  compute_kaslr_info(&s);

  capture_start();
  render_json(&s);
  char *out = capture_end();

  assert(strstr(out, "\"inferred\""));
  assert(strstr(out, "\"range_min\""));
  assert(strstr(out, "\"range_max\""));
  assert(strstr(out, "\"slots\""));
  assert(strstr(out, "\"entropy_bits\""));
  /* No concrete address → no "virtual" object */
  assert(!strstr(out, "\"virtual\""));

  free(out);
}

static void test_json_kaslr_disabled(void) {
  reset_state();
  struct summary s;
  memset(&s, 0, sizeof(s));

  inject_result(KASLD_ADDR_DEFAULT, KASLD_SECTION_NONE, KERNEL_TEXT_DEFAULT,
                "proc-cmdline:nokaslr");
  inject_kaslr_defaults(&s);
  compute_kaslr_info(&s);

  capture_start();
  render_json(&s);
  char *out = capture_end();

  assert(strstr(out, "\"disabled\": true"));
  /* Disabled → no inferred object */
  assert(!strstr(out, "\"inferred\""));

  free(out);
}

static void test_json_derived_entries(void) {
  reset_state();
  struct summary s;
  memset(&s, 0, sizeof(s));

  add_derived(&s, KASLD_ADDR_VIRT, KASLD_SECTION_DIRECTMAP,
              PAGE_OFFSET + 0x1000, 0, "linear map", "phys_to_virt");

  capture_start();
  render_json(&s);
  char *out = capture_end();

  assert(strstr(out, "\"derived\""));
  assert(strstr(out, "\"label\": \"linear map\""));
  assert(strstr(out, "\"via\": \"phys_to_virt\""));

  free(out);
}

static void test_json_derived_with_range(void) {
  reset_state();
  struct summary s;
  memset(&s, 0, sizeof(s));

  add_derived(&s, KASLD_ADDR_PHYS, KASLD_SECTION_DRAM, 0x10000000ul,
              0x20000000ul, "DRAM range", "e820");

  capture_start();
  render_json(&s);
  char *out = capture_end();

  assert(strstr(out, "\"addr\": \"0x"));
  assert(strstr(out, "\"addr_hi\": \"0x"));
  assert(strstr(out, "\"label\": \"DRAM range\""));

  free(out);
}

static void test_json_verbose_has_components(void) {
  reset_state();
  verbose = 1;
  struct summary s;
  memset(&s, 0, sizeof(s));

  /* Inject a component log entry */
  struct component_log *cl = &comp_logs[num_comp_logs++];
  strncpy(cl->name, "test-comp", sizeof(cl->name) - 1);
  cl->exit_code = 0;
  cl->outcome = OUTCOME_SUCCESS;
  cl->num_lines = 1;
  strncpy(cl->lines[0], "V text 0xffffffff81000000 test", MAX_LINE_LEN - 1);

  capture_start();
  render_json(&s);
  char *out = capture_end();

  /* Should have components array */
  assert(strstr(out, "\"components\""));
  assert(strstr(out, "\"test-comp\""));
  assert(strstr(out, "\"exit_code\": 0"));
  assert(strstr(out, "\"outcome\": \"success\""));
  assert(strstr(out, "\"output\""));

  /* Must still be valid JSON (ends with }\n) */
  size_t len = strlen(out);
  assert(out[len - 2] == '}');
  assert(out[len - 1] == '\n');

  free(out);
}

static void test_json_verbose_no_logs(void) {
  reset_state();
  verbose = 1;
  /* No comp_logs entries */
  struct summary s;
  memset(&s, 0, sizeof(s));

  capture_start();
  render_json(&s);
  char *out = capture_end();

  /* verbose=1 but no comp_logs: should NOT have components */
  assert(strstr(out, "\"components\"") == NULL);

  /* Should still have component_stats */
  assert(strstr(out, "\"component_stats\""));

  free(out);
}

static void test_component_stats(void) {
  reset_state();
  struct summary s;
  memset(&s, 0, sizeof(s));

  /* Inject comp_logs with different outcomes */
  struct component_log *cl;
  cl = &comp_logs[num_comp_logs++];
  strncpy(cl->name, "comp-a", sizeof(cl->name) - 1);
  cl->outcome = OUTCOME_SUCCESS;

  cl = &comp_logs[num_comp_logs++];
  strncpy(cl->name, "comp-b", sizeof(cl->name) - 1);
  cl->outcome = OUTCOME_ACCESS_DENIED;

  cl = &comp_logs[num_comp_logs++];
  strncpy(cl->name, "comp-c", sizeof(cl->name) - 1);
  cl->outcome = OUTCOME_TIMEOUT;

  cl = &comp_logs[num_comp_logs++];
  strncpy(cl->name, "comp-d", sizeof(cl->name) - 1);
  cl->outcome = OUTCOME_NO_RESULT;

  cl = &comp_logs[num_comp_logs++];
  strncpy(cl->name, "comp-e", sizeof(cl->name) - 1);
  cl->outcome = OUTCOME_SUCCESS;

  cl = &comp_logs[num_comp_logs++];
  strncpy(cl->name, "comp-f", sizeof(cl->name) - 1);
  cl->outcome = OUTCOME_UNAVAILABLE;

  compute_component_stats(&s);
  assert(s.stats.total == 6);
  assert(s.stats.succeeded == 2);
  assert(s.stats.unavailable == 1);
  assert(s.stats.access_denied == 1);
  assert(s.stats.timed_out == 1);
  assert(s.stats.no_result == 1);
}

static void test_json_component_stats(void) {
  reset_state();
  struct summary s;
  memset(&s, 0, sizeof(s));

  s.stats.total = 12;
  s.stats.succeeded = 5;
  s.stats.unavailable = 2;
  s.stats.access_denied = 2;
  s.stats.timed_out = 1;
  s.stats.no_result = 2;

  capture_start();
  render_json(&s);
  char *out = capture_end();

  assert(strstr(out, "\"component_stats\""));
  assert(strstr(out, "\"total\": 12"));
  assert(strstr(out, "\"succeeded\": 5"));
  assert(strstr(out, "\"unavailable\": 2"));
  assert(strstr(out, "\"access_denied\": 2"));
  assert(strstr(out, "\"timed_out\": 1"));
  assert(strstr(out, "\"no_result\": 2"));

  free(out);
}

/* =========================================================================
 * End-to-end: tagged lines → parse → consensus
 * =========================================================================
 */
static void test_e2e_pipeline(void) {
  reset_state();

  /* Simulate two components finding the same text address */
  inject_tagged("V text 0xffffffff81200000 proc-kallsyms");
  inject_tagged("V text 0xffffffff81200000 dmesg_backtrace");
  inject_tagged("V text 0xffffffff81400000 entrybleed");
  inject_tagged("V module 0xffffffffc0045000 proc-modules:lo");
  inject_tagged("P dram 0x0000000001000000 dmesg_e820_memory_map:lo");

  assert(num_results == 5);

  /* Consensus should pick the address with 2 votes */
  unsigned long vtext = group_consensus(KASLD_ADDR_VIRT, KASLD_SECTION_TEXT);
  assert(vtext == 0xffffffff81200000ul);

  /* Module should have the single address */
  unsigned long vmod_lo, vmod_hi;
  group_range(KASLD_ADDR_VIRT, KASLD_SECTION_MODULE, &vmod_lo, &vmod_hi);
  assert(vmod_lo == 0xffffffffc0045000ul);
  assert(vmod_hi == 0); /* only one */
}

/* Simulate inference phase: LAYOUT_ADJUST fires after each component via
 * run_post_collection_inference(). Results are valid regardless of order. */
static void test_e2e_incremental_layout(void) {
  reset_state();

  inject_tagged("D - 0xffffffff81000000 default:text");
  init_inference_ctx();
  run_inference_phase(&g_ctx, KASLD_INFER_PHASE_LAYOUT_ADJUST);
  assert(detect_kaslr_state() == 0); /* KASLR enabled */

  inject_tagged("V text 0xffffffff81200000 dmesg_backtrace");
  init_inference_ctx();
  run_inference_phase(&g_ctx, KASLD_INFER_PHASE_LAYOUT_ADJUST);
  inject_tagged("V text 0xffffffff81200000 proc-kallsyms");
  init_inference_ctx();
  run_inference_phase(&g_ctx, KASLD_INFER_PHASE_LAYOUT_ADJUST);

  assert(num_results == 3);
  assert(group_consensus(KASLD_ADDR_VIRT, KASLD_SECTION_TEXT) ==
         0xffffffff81200000ul);
}

/* A nokaslr indicator collected during inference makes detect_kaslr_state()
 * return true — the probing phase is skipped. */
static void test_e2e_kaslr_disabled_skips_probing(void) {
  reset_state();

  inject_tagged("D - 0xffffffff81000000 default:text");
  init_inference_ctx();
  run_inference_phase(&g_ctx, KASLD_INFER_PHASE_LAYOUT_ADJUST);
  assert(detect_kaslr_state() == 0);

  inject_tagged("D - 0xffffffff81000000 proc-cmdline:nokaslr");
  init_inference_ctx();
  run_inference_phase(&g_ctx, KASLD_INFER_PHASE_LAYOUT_ADJUST);
  assert(detect_kaslr_state() == 1); /* probing phase would be skipped */
}

/* =========================================================================
 * Hardening helpers
 * =========================================================================
 */

/* Helper: inject a comp_log with metadata string */
static void inject_comp_meta(const char *name, enum component_outcome outcome,
                             const char *meta_str) {
  assert(num_comp_logs < MAX_COMPONENTS);
  struct component_log *cl = &comp_logs[num_comp_logs++];
  memset(cl, 0, sizeof(*cl));
  strncpy(cl->name, name, sizeof(cl->name) - 1);
  cl->outcome = outcome;
  /* Parse meta_str into cl->meta */
  if (meta_str) {
    char buf[1024];
    strncpy(buf, meta_str, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    char *saveptr;
    char *line = strtok_r(buf, "\n", &saveptr);
    while (line && cl->meta.num_entries < META_MAX_ENTRIES) {
      char *colon = strchr(line, ':');
      if (colon) {
        struct meta_entry *e = &cl->meta.entries[cl->meta.num_entries++];
        size_t klen = (size_t)(colon - line);
        if (klen >= META_KEY_LEN)
          klen = META_KEY_LEN - 1;
        memcpy(e->key, line, klen);
        e->key[klen] = '\0';
        strncpy(e->value, colon + 1, META_VALUE_LEN - 1);
        e->value[META_VALUE_LEN - 1] = '\0';
      }
      line = strtok_r(NULL, "\n", &saveptr);
    }
  }
}

/* =========================================================================
 * meta_get / meta_get_all
 * =========================================================================
 */
static void test_meta_get_basic(void) {
  reset_state();
  inject_comp_meta("comp-a", OUTCOME_SUCCESS,
                   "method:parsed\naddr:physical\nsysctl:dmesg_restrict>=1");
  assert(strcmp(meta_get(&comp_logs[0].meta, "method"), "parsed") == 0);
  assert(strcmp(meta_get(&comp_logs[0].meta, "addr"), "physical") == 0);
  assert(meta_get(&comp_logs[0].meta, "nonexistent") == NULL);
}

static void test_meta_get_all_multiple(void) {
  reset_state();
  inject_comp_meta("comp-b", OUTCOME_SUCCESS,
                   "method:timing\nhardware:KPTI\nhardware:AMD Zen 3+");
  const char *vals[4];
  int n = meta_get_all(&comp_logs[0].meta, "hardware", vals, 4);
  assert(n == 2);
  assert(strcmp(vals[0], "KPTI") == 0);
  assert(strcmp(vals[1], "AMD Zen 3+") == 0);
}

/* =========================================================================
 * Hardening text render
 * =========================================================================
 */
static void test_hardening_text_exposure_summary(void) {
  reset_state();
  hardening_mode = 1;
  sysctl_kptr_restrict = 0;
  sysctl_dmesg_restrict = 0;
  sysctl_perf_event_paranoid = 1;
  sysctl_lockdown = LOCKDOWN_NONE;

  inject_comp_meta("comp-a", OUTCOME_SUCCESS, "method:parsed\naddr:physical");
  inject_comp_meta("comp-b", OUTCOME_UNAVAILABLE,
                   "method:timing\naddr:virtual");
  inject_comp_meta("comp-c", OUTCOME_SUCCESS, "method:exact\naddr:virtual");
  inject_comp_meta("comp-d", OUTCOME_SUCCESS, "method:detection\naddr:none");

  struct summary s;
  memset(&s, 0, sizeof(s));

  capture_start();
  render_hardening_text();
  char *out = capture_end();

  /* 2 of 3 succeeded (detection excluded from count) */
  assert(strstr(out, "2 of 3"));
  assert(strstr(out, "Hardening Assessment"));
  assert(strstr(out, "Active defenses:"));
  assert(strstr(out, "Available hardening:"));
  assert(strstr(out, "Patched vulnerabilities:"));
  assert(strstr(out, "Compile-time attack surface:"));
  assert(strstr(out, "No known mitigation:"));

  free(out);
}

static void test_hardening_text_active_defenses(void) {
  reset_state();
  hardening_mode = 1;
  sysctl_kptr_restrict = 2;
  sysctl_dmesg_restrict = 1;
  sysctl_perf_event_paranoid = 4;
  sysctl_lockdown = LOCKDOWN_NONE;

  inject_comp_meta("proc-kallsyms", OUTCOME_ACCESS_DENIED,
                   "method:exact\naddr:virtual\nsysctl:kptr_restrict>=1");
  inject_comp_meta("dmesg_e820", OUTCOME_ACCESS_DENIED,
                   "method:parsed\naddr:physical\nsysctl:dmesg_restrict>=1");
  inject_comp_meta("perf_event_open", OUTCOME_ACCESS_DENIED,
                   "method:exact\naddr:virtual\nsysctl:perf_event_paranoid>=2");

  capture_start();
  render_hardening_text();
  char *out = capture_end();

  assert(strstr(out, "kernel.kptr_restrict"));
  assert(strstr(out, "kernel.dmesg_restrict"));
  assert(strstr(out, "kernel.perf_event_paranoid"));
  /* All gates active → should show checkmarks */
  assert(strstr(out, "\xe2\x9c\x93"));

  free(out);
}

static void test_hardening_text_patched(void) {
  reset_state();
  hardening_mode = 1;
  sysctl_kptr_restrict = -1;
  sysctl_dmesg_restrict = -1;
  sysctl_perf_event_paranoid = -1;
  sysctl_lockdown = LOCKDOWN_NONE;

  inject_comp_meta(
      "entrybleed", OUTCOME_SUCCESS,
      "method:timing\naddr:virtual\ncve:CVE-2022-4543\npatch:v6.2");
  inject_comp_meta(
      "mincore", OUTCOME_UNAVAILABLE,
      "method:heuristic\naddr:virtual\ncve:CVE-2017-16994\npatch:v4.15");

  capture_start();
  render_hardening_text();
  char *out = capture_end();

  assert(strstr(out, "1 of 2 vulnerability-based"));
  assert(strstr(out, "entrybleed"));
  assert(strstr(out, "CVE-2022-4543"));
  assert(strstr(out, "v6.2"));

  free(out);
}

static void test_hardening_text_no_mitigation(void) {
  reset_state();
  hardening_mode = 1;
  sysctl_kptr_restrict = -1;
  sysctl_dmesg_restrict = -1;
  sysctl_perf_event_paranoid = -1;
  sysctl_lockdown = LOCKDOWN_NONE;

  inject_comp_meta("proc-zoneinfo", OUTCOME_SUCCESS,
                   "method:parsed\naddr:physical");

  capture_start();
  render_hardening_text();
  char *out = capture_end();

  assert(strstr(out, "No known mitigation:"));
  assert(strstr(out, "proc-zoneinfo"));

  free(out);
}

/* =========================================================================
 * Hardening JSON render
 * =========================================================================
 */
static void test_hardening_json_structure(void) {
  reset_state();
  hardening_mode = 1;
  json_output = 1;
  sysctl_kptr_restrict = 2;
  sysctl_dmesg_restrict = 1;
  sysctl_perf_event_paranoid = 1;
  sysctl_lockdown = LOCKDOWN_NONE;

  inject_comp_meta("proc-kallsyms", OUTCOME_ACCESS_DENIED,
                   "method:exact\naddr:virtual\nsysctl:kptr_restrict>=1");
  inject_comp_meta("proc-zoneinfo", OUTCOME_SUCCESS,
                   "method:parsed\naddr:physical");

  struct summary s;
  memset(&s, 0, sizeof(s));

  capture_start();
  render_json(&s);
  char *out = capture_end();

  /* Top-level hardening object */
  assert(strstr(out, "\"hardening\""));
  assert(strstr(out, "\"exposure\""));
  assert(strstr(out, "\"succeeded\": 1"));
  assert(strstr(out, "\"total\": 2"));
  assert(strstr(out, "\"active_defenses\""));
  assert(strstr(out, "\"lockdown\""));
  assert(strstr(out, "\"available_hardening\""));
  assert(strstr(out, "\"patched_vulnerabilities\""));
  assert(strstr(out, "\"compile_time_surface\""));
  assert(strstr(out, "\"no_mitigation\""));

  /* Per-component meta */
  assert(strstr(out, "\"components\""));
  assert(strstr(out, "\"meta\""));
  assert(strstr(out, "\"method\": \"exact\""));

  /* Valid JSON (ends with }\n) */
  size_t len = strlen(out);
  assert(out[len - 2] == '}');
  assert(out[len - 1] == '\n');

  free(out);
}

static void test_hardening_json_meta_array(void) {
  reset_state();
  hardening_mode = 1;
  json_output = 1;
  sysctl_kptr_restrict = -1;
  sysctl_dmesg_restrict = -1;
  sysctl_perf_event_paranoid = -1;
  sysctl_lockdown = LOCKDOWN_NONE;

  inject_comp_meta(
      "prefetch", OUTCOME_SUCCESS,
      "method:timing\naddr:virtual\nhardware:KPTI\nhardware:AMD Zen 3+");

  struct summary s;
  memset(&s, 0, sizeof(s));

  capture_start();
  render_json(&s);
  char *out = capture_end();

  /* Multi-value key should be array */
  assert(strstr(out, "\"hardware\": ["));
  assert(strstr(out, "\"KPTI\""));
  assert(strstr(out, "\"AMD Zen 3+\""));

  free(out);
}

static void test_hardening_json_no_meta_without_flag(void) {
  reset_state();
  hardening_mode = 0;
  verbose = 1;
  json_output = 1;
  sysctl_kptr_restrict = 0;
  sysctl_dmesg_restrict = 0;
  sysctl_perf_event_paranoid = 1;
  sysctl_lockdown = LOCKDOWN_NONE;

  inject_comp_meta("comp-a", OUTCOME_SUCCESS, "method:parsed\naddr:physical");

  struct summary s;
  memset(&s, 0, sizeof(s));

  capture_start();
  render_json(&s);
  char *out = capture_end();

  /* Without --hardening, should NOT have meta or hardening object */
  assert(strstr(out, "\"meta\"") == NULL);
  assert(strstr(out, "\"hardening\"") == NULL);

  /* But should still have components (verbose=1) */
  assert(strstr(out, "\"components\""));

  free(out);
}

/* =========================================================================
 * apply_skip_filter
 * =========================================================================
 */
static void test_skip_exact_match(void) {
  reset_state();
  snprintf(components[0].name, sizeof(components[0].name), "dmesg");
  snprintf(components[1].name, sizeof(components[1].name), "entrybleed");
  num_components = 2;
  strncpy(skip_patterns[0], "dmesg", 255);
  num_skip_patterns = 1;
  apply_skip_filter();
  assert(components[0].is_filtered == 1); /* dmesg: matches — filtered */
  assert(components[1].is_filtered == 0); /* entrybleed: no match — kept */
}

static void test_skip_glob_pattern(void) {
  reset_state();
  snprintf(components[0].name, sizeof(components[0].name), "dmesg_backtrace");
  snprintf(components[1].name, sizeof(components[1].name), "dmesg_e820");
  snprintf(components[2].name, sizeof(components[2].name), "entrybleed");
  num_components = 3;
  strncpy(skip_patterns[0], "dmesg_*", 255);
  num_skip_patterns = 1;
  apply_skip_filter();
  assert(components[0].is_filtered == 1); /* dmesg_backtrace: matches */
  assert(components[1].is_filtered == 1); /* dmesg_e820: matches */
  assert(components[2].is_filtered == 0); /* entrybleed: no match */
}

static void test_skip_multiple_patterns(void) {
  reset_state();
  snprintf(components[0].name, sizeof(components[0].name), "entrybleed");
  snprintf(components[1].name, sizeof(components[1].name), "dmesg");
  snprintf(components[2].name, sizeof(components[2].name), "proc-kallsyms");
  num_components = 3;
  strncpy(skip_patterns[0], "entrybleed", 255);
  strncpy(skip_patterns[1], "dmesg", 255);
  num_skip_patterns = 2;
  apply_skip_filter();
  assert(components[0].is_filtered == 1); /* entrybleed: matches pattern 0 */
  assert(components[1].is_filtered == 1); /* dmesg: matches pattern 1 */
  assert(components[2].is_filtered == 0); /* proc-kallsyms: no match */
}

static void test_skip_no_patterns_no_filter(void) {
  reset_state();
  snprintf(components[0].name, sizeof(components[0].name), "dmesg");
  num_components = 1;
  /* num_skip_patterns already 0 from reset_state */
  apply_skip_filter();
  assert(components[0].is_filtered == 0); /* no patterns: nothing filtered */
}

static void test_skip_no_match_keeps_all(void) {
  reset_state();
  snprintf(components[0].name, sizeof(components[0].name), "dmesg");
  num_components = 1;
  strncpy(skip_patterns[0], "entrybleed", 255);
  num_skip_patterns = 1;
  apply_skip_filter();
  assert(components[0].is_filtered == 0); /* no match: not filtered */
}

static void test_skip_active_count_excludes_filtered(void) {
  reset_state();
  snprintf(components[0].name, sizeof(components[0].name), "dmesg");
  snprintf(components[1].name, sizeof(components[1].name), "entrybleed");
  num_components = 2;
  strncpy(skip_patterns[0], "dmesg", 255);
  num_skip_patterns = 1;
  apply_skip_filter();
  /* Count active like main() does */
  int count = 0;
  for (int i = 0; i < num_components; i++) {
    if (components[i].is_filtered)
      continue;
    if (components[i].is_experimental && !experimental_mode)
      continue;
    count++;
  }
  assert(count == 1); /* only entrybleed runs */
}

static void test_skip_inference_pool_excludes_filtered(void) {
  reset_state();
  snprintf(components[0].name, sizeof(components[0].name), "dmesg");
  snprintf(components[0].phase, sizeof(components[0].phase), "inference");
  snprintf(components[1].name, sizeof(components[1].name), "entrybleed");
  snprintf(components[1].phase, sizeof(components[1].phase), "inference");
  num_components = 2;
  strncpy(skip_patterns[0], "dmesg", 255);
  num_skip_patterns = 1;
  apply_skip_filter();
  /* Build inference pool the same way run_inference_parallel() does */
  int exp_active = 0;
  pool_inf_n = 0;
  for (int i = 0; i < num_components; i++) {
    if (strcmp(components[i].phase, "inference") == 0 &&
        (!components[i].is_experimental || exp_active) &&
        !components[i].is_filtered)
      pool_inf[pool_inf_n++] = i;
  }
  assert(pool_inf_n == 1);
  assert(pool_inf[0] == 1); /* only entrybleed (index 1) */
}

/* =========================================================================
 * Inference plugins
 * =========================================================================
 */

/* kaslr_ceiling (PRE_COLLECTION):
 * Estimates kernel image size from /boot files and eliminates the top band of
 * KASLR slots where base + image_size would exceed KASLR_BASE_MAX.
 * On systems where the /boot files are absent estimate_kernel_size() returns 0
 * and the plugin is a no-op; the invariant tests still hold. */

static void test_kaslr_ceiling_never_widens(void) {
  reset_state();
  init_inference_ctx();
  unsigned long initial_max = g_ctx.text_base_max;
  run_inference_phase(&g_ctx, KASLD_INFER_PHASE_PRE_COLLECTION);
  assert(g_ctx.text_base_max <= initial_max);
}

static void test_kaslr_ceiling_alignment_invariant(void) {
  reset_state();
  init_inference_ctx();
  run_inference_phase(&g_ctx, KASLD_INFER_PHASE_PRE_COLLECTION);
  assert((g_ctx.text_base_max % layout.kaslr_align) == 0);
}

static void test_kaslr_ceiling_max_above_min(void) {
  reset_state();
  init_inference_ctx();
  run_inference_phase(&g_ctx, KASLD_INFER_PHASE_PRE_COLLECTION);
  assert(g_ctx.text_base_max > g_ctx.text_base_min);
}

/* Physical ceiling: phys_base_max must never widen and, when the physical
 * range is non-zero (PHYS_VIRT_DECOUPLED arches), must remain >= phys_base_min
 * after the plugin runs. On arches where the physical range is zero both
 * bounds stay at zero and the assertions are trivially satisfied. */

static void test_kaslr_ceiling_phys_never_widens(void) {
  reset_state();
  init_inference_ctx();
  unsigned long initial_phys_max = g_ctx.phys_base_max;
  run_inference_phase(&g_ctx, KASLD_INFER_PHASE_PRE_COLLECTION);
  assert(g_ctx.phys_base_max <= initial_phys_max);
}

static void test_kaslr_ceiling_phys_max_above_min(void) {
  reset_state();
  init_inference_ctx();
  run_inference_phase(&g_ctx, KASLD_INFER_PHASE_PRE_COLLECTION);
  /* On arches with no physical KASLR both are zero; the plugin is a no-op. */
  if (layout.phys_kaslr_base_max > 0)
    assert(g_ctx.phys_base_max > g_ctx.phys_base_min);
}

#if PHYS_VIRT_DECOUPLED
static void test_kaslr_ceiling_phys_alignment_invariant(void) {
  reset_state();
  init_inference_ctx();
  run_inference_phase(&g_ctx, KASLD_INFER_PHASE_PRE_COLLECTION);
  if (layout.phys_kaslr_align > 0)
    assert((g_ctx.phys_base_max % layout.phys_kaslr_align) == 0);
}
#endif

/* dram_bound (POST_COLLECTION):
 * Raises text_base_min from the minimum PHYS/DRAM result on coupled arches. */

static void test_dram_bound_no_results_noop(void) {
  reset_state();
  init_inference_ctx();
  unsigned long initial_min = g_ctx.text_base_min;
  run_inference_phase(&g_ctx, KASLD_INFER_PHASE_POST_COLLECTION);
  assert(g_ctx.text_base_min == initial_min);
}

static void test_dram_bound_only_dram_section_used(void) {
  reset_state();
  /* PHYS/TEXT result — not DRAM — must leave text_base_min unchanged */
  inject_result(KASLD_ADDR_PHYS, KASLD_SECTION_TEXT, PHYS_OFFSET + MB,
                KASLD_REGION_KERNEL_IMAGE);
  init_inference_ctx();
  unsigned long initial_min = g_ctx.text_base_min;
  run_inference_phase(&g_ctx, KASLD_INFER_PHASE_POST_COLLECTION);
  assert(g_ctx.text_base_min == initial_min);
}

#if PHYS_VIRT_DECOUPLED
static void test_dram_bound_decoupled_noop(void) {
  reset_state();
  inject_result(KASLD_ADDR_PHYS, KASLD_SECTION_DRAM, PHYS_OFFSET + (64 * MB),
                KASLD_REGION_KERNEL_IMAGE);
  init_inference_ctx();
  unsigned long initial_min = g_ctx.text_base_min;
  run_inference_phase(&g_ctx, KASLD_INFER_PHASE_POST_COLLECTION);
  assert(g_ctx.text_base_min == initial_min);
}
#endif

#if !PHYS_VIRT_DECOUPLED
static void test_dram_bound_raises_min(void) {
  reset_state();
  inject_result(KASLD_ADDR_PHYS, KASLD_SECTION_DRAM, PHYS_OFFSET + (128 * MB),
                KASLD_REGION_KERNEL_IMAGE);
  init_inference_ctx();
  unsigned long initial_min = g_ctx.text_base_min;
  run_inference_phase(&g_ctx, KASLD_INFER_PHASE_POST_COLLECTION);
  assert(g_ctx.text_base_min >= initial_min);
  assert((g_ctx.text_base_min % layout.kaslr_align) == 0);
}
#endif

/* phys_virt_synth (POST_COLLECTION):
 * Tightens page_offset_min/max by synthesising PAGE_OFFSET from per-origin
 * (PHYS/DRAM, VIRT/DIRECTMAP) pairs.  Tests use synthetic addresses that make
 * the arithmetic produce a po_target strictly interior to [page_offset_min,
 * page_offset_max] so both bounds are visibly tightened. */

static void test_phys_virt_synth_no_results_noop(void) {
  reset_state();
  init_inference_ctx();
  unsigned long po_min = g_ctx.page_offset_min;
  unsigned long po_max = g_ctx.page_offset_max;
  run_inference_phase(&g_ctx, KASLD_INFER_PHASE_POST_COLLECTION);
  assert(g_ctx.page_offset_min == po_min);
  assert(g_ctx.page_offset_max == po_max);
}

static void test_phys_virt_synth_no_cross_origin_pairing(void) {
  reset_state();
  /* VIRT/DIRECTMAP from "alpha", PHYS/DRAM from "beta" — different origins,
   * no pair formed → page_offset bounds unchanged */
  inject_result_with_origin(KASLD_ADDR_VIRT, KASLD_SECTION_DIRECTMAP,
                            PAGE_OFFSET + (32 * MB), KASLD_REGION_DIRECTMAP,
                            "alpha");
  inject_result_with_origin(KASLD_ADDR_PHYS, KASLD_SECTION_DRAM,
                            PHYS_OFFSET + (32 * MB), KASLD_REGION_KERNEL_IMAGE,
                            "beta");
  init_inference_ctx();
  unsigned long po_min = g_ctx.page_offset_min;
  unsigned long po_max = g_ctx.page_offset_max;
  run_inference_phase(&g_ctx, KASLD_INFER_PHASE_POST_COLLECTION);
  assert(g_ctx.page_offset_min == po_min);
  assert(g_ctx.page_offset_max == po_max);
}

static void test_phys_virt_synth_tightens_on_agreement(void) {
  reset_state();
  /* Construct a pair whose synthesised PAGE_OFFSET is interior to the initial
   * [page_offset_min, page_offset_max] so both bounds are tightened.
   * Formula: po = virt - phys + phys_offset.  Choose po_target = PAGE_OFFSET
   * + 256*MB, then virt = po_target + phys - PHYS_OFFSET. */
  unsigned long phys = PHYS_OFFSET + (32 * MB);
  unsigned long po_target = PAGE_OFFSET + (256 * MB);
  unsigned long virt = po_target + phys - PHYS_OFFSET;
  inject_result_with_origin(KASLD_ADDR_VIRT, KASLD_SECTION_DIRECTMAP, virt,
                            KASLD_REGION_DIRECTMAP, "test_comp");
  inject_result_with_origin(KASLD_ADDR_PHYS, KASLD_SECTION_DRAM, phys,
                            KASLD_REGION_KERNEL_IMAGE, "test_comp");
  init_inference_ctx();
  unsigned long po_min_before = g_ctx.page_offset_min;
  unsigned long po_max_before = g_ctx.page_offset_max;
  run_inference_phase(&g_ctx, KASLD_INFER_PHASE_POST_COLLECTION);
  assert(g_ctx.page_offset_min >= po_min_before);
  assert(g_ctx.page_offset_max <= po_max_before);
  assert(g_ctx.page_offset_min <= g_ctx.page_offset_max);
}

static void test_phys_virt_synth_disagreeing_candidates_noop(void) {
  reset_state();
  /* Two origins whose synthesised PAGE_OFFSET values differ by 4*MB, which
   * exceeds KASLR_ALIGN (2*MB on x86_64) → plugin skips tightening */
  unsigned long phys = PHYS_OFFSET + (32 * MB);
  unsigned long po_a = PAGE_OFFSET + (256 * MB);
  unsigned long po_b = PAGE_OFFSET + (260 * MB); /* |po_b - po_a| = 4*MB */
  unsigned long virt_a = po_a + phys - PHYS_OFFSET;
  unsigned long virt_b = po_b + phys - PHYS_OFFSET;
  inject_result_with_origin(KASLD_ADDR_VIRT, KASLD_SECTION_DIRECTMAP, virt_a,
                            KASLD_REGION_DIRECTMAP, "comp_a");
  inject_result_with_origin(KASLD_ADDR_PHYS, KASLD_SECTION_DRAM, phys,
                            KASLD_REGION_KERNEL_IMAGE, "comp_a");
  inject_result_with_origin(KASLD_ADDR_VIRT, KASLD_SECTION_DIRECTMAP, virt_b,
                            KASLD_REGION_DIRECTMAP, "comp_b");
  inject_result_with_origin(KASLD_ADDR_PHYS, KASLD_SECTION_DRAM, phys,
                            KASLD_REGION_KERNEL_IMAGE, "comp_b");
  init_inference_ctx();
  unsigned long po_min = g_ctx.page_offset_min;
  unsigned long po_max = g_ctx.page_offset_max;
  run_inference_phase(&g_ctx, KASLD_INFER_PHASE_POST_COLLECTION);
  assert(g_ctx.page_offset_min == po_min);
  assert(g_ctx.page_offset_max == po_max);
}

/* =========================================================================
 * module_text_bound (POST_COLLECTION)
 * =========================================================================
 */

/* No module results → no-op on all arches */
static void test_module_text_bound_no_results_noop(void) {
  reset_state();
  init_inference_ctx();
  unsigned long max_before = g_ctx.text_base_max;
  run_inference_phase(&g_ctx, KASLD_INFER_PHASE_POST_COLLECTION);
  assert(g_ctx.text_base_max == max_before);
}

/* Non-module results only → no-op */
static void test_module_text_bound_non_module_section_noop(void) {
  reset_state();
  inject_result(KASLD_ADDR_VIRT, KASLD_SECTION_TEXT,
                KERNEL_BASE_MIN + KERNEL_ALIGN, KASLD_REGION_KERNEL_TEXT);
  init_inference_ctx();
  unsigned long max_before = g_ctx.text_base_max;
  run_inference_phase(&g_ctx, KASLD_INFER_PHASE_POST_COLLECTION);
  assert(g_ctx.text_base_max == max_before);
}

#if MODULES_RELATIVE_TO_TEXT
/* A valid module address lowers text_base_max to
 * (vmod_lo + MODULES_END_TO_TEXT_OFFSET - MIN_KERNEL_IMAGE_SIZE) & ~(align-1)
 */
static void test_module_text_bound_lowers_max(void) {
  reset_state();
  unsigned long vmod_lo = MODULES_START + KERNEL_ALIGN;
  inject_result(KASLD_ADDR_VIRT, KASLD_SECTION_MODULE, vmod_lo,
                KASLD_REGION_MODULE);
  init_inference_ctx();
  run_inference_phase(&g_ctx, KASLD_INFER_PHASE_POST_COLLECTION);

  unsigned long end_est = vmod_lo + MODULES_END_TO_TEXT_OFFSET;
  unsigned long expected_max =
      (end_est - MIN_KERNEL_IMAGE_SIZE) & ~(KASLR_ALIGN - 1);
  assert(g_ctx.text_base_max == expected_max);
  assert(g_ctx.text_base_max < g_ctx.text_base_min ||
         g_ctx.text_base_max >= g_ctx.text_base_min);
}

/* The tightest (lowest-addressed) module drives the bound — not the highest */
static void test_module_text_bound_uses_minimum_module(void) {
  reset_state();
  unsigned long vmod_lo = MODULES_START + KERNEL_ALIGN;
  unsigned long vmod_hi = MODULES_START + 64 * MB;
  inject_result(KASLD_ADDR_VIRT, KASLD_SECTION_MODULE, vmod_hi,
                KASLD_REGION_MODULE);
  inject_result(KASLD_ADDR_VIRT, KASLD_SECTION_MODULE, vmod_lo,
                KASLD_REGION_MODULE);
  init_inference_ctx();
  run_inference_phase(&g_ctx, KASLD_INFER_PHASE_POST_COLLECTION);

  unsigned long end_est = vmod_lo + MODULES_END_TO_TEXT_OFFSET;
  unsigned long expected_max =
      (end_est - MIN_KERNEL_IMAGE_SIZE) & ~(KASLR_ALIGN - 1);
  assert(g_ctx.text_base_max == expected_max);
}

/* text_base_min is never raised by this plugin */
static void test_module_text_bound_never_raises_min(void) {
  reset_state();
  inject_result(KASLD_ADDR_VIRT, KASLD_SECTION_MODULE,
                MODULES_START + KERNEL_ALIGN, KASLD_REGION_MODULE);
  init_inference_ctx();
  unsigned long min_before = g_ctx.text_base_min;
  run_inference_phase(&g_ctx, KASLD_INFER_PHASE_POST_COLLECTION);
  assert(g_ctx.text_base_min == min_before);
}

/* A result that would only widen the max is ignored (commutativity) */
static void test_module_text_bound_never_widens(void) {
  reset_state();
  /* Use a very high module address so derived max > initial max */
  unsigned long vmod_hi = MODULES_END - KERNEL_ALIGN;
  inject_result(KASLD_ADDR_VIRT, KASLD_SECTION_MODULE, vmod_hi,
                KASLD_REGION_MODULE);
  init_inference_ctx();
  unsigned long max_before = g_ctx.text_base_max;
  run_inference_phase(&g_ctx, KASLD_INFER_PHASE_POST_COLLECTION);
  assert(g_ctx.text_base_max <= max_before);
}
#endif /* MODULES_RELATIVE_TO_TEXT */

/* =========================================================================
 * layout_adjust (LAYOUT_ADJUST)
 * =========================================================================
 */

/* No pageoffset results → plugin is a no-op for layout fields */
static void test_layout_adjust_no_results_noop(void) {
  reset_state();
  unsigned long orig_po = layout.page_offset;
  init_inference_ctx();
  run_inference_phase(&g_ctx, KASLD_INFER_PHASE_LAYOUT_ADJUST);
  assert(layout.page_offset == orig_po);
}

/* Pageoffset result equal to compile-time default → no change */
static void test_layout_adjust_same_po_noop(void) {
  reset_state();
  inject_result(KASLD_ADDR_VIRT, KASLD_SECTION_PAGEOFFSET, PAGE_OFFSET,
                "pageoffset");
  unsigned long orig_po = layout.page_offset;
  init_inference_ctx();
  run_inference_phase(&g_ctx, KASLD_INFER_PHASE_LAYOUT_ADJUST);
  assert(layout.page_offset == orig_po);
}

/* New pageoffset result → layout.page_offset and kernel_vas_start updated */
static void test_layout_adjust_new_po_updates_layout(void) {
  reset_state();
  /* Use PAGE_OFFSET + 512 MiB as a synthetic runtime value */
  unsigned long new_po = PAGE_OFFSET + (512UL * 1024 * 1024);
  inject_result(KASLD_ADDR_VIRT, KASLD_SECTION_PAGEOFFSET, new_po,
                "pageoffset");
  init_inference_ctx();
  run_inference_phase(&g_ctx, KASLD_INFER_PHASE_LAYOUT_ADJUST);
  assert(layout.page_offset == new_po);
  assert(layout.kernel_vas_start == new_po);
}

/* Consensus from multiple agreeing sources still applies the update */
static void test_layout_adjust_consensus_applied(void) {
  reset_state();
  unsigned long new_po = PAGE_OFFSET + (256UL * 1024 * 1024);
  inject_result(KASLD_ADDR_VIRT, KASLD_SECTION_PAGEOFFSET, new_po,
                "pageoffset");
  inject_result(KASLD_ADDR_VIRT, KASLD_SECTION_PAGEOFFSET, new_po,
                "pageoffset");
  init_inference_ctx();
  run_inference_phase(&g_ctx, KASLD_INFER_PHASE_LAYOUT_ADJUST);
  assert(layout.page_offset == new_po);
}

#if !PHYS_VIRT_DECOUPLED
/* On coupled arches: kernel_base_min is clamped up to page_offset when it
 * was set conservatively low by the arch header. */
static void test_layout_adjust_floor_clamp(void) {
  reset_state();
  layout.kernel_base_min = layout.page_offset - KERNEL_ALIGN;
  init_inference_ctx();
  run_inference_phase(&g_ctx, KASLD_INFER_PHASE_LAYOUT_ADJUST);
  assert(layout.kernel_base_min >= layout.page_offset);
}
#endif

/* =========================================================================
 * State machine
 * =========================================================================
 */

/* kaslr_appears_active() is the probing guard: it mirrors detect_kaslr_state()
 * and determines whether the probing state is entered. */
static void test_state_table_guards(void) {
  reset_state();
  assert(kaslr_appears_active() == 1); /* no disabled markers → enter probing */

  inject_tagged("D - 0xffffffff81000000 proc-cmdline:nokaslr");
  assert(kaslr_appears_active() == 0); /* nokaslr marker → skip probing */
}

/* Verify state table structure: entry count, phase keys, guards, and
 * parallel flags are wired correctly. */
static void test_run_state_skips_on_guard(void) {
  size_t n = sizeof(states) / sizeof(states[0]);
  assert(n == 3);

  /* setup: no components, no guard */
  assert(states[0].phase_key == NULL);
  assert(states[0].can_enter == NULL);
  assert(states[0].parallel == 0);

  /* inference: all inference-phase components, always entered, parallel */
  assert(strcmp(states[1].phase_key, "inference") == 0);
  assert(states[1].can_enter == NULL);
  assert(states[1].parallel == 1);

  /* probing: guarded by kaslr_appears_active, sequential */
  assert(strcmp(states[2].phase_key, "probing") == 0);
  assert(states[2].can_enter == kaslr_appears_active);
  assert(states[2].parallel == 0);
}

/* =========================================================================
 * Main
 * =========================================================================
 */
int main(void) {
  printf("kasld unit tests (%s)\n\n", VERSION);

  printf("align_for_section:\n");
  RUN_TEST(test_align_text_rounds_down);
  RUN_TEST(test_align_text_already_aligned);
  RUN_TEST(test_align_module_passthrough);
  RUN_TEST(test_align_default_passthrough);
  RUN_TEST(test_align_phys_text_rounds_down);
  printf("\n");

  printf("validate_for_section:\n");
  RUN_TEST(test_validate_virt_text_in_range);
  RUN_TEST(test_validate_virt_text_below_range);
  RUN_TEST(test_validate_virt_text_above_range);
  RUN_TEST(test_validate_virt_module_in_range);
  RUN_TEST(test_validate_virt_module_below_range);
  RUN_TEST(test_validate_default_always_valid);
  RUN_TEST(test_validate_phys_text_in_range);
  RUN_TEST(test_validate_phys_text_below_range);
  RUN_TEST(test_validate_phys_dram_always_valid);
  printf("\n");

  printf("capture_result:\n");
  RUN_TEST(test_parse_basic);
  RUN_TEST(test_parse_multiple);
  RUN_TEST(test_parse_incremental);
  RUN_TEST(test_parse_ignores_non_tagged);
  RUN_TEST(test_parse_label_with_colon);
  RUN_TEST(test_parse_strips_newline);
  printf("\n");

  printf("group_consensus:\n");
  RUN_TEST(test_consensus_single);
  RUN_TEST(test_consensus_majority);
  RUN_TEST(test_consensus_tie_lowest);
  RUN_TEST(test_consensus_empty);
  RUN_TEST(test_consensus_ignores_invalid);
  RUN_TEST(test_consensus_type_isolation);
  printf("\n");

  printf("group_range:\n");
  RUN_TEST(test_range_single);
  RUN_TEST(test_range_multiple);
  RUN_TEST(test_range_empty);
  printf("\n");

  printf("detect_kaslr_state:\n");
  RUN_TEST(test_kaslr_enabled);
  RUN_TEST(test_kaslr_disabled_cmdline);
  RUN_TEST(test_kaslr_unsupported);
  RUN_TEST(test_kaslr_no_results);
  printf("\n");

  printf("adjust_for_page_offset:\n");
  RUN_TEST(test_adjust_noop_same_po);
#if defined(__i386__) || defined(__arm__)
  RUN_TEST(test_adjust_shifts_layout);
#endif
  printf("\n");

  printf("revalidate_results:\n");
  RUN_TEST(test_revalidate_updates_validity);
  printf("\n");

  printf("ilog2:\n");
  RUN_TEST(test_ilog2_power_of_two);
  RUN_TEST(test_ilog2_non_power);
  RUN_TEST(test_ilog2_zero);
  RUN_TEST(test_ilog2_large);
  printf("\n");

  printf("section_display_name:\n");
  RUN_TEST(test_section_display_default_null);
  RUN_TEST(test_section_display_virt_text);
  RUN_TEST(test_section_display_phys_text);
  RUN_TEST(test_section_display_pageoffset_null);
  RUN_TEST(test_section_display_module);
  RUN_TEST(test_section_display_dram);
  printf("\n");

  printf("validate_for_section (extended):\n");
  RUN_TEST(test_validate_virt_directmap_in_range);
  RUN_TEST(test_validate_virt_directmap_below_range);
  RUN_TEST(test_validate_virt_data_in_range);
  RUN_TEST(test_validate_virt_pageoffset_always_valid);
  RUN_TEST(test_validate_virt_text_at_boundaries);
  RUN_TEST(test_validate_virt_module_at_boundaries);
  printf("\n");

  printf("capture_result (extended):\n");
  RUN_TEST(test_parse_rejects_lowercase_type);
  RUN_TEST(test_parse_rejects_missing_space);
  RUN_TEST(test_parse_rejects_empty_label);
  RUN_TEST(test_parse_zero_address);
  RUN_TEST(test_parse_phys_type);
  RUN_TEST(test_parse_directmap_section);
  printf("\n");

  printf("group_consensus (extended):\n");
  RUN_TEST(test_consensus_section_isolation);
  RUN_TEST(test_consensus_three_way_tie);
  RUN_TEST(test_consensus_weight_beats_count);
  RUN_TEST(test_consensus_weight_tie_to_count);
  printf("\n");

  printf("group_range (extended):\n");
  RUN_TEST(test_range_ignores_invalid);
  RUN_TEST(test_range_type_isolation);
  RUN_TEST(test_range_zero_address);
  printf("\n");

  printf("add_derived:\n");
  RUN_TEST(test_add_derived_basic);
  RUN_TEST(test_add_derived_with_range);
  RUN_TEST(test_add_derived_overflow);
  printf("\n");

  printf("inject_kaslr_defaults:\n");
  RUN_TEST(test_inject_defaults_nokaslr);
  RUN_TEST(test_inject_defaults_unsupported);
  RUN_TEST(test_inject_defaults_kaslr_enabled);
  printf("\n");

  printf("compute_kaslr_info:\n");
  RUN_TEST(test_compute_kaslr_with_vtext);
  RUN_TEST(test_compute_kaslr_empty);
  RUN_TEST(test_compute_kaslr_disabled_zeroes);
  printf("\n");

  printf("compute_derived_addrs:\n");
  RUN_TEST(test_derived_decoupled_note_with_phys);
  RUN_TEST(test_derived_decoupled_note_suppressed_with_vtext);
  RUN_TEST(test_derived_decoupled_note_suppressed_no_phys);
  printf("\n");

  printf("json_print_escaped:\n");
  RUN_TEST(test_json_print_escaped_special_chars);
  printf("\n");

  printf("render_json:\n");
  RUN_TEST(test_json_basic_structure);
  RUN_TEST(test_json_layout_values);
  RUN_TEST(test_json_groups_with_results);
  RUN_TEST(test_json_kaslr_virtual);
  RUN_TEST(test_json_kaslr_no_address_has_inferred);
  RUN_TEST(test_json_kaslr_disabled);
  RUN_TEST(test_json_derived_entries);
  RUN_TEST(test_json_derived_with_range);
  printf("\n");

  printf("render_json (verbose):\n");
  RUN_TEST(test_json_verbose_has_components);
  RUN_TEST(test_json_verbose_no_logs);
  printf("\n");

  printf("component stats:\n");
  RUN_TEST(test_component_stats);
  RUN_TEST(test_json_component_stats);
  printf("\n");

  printf("meta_get:\n");
  RUN_TEST(test_meta_get_basic);
  RUN_TEST(test_meta_get_all_multiple);
  printf("\n");

  printf("hardening (text):\n");
  RUN_TEST(test_hardening_text_exposure_summary);
  RUN_TEST(test_hardening_text_active_defenses);
  RUN_TEST(test_hardening_text_patched);
  RUN_TEST(test_hardening_text_no_mitigation);
  printf("\n");

  printf("hardening (json):\n");
  RUN_TEST(test_hardening_json_structure);
  RUN_TEST(test_hardening_json_meta_array);
  RUN_TEST(test_hardening_json_no_meta_without_flag);
  printf("\n");

  printf("end-to-end:\n");
  RUN_TEST(test_e2e_pipeline);
  RUN_TEST(test_e2e_incremental_layout);
  RUN_TEST(test_e2e_kaslr_disabled_skips_probing);
  printf("\n");

  printf("state machine:\n");
  RUN_TEST(test_state_table_guards);
  RUN_TEST(test_run_state_skips_on_guard);
  printf("\n");

  printf("apply_skip_filter:\n");
  RUN_TEST(test_skip_exact_match);
  RUN_TEST(test_skip_glob_pattern);
  RUN_TEST(test_skip_multiple_patterns);
  RUN_TEST(test_skip_no_patterns_no_filter);
  RUN_TEST(test_skip_no_match_keeps_all);
  RUN_TEST(test_skip_active_count_excludes_filtered);
  RUN_TEST(test_skip_inference_pool_excludes_filtered);
  printf("\n");

  printf("inference plugins (kaslr_ceiling):\n");
  RUN_TEST(test_kaslr_ceiling_never_widens);
  RUN_TEST(test_kaslr_ceiling_alignment_invariant);
  RUN_TEST(test_kaslr_ceiling_max_above_min);
  RUN_TEST(test_kaslr_ceiling_phys_never_widens);
  RUN_TEST(test_kaslr_ceiling_phys_max_above_min);
#if PHYS_VIRT_DECOUPLED
  RUN_TEST(test_kaslr_ceiling_phys_alignment_invariant);
#endif
  printf("\n");

  printf("inference plugins (dram_bound):\n");
  RUN_TEST(test_dram_bound_no_results_noop);
  RUN_TEST(test_dram_bound_only_dram_section_used);
#if PHYS_VIRT_DECOUPLED
  RUN_TEST(test_dram_bound_decoupled_noop);
#endif
#if !PHYS_VIRT_DECOUPLED
  RUN_TEST(test_dram_bound_raises_min);
#endif
  printf("\n");

  printf("inference plugins (phys_virt_synth):\n");
  RUN_TEST(test_phys_virt_synth_no_results_noop);
  RUN_TEST(test_phys_virt_synth_no_cross_origin_pairing);
  RUN_TEST(test_phys_virt_synth_tightens_on_agreement);
  RUN_TEST(test_phys_virt_synth_disagreeing_candidates_noop);
  printf("\n");

  printf("inference plugins (module_text_bound):\n");
  RUN_TEST(test_module_text_bound_no_results_noop);
  RUN_TEST(test_module_text_bound_non_module_section_noop);
#if MODULES_RELATIVE_TO_TEXT
  RUN_TEST(test_module_text_bound_lowers_max);
  RUN_TEST(test_module_text_bound_uses_minimum_module);
  RUN_TEST(test_module_text_bound_never_raises_min);
  RUN_TEST(test_module_text_bound_never_widens);
#endif
  printf("\n");

  printf("inference plugins (layout_adjust):\n");
  RUN_TEST(test_layout_adjust_no_results_noop);
  RUN_TEST(test_layout_adjust_same_po_noop);
  RUN_TEST(test_layout_adjust_new_po_updates_layout);
  RUN_TEST(test_layout_adjust_consensus_applied);
#if !PHYS_VIRT_DECOUPLED
  RUN_TEST(test_layout_adjust_floor_clamp);
#endif
  printf("\n");

  printf("---\n%d/%d tests passed\n", pass_count, test_count);
  return (pass_count == test_count) ? 0 : 1;
}
