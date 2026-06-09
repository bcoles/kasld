// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Result-collection helpers shared by the test binaries that #include
// orchestrator.c directly (test_kasld, test_render). Factored out so the two
// suites don't keep drifting copies — the same rationale as test_harness.h.
//
// MUST be included AFTER "../src/orchestrator.c": these reference its
// results[] / num_results / result_init() / MAX_RESULTS / struct result.
// ---
// <bcoles@gmail.com>

#ifndef KASLD_TEST_ORCH_COMMON_H
#define KASLD_TEST_ORCH_COMMON_H

#include <limits.h>

/* Seed the engine-bounds carrier the same way orchestrator's main() does.
 * Under KASLD_TESTING the orchestrator's main() is excluded, so suites that
 * read layout (compute_kaslr_info coverage, the renderer's derived paths) must
 * start it from the honest window themselves. Call once at the top of main().
 */
static void test_init_layout_engine_bounds(void) {
  layout.virt_page_offset_min = layout.virt_kernel_vas_start;
  layout.virt_page_offset_max = layout.virt_kernel_vas_end;
  layout.virt_vmalloc_base_min = 0;
  layout.virt_vmalloc_base_max = ULONG_MAX;
  layout.virt_vmemmap_base_min = 0;
  layout.virt_vmemmap_base_max = ULONG_MAX;
}

/* Reset the shared result table to empty + zeroed slots. */
static void reset_results(void) {
  num_results = 0;
  for (int i = 0; i < MAX_RESULTS; i++)
    result_init(&results[i]);
}

/* Append a fresh zeroed result and return it for the caller to populate. */
static struct result *push_result(void) {
  struct result *r = &results[num_results++];
  result_init(r);
  return r;
}

#endif /* KASLD_TEST_ORCH_COMMON_H */
