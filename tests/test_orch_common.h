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

#include <assert.h>
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

/* Reset the per-component execution log. The array is indexed by discovery
 * slot, so clearing it means clearing every slot's `ran` marker. */
static void reset_comp_logs(void) {
  for (int i = 0; i < MAX_COMPONENTS; i++)
    memset(&comp_logs[i], 0, sizeof(comp_logs[i]));
}

/* Register `name` in the discovery table and return its slot, so a synthetic
 * result can carry provenance that resolves back to a component name the way a
 * real run's does. Idempotent: registering the same name twice returns the
 * slot it already holds. */
static int test_origin(const char *name) {
  if (!name || !*name)
    return ORIGIN_NONE;
  for (int i = 0; i < num_components; i++)
    if (strcmp(components[i].name, name) == 0)
      return i;
  assert(num_components < MAX_COMPONENTS);
  int slot = num_components++;
  memset(&components[slot], 0, sizeof(components[slot]));
  snprintf(components[slot].name, sizeof(components[slot].name), "%s", name);
  return slot;
}

/* Credit `name` as a contributor to `r`. */
static void add_origin(struct result *r, const char *name) {
  origin_set_add(&r->origins, test_origin(name));
}

/* Seed the execution-log slot belonging to `name`, registering the component
 * if this is its first mention. Returns the zeroed, marked-as-run slot for the
 * caller to populate. */
static struct component_log *seed_comp_log(const char *name) {
  struct component_log *cl = &comp_logs[test_origin(name)];
  memset(cl, 0, sizeof(*cl));
  cl->ran = 1;
  snprintf(cl->name, sizeof(cl->name), "%s", name);
  return cl;
}

/* The name of a result's first contributor, or "" when it has none. */
static const char *first_origin(const struct result *r) {
  return kasld_origin_name(origin_set_next(&r->origins, 0));
}

#endif /* KASLD_TEST_ORCH_COMMON_H */
