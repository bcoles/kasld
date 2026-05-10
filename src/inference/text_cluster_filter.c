// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Inference plugin: TEXT-result cluster outlier rejection (POST_COLLECTION)
//
// All valid VIRT/TEXT results from a single boot lie in
// [text_base, text_base + KERNEL_IMAGE_SIZE), which on every supported arch
// is at most ~256 MiB wide. Components that misclassify a leak (e.g. a heap
// pointer mistaken for a kernel text address) typically produce results that
// are *far* outside this window — often by gigabytes.
//
// layout_adjust.c invalidates results outside [text_base_min, text_base_max].
// That window may itself be wide if no per-arch tightening plugin has fired.
// A complementary check that ignores the computed window and relies on
// inter-result agreement can invalidate outliers earlier and let the bound
// computation converge faster.
//
// Algorithm:
//   1. Collect all valid VIRT/TEXT results into a sorted vector V.
//   2. If |V| < CLUSTER_MIN, skip — too few results for meaningful agreement.
//   3. Compute median M.
//   4. Count results within MAX_KERNEL_IMAGE_SIZE of M (the cluster).
//   5. If cluster size is not a strict majority of |V|, skip — no clear
//      consensus, refuse to invalidate.
//   6. For each r ∈ V with |r − M| > CLUSTER_OUTLIER_THRESHOLD: mark invalid.
//
// Soundness: the rule is unsound when *most* results are misclassifications
// and a minority is correct. Mitigations:
//   - CLUSTER_MIN ≥ 3 ensures a single garbage value cannot dominate.
//   - The strict-majority check (cluster > |V|/2) refuses to invalidate
//     when there is no clear cluster; in that ambiguous case the existing
//     bound-based revalidation in layout_adjust.c handles the results.
//   - CLUSTER_OUTLIER_THRESHOLD is set to 1 GiB — well above any plausible
//     intra-cluster spread (max image size ~256 MiB) but below the typical
//     deviation of garbage pointers (heap/userspace addresses are usually
//     many GiB or TiB from the kernel text region in median terms).
//
// Phase: POST_COLLECTION. Cross-arch (no arch guard).
//
// Bound effect: cleaner result set; subsequent inference passes recompute
// text_base_min/max from the surviving results, which excludes the outlier
// extremes that would otherwise widen the window.
// ---
// <bcoles@gmail.com>

#define _POSIX_C_SOURCE 200809L

#include "../include/kasld_inference.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Minimum number of valid TEXT results required to apply the filter.
 *
 * Set to 5 (not 3) to avoid a known degenerate case at exactly 3 results:
 * with [garbage, garbage+δ, correct], the median falls on a garbage value
 * (vals[1]), the cluster around it has 2 members (the two garbages within
 * MAX_KERNEL_IMAGE_SIZE of each other), and 2*2=4 > 3 satisfies the
 * strict-majority guard — invalidating the only correct result. With ≥ 5
 * results, a 3-of-5 cluster wins only when at least one cluster member is
 * the correct value, since two independent garbage leaks rarely fall within
 * MAX_KERNEL_IMAGE_SIZE of each other in practice. */
#define CLUSTER_MIN 5

/* Max plausible kernel binary size (init_size). Used to determine whether a
 * result lies within the cluster around the median. 256 MiB is well above
 * any observed mainline kernel image; typical builds are 50–100 MiB. */
#define MAX_KERNEL_IMAGE_SIZE (256ul * 1024 * 1024)

/* Distance from the median above which a result is considered an outlier.
 * Set to 4 × MAX_KERNEL_IMAGE_SIZE = 1 GiB. A real text leak from any
 * mainline kernel will be at most MAX_KERNEL_IMAGE_SIZE from the median of
 * other text leaks; the 4× safety factor avoids false rejections even in
 * pathological large-image-size scenarios. */
#define CLUSTER_OUTLIER_THRESHOLD (4ul * MAX_KERNEL_IMAGE_SIZE)

static int cmp_ulong(const void *a, const void *b) {
  unsigned long x = *(const unsigned long *)a;
  unsigned long y = *(const unsigned long *)b;
  if (x < y)
    return -1;
  if (x > y)
    return 1;
  return 0;
}

static unsigned long abs_diff(unsigned long a, unsigned long b) {
  return a > b ? a - b : b - a;
}

static void text_cluster_filter_run(struct kasld_analysis_ctx *ctx) {
  (void)ctx;

  /* Two-pass: first count to size the buffer, then collect. */
  int count = 0;
  for (int i = 0; i < num_results; i++) {
    const struct result *r = &results[i];
    if (!r->valid)
      continue;
    if (r->type != KASLD_ADDR_VIRT)
      continue;
    if (strcmp(r->section, KASLD_SECTION_TEXT) != 0)
      continue;
    count++;
  }

  if (count < CLUSTER_MIN)
    return;

  unsigned long *vals = malloc((size_t)count * sizeof(*vals));
  if (!vals)
    return;

  int j = 0;
  for (int i = 0; i < num_results; i++) {
    const struct result *r = &results[i];
    if (!r->valid)
      continue;
    if (r->type != KASLD_ADDR_VIRT)
      continue;
    if (strcmp(r->section, KASLD_SECTION_TEXT) != 0)
      continue;
    vals[j++] = r->raw;
  }

  qsort(vals, (size_t)count, sizeof(*vals), cmp_ulong);
  unsigned long median = vals[count / 2];

  /* Count results within MAX_KERNEL_IMAGE_SIZE of the median. */
  int cluster_size = 0;
  for (int i = 0; i < count; i++) {
    if (abs_diff(vals[i], median) <= MAX_KERNEL_IMAGE_SIZE)
      cluster_size++;
  }

  free(vals);

  /* Strict majority required: refuse to act if the cluster is not a clear
   * winner. count/2 floors for odd counts; we want > half, so > count/2 in
   * integer arithmetic means cluster_size * 2 > count. */
  if (cluster_size * 2 <= count) {
    if (verbose && !quiet)
      fprintf(stdout,
              "[infer] text_cluster_filter: no clear cluster"
              " (cluster=%d/%d around median %#lx); skipping\n",
              cluster_size, count, median);
    return;
  }

  if (verbose && !quiet)
    fprintf(stdout,
            "[infer] text_cluster_filter: median=%#lx cluster=%d/%d"
            " threshold=%#lx\n",
            median, cluster_size, count, CLUSTER_OUTLIER_THRESHOLD);

  int invalidated = 0;
  for (int i = 0; i < num_results; i++) {
    struct result *r = &results[i];
    if (!r->valid)
      continue;
    if (r->type != KASLD_ADDR_VIRT)
      continue;
    if (strcmp(r->section, KASLD_SECTION_TEXT) != 0)
      continue;
    if (abs_diff(r->raw, median) <= CLUSTER_OUTLIER_THRESHOLD)
      continue;

    if (verbose && !quiet)
      fprintf(stdout,
              "[infer] text_cluster_filter: invalidating VIRT/TEXT result"
              " %#lx (|delta|=%#lx > %#lx from median %#lx)\n",
              r->raw, abs_diff(r->raw, median),
              (unsigned long)CLUSTER_OUTLIER_THRESHOLD, median);
    r->valid = 0;
    invalidated++;
  }

  if (invalidated)
    revalidate_results();
}

static const struct kasld_inference text_cluster_filter = {
    .name = "text_cluster_filter",
    .phase = KASLD_INFER_PHASE_POST_COLLECTION,
    .run = text_cluster_filter_run,
};

KASLD_REGISTER_INFERENCE(text_cluster_filter);
