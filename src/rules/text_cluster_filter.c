// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Curation rule: virtual text-cluster outlier rejection.
//
// Genuine
// kernel-text leaks cluster within one image size of each other; a stray
// virtual address far from that cluster is a misclassification. The rule finds
// the median of the valid virtual observations, requires a strict majority to
// sit within one image size of it (else it refuses to act), and invalidates
// (V_INVALID) any virtual observation more than CLUSTER_OUTLIER_THRESHOLD from
// the median.
//
// A set-based curator (it reasons over the whole virtual observation set),
// unlike the per-observation coupling_validate. Still pure and evidence-only,
// so it settles before the constraint rules consume the set.
// ---
// <bcoles@gmail.com>

#include "../include/kasld/engine_rules.h"

#include <stdlib.h>
#include <string.h>

#define CLUSTER_MIN 5
#define MAX_KERNEL_IMAGE_SIZE (256ul * 1024 * 1024)
#define CLUSTER_OUTLIER_THRESHOLD (4ul * MAX_KERNEL_IMAGE_SIZE)

/* Working cap on virtual samples considered. Far above realistic leak counts;
 * keeps the median computation allocation-free (rules stay pure/no-malloc). */
#define TCF_MAX_SAMPLES 512

static unsigned long abs_diff(unsigned long a, unsigned long b) {
  return a > b ? a - b : b - a;
}

static int cmp_ulong(const void *a, const void *b) {
  unsigned long x = *(const unsigned long *)a, y = *(const unsigned long *)b;
  return (x > y) - (x < y);
}

int rule_text_cluster_filter(const struct evidence_set *ev, struct verdict *out,
                             int out_max) {
  unsigned long vals[TCF_MAX_SAMPLES];
  int count = 0;
  for (int i = 0; i < ev->n_obs && count < TCF_MAX_SAMPLES; i++) {
    const struct observation *o = &ev->obs[i];
    if (o->valid && o->value_kind == OBS_ADDRESS &&
        o->eff_type == KASLD_TYPE_VIRT)
      vals[count++] = obs_anchor(o);
  }
  if (count < CLUSTER_MIN)
    return 0;

  qsort(vals, (size_t)count, sizeof(*vals), cmp_ulong);
  unsigned long median = vals[count / 2];

  /* Strict majority within one image size of the median, or refuse to act. */
  int cluster = 0;
  for (int i = 0; i < count; i++)
    if (abs_diff(vals[i], median) <= MAX_KERNEL_IMAGE_SIZE)
      cluster++;
  if (cluster * 2 <= count)
    return 0;

  int n = 0;
  for (int i = 0; i < ev->n_obs && n < out_max; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->value_kind != OBS_ADDRESS ||
        o->eff_type != KASLD_TYPE_VIRT)
      continue;
    if (abs_diff(obs_anchor(o), median) <= CLUSTER_OUTLIER_THRESHOLD)
      continue;

    struct verdict *v = &out[n++];
    memset(v, 0, sizeof(*v));
    v->observation_id = o->id;
    v->kind = V_INVALID;
    v->conf = o->conf;
    v->derived_from[0] = o->id;
    v->lineage_count = 1;
    snprintf(v->origin, ORIGIN_LEN, "text_cluster_filter");
  }
  return n;
}
