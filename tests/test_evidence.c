// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Unit tests for the evidence store + verdict application:
// monotonic id assignment, source immutability, invalidate,
// pure-recompute idempotence, invalidate-wins, stale-id tolerance.
// Standalone — links only evidence.c.
// ---
// <bcoles@gmail.com>

#include "include/kasld/evidence.h"
#include "test_harness.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static struct observation mk_obs(enum kasld_addr_type type,
                                 enum kasld_region region, unsigned long lo,
                                 const char *origin) {
  struct observation o;
  memset(&o, 0, sizeof(o));
  o.type = type;
  o.region = region;
  o.lo = lo;
  o.set_mask = LO_SET;
  o.pos = POS_BASE;
  o.conf = CONF_PARSED;
  snprintf(o.origin, ORIGIN_LEN, "%s", origin);
  return o;
}

static struct verdict mk_invalidate(uint32_t id, const char *origin) {
  struct verdict v;
  memset(&v, 0, sizeof(v));
  v.observation_id = id;
  v.kind = V_INVALID;
  v.conf = CONF_DERIVED;
  snprintf(v.origin, ORIGIN_LEN, "%s", origin);
  return v;
}

/* Tests always pass an id that evidence_add() just handed back, so the
 * lookup is required to succeed. Asserting it here both encodes that
 * invariant and lets -Wnull-dereference prove the trailing field reads
 * (every caller of the form `obs_by_id(...)->field`) are safe. */
static struct observation *obs_by_id(struct evidence_set *ev, uint32_t id) {
  for (int i = 0; i < ev->n_obs; i++)
    if (ev->obs[i].id == id)
      return &ev->obs[i];
  assert(0 && "obs_by_id: id not found");
  return NULL; /* unreachable; keeps the compiler happy when NDEBUG is set */
}

static void test_add_assigns_monotonic_ids(void) {
  struct evidence_set ev;
  evidence_init(&ev);
  struct observation a = mk_obs(KASLD_TYPE_PHYS, REGION_RAM, 0x100000, "c1");
  struct observation b =
      mk_obs(KASLD_TYPE_VIRT, REGION_KERNEL_TEXT, 0xffffffff81000000ul, "c2");
  uint32_t ia = evidence_add(&ev, &a);
  uint32_t ib = evidence_add(&ev, &b);
  assert(ia == 1 && ib == 2); /* monotonic from 1 */
  assert(ev.n_obs == 2);
  /* Source fields preserved. */
  assert(obs_by_id(&ev, ia)->region == REGION_RAM);
  assert(obs_by_id(&ev, ib)->lo == 0xffffffff81000000ul);
}

static void test_resolve_no_verdicts_all_active(void) {
  struct evidence_set ev;
  evidence_init(&ev);
  struct observation a = mk_obs(KASLD_TYPE_PHYS, REGION_RAM, 0x100000, "c1");
  uint32_t id = evidence_add(&ev, &a);
  evidence_resolve(&ev);
  struct observation *o = obs_by_id(&ev, id);
  assert(evidence_active(o));
  assert(o->eff_region == REGION_RAM && o->eff_type == KASLD_TYPE_PHYS);
}

static void test_invalidate(void) {
  struct evidence_set ev;
  evidence_init(&ev);
  struct observation a = mk_obs(KASLD_TYPE_PHYS, REGION_RAM, 0x100000, "c1");
  struct observation b =
      mk_obs(KASLD_TYPE_PHYS, REGION_INITRD, 0x2e000000, "c2");
  uint32_t ia = evidence_add(&ev, &a);
  uint32_t ib = evidence_add(&ev, &b);
  struct verdict v = mk_invalidate(ib, "initrd_phys_avoid");
  evidence_add_verdict(&ev, &v);
  evidence_resolve(&ev);
  assert(evidence_active(obs_by_id(&ev, ia)));
  assert(!evidence_active(obs_by_id(&ev, ib)));
}

static void test_resolve_idempotent_and_reversible(void) {
  struct evidence_set ev;
  evidence_init(&ev);
  struct observation a = mk_obs(KASLD_TYPE_PHYS, REGION_RAM, 0x100000, "c1");
  uint32_t id = evidence_add(&ev, &a);
  struct verdict v = mk_invalidate(id, "x");
  evidence_add_verdict(&ev, &v);

  evidence_resolve(&ev);
  assert(!evidence_active(obs_by_id(&ev, id)));
  evidence_resolve(&ev); /* idempotent */
  assert(!evidence_active(obs_by_id(&ev, id)));

  /* Drop the verdict and re-resolve: invalidation is un-applied (pure
   * recompute from source). */
  ev.n_verdicts = 0;
  evidence_resolve(&ev);
  assert(evidence_active(obs_by_id(&ev, id)));
}

static void test_stale_verdict_ignored(void) {
  struct evidence_set ev;
  evidence_init(&ev);
  struct observation a = mk_obs(KASLD_TYPE_PHYS, REGION_RAM, 0x100000, "c1");
  uint32_t id = evidence_add(&ev, &a);
  struct verdict v = mk_invalidate(9999, "ghost"); /* no such observation */
  evidence_add_verdict(&ev, &v);
  evidence_resolve(&ev); /* must not crash */
  assert(evidence_active(obs_by_id(&ev, id)));
}

/* Scalar observations (§0.8): a component emits a non-address measurement
 * (MemTotal here). It stores, survives resolve, and can be invalidated. */
static struct observation mk_scalar(enum kasld_scalar_fact fact,
                                    unsigned long value, const char *origin) {
  struct observation o;
  memset(&o, 0, sizeof(o));
  o.value_kind = OBS_SCALAR;
  o.scalar_fact = fact;
  o.scalar_value = value;
  o.conf = CONF_PARSED;
  snprintf(o.origin, ORIGIN_LEN, "%s", origin);
  return o;
}

static void test_scalar_observation(void) {
  struct evidence_set ev;
  evidence_init(&ev);
  struct observation m =
      mk_scalar(SF_PHYS_MEMTOTAL, 12884901888ul, "proc-meminfo"); /* 12 GiB */
  uint32_t id = evidence_add(&ev, &m);
  evidence_resolve(&ev);
  struct observation *o = obs_by_id(&ev, id);
  assert(o->value_kind == OBS_SCALAR);
  assert(o->scalar_fact == SF_PHYS_MEMTOTAL);
  assert(o->scalar_value == 12884901888ul);
  assert(evidence_active(o));

  /* Invalidate works on a scalar. */
  struct verdict iv = mk_invalidate(id, "x");
  evidence_add_verdict(&ev, &iv);
  evidence_resolve(&ev);
  assert(!evidence_active(o));
}

/* The two-ended image-size interval: min = max-over-lower-bounds (ceiling),
 * max = min-over-upper-bounds (floor), and the floored convenience. */
static void test_image_size_accessors(void) {
  struct evidence_set ev;
  evidence_init(&ev);

  /* No size facts: both ends 0; or_floor returns the conservative floor. */
  assert(evidence_image_size_min(&ev, NULL, NULL) == 0);
  assert(evidence_image_size_max(&ev, NULL, NULL) == 0);
  assert(evidence_image_size_min_or_floor(&ev) == KASLD_MIN_IMAGE_SIZE);

  /* Two lower bounds: min takes the LARGEST (tightest sound ceiling input). */
  struct observation lo1 = mk_scalar(SF_IMAGE_SIZE_MIN, 0x1000000ul, "a");
  struct observation lo2 = mk_scalar(SF_IMAGE_SIZE_MIN, 0x3000000ul, "b");
  evidence_add(&ev, &lo1);
  evidence_add(&ev, &lo2);
  evidence_resolve(&ev);
  assert(evidence_image_size_min(&ev, NULL, NULL) == 0x3000000ul);
  /* A MIN-only fact never feeds the MAX (floor) accessor. */
  assert(evidence_image_size_max(&ev, NULL, NULL) == 0);
  assert(evidence_image_size_min_or_floor(&ev) == 0x3000000ul);

  /* Two upper bounds: max takes the SMALLEST (tightest sound floor input). */
  struct observation hi1 = mk_scalar(SF_IMAGE_SIZE_MAX, 0x4000000ul, "c");
  struct observation hi2 = mk_scalar(SF_IMAGE_SIZE_MAX, 0x3000000ul, "d");
  evidence_add(&ev, &hi1);
  evidence_add(&ev, &hi2);
  evidence_resolve(&ev);
  assert(evidence_image_size_max(&ev, NULL, NULL) == 0x3000000ul);

  /* or_floor never drops below the floor even with a tiny observed min. */
  evidence_init(&ev);
  struct observation tiny = mk_scalar(SF_IMAGE_SIZE_MIN, 0x100000ul, "e");
  evidence_add(&ev, &tiny);
  evidence_resolve(&ev);
  assert(evidence_image_size_min(&ev, NULL, NULL) == 0x100000ul);
  assert(evidence_image_size_min_or_floor(&ev) == KASLD_MIN_IMAGE_SIZE);
}

int main(void) {
  TEST_SUITE("test_evidence");

  BEGIN_CATEGORY("Observation store");
  RUN(test_add_assigns_monotonic_ids);
  RUN(test_scalar_observation);
  RUN(test_image_size_accessors);

  BEGIN_CATEGORY("Verdict resolution");
  RUN(test_resolve_no_verdicts_all_active);
  RUN(test_invalidate);
  RUN(test_resolve_idempotent_and_reversible);
  RUN(test_stale_verdict_ignored);

  return TEST_DONE();
}
