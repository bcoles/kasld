// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Unit tests for the evidential inference core: per-lattice meet,
// bottom test, the greedy conflict-aware resolver, trust-stratified
// estimate_at, and the honest-top soundness validation for the compiled
// arch. Standalone — links only estimate.c + quantities.c, no orchestrator.
// ---
// <bcoles@gmail.com>

#include "include/kasld/estimate.h"
#include "include/kasld/quantity.h"
#include "test_harness.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

/* Build a constraint. lineage_count doubles as the corroboration count for
 * the within-tier tie-break. */
static struct constraint mk(enum kasld_quantity q, enum constraint_op op,
                            unsigned long v, enum kasld_confidence conf,
                            uint32_t id) {
  struct constraint c;
  memset(&c, 0, sizeof(c));
  c.q = q;
  c.op = op;
  c.value = v;
  c.conf = conf;
  c.id = id;
  c.lineage_count = 1;
  return c;
}

/* ========================================================================
 * Interval meet
 * ======================================================================== */
static void test_interval_meet_bounds(void) {
  struct estimate e;
  quantities[Q_VIRT_IMAGE_BASE].init_top(&e);
  unsigned long top_lo = e.lo, top_hi = e.hi;

  struct constraint up = mk(Q_VIRT_IMAGE_BASE, C_UPPER_BOUND,
                            top_lo + 0x10000000ul, CONF_PARSED, 1);
  estimate_meet(&e, &quantities[Q_VIRT_IMAGE_BASE], &up);
  assert(e.hi == top_lo + 0x10000000ul);
  assert(e.hi_binding == 1);
  assert(e.lo == top_lo); /* unchanged */
  assert(!estimate_is_bottom(&e, &quantities[Q_VIRT_IMAGE_BASE]));

  struct constraint lo = mk(Q_VIRT_IMAGE_BASE, C_LOWER_BOUND,
                            top_lo + 0x1000000ul, CONF_PARSED, 2);
  estimate_meet(&e, &quantities[Q_VIRT_IMAGE_BASE], &lo);
  assert(e.lo == top_lo + 0x1000000ul);
  assert(e.lo_binding == 2);

  /* A looser upper bound does not widen. */
  struct constraint loose =
      mk(Q_VIRT_IMAGE_BASE, C_UPPER_BOUND, top_hi, CONF_PARSED, 3);
  estimate_meet(&e, &quantities[Q_VIRT_IMAGE_BASE], &loose);
  assert(e.hi == top_lo + 0x10000000ul); /* still the tighter one */
  assert(e.hi_binding == 1);
}

static void test_interval_meet_equals_and_bottom(void) {
  struct estimate e;
  quantities[Q_VIRT_IMAGE_BASE].init_top(&e);
  unsigned long base = e.lo;

  struct constraint eq =
      mk(Q_VIRT_IMAGE_BASE, C_EQUALS, base + 0x2000000ul, CONF_DERIVED, 1);
  estimate_meet(&e, &quantities[Q_VIRT_IMAGE_BASE], &eq);
  assert(e.lo == base + 0x2000000ul && e.hi == base + 0x2000000ul);

  /* Contradicting equals → bottom. */
  struct estimate e2;
  quantities[Q_VIRT_IMAGE_BASE].init_top(&e2);
  struct constraint a =
      mk(Q_VIRT_IMAGE_BASE, C_UPPER_BOUND, base + 0x1000000ul, CONF_PARSED, 1);
  struct constraint b =
      mk(Q_VIRT_IMAGE_BASE, C_LOWER_BOUND, base + 0x2000000ul, CONF_PARSED, 2);
  estimate_meet(&e2, &quantities[Q_VIRT_IMAGE_BASE], &a);
  estimate_meet(&e2, &quantities[Q_VIRT_IMAGE_BASE], &b);
  assert(estimate_is_bottom(&e2, &quantities[Q_VIRT_IMAGE_BASE]));
}

/* ========================================================================
 * Max-align meet (never bottom)
 * ======================================================================== */
static void test_maxalign_meet(void) {
  struct estimate e;
  quantities[Q_VIRT_KASLR_ALIGN].init_top(&e);
  assert(e.lo == 1ul);

  struct constraint a1 =
      mk(Q_VIRT_KASLR_ALIGN, C_AT_LEAST_ALIGN, 0x1000ul, CONF_INFERRED, 1);
  estimate_meet(&e, &quantities[Q_VIRT_KASLR_ALIGN], &a1);
  assert(e.lo == 0x1000ul);

  struct constraint a2 =
      mk(Q_VIRT_KASLR_ALIGN, C_AT_LEAST_ALIGN, 0x200000ul, CONF_INFERRED, 2);
  estimate_meet(&e, &quantities[Q_VIRT_KASLR_ALIGN], &a2);
  assert(e.lo == 0x200000ul); /* max */

  struct constraint a3 =
      mk(Q_VIRT_KASLR_ALIGN, C_AT_LEAST_ALIGN, 0x1000ul, CONF_INFERRED, 3);
  estimate_meet(&e, &quantities[Q_VIRT_KASLR_ALIGN], &a3);
  assert(e.lo == 0x200000ul); /* unchanged; max stays */
  assert(!estimate_is_bottom(&e, &quantities[Q_VIRT_KASLR_ALIGN]));
}

/* ========================================================================
 * Finite-set meet
 * ======================================================================== */
static int finset_has(enum kasld_quantity q, const struct estimate *e,
                      unsigned long value) {
  const struct quantity_def *qd = &quantities[q];
  for (int i = 0; i < qd->n_candidates; i++)
    if (qd->candidates[i] == value)
      return (e->lo & (1ul << i)) != 0;
  return 0;
}

static void test_finset_meet(void) {
  const struct quantity_def *qd = &quantities[Q_VA_BITS];
  assert(qd->n_candidates >= 1);

  struct estimate e;
  qd->init_top(&e);
  /* Top admits every candidate. */
  for (int i = 0; i < qd->n_candidates; i++)
    assert(finset_has(Q_VA_BITS, &e, qd->candidates[i]));

  /* C_EQUALS to a real candidate narrows to just that one. */
  struct estimate e2 = e;
  struct constraint eq =
      mk(Q_VA_BITS, C_EQUALS, qd->candidates[0], CONF_PARSED, 1);
  estimate_meet(&e2, qd, &eq);
  assert(finset_has(Q_VA_BITS, &e2, qd->candidates[0]));
  assert(!estimate_is_bottom(&e2, qd));
  if (qd->n_candidates > 1)
    assert(!finset_has(Q_VA_BITS, &e2, qd->candidates[1]));

  /* C_EQUALS to a non-candidate empties the set → bottom. */
  struct estimate e3 = e;
  struct constraint bad = mk(Q_VA_BITS, C_EQUALS, 999ul, CONF_PARSED, 2);
  estimate_meet(&e3, qd, &bad);
  assert(estimate_is_bottom(&e3, qd));
}

/* ========================================================================
 * Greedy resolver: contradictions resolved by trust priority
 * ======================================================================== */
static void test_resolve_stronger_wins(void) {
  struct estimate top;
  quantities[Q_VIRT_IMAGE_BASE].init_top(&top);
  unsigned long base = top.lo;

  /* PARSED upper bound vs TIMING lower bound that contradicts it. */
  struct constraint cs[2];
  cs[0] =
      mk(Q_VIRT_IMAGE_BASE, C_UPPER_BOUND, base + 0x1000000ul, CONF_PARSED, 10);
  cs[1] =
      mk(Q_VIRT_IMAGE_BASE, C_LOWER_BOUND, base + 0x2000000ul, CONF_TIMING, 11);

  struct resolve_result r;
  estimate_resolve(Q_VIRT_IMAGE_BASE, CONF_BRUTE, cs, 2, &r);

  /* PARSED upper accepted; contradicting TIMING lower rejected. */
  assert(r.est.hi == base + 0x1000000ul);
  assert(r.est.lo == base); /* lower bound was the rejected one */
  assert(r.n_conflicts == 1 && r.conflicts[0] == 11);
}

static void test_resolve_priority_flips_with_confidence(void) {
  struct estimate top;
  quantities[Q_VIRT_IMAGE_BASE].init_top(&top);
  unsigned long base = top.lo;

  /* Same shapes, confidences swapped: now the lower bound is PARSED. */
  struct constraint cs[2];
  cs[0] =
      mk(Q_VIRT_IMAGE_BASE, C_UPPER_BOUND, base + 0x1000000ul, CONF_TIMING, 10);
  cs[1] =
      mk(Q_VIRT_IMAGE_BASE, C_LOWER_BOUND, base + 0x2000000ul, CONF_PARSED, 11);

  struct resolve_result r;
  estimate_resolve(Q_VIRT_IMAGE_BASE, CONF_BRUTE, cs, 2, &r);

  assert(r.est.lo == base + 0x2000000ul);
  assert(r.n_conflicts == 1 && r.conflicts[0] == 10); /* upper rejected */
}

static void test_resolve_deterministic_and_no_conflict(void) {
  struct estimate top;
  quantities[Q_VIRT_IMAGE_BASE].init_top(&top);
  unsigned long base = top.lo;

  /* Two compatible upper bounds; tightest wins, no conflict. */
  struct constraint cs[2];
  cs[0] =
      mk(Q_VIRT_IMAGE_BASE, C_UPPER_BOUND, base + 0x4000000ul, CONF_PARSED, 1);
  cs[1] =
      mk(Q_VIRT_IMAGE_BASE, C_UPPER_BOUND, base + 0x2000000ul, CONF_DERIVED, 2);

  struct resolve_result r;
  estimate_resolve(Q_VIRT_IMAGE_BASE, CONF_BRUTE, cs, 2, &r);
  assert(r.est.hi == base + 0x2000000ul); /* tighter */
  assert(r.est.hi_binding == 2);
  assert(r.n_conflicts == 0);
}

/* ========================================================================
 * Trust-stratified estimate_at (higher floor → fewer constraints → looser)
 * ======================================================================== */
static void test_estimate_at_trust_floor(void) {
  struct estimate top;
  quantities[Q_VIRT_IMAGE_BASE].init_top(&top);
  unsigned long base = top.lo;

  struct constraint cs[2];
  cs[0] = mk(Q_VIRT_IMAGE_BASE, C_UPPER_BOUND, base + 0x4000000ul, CONF_PARSED,
             1); /* trusted, looser */
  cs[1] = mk(Q_VIRT_IMAGE_BASE, C_UPPER_BOUND, base + 0x1000000ul, CONF_TIMING,
             2); /* shaky, tighter */

  struct resolve_result all, trusted;
  estimate_resolve(Q_VIRT_IMAGE_BASE, CONF_BRUTE, cs, 2, &all);
  estimate_resolve(Q_VIRT_IMAGE_BASE, CONF_PARSED, cs, 2, &trusted);

  /* Accepting everything gives the tighter (timing) bound. */
  assert(all.est.hi == base + 0x1000000ul && all.est.hi_binding == 2);
  /* Restricting to PARSED-or-better gives the looser, rock-solid bound. */
  assert(trusted.est.hi == base + 0x4000000ul && trusted.est.hi_binding == 1);
}

/* ========================================================================
 * quantity_ranges — set-ready consumer value-access (§0.7)
 * ======================================================================== */
static void test_quantity_ranges_interval_plain(void) {
  struct estimate e;
  quantities[Q_VIRT_IMAGE_BASE].init_top(&e);
  struct range out[8];
  int n = quantity_ranges(Q_VIRT_IMAGE_BASE, &e, NULL, 0, out, 8);
  assert(n == 1);
  assert(out[0].lo == e.lo && out[0].hi == e.hi);
}

static void test_quantity_ranges_interval_with_interior_hole(void) {
  struct estimate e;
  quantities[Q_VIRT_IMAGE_BASE].init_top(&e);
  unsigned long base = e.lo;
  /* An interior C_EXCLUDE hole splits the interval into two ranges. */
  struct constraint cs[1];
  cs[0] = mk(Q_VIRT_IMAGE_BASE, C_EXCLUDE, base + 0x1000000ul, CONF_DERIVED, 1);
  cs[0].value2 = base + 0x1fffffful; /* hole [base+16M, base+32M-1] */

  struct range out[8];
  int n = quantity_ranges(Q_VIRT_IMAGE_BASE, &e, cs, 1, out, 8);
  assert(n == 2);
  assert(out[0].lo == base && out[0].hi == base + 0x1000000ul - 1);
  assert(out[1].lo == base + 0x2000000ul && out[1].hi == e.hi);
}

static void test_quantity_slots_hole_aware(void) {
  struct estimate e;
  quantities[Q_VIRT_IMAGE_BASE].init_top(&e);
  unsigned long base = e.lo;
  e.hi = base + 0x4000000ul;         /* 64 MiB span */
  unsigned long align = 0x1000000ul; /* 16 MiB slots */

  /* No holes: (hi - lo) / align. */
  unsigned long full = quantity_slots(Q_VIRT_IMAGE_BASE, &e, NULL, 0, align);
  assert(full == (e.hi - e.lo) / align);

  /* An interior hole strictly reduces the count. */
  struct constraint cs[1];
  cs[0] = mk(Q_VIRT_IMAGE_BASE, C_EXCLUDE, base + 0x1000000ul, CONF_DERIVED, 1);
  cs[0].value2 = base + 0x1fffffful; /* hole [base+16M, base+32M-1] */
  unsigned long holed = quantity_slots(Q_VIRT_IMAGE_BASE, &e, cs, 1, align);
  assert(holed < full);

  /* align 0 is defined as 0 slots (no division). */
  assert(quantity_slots(Q_VIRT_IMAGE_BASE, &e, NULL, 0, 0) == 0);
}

static void test_quantity_ranges_finset(void) {
  const struct quantity_def *qd = &quantities[Q_VA_BITS];
  struct estimate e;
  qd->init_top(&e); /* all candidates live */
  struct range out[16];
  int n = quantity_ranges(Q_VA_BITS, &e, NULL, 0, out, 16);
  assert(n == qd->n_candidates);
  for (int i = 0; i < n; i++)
    assert(out[i].lo == out[i].hi); /* degenerate point per candidate */
}

static void test_quantity_ranges_maxalign_empty(void) {
  struct estimate e;
  quantities[Q_VIRT_KASLR_ALIGN].init_top(&e);
  struct range out[4];
  int n = quantity_ranges(Q_VIRT_KASLR_ALIGN, &e, NULL, 0, out, 4);
  assert(n == 0); /* an alignment is not an address set */
}

/* ========================================================================
 * Honest-top soundness validation (compiled arch)
 * ======================================================================== */
static int interval_admits(enum kasld_quantity q, unsigned long v) {
  struct estimate e;
  quantities[q].init_top(&e);
  return v >= e.lo && v <= e.hi;
}

static void test_honest_tops_admit_known_values(void) {
  /* Every arch: the KASLR-off default text base must be inside the top. The
   * virtual top is [KASLR_VIRT_TEXT_MIN_WIDE, KASLR_VIRT_TEXT_MAX]; the _WIDE
   * floor is KASLR_VIRT_TEXT_MIN on arches without a configurable
   * PHYSICAL_START, and is wider on arches like x86_64 where
   * KASLR_VIRT_TEXT_MIN bakes in CONFIG_PHYSICAL_START at its compile-time
   * default (a smaller config would otherwise leave text outside the window —
   * soundness violation we now avoid). */
  assert(interval_admits(Q_VIRT_IMAGE_BASE,
                         (unsigned long)KERNEL_VIRT_TEXT_DEFAULT));
  assert(interval_admits(Q_VIRT_IMAGE_BASE,
                         (unsigned long)KASLR_VIRT_TEXT_MIN_WIDE));
  assert(interval_admits(Q_VIRT_IMAGE_BASE,
                         (unsigned long)KASLR_VIRT_TEXT_MAX - 1ul));
  /* And the COMPILE-TIME KASLR_VIRT_TEXT_MIN (the heuristic floor) is admitted,
   * sitting at-or-above the widened floor. */
  assert(
      interval_admits(Q_VIRT_IMAGE_BASE, (unsigned long)KASLR_VIRT_TEXT_MIN));

#if defined(__aarch64__)
  /* Pre-v5.4 arm64 layout: the kernel image sits LOW, below _PAGE_END, at
   * VA_START(48) + 128 MiB module region; _text a TEXT_OFFSET above it (v4.14
   * real value 0xffff000008080000). The honest top must admit it, or an
   * unprivileged report on a pre-v5.4 kernel excludes the true text base. */
  assert(interval_admits(Q_VIRT_IMAGE_BASE, 0xffff000008080000ul));
#endif
#if defined(__s390__) || defined(__s390x__)
  /* Pre-v6.8 s390 runs identity-mapped: kernel text near address 0 (image base
   * at the bottom of RAM, _stext at IMAGE_BASE_OFFSET). The honest top must
   * admit the low identity-mapped text base. */
  assert(interval_admits(Q_VIRT_IMAGE_BASE, (unsigned long)IMAGE_BASE_OFFSET));
  assert(interval_admits(Q_VIRT_IMAGE_BASE, 0x200ul));
#endif

#if defined(__x86_64__) || defined(__amd64__)
  /* Physical text base: the honest top must admit a HIGH load address —
   * the whole point of demoting the 16 GiB KERNEL_PHYS_MAX heuristic.
   * 256 GiB would fail against the old hard cap. The FLOOR is now
   * KASLR_PHYS_MIN_WIDE (== PHYSICAL_START_MIN_PRACTICAL = 2 MiB on x86_64)
   * so kernels built with a non-default CONFIG_PHYSICAL_START as low as
   * 2 MiB are admitted; addresses below that minimum are excluded. */
  assert(interval_admits(Q_PHYS_IMAGE_BASE, (unsigned long)PHYSICAL_START));
  assert(interval_admits(Q_PHYS_IMAGE_BASE, (unsigned long)KASLR_PHYS_MIN));
  assert(
      interval_admits(Q_PHYS_IMAGE_BASE, (unsigned long)KASLR_PHYS_MIN_WIDE));
  assert(!interval_admits(Q_PHYS_IMAGE_BASE,
                          (unsigned long)KASLR_PHYS_MIN_WIDE - 1ul));
  assert(interval_admits(Q_PHYS_IMAGE_BASE, 0x4000000000ul)); /* 256 GiB */
  assert(!interval_admits(Q_PHYS_IMAGE_BASE, PHYS_ADDR_TOP + 1ul));

  /* PAGE_OFFSET top spans both 5-level (the compile default) and 4-level. */
  assert(interval_admits(Q_PAGE_OFFSET, (unsigned long)PAGE_OFFSET));
  assert(interval_admits(Q_PAGE_OFFSET, 0xffff888000000000ul)); /* 4-level */

  /* The Q_VA_BITS top admits every architectural VA-bits candidate. */
  {
    struct estimate e;
    quantities[Q_VA_BITS].init_top(&e);
    static const unsigned long cands[] = VA_BITS_CANDIDATES;
    for (size_t i = 0; i < sizeof(cands) / sizeof(cands[0]); i++)
      assert(finset_has(Q_VA_BITS, &e, cands[i]));
  }
#endif
}

/* ========================================================================
 * C_STRIDE: q ≡ value (mod modulus) annotation on LK_INTERVAL.
 * ======================================================================== */
static struct constraint mk_stride(enum kasld_quantity q, unsigned long residue,
                                   unsigned long modulus, uint32_t id) {
  struct constraint c;
  memset(&c, 0, sizeof(c));
  c.q = q;
  c.op = C_STRIDE;
  c.value = residue;
  c.value2 = modulus;
  c.conf = CONF_PARSED;
  c.id = id;
  c.lineage_count = 1;
  return c;
}

/* First stride constraint sets the annotation; the estimate's stride pair
 * matches the residue and modulus. */
static void test_stride_first_constraint_sets_annotation(void) {
  struct estimate e;
  quantities[Q_VIRT_IMAGE_BASE].init_top(&e);
  struct constraint c =
      mk_stride(Q_VIRT_IMAGE_BASE, 0x1234ul, 0x100000ul /* 1 MiB */, 1);
  estimate_meet(&e, &quantities[Q_VIRT_IMAGE_BASE], &c);
  assert(e.stride == 0x100000ul);
  assert(e.stride_offset == 0x1234ul);
  assert(e.stride_binding == 1);
  assert(!estimate_is_bottom(&e, &quantities[Q_VIRT_IMAGE_BASE]));
}

/* Two stride constraints with the same modulus agree → estimate stays
 * non-bottom and annotation is preserved. */
static void test_stride_same_modulus_agreeing_residues(void) {
  struct estimate e;
  quantities[Q_VIRT_IMAGE_BASE].init_top(&e);
  struct constraint c1 = mk_stride(Q_VIRT_IMAGE_BASE, 0x1000ul, 0x10000ul, 1);
  struct constraint c2 = mk_stride(Q_VIRT_IMAGE_BASE, 0x11000ul, 0x10000ul, 2);
  estimate_meet(&e, &quantities[Q_VIRT_IMAGE_BASE], &c1);
  estimate_meet(&e, &quantities[Q_VIRT_IMAGE_BASE], &c2);
  assert(e.stride == 0x10000ul);
  assert(e.stride_offset == 0x1000ul);
  assert(!estimate_is_bottom(&e, &quantities[Q_VIRT_IMAGE_BASE]));
}

/* Two stride constraints with the same modulus, disagreeing residues →
 * estimate goes bottom (the system is unsatisfiable). */
static void test_stride_same_modulus_disagreeing_residues_bottom(void) {
  struct estimate e;
  quantities[Q_VIRT_IMAGE_BASE].init_top(&e);
  struct constraint c1 = mk_stride(Q_VIRT_IMAGE_BASE, 0x1000ul, 0x10000ul, 1);
  struct constraint c2 = mk_stride(Q_VIRT_IMAGE_BASE, 0x2000ul, 0x10000ul, 2);
  estimate_meet(&e, &quantities[Q_VIRT_IMAGE_BASE], &c1);
  estimate_meet(&e, &quantities[Q_VIRT_IMAGE_BASE], &c2);
  assert(estimate_is_bottom(&e, &quantities[Q_VIRT_IMAGE_BASE]));
}

/* Two stride constraints with different (non-coprime) moduli combine via
 * CRT to lcm(m1, m2) with a consistent residue. */
static void test_stride_crt_combines_to_lcm(void) {
  struct estimate e;
  quantities[Q_VIRT_IMAGE_BASE].init_top(&e);
  /* x ≡ 1 (mod 6), x ≡ 4 (mod 9) — gcd(6,9)=3; (4-1) mod 3 == 0 so solvable.
   * lcm(6, 9) = 18; solution class: x ≡ 13 (mod 18). */
  struct constraint c1 = mk_stride(Q_VIRT_IMAGE_BASE, 1ul, 6ul, 1);
  struct constraint c2 = mk_stride(Q_VIRT_IMAGE_BASE, 4ul, 9ul, 2);
  estimate_meet(&e, &quantities[Q_VIRT_IMAGE_BASE], &c1);
  estimate_meet(&e, &quantities[Q_VIRT_IMAGE_BASE], &c2);
  assert(e.stride == 18ul);
  assert(e.stride_offset == 13ul);
  assert(!estimate_is_bottom(&e, &quantities[Q_VIRT_IMAGE_BASE]));
}

/* CRT spotting inconsistency: x ≡ 1 (mod 6), x ≡ 5 (mod 9) — (5-1) mod
 * gcd(6,9)=3 is 1, so no joint solution exists. */
static void test_stride_crt_inconsistent_bottom(void) {
  struct estimate e;
  quantities[Q_VIRT_IMAGE_BASE].init_top(&e);
  struct constraint c1 = mk_stride(Q_VIRT_IMAGE_BASE, 1ul, 6ul, 1);
  struct constraint c2 = mk_stride(Q_VIRT_IMAGE_BASE, 5ul, 9ul, 2);
  estimate_meet(&e, &quantities[Q_VIRT_IMAGE_BASE], &c1);
  estimate_meet(&e, &quantities[Q_VIRT_IMAGE_BASE], &c2);
  assert(estimate_is_bottom(&e, &quantities[Q_VIRT_IMAGE_BASE]));
}

/* Stride with no residue-class member in the interval → bottom. */
static void test_stride_no_intersection_with_interval_bottom(void) {
  struct estimate e;
  quantities[Q_VIRT_IMAGE_BASE].init_top(&e);
  /* Pin the interval to a single point not matching the stride class. */
  e.lo = e.hi = 0x100ul; /* the only admitted value */
  struct constraint c = mk_stride(Q_VIRT_IMAGE_BASE, 7ul, 16ul, 1);
  /* 0x100 mod 16 == 0; residue 7 — disjoint. */
  estimate_meet(&e, &quantities[Q_VIRT_IMAGE_BASE], &c);
  assert(estimate_is_bottom(&e, &quantities[Q_VIRT_IMAGE_BASE]));
}

/* quantity_slots with a stride > align counts residue-class members, not
 * raw align-step members. Demonstrates entropy collapse — the s390
 * segment-mod use case. */
static void test_quantity_slots_with_stride(void) {
  struct constraint cs[1];
  cs[0] = mk_stride(Q_VIRT_IMAGE_BASE, 0x200000ul, 0x100000ul, 1);
  struct estimate e;
  quantities[Q_VIRT_IMAGE_BASE].init_top(&e);
  e.stride = 0x100000ul;        /* 1 MiB */
  e.stride_offset = 0x200000ul; /* anchor inside the class */
  /* Pin a small window so the count is meaningfully bounded. */
  e.lo = 0x10000000ul;
  e.hi = 0x10000000ul + 0x800000ul; /* 8 MiB window */
  /* With align = 16 KiB: 8 MiB / 16 KiB = 512 align-slots, but only
   * 8 MiB / 1 MiB = 8 stride-class slots. */
  unsigned long slots =
      quantity_slots(Q_VIRT_IMAGE_BASE, &e, cs, 1, 0x4000ul /* 16 KiB */);
  assert(slots == 8 || slots == 9); /* off-by-one at edge tolerable */
}

int main(void) {
  TEST_SUITE("test_estimate");

  BEGIN_CATEGORY("Lattice meet");
  RUN(test_interval_meet_bounds);
  RUN(test_interval_meet_equals_and_bottom);
  RUN(test_maxalign_meet);
  RUN(test_finset_meet);

  BEGIN_CATEGORY("Stride (C_STRIDE) algebra");
  RUN(test_stride_first_constraint_sets_annotation);
  RUN(test_stride_same_modulus_agreeing_residues);
  RUN(test_stride_same_modulus_disagreeing_residues_bottom);
  RUN(test_stride_crt_combines_to_lcm);
  RUN(test_stride_crt_inconsistent_bottom);
  RUN(test_stride_no_intersection_with_interval_bottom);
  RUN(test_quantity_slots_with_stride);

  BEGIN_CATEGORY("Greedy resolver");
  RUN(test_resolve_stronger_wins);
  RUN(test_resolve_priority_flips_with_confidence);
  RUN(test_resolve_deterministic_and_no_conflict);
  RUN(test_estimate_at_trust_floor);

  BEGIN_CATEGORY("Consumer value-access (quantity_ranges/slots)");
  RUN(test_quantity_ranges_interval_plain);
  RUN(test_quantity_ranges_interval_with_interior_hole);
  RUN(test_quantity_slots_hole_aware);
  RUN(test_quantity_ranges_finset);
  RUN(test_quantity_ranges_maxalign_empty);

  BEGIN_CATEGORY("Honest-top soundness");
  RUN(test_honest_tops_admit_known_values);

  return TEST_DONE();
}
