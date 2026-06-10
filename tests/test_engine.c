// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Unit tests for the inference engine and every rule in src/rules/. Each rule
// is exercised in isolation over synthetic in-memory evidence; further tests
// cover the fixpoint loop's cross-quantity propagation (e.g. virt_page_offset
// -> vmalloc, which needs multiple passes) and the resolver's conflict
// handling. Arch-gated rule bodies run their active path under
// tests/test-cross.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine.h"
#include "include/kasld/regions.h"
#include "test_harness.h"

#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

/* The real ported rule under test. */
int rule_range_from_interior(const struct evidence_set *ev,
                             const struct estimate *est, struct constraint *out,
                             int out_max);

static struct observation mk_obs(enum kasld_addr_type type,
                                 enum kasld_region region, unsigned long addr,
                                 uint32_t set_mask, enum kasld_position pos,
                                 enum kasld_confidence conf) {
  struct observation o;
  memset(&o, 0, sizeof(o));
  o.type = type;
  o.region = region;
  if (set_mask & SAMPLE_SET)
    o.sample = addr;
  if (set_mask & LO_SET)
    o.lo = addr;
  o.set_mask = set_mask;
  o.pos = pos;
  o.conf = conf;
  return o;
}

/* ========================================================================
 * Pilot rule via the engine
 * ======================================================================== */
static void test_engine_interior_ceiling(void) {
  struct engine e;
  engine_init(&e);

  struct estimate top;
  quantities[Q_VIRT_TEXT_BASE].init_top(&top);
  unsigned long sample = top.lo + 0x1234000ul; /* inside the window */

  struct observation o = mk_obs(KASLD_TYPE_VIRT, REGION_KERNEL_IMAGE, sample,
                                SAMPLE_SET, POS_INTERIOR, CONF_PARSED);
  evidence_add(&e.ev, &o);

  const rule_fn rules[] = {rule_range_from_interior};
  engine_run(&e, rules, 1);

  /* text base must be <= the interior sample. */
  assert(e.est[Q_VIRT_TEXT_BASE].hi == sample);
  assert(e.est[Q_VIRT_TEXT_BASE].lo == top.lo); /* floor unchanged */
}

/* ========================================================================
 * Cross-quantity fixpoint: virt_page_offset -> vmalloc
 * ======================================================================== */
/* 64-bit-only: the synthetic vmalloc gap (1 TiB) and virt_page_offset values
 * exceed a 32-bit `unsigned long`. The cross-quantity fixpoint mechanism is
 * identical on every width; it is exercised here on 64-bit (host + 64-bit
 * cross). */
#if __SIZEOF_LONG__ >= 8
#define VMALLOC_GAP 0x10000000000ul /* 1 TiB, synthetic */

static int rule_pin_page_offset(const struct evidence_set *ev,
                                const struct estimate *est,
                                struct constraint *out, int out_max) {
  (void)est;
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->eff_region != REGION_PAGE_OFFSET || !HAS_LO(o))
      continue;
    if (out_max < 1)
      return 0;
    memset(&out[0], 0, sizeof(out[0]));
    out[0].q = Q_PAGE_OFFSET;
    out[0].op = C_EQUALS;
    out[0].value = o->lo;
    out[0].conf = o->conf;
    out[0].derived_from[0] = o->id;
    out[0].lineage_count = 1;
    snprintf(out[0].origin, ORIGIN_LEN, "pin_page_offset");
    return 1;
  }
  return 0;
}

/* Test helper: emit C_UPPER_BOUND on Q_PAGE_OFFSET from any REGION_PAGE_OFFSET
 * observation. Mirrors rule_pin_page_offset but narrows hi only, leaving lo
 * free — for tests that need a windowed (not pinned) Q_PAGE_OFFSET. */
static int rule_cap_page_offset(const struct evidence_set *ev,
                                const struct estimate *est,
                                struct constraint *out, int out_max) {
  (void)est;
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->eff_region != REGION_PAGE_OFFSET || !HAS_LO(o))
      continue;
    if (out_max < 1)
      return 0;
    memset(&out[0], 0, sizeof(out[0]));
    out[0].q = Q_PAGE_OFFSET;
    out[0].op = C_UPPER_BOUND;
    out[0].value = o->lo;
    out[0].conf = o->conf;
    out[0].derived_from[0] = o->id;
    out[0].lineage_count = 1;
    snprintf(out[0].origin, ORIGIN_LEN, "cap_page_offset");
    return 1;
  }
  return 0;
}

static int rule_vmalloc_from_po(const struct evidence_set *ev,
                                const struct estimate *est,
                                struct constraint *out, int out_max) {
  (void)ev;
  const struct estimate *po = &est[Q_PAGE_OFFSET];
  /* Fire only once virt_page_offset is pinned to a point. */
  if (po->lo != po->hi || out_max < 1)
    return 0;
  if (po->lo > ULONG_MAX - VMALLOC_GAP)
    return 0;
  memset(&out[0], 0, sizeof(out[0]));
  out[0].q = Q_VMALLOC_BASE;
  out[0].op = C_LOWER_BOUND;
  out[0].value = po->lo + VMALLOC_GAP;
  out[0].conf = CONF_DERIVED;
  out[0].lineage_count = 0;
  snprintf(out[0].origin, ORIGIN_LEN, "vmalloc_from_po");
  return 1;
}

static void test_engine_cross_quantity_fixpoint(void) {
  struct engine e;
  engine_init(&e);

  struct estimate po_top;
  quantities[Q_PAGE_OFFSET].init_top(&po_top);
  unsigned long po_val = po_top.lo + 0x8aa754a000ul; /* inside VAS window */

  struct observation o = mk_obs(KASLD_TYPE_VIRT, REGION_PAGE_OFFSET, po_val,
                                LO_SET, POS_BASE, CONF_DERIVED);
  evidence_add(&e.ev, &o);

  /* Order rules so the consumer (vmalloc) is listed BEFORE the producer
   * (virt_page_offset) — proving the result comes from cross-pass propagation,
   * not intra-pass rule ordering. */
  const rule_fn rules[] = {rule_vmalloc_from_po, rule_pin_page_offset};
  engine_run(&e, rules, 2);

  /* virt_page_offset pinned. */
  assert(e.est[Q_PAGE_OFFSET].lo == po_val &&
         e.est[Q_PAGE_OFFSET].hi == po_val);
  /* vmalloc lower bound derived from the pinned virt_page_offset. */
  assert(e.est[Q_VMALLOC_BASE].lo == po_val + VMALLOC_GAP);
  /* Required at least two passes: pin in pass 1, derive vmalloc in pass 2. */
  assert(e.passes >= 2);
}
#endif /* __SIZEOF_LONG__ >= 8 (cross-quantity fixpoint) */

/* ========================================================================
 * Termination: convergence on stable input
 * ======================================================================== */
static void test_engine_converges_and_is_stable(void) {
  struct engine e;
  engine_init(&e);
  struct estimate top;
  quantities[Q_VIRT_TEXT_BASE].init_top(&top);
  struct observation o =
      mk_obs(KASLD_TYPE_VIRT, REGION_KERNEL_IMAGE, top.lo + 0x800000ul,
             SAMPLE_SET, POS_INTERIOR, CONF_PARSED);
  evidence_add(&e.ev, &o);

  const rule_fn rules[] = {rule_range_from_interior};
  engine_run(&e, rules, 1);
  assert(e.passes <= ENGINE_MAX_PASSES);

  /* A second run from scratch yields identical estimates (determinism). */
  struct engine e2;
  engine_init(&e2);
  evidence_add(&e2.ev, &o);
  engine_run(&e2, rules, 1);
  assert(e2.est[Q_VIRT_TEXT_BASE].hi == e.est[Q_VIRT_TEXT_BASE].hi);
  /* Re-emitted identical constraints do not grow the store unboundedly. */
  assert(e.n_constraints <= 4);
}

/* Saturation flag is clean on a healthy run. */
static void test_engine_saturation_clean(void) {
  struct engine e;
  engine_init(&e);
  struct estimate top;
  quantities[Q_VIRT_TEXT_BASE].init_top(&top);
  struct observation o =
      mk_obs(KASLD_TYPE_VIRT, REGION_KERNEL_IMAGE, top.lo + 0x800000ul,
             SAMPLE_SET, POS_INTERIOR, CONF_PARSED);
  evidence_add(&e.ev, &o);
  const rule_fn rules[] = {rule_range_from_interior};
  engine_run(&e, rules, 1);
  assert(e.saturation == 0);
}

/* A test-local rule that emits ENGINE_RULE_MAX_EMIT fresh-valued
 * constraints per call (distinct origins + values, so dedup doesn't collapse
 * them). Each invocation advances a static counter, so registering this rule
 * pointer multiple times in one pass produces compounding emissions. */
static int sat_fresh_emit_counter = 0;
static int sat_fresh_emit_rule(const struct evidence_set *ev,
                               const struct estimate *est,
                               struct constraint *out, int out_max) {
  (void)ev;
  (void)est;
  int n = 0;
  while (n < out_max) {
    struct constraint *c = &out[n++];
    memset(c, 0, sizeof(*c));
    c->q = Q_VIRT_TEXT_BASE;
    c->op = C_UPPER_BOUND;
    c->value =
        0xffffffffc0000000ul - (unsigned long)sat_fresh_emit_counter * 0x100ul;
    c->conf = CONF_HEURISTIC;
    snprintf(c->origin, ORIGIN_LEN, "sat_fresh_%d", sat_fresh_emit_counter);
    sat_fresh_emit_counter++;
  }
  return n;
}

/* Force ENGINE_MAX_CONSTRAINTS by registering the fresh-emit rule enough
 * times in one pass that the cumulative emissions exceed
 * ENGINE_MAX_CONSTRAINTS. ENGINE_RULE_MAX_EMIT = 32, so
 * ceil(ENGINE_MAX_CONSTRAINTS / 32) + 1 registrations is enough. */
static void test_engine_saturation_constraints_full(void) {
  sat_fresh_emit_counter = 0;
  struct engine e;
  engine_init(&e);
  /* Constant-sized so the array is a regular automatic, not a VLA
   * (ENGINE_MAX_CONSTRAINTS and ENGINE_RULE_MAX_EMIT are #defines, but
   * an `int needed = expr; T arr[needed];` form is still a VLA per C99). */
  enum { needed = (ENGINE_MAX_CONSTRAINTS / ENGINE_RULE_MAX_EMIT) + 1 };
  rule_fn rules[needed];
  for (int i = 0; i < needed; i++)
    rules[i] = sat_fresh_emit_rule;
  engine_run(&e, rules, needed);
  assert(e.saturation & ENGINE_SAT_CONSTRAINTS_FULL);
  assert(e.n_constraints == ENGINE_MAX_CONSTRAINTS);
  /* Soundness under cap: the resolved estimate must be a valid (non-bottom)
   * range — the cap drops late-arriving constraints, it cannot corrupt
   * already-meet'd ones. */
  assert(!estimate_is_bottom(&e.est[Q_VIRT_TEXT_BASE],
                             &quantities[Q_VIRT_TEXT_BASE]));
  assert(e.est[Q_VIRT_TEXT_BASE].lo <= e.est[Q_VIRT_TEXT_BASE].hi);
}

/* Force ESTIMATE_MAX_WORK by handing estimate_resolve more than
 * ESTIMATE_MAX_WORK in-scope constraints. The bit propagates from the
 * resolve_result into engine.saturation on the next resolve_all pass. */
static void test_engine_saturation_estimate_work_full(void) {
  /* Direct estimate_resolve test (bypasses the engine loop). */
  struct constraint many[ESTIMATE_MAX_WORK + 4];
  for (int i = 0; i < ESTIMATE_MAX_WORK + 4; i++) {
    memset(&many[i], 0, sizeof(many[i]));
    many[i].q = Q_VIRT_TEXT_BASE;
    many[i].op = C_UPPER_BOUND;
    many[i].value = 0xffffffffc0000000ul - (unsigned long)i * 0x1000ul;
    many[i].conf = CONF_HEURISTIC;
    many[i].id = (uint32_t)(i + 1);
  }
  struct resolve_result r;
  estimate_resolve(Q_VIRT_TEXT_BASE, CONF_BRUTE, many, ESTIMATE_MAX_WORK + 4,
                   &r);
  assert(r.saturation & ESTIMATE_SAT_WORK_FULL);
  /* Soundness: even with the gather truncated, the resolved estimate is
   * a valid non-bottom interval. The resolver sorts by confidence /
   * lineage before the greedy meet (see estimate.c), so dropping items
   * past the cap can only widen — never corrupt — the resolved window. */
  assert(!estimate_is_bottom(&r.est, &quantities[Q_VIRT_TEXT_BASE]));
  assert(r.est.lo <= r.est.hi);
}

/* A test-local constraint rule that LIES about its emission count: it fills
 * the buffer with one valid harmless constraint and returns
 * ENGINE_RULE_MAX_EMIT + 1 — the engine should clamp the count to the cap
 * and set ENGINE_SAT_RULE_EMIT_OVERFLOW. The lie is the canonical way to
 * exercise the cap from outside the engine (no rule legitimately wants more
 * than the cap allows). */
static int sat_rule_lies_about_emit(const struct evidence_set *ev,
                                    const struct estimate *est,
                                    struct constraint *out, int out_max) {
  (void)ev;
  (void)est;
  if (out_max > 0) {
    memset(&out[0], 0, sizeof(out[0]));
    out[0].q = Q_VIRT_TEXT_BASE;
    out[0].op = C_UPPER_BOUND;
    /* Vacuous upper bound (always-true on any address width). The test
     * asserts on the saturation flag, not on the resolved value, so any
     * non-bottom-forcing value works — and ULONG_MAX is width-portable
     * across 32-bit and 64-bit cross targets. */
    out[0].value = ULONG_MAX;
    out[0].conf = CONF_HEURISTIC;
    snprintf(out[0].origin, ORIGIN_LEN, "sat_lie");
  }
  return ENGINE_RULE_MAX_EMIT + 1; /* claim more than we filled */
}

static void test_engine_saturation_rule_emit_overflow(void) {
  struct engine e;
  engine_init(&e);
  const rule_fn rules[] = {sat_rule_lies_about_emit};
  engine_run(&e, rules, 1);
  assert(e.saturation & ENGINE_SAT_RULE_EMIT_OVERFLOW);
  /* Estimate remains sound: the one actually-filled constraint was
   * applied; everything else was clamped before reaching the store. */
  assert(!estimate_is_bottom(&e.est[Q_VIRT_TEXT_BASE],
                             &quantities[Q_VIRT_TEXT_BASE]));
  assert(e.est[Q_VIRT_TEXT_BASE].lo <= e.est[Q_VIRT_TEXT_BASE].hi);
  assert(e.n_constraints <= ENGINE_RULE_MAX_EMIT); /* clamp held */
}

/* Verdict-rule sibling: lies about how many verdicts it produced. The
 * engine clamps and sets ENGINE_SAT_VRULE_EMIT_OVERFLOW. */
static int sat_vrule_lies_about_emit(const struct evidence_set *ev,
                                     struct verdict *out, int out_max) {
  (void)ev;
  if (out_max > 0) {
    memset(&out[0], 0, sizeof(out[0]));
    out[0].kind = V_INVALID;
    out[0].observation_id =
        0xffffffffu; /* stale id — verdict harmlessly ignored */
    snprintf(out[0].origin, ORIGIN_LEN, "sat_vlie");
  }
  return ENGINE_RULE_MAX_EMIT + 1; /* claim more than we filled */
}

static void test_engine_saturation_vrule_emit_overflow(void) {
  struct engine e;
  engine_init(&e);
  const verdict_fn vrules[] = {sat_vrule_lies_about_emit};
  engine_run_full(&e, NULL, 0, vrules, 1);
  assert(e.saturation & ENGINE_SAT_VRULE_EMIT_OVERFLOW);
  /* All estimates remain at their honest tops (no constraint rules ran),
   * which is well-defined and non-bottom for every quantity. */
  for (int q = 0; q < Q__COUNT; q++)
    assert(!estimate_is_bottom(&e.est[q], &quantities[q]));
}

/* Force ESTIMATE_MAX_CONFLICTS by feeding many contradictory low-confidence
 * constraints — each is rejected as bottom-forcing; once the conflict array
 * is full, ESTIMATE_SAT_CONFLICTS_FULL is set. */
static void test_engine_saturation_conflicts_full(void) {
  /* One high-priority lower bound + (ESTIMATE_MAX_CONFLICTS + 4) upper bounds
   * below it. Each upper bound forces bottom against the lower bound, gets
   * rejected; the conflict array fills at MAX_CONFLICTS and the rest set the
   * saturation flag.
   *
   * Bounds are derived from the quantity's own honest top so the test is
   * portable across every 32- and 64-bit arch (a hard-coded x86_64 layout
   * would truncate on 32-bit targets and miss the window). The saturation
   * logic is arch-neutral; only the values need to land inside the window. */
  struct estimate top;
  quantities[Q_VIRT_TEXT_BASE].init_top(&top);
  const unsigned long lb_val = top.lo + 0x10000ul;
  const unsigned long ub_base = top.lo + 0x1000ul; /* below lb_val */

  enum { N_CONFLICTING = ESTIMATE_MAX_CONFLICTS + 4 };
  struct constraint cs[1 + N_CONFLICTING];
  int n = 0;
  memset(&cs[n], 0, sizeof(cs[n]));
  cs[n].q = Q_VIRT_TEXT_BASE;
  cs[n].op = C_LOWER_BOUND;
  cs[n].value = lb_val;
  cs[n].conf = CONF_PARSED; /* highest conf — accepted first */
  cs[n].id = (uint32_t)(n + 1);
  n++;
  for (int i = 0; i < N_CONFLICTING; i++) {
    memset(&cs[n], 0, sizeof(cs[n]));
    cs[n].q = Q_VIRT_TEXT_BASE;
    cs[n].op = C_UPPER_BOUND;
    cs[n].value = ub_base - (unsigned long)i * 4ul; /* each below lb_val */
    cs[n].conf = CONF_HEURISTIC;
    cs[n].id = (uint32_t)(n + 1);
    n++;
  }
  struct resolve_result r;
  estimate_resolve(Q_VIRT_TEXT_BASE, CONF_BRUTE, cs, n, &r);
  assert(r.saturation & ESTIMATE_SAT_CONFLICTS_FULL);
  assert(r.n_conflicts == ESTIMATE_MAX_CONFLICTS); /* recorded up to the cap */
  /* Soundness: the lower bound was accepted; the conflicting upper bounds
   * were rejected; the resolved estimate carries the accepted lower bound
   * against the honest top. Must remain non-bottom with lo <= hi. */
  assert(!estimate_is_bottom(&r.est, &quantities[Q_VIRT_TEXT_BASE]));
  assert(r.est.lo <= r.est.hi);
  assert(r.est.lo >= lb_val);
}

/* ========================================================================
 * ceiling_from_image_size rule (Stage D)
 * ======================================================================== */
int rule_ceiling_from_image_size(const struct evidence_set *ev,
                                 const struct estimate *est,
                                 struct constraint *out, int out_max);

static struct observation mk_image_size(unsigned long bytes,
                                        enum kasld_confidence conf) {
  struct observation o;
  memset(&o, 0, sizeof(o));
  o.value_kind = OBS_SCALAR;
  o.scalar_fact = SF_IMAGE_SIZE;
  o.scalar_value = bytes;
  o.conf = conf;
  return o;
}

static unsigned long min_ul(unsigned long a, unsigned long b) {
  return a < b ? a : b;
}

static struct observation mk_scalar(enum kasld_scalar_fact fact,
                                    unsigned long value,
                                    enum kasld_confidence conf) {
  struct observation o;
  memset(&o, 0, sizeof(o));
  o.value_kind = OBS_SCALAR;
  o.scalar_fact = fact;
  o.scalar_value = value;
  o.conf = conf;
  return o;
}

/* phys_ceiling_from_memtotal rule (Stage D), decoupled arches only. */
int rule_phys_ceiling_from_memtotal(const struct evidence_set *ev,
                                    const struct estimate *est,
                                    struct constraint *out, int out_max);

/* MemTotal + an observed physical DRAM floor yield the aligned phys ceiling
 * phys_floor + MemTotal - 4MiB, matching the legacy plugin. */
static void test_phys_ceiling_from_memtotal(void) {
#if !TEXT_TRACKS_DIRECTMAP
  struct engine e;
  engine_init(&e);
  unsigned long mem = 0x40000000ul; /* 1 GiB */
  /* DRAM start relative to the arch's physical base (0 on x86_64, 2 GiB on
   * riscv64, ...), so the derived ceiling is a valid physical address on every
   * decoupled arch — not an x86_64-shaped literal. */
  unsigned long floor = (unsigned long)PHYS_OFFSET + 0x8000000ul;
  struct observation m = mk_scalar(SF_PHYS_MEMTOTAL, mem, CONF_PARSED);
  struct observation d = mk_obs(KASLD_TYPE_PHYS, REGION_RAM, floor,
                                LO_SET | SAMPLE_SET, POS_BASE, CONF_PARSED);
  evidence_add(&e.ev, &m);
  evidence_add(&e.ev, &d);

  const rule_fn rules[] = {rule_phys_ceiling_from_memtotal};
  engine_run(&e, rules, 1);

  struct estimate top;
  quantities[Q_PHYS_TEXT_BASE].init_top(&top);
  unsigned long ceiling = (floor + mem - (4ul << 20)) & ~(KASLR_PHYS_ALIGN - 1);
  if (ceiling > (unsigned long)KASLR_PHYS_MIN)
    assert(e.est[Q_PHYS_TEXT_BASE].hi == min_ul(ceiling, top.hi)); /* fired */
  else
    assert(e.est[Q_PHYS_TEXT_BASE].hi ==
           top.hi); /* below KASLR_PHYS_MIN: inert */
#endif
}

/* When a REGION_RAM POS_TOP observation is available (proc_zoneinfo's
 * (start_pfn + spanned) emission), prefer the SPANNED DRAM extent over
 * MemTotal. On systems with large reserved regions inside DRAM, MemTotal
 * is substantially below the spanned extent and the kernel may sit
 * above the MemTotal-derived ceiling — the regression that arm64 EFI
 * hosts with >1 GiB of crashkernel/EFI-runtime reservations hit. */
static void test_phys_ceiling_prefers_dram_top_over_memtotal(void) {
#if !TEXT_TRACKS_DIRECTMAP
  struct engine e;
  engine_init(&e);
  const unsigned long P = (unsigned long)PHYS_OFFSET;
  /* Arm64-fixture-shaped numbers, scaled down so the spanned DRAM hi
   * stays under every decoupled arch's KERNEL_PHYS_MAX (the smallest
   * is riscv64 at PHYS_OFFSET + 4 GiB). Preserves the bug shape:
   * kernel sits above floor+memtotal but inside the spanned extent.
   *   memtotal      = 1.0 GiB (usable RAM)
   *   spanned DRAM  = 2.0 GiB (lots of reservations inside)
   *   actual kernel = 1.5 GiB above floor — would be rejected by
   *                   the MemTotal-only ceiling (floor + 1.0 GiB),
   *                   admitted by the dram_top ceiling (floor + 2.0 GiB).
   */
  const unsigned long memtotal = 0x40000000ul;          /* 1 GiB */
  const unsigned long floor = P + 0x40000000ul;         /* DRAM floor */
  const unsigned long top = floor + 0x80000000ul - 1ul; /* spanned DRAM hi */
  const unsigned long kernel_phys =
      floor + 0x60000000ul; /* above floor+memtotal */

  struct observation m = mk_scalar(SF_PHYS_MEMTOTAL, memtotal, CONF_PARSED);
  struct observation b = mk_obs(KASLD_TYPE_PHYS, REGION_RAM, floor,
                                LO_SET | SAMPLE_SET, POS_BASE, CONF_PARSED);
  /* mk_obs() does not populate o.hi; build the POS_TOP observation by
   * hand, matching the shape proc_zoneinfo emits (HI_SET only). */
  struct observation t;
  memset(&t, 0, sizeof(t));
  t.type = KASLD_TYPE_PHYS;
  t.region = REGION_RAM;
  t.hi = top;
  t.set_mask = HI_SET;
  t.pos = POS_TOP;
  t.conf = CONF_PARSED;
  evidence_add(&e.ev, &m);
  evidence_add(&e.ev, &b);
  evidence_add(&e.ev, &t);

  const rule_fn rules[] = {rule_phys_ceiling_from_memtotal};
  engine_run(&e, rules, 1);

  /* The dram_top-derived ceiling must admit kernel_phys; the MemTotal-
   * derived ceiling would have rejected it (floor + memtotal = floor +
   * 0xd2eb0000 < kernel_phys = floor + 0xf18b0000). */
  assert(kernel_phys <= e.est[Q_PHYS_TEXT_BASE].hi);
#endif
}

/* No DRAM observation: phys_floor falls back to PHYS_OFFSET, the ceiling still
 * resolves (proves the fallback path). */
static void test_phys_ceiling_no_dram_floor(void) {
#if !TEXT_TRACKS_DIRECTMAP
  struct engine e;
  engine_init(&e);
  unsigned long mem = 0x40000000ul;
  struct observation m = mk_scalar(SF_PHYS_MEMTOTAL, mem, CONF_PARSED);
  evidence_add(&e.ev, &m);

  const rule_fn rules[] = {rule_phys_ceiling_from_memtotal};
  engine_run(&e, rules, 1);

  unsigned long expect =
      (PHYS_OFFSET + mem - (4ul << 20)) & ~(KASLR_PHYS_ALIGN - 1);
  if (expect > KASLR_PHYS_MIN)
    assert(e.est[Q_PHYS_TEXT_BASE].hi == expect);
#endif
}

/* A measured image size yields exactly the aligned ceiling
 * (WINDOW_MAX - size) rounded down to a slot — matching the legacy plugin. */
static void test_ceiling_from_image_size(void) {
  struct engine e;
  engine_init(&e);
  unsigned long ksize = 0x1000000ul; /* 16 MiB, well within the window */
  struct observation o = mk_image_size(ksize, CONF_PARSED);
  evidence_add(&e.ev, &o);

  const rule_fn rules[] = {rule_ceiling_from_image_size};
  engine_run(&e, rules, 1);

  struct estimate top;
  quantities[Q_VIRT_TEXT_BASE].init_top(&top);
  unsigned long expect =
      min_ul((KASLR_VIRT_TEXT_MAX - ksize) & ~(KASLR_VIRT_ALIGN - 1), top.hi);
  assert(e.est[Q_VIRT_TEXT_BASE].hi == expect);
  assert(e.est[Q_VIRT_TEXT_BASE].hi < top.hi); /* the rule actually fired */

#if !TEXT_TRACKS_DIRECTMAP
  struct estimate ptop;
  quantities[Q_PHYS_TEXT_BASE].init_top(&ptop);
  unsigned long pexpect =
      min_ul((KASLR_PHYS_MAX - ksize) & ~(KASLR_PHYS_ALIGN - 1), ptop.hi);
  assert(e.est[Q_PHYS_TEXT_BASE].hi == pexpect);
#endif
}

/* The exact init_size (larger than the under-estimate) yields a tighter, still
 * sound ceiling; ceiling_from_image_size takes the largest sound size. */
static void test_ceiling_prefers_exact_init_size(void) {
  struct engine e;
  engine_init(&e);
  unsigned long est_size = 0x1000000ul;  /* 16 MiB estimate (under) */
  unsigned long init_size = 0x3000000ul; /* 48 MiB exact (larger) */
  struct observation a = mk_scalar(SF_IMAGE_SIZE, est_size, CONF_PARSED);
  struct observation b = mk_scalar(SF_INIT_SIZE, init_size, CONF_PARSED);
  evidence_add(&e.ev, &a);
  evidence_add(&e.ev, &b);

  const rule_fn rules[] = {rule_ceiling_from_image_size};
  engine_run(&e, rules, 1);

  struct estimate top;
  quantities[Q_VIRT_TEXT_BASE].init_top(&top);
  unsigned long expect = min_ul(
      (KASLR_VIRT_TEXT_MAX - init_size) & ~(KASLR_VIRT_ALIGN - 1), top.hi);
  assert(e.est[Q_VIRT_TEXT_BASE].hi == expect); /* exact init_size wins */
}

/* No image-size observation -> no ceiling constraint -> estimate stays at top.
 */
static void test_ceiling_no_evidence(void) {
  struct engine e;
  engine_init(&e);
  const rule_fn rules[] = {rule_ceiling_from_image_size};
  engine_run(&e, rules, 1);
  struct estimate top;
  quantities[Q_VIRT_TEXT_BASE].init_top(&top);
  assert(e.est[Q_VIRT_TEXT_BASE].hi == top.hi);
}

/* An image larger than the whole window cannot constrain the base (soundness:
 * never emit a bound that would empty the range). */
static void test_ceiling_oversized_image(void) {
  struct engine e;
  engine_init(&e);
  struct observation o = mk_image_size(ULONG_MAX, CONF_PARSED);
  evidence_add(&e.ev, &o);
  const rule_fn rules[] = {rule_ceiling_from_image_size};
  engine_run(&e, rules, 1);
  struct estimate top;
  quantities[Q_VIRT_TEXT_BASE].init_top(&top);
  assert(e.est[Q_VIRT_TEXT_BASE].hi == top.hi);
}

/* dram_floor_bound rule (Stage D): min phys DRAM -> a lower bound on the
 * kernel base (phys on decoupled arches, virt on coupled). */
int rule_dram_floor_bound(const struct evidence_set *ev,
                          const struct estimate *est, struct constraint *out,
                          int out_max);

static void test_dram_floor_bound(void) {
  struct engine e;
  engine_init(&e);
  unsigned long floor = 0x40000000ul; /* DRAM starts at 1 GiB (QEMU virt) */
  struct observation d = mk_obs(KASLD_TYPE_PHYS, REGION_RAM, floor,
                                LO_SET | SAMPLE_SET, POS_BASE, CONF_PARSED);
  evidence_add(&e.ev, &d);

  const rule_fn rules[] = {rule_dram_floor_bound};
  engine_run(&e, rules, 1);

#if !TEXT_TRACKS_DIRECTMAP
  /* Physical floor: min DRAM rounded UP to a slot. */
  unsigned long expect =
      (floor + KASLR_PHYS_ALIGN - 1) & ~(KASLR_PHYS_ALIGN - 1);
  if (expect > KASLR_PHYS_MIN) {
    assert(e.est[Q_PHYS_TEXT_BASE].lo == expect);
    struct estimate top;
    quantities[Q_PHYS_TEXT_BASE].init_top(&top);
    assert(e.est[Q_PHYS_TEXT_BASE].lo > top.lo); /* the rule raised the floor */
  }
#else
  /* Virtual floor via the compile-time conversion, rounded DOWN. */
  if (floor >= PHYS_OFFSET) {
    unsigned long expect = (floor - PHYS_OFFSET + PAGE_OFFSET + TEXT_OFFSET) &
                           ~(KASLR_VIRT_ALIGN - 1);
    if (expect > KASLR_VIRT_TEXT_MIN)
      assert(e.est[Q_VIRT_TEXT_BASE].lo == expect);
  }
#endif
}

/* The floor must never invert the interval: a lower bound is only emitted
 * when it stays below the resolved ceiling (engine guarantees non-bottom). */
static void test_dram_floor_no_dram(void) {
  struct engine e;
  engine_init(&e);
  const rule_fn rules[] = {rule_dram_floor_bound};
  engine_run(&e, rules, 1);
  struct estimate vtop;
  quantities[Q_VIRT_TEXT_BASE].init_top(&vtop);
  assert(e.est[Q_VIRT_TEXT_BASE].lo ==
         vtop.lo); /* no DRAM -> floor untouched */
}

/* dram_floor_bound MUST NOT treat a non-RAM dram-section observation
 * (initrd, vmcoreinfo, swiotlb, crashkernel, …) as a floor on the kernel
 * text. Those regions sit *inside* DRAM but say nothing about how far
 * below them DRAM extends; the kernel can legitimately be below. ppc64le
 * routinely loads text at phys 0 with the initrd at e.g. 0x2c90000 —
 * treating the initrd address as a phys-text floor excludes the truth.
 *
 * The test plants an initrd-only phys evidence set (no REGION_RAM
 * observation), runs dram_floor_bound in isolation, and asserts the
 * floor is NOT raised on either coupling axis. Widening the rule's
 * region filter back to is_phys_dram_region(...) would break this. */
static void test_dram_floor_ignores_non_ram_dram_regions(void) {
  struct engine e;
  engine_init(&e);
  /* High-address phys initrd — well above any plausible kernel-text floor.
   * If the rule incorrectly used this as a floor it would push
   * Q_PHYS_TEXT_BASE.lo (decoupled) or Q_VIRT_TEXT_BASE.lo (coupled) up to
   * around 0x40000000. */
  struct observation initrd =
      mk_obs(KASLD_TYPE_PHYS, REGION_INITRD, 0x40000000ul, LO_SET, POS_BASE,
             CONF_PARSED);
  evidence_add(&e.ev, &initrd);
  const rule_fn rules[] = {rule_dram_floor_bound};
  engine_run(&e, rules, 1);

  struct estimate vtop, ptop;
  quantities[Q_VIRT_TEXT_BASE].init_top(&vtop);
  quantities[Q_PHYS_TEXT_BASE].init_top(&ptop);
  /* Both axes must remain at their honest tops — the rule emitted nothing. */
  assert(e.est[Q_VIRT_TEXT_BASE].lo == vtop.lo);
  assert(e.est[Q_PHYS_TEXT_BASE].lo == ptop.lo);
}

/* page_offset_from_landmark rule (Stage F, pulled forward). */
int rule_page_offset_from_landmark(const struct evidence_set *ev,
                                   const struct estimate *est,
                                   struct constraint *out, int out_max);

/* Pick a landmark inside Q_PAGE_OFFSET's window. A fixed +1 GiB overflowed
 * on arches where top.lo sits high in a 32-bit address space (ppc32:
 * 0xc0000000 + 0x40000000 wraps to 0). Scale by the actual window so the
 * landmark always lands strictly inside on every arch / width. */
static unsigned long po_window_bump(const struct estimate *top) {
  unsigned long window = top->hi - top->lo;
  unsigned long bump = window / 4;
  if (bump > 0x40000000ul)
    bump = 0x40000000ul;
  if (bump < 0x10000ul)
    bump = 0x10000ul;
  return bump;
}

/* A single landmark pins Q_PAGE_OFFSET to its value. */
static void test_page_offset_pin(void) {
  struct engine e;
  engine_init(&e);
  struct estimate top;
  quantities[Q_PAGE_OFFSET].init_top(&top);
  unsigned long val = top.lo + po_window_bump(&top);
  struct observation o = mk_obs(KASLD_TYPE_VIRT, REGION_PAGE_OFFSET, val,
                                LO_SET, POS_BASE, CONF_PARSED);
  evidence_add(&e.ev, &o);

  const rule_fn rules[] = {rule_page_offset_from_landmark};
  engine_run(&e, rules, 1);
  assert(e.est[Q_PAGE_OFFSET].lo == val);
  assert(e.est[Q_PAGE_OFFSET].hi == val);
}

/* Conflicting landmarks: the stronger-confidence one wins; the contradicting
 * weaker one is skipped (would invert the interval) — reproducing
 * layout_adjust's consensus structurally. */
static void test_page_offset_conflict(void) {
  struct engine e;
  engine_init(&e);
  struct estimate top;
  quantities[Q_PAGE_OFFSET].init_top(&top);
  unsigned long bump = po_window_bump(&top);
  unsigned long strong = top.lo + bump;
  unsigned long weak = top.lo + bump + (bump / 2 ? bump / 2 : 0x1000ul);
  struct observation a = mk_obs(KASLD_TYPE_VIRT, REGION_PAGE_OFFSET, strong,
                                LO_SET, POS_BASE, CONF_PARSED);
  struct observation b = mk_obs(KASLD_TYPE_VIRT, REGION_PAGE_OFFSET, weak,
                                LO_SET, POS_BASE, CONF_HEURISTIC);
  evidence_add(&e.ev, &a);
  evidence_add(&e.ev, &b);

  const rule_fn rules[] = {rule_page_offset_from_landmark};
  engine_run(&e, rules, 1);
  assert(e.est[Q_PAGE_OFFSET].lo == strong); /* parsed beats heuristic */
  assert(e.est[Q_PAGE_OFFSET].hi == strong);
  /* The rejected weaker landmark is retained as a conflict for --verbose
   * explainability (engine_report_conflicts), not silently dropped. Both
   * `strong` and `weak` are now derived from a window-scaled bump (see
   * po_window_bump), so neither wraps on a 32-bit address space — the
   * contradiction fires uniformly across widths. */
  assert(e.n_conflicts[Q_PAGE_OFFSET] >= 1);
}

/* No landmark: virt_page_offset stays at its honest VAS-window top. */
static void test_page_offset_none(void) {
  struct engine e;
  engine_init(&e);
  const rule_fn rules[] = {rule_page_offset_from_landmark};
  engine_run(&e, rules, 1);
  struct estimate top;
  quantities[Q_PAGE_OFFSET].init_top(&top);
  assert(e.est[Q_PAGE_OFFSET].lo == top.lo);
  assert(e.est[Q_PAGE_OFFSET].hi == top.hi);
}

/* virt_ceiling_from_memtotal (Stage D, coupled arches): cross-quantity rule. */
int rule_virt_ceiling_from_memtotal(const struct evidence_set *ev,
                                    const struct estimate *est,
                                    struct constraint *out, int out_max);

/* page_offset_from_landmark pins Q_PAGE_OFFSET, then (on a coupled arch)
 * virt_ceiling_from_memtotal reads that pinned value to bound Q_VIRT_TEXT_BASE
 * — exercising cross-quantity dependency through the fixpoint loop. On a
 * decoupled arch (e.g. the x86_64 host) the coupled rule is inert. */
static void test_virt_ceiling_from_memtotal(void) {
  struct engine e;
  engine_init(&e);
  unsigned long mem = 0x40000000ul;
  struct observation m = mk_scalar(SF_PHYS_MEMTOTAL, mem, CONF_PARSED);
  evidence_add(&e.ev, &m);

  struct estimate potop;
  quantities[Q_PAGE_OFFSET].init_top(&potop);
  /* Pick a landmark inside the Q_PAGE_OFFSET window. A fixed +1 GiB
   * overflowed when potop.lo sits high in a 32-bit space (ppc32:
   * 0xc0000000 + 0x40000000 wraps to 0). Scale by the actual window. */
  unsigned long window = potop.hi - potop.lo;
  unsigned long bump = window / 4;
  if (bump > 0x40000000ul)
    bump = 0x40000000ul;
  if (bump < 0x10000ul)
    bump = 0x10000ul;
  unsigned long po = potop.lo + bump;
  struct observation pl = mk_obs(KASLD_TYPE_VIRT, REGION_PAGE_OFFSET, po,
                                 LO_SET, POS_BASE, CONF_PARSED);
  evidence_add(&e.ev, &pl);
  struct observation d = mk_obs(KASLD_TYPE_PHYS, REGION_RAM, PHYS_OFFSET,
                                LO_SET | SAMPLE_SET, POS_BASE, CONF_PARSED);
  evidence_add(&e.ev, &d);

  const rule_fn rules[] = {rule_page_offset_from_landmark,
                           rule_virt_ceiling_from_memtotal};
  engine_run(&e, rules, 2);

  assert(e.est[Q_PAGE_OFFSET].lo == po); /* landmark pinned it */
  assert(e.est[Q_PAGE_OFFSET].hi == po);

  struct estimate vtop;
  quantities[Q_VIRT_TEXT_BASE].init_top(&vtop);
#if !TEXT_TRACKS_DIRECTMAP
  assert(e.est[Q_VIRT_TEXT_BASE].hi == vtop.hi); /* coupled rule inert here */
#else
  /* phys_floor == PHYS_OFFSET so the offset term is zero. */
  unsigned long expect =
      (po + mem - (4ul << 20) + TEXT_OFFSET) & ~(KASLR_VIRT_ALIGN - 1);
  if (expect > KASLR_VIRT_TEXT_MIN && expect < vtop.hi)
    assert(e.est[Q_VIRT_TEXT_BASE].hi == expect);
#endif
}

/* phys_bits_ceiling (Stage D): CPU physical-address-width ceiling. */
int rule_phys_bits_ceiling(const struct evidence_set *ev,
                           const struct estimate *est, struct constraint *out,
                           int out_max);

static void test_phys_bits_ceiling(void) {
  /* Models a 46-bit physical-address width: `1UL << 46` is undefined on a
   * 32-bit `unsigned long`, and a 32-bit kernel never has a PA width that wide.
   * Runs on 64-bit (both the decoupled and the coupled mips64/ppc64/loongarch64
   * branches); skipped on 32-bit. */
#if __SIZEOF_LONG__ >= 8
  struct engine e;
  engine_init(&e);
  int bits = 46; /* common x86_64 guest PA width */
  struct observation o =
      mk_scalar(SF_PHYS_ADDR_BITS, (unsigned long)bits, CONF_PARSED);
  evidence_add(&e.ev, &o);

  const rule_fn rules[] = {rule_phys_bits_ceiling};
  engine_run(&e, rules, 1);

#if !TEXT_TRACKS_DIRECTMAP
  unsigned long expect =
      ((1UL << bits) - (4ul << 20)) & ~(KASLR_PHYS_ALIGN - 1);
  struct estimate top;
  quantities[Q_PHYS_TEXT_BASE].init_top(&top);
  if (expect > KASLR_PHYS_MIN && expect < top.hi)
    assert(e.est[Q_PHYS_TEXT_BASE].hi == expect);
#else
  unsigned long expect = (PAGE_OFFSET + TEXT_OFFSET +
                          ((1UL << bits) - (4ul << 20)) - PHYS_OFFSET) &
                         ~(KASLR_VIRT_ALIGN - 1);
  struct estimate vtop;
  quantities[Q_VIRT_TEXT_BASE].init_top(&vtop);
  if (expect > KASLR_VIRT_TEXT_MIN && expect < vtop.hi)
    assert(e.est[Q_VIRT_TEXT_BASE].hi == expect);
#endif
#endif /* __SIZEOF_LONG__ >= 8 */
}

/* Field absent (other arches) -> no constraint. */
static void test_phys_bits_absent(void) {
  struct engine e;
  engine_init(&e);
  const rule_fn rules[] = {rule_phys_bits_ceiling};
  engine_run(&e, rules, 1);
  struct estimate ptop;
  quantities[Q_PHYS_TEXT_BASE].init_top(&ptop);
  assert(e.est[Q_PHYS_TEXT_BASE].hi == ptop.hi);
}

/* dram_ceiling (Stage D, coupled): top-of-RAM ceiling, cross-quantity. */
int rule_dram_ceiling(const struct evidence_set *ev, const struct estimate *est,
                      struct constraint *out, int out_max);

static void test_dram_ceiling(void) {
  struct engine e;
  engine_init(&e);
  unsigned long ksize = 0x1000000ul;                   /* 16 MiB image */
  unsigned long dram_top = PHYS_OFFSET + 0x40000000ul; /* 1 GiB of RAM */
  struct observation is = mk_scalar(SF_IMAGE_SIZE, ksize, CONF_PARSED);
  evidence_add(&e.ev, &is);

  struct estimate potop;
  quantities[Q_PAGE_OFFSET].init_top(&potop);
  /* Pick a landmark inside the Q_PAGE_OFFSET window. A fixed +1 GiB
   * overflowed when potop.lo sits high in a 32-bit space (ppc32:
   * 0xc0000000 + 0x40000000 wraps to 0). Scale by the actual window. */
  unsigned long window = potop.hi - potop.lo;
  unsigned long bump = window / 4;
  if (bump > 0x40000000ul)
    bump = 0x40000000ul;
  if (bump < 0x10000ul)
    bump = 0x10000ul;
  unsigned long po = potop.lo + bump;
  struct observation pl = mk_obs(KASLD_TYPE_VIRT, REGION_PAGE_OFFSET, po,
                                 LO_SET, POS_BASE, CONF_PARSED);
  evidence_add(&e.ev, &pl);

  struct observation ram;
  memset(&ram, 0, sizeof(ram));
  ram.value_kind = OBS_ADDRESS;
  ram.type = KASLD_TYPE_PHYS;
  ram.region = REGION_RAM;
  ram.hi = dram_top;
  ram.set_mask = HI_SET;
  ram.conf = CONF_PARSED;
  evidence_add(&e.ev, &ram);

  const rule_fn rules[] = {rule_page_offset_from_landmark, rule_dram_ceiling};
  engine_run(&e, rules, 2);

  struct estimate vtop;
  quantities[Q_VIRT_TEXT_BASE].init_top(&vtop);
#if !TEXT_TRACKS_DIRECTMAP
  assert(e.est[Q_VIRT_TEXT_BASE].hi == vtop.hi); /* inert on decoupled */
#else
  unsigned long expect =
      (((dram_top - ksize) - PHYS_OFFSET) + po + TEXT_OFFSET) &
      ~(KASLR_VIRT_ALIGN - 1);
  if (expect > KASLR_VIRT_TEXT_MIN && expect < vtop.hi)
    assert(e.est[Q_VIRT_TEXT_BASE].hi == expect);
#endif
}

/* coupling_validate (Stage E): a curation/verdict rule. Exercises the engine's
 * verdict path (emit verdict -> evidence_resolve -> observation invalidated).
 */
int rule_coupling_validate(const struct evidence_set *ev, struct verdict *out,
                           int out_max);

static void test_coupling_validate(void) {
#if defined(__x86_64__)
  struct engine e;
  engine_init(&e);
  /* DIRECTMAP at/above KERNEL_VIRT_TEXT_MIN is misclassified -> invalidated. */
  struct observation bad =
      mk_obs(KASLD_TYPE_VIRT, REGION_DIRECTMAP, KERNEL_VIRT_TEXT_MIN + 0x1000ul,
             LO_SET | SAMPLE_SET, POS_BASE, CONF_PARSED);
  uint32_t bid = evidence_add(&e.ev, &bad);
  /* A legitimate directmap address below KERNEL_VIRT_TEXT_MIN stays valid. */
  struct observation ok = mk_obs(KASLD_TYPE_VIRT, REGION_DIRECTMAP,
                                 KERNEL_VIRT_TEXT_MIN - 0x1000000ul,
                                 LO_SET | SAMPLE_SET, POS_BASE, CONF_PARSED);
  uint32_t okid = evidence_add(&e.ev, &ok);

  const verdict_fn vrules[] = {rule_coupling_validate};
  engine_run_full(&e, NULL, 0, vrules, 1);

  int saw_bad = 0, saw_ok = 0;
  for (int i = 0; i < e.ev.n_obs; i++) {
    if (e.ev.obs[i].id == bid) {
      assert(e.ev.obs[i].valid == 0); /* curated out */
      saw_bad = 1;
    }
    if (e.ev.obs[i].id == okid) {
      assert(e.ev.obs[i].valid == 1); /* untouched */
      saw_ok = 1;
    }
  }
  assert(saw_bad && saw_ok);
#endif
}

/* text_cluster_filter (Stage E): set-based curation — invalidate VIRT outliers
 * far from the cluster median, keep the cluster. */
int rule_text_cluster_filter(const struct evidence_set *ev, struct verdict *out,
                             int out_max);

static void test_text_cluster_filter(void) {
  /* Models a 64-bit kernel-text base with a 2 GiB-distant outlier; neither the
   * base nor base+2 GiB fits a 32-bit `unsigned long`. The cluster-curation
   * logic itself is width-independent and covered on 64-bit. */
#if __SIZEOF_LONG__ >= 8
  struct engine e;
  engine_init(&e);
  /* A tight cluster of 5 text leaks + 1 far outlier. */
  unsigned long base = 0xffffffff81000000ul;
  uint32_t cid[5], oid;
  for (int i = 0; i < 5; i++) {
    struct observation o = mk_obs(KASLD_TYPE_VIRT, REGION_KERNEL_TEXT,
                                  base + (unsigned long)i * 0x1000ul,
                                  LO_SET | SAMPLE_SET, POS_BASE, CONF_PARSED);
    cid[i] = evidence_add(&e.ev, &o);
  }
  struct observation outlier =
      mk_obs(KASLD_TYPE_VIRT, REGION_KERNEL_TEXT, base + 0x80000000ul,
             LO_SET | SAMPLE_SET, POS_BASE, CONF_PARSED); /* 2 GiB away */
  oid = evidence_add(&e.ev, &outlier);

  const verdict_fn vrules[] = {rule_text_cluster_filter};
  engine_run_full(&e, NULL, 0, vrules, 1);

  for (int i = 0; i < e.ev.n_obs; i++) {
    if (e.ev.obs[i].id == oid)
      assert(e.ev.obs[i].valid == 0); /* outlier curated out */
    for (int k = 0; k < 5; k++)
      if (e.ev.obs[i].id == cid[k])
        assert(e.ev.obs[i].valid == 1); /* cluster kept */
  }
#endif /* __SIZEOF_LONG__ >= 8 */
}

/* initrd_phys_exclude (Stage E): the first C_EXCLUDE rule — carves the initrd
 * forbidden zone out of Q_PHYS_TEXT_BASE's candidate set. */
int rule_initrd_phys_exclude(const struct evidence_set *ev,
                             const struct estimate *est, struct constraint *out,
                             int out_max);

static void test_initrd_phys_exclude(void) {
#if !TEXT_TRACKS_DIRECTMAP
  struct engine e;
  engine_init(&e);
  unsigned long ksize = 0x1000000ul;                 /* 16 MiB image */
  unsigned long istart = PHYS_OFFSET + 0x10000000ul; /* initrd at +256 MiB */
  unsigned long iend = istart + 0x1000000ul;         /* 16 MiB initrd */
  struct observation is = mk_scalar(SF_IMAGE_SIZE, ksize, CONF_PARSED);
  evidence_add(&e.ev, &is);
  struct observation initrd;
  memset(&initrd, 0, sizeof(initrd));
  initrd.value_kind = OBS_ADDRESS;
  initrd.type = KASLD_TYPE_PHYS;
  initrd.region = REGION_INITRD;
  initrd.lo = istart;
  initrd.hi = iend;
  initrd.set_mask = LO_SET | HI_SET;
  initrd.conf = CONF_PARSED;
  evidence_add(&e.ev, &initrd);

  const rule_fn rules[] = {rule_initrd_phys_exclude};
  engine_run(&e, rules, 1);

  /* A C_EXCLUDE constraint on Q_PHYS_TEXT_BASE was emitted. */
  int found = 0;
  for (int i = 0; i < e.n_constraints; i++)
    if (e.constraints[i].q == Q_PHYS_TEXT_BASE &&
        e.constraints[i].op == C_EXCLUDE)
      found = 1;
  assert(found);

  /* The hole is interior (edges unchanged) but removes candidate positions:
   * slots with the carved hole < slots over the bare interval. */
  const struct estimate *est = &e.est[Q_PHYS_TEXT_BASE];
  unsigned long with = quantity_slots(Q_PHYS_TEXT_BASE, est, e.constraints,
                                      e.n_constraints, KASLR_PHYS_ALIGN);
  unsigned long bare =
      quantity_slots(Q_PHYS_TEXT_BASE, est, NULL, 0, KASLR_PHYS_ALIGN);
  assert(with < bare);
#endif
}

/* cmdline_phys_exclude: the kernel placement code refuses to overlap the
 * bootloader cmdline buffer, so its phys range is a forbidden band in
 * Q_PHYS_TEXT_BASE — same C_EXCLUDE mechanism as the initrd hole. */
int rule_cmdline_phys_exclude(const struct evidence_set *ev,
                              const struct estimate *est,
                              struct constraint *out, int out_max);

static void test_cmdline_phys_exclude(void) {
#if !TEXT_TRACKS_DIRECTMAP
  struct engine e;
  engine_init(&e);
  unsigned long ksize = 0x1000000ul;                 /* 16 MiB image */
  unsigned long cstart = PHYS_OFFSET + 0x10000000ul; /* cmdline at +256 MiB */
  unsigned long cend = cstart + 0x800ul - 1;         /* 2 KiB cmdline */
  struct observation is = mk_scalar(SF_IMAGE_SIZE, ksize, CONF_PARSED);
  evidence_add(&e.ev, &is);
  struct observation cmdline;
  memset(&cmdline, 0, sizeof(cmdline));
  cmdline.value_kind = OBS_ADDRESS;
  cmdline.type = KASLD_TYPE_PHYS;
  cmdline.region = REGION_CMDLINE;
  cmdline.lo = cstart;
  cmdline.hi = cend;
  cmdline.set_mask = LO_SET | HI_SET;
  cmdline.conf = CONF_PARSED;
  evidence_add(&e.ev, &cmdline);

  const rule_fn rules[] = {rule_cmdline_phys_exclude};
  engine_run(&e, rules, 1);

  int found = 0;
  for (int i = 0; i < e.n_constraints; i++)
    if (e.constraints[i].q == Q_PHYS_TEXT_BASE &&
        e.constraints[i].op == C_EXCLUDE)
      found = 1;
  assert(found);

  /* Interior hole: edges unchanged, hole-aware slot count strictly smaller. */
  const struct estimate *est = &e.est[Q_PHYS_TEXT_BASE];
  unsigned long with = quantity_slots(Q_PHYS_TEXT_BASE, est, e.constraints,
                                      e.n_constraints, KASLR_PHYS_ALIGN);
  unsigned long bare =
      quantity_slots(Q_PHYS_TEXT_BASE, est, NULL, 0, KASLR_PHYS_ALIGN);
  assert(with < bare);
#endif
}

/* phys_reservation_exclude: a leaked extent of a region the kernel image can't
 * occupy (crashkernel, MMIO, ...) carves a forbidden band out of the candidate
 * set; a plain-RAM extent of the same shape does NOT. */
int rule_phys_reservation_exclude(const struct evidence_set *ev,
                                  const struct estimate *est,
                                  struct constraint *out, int out_max);

static int has_phys_exclude(const struct engine *e) {
  for (int i = 0; i < e->n_constraints; i++)
    if (e->constraints[i].q == Q_PHYS_TEXT_BASE &&
        e->constraints[i].op == C_EXCLUDE)
      return 1;
  return 0;
}

static void test_phys_reservation_exclude(void) {
#if !TEXT_TRACKS_DIRECTMAP
  const rule_fn rules[] = {rule_phys_reservation_exclude};
  unsigned long ksize = 0x1000000ul;                 /* 16 MiB image */
  unsigned long rstart = PHYS_OFFSET + 0x10000000ul; /* reserved at +256 MiB */
  unsigned long rend = rstart + 0x4000000ul;         /* 64 MiB */

  /* Positive: a crashkernel extent carves a hole; slot count drops. */
  struct engine e;
  engine_init(&e);
  struct observation is = mk_scalar(SF_IMAGE_SIZE, ksize, CONF_PARSED);
  evidence_add(&e.ev, &is);
  struct observation crash;
  memset(&crash, 0, sizeof(crash));
  crash.value_kind = OBS_ADDRESS;
  crash.type = KASLD_TYPE_PHYS;
  crash.region = REGION_CRASHKERNEL;
  crash.lo = rstart;
  crash.hi = rend;
  crash.set_mask = LO_SET | HI_SET;
  crash.conf = CONF_PARSED;
  evidence_add(&e.ev, &crash);
  engine_run(&e, rules, 1);
  assert(has_phys_exclude(&e));
  const struct estimate *est = &e.est[Q_PHYS_TEXT_BASE];
  assert(quantity_slots(Q_PHYS_TEXT_BASE, est, e.constraints, e.n_constraints,
                        KASLR_PHYS_ALIGN) <
         quantity_slots(Q_PHYS_TEXT_BASE, est, NULL, 0, KASLR_PHYS_ALIGN));

  /* Negative: a NON-forbidden region (plain RAM) emits no exclude — the image
   * CAN live in RAM. */
  struct engine e2;
  engine_init(&e2);
  struct observation is2 = mk_scalar(SF_IMAGE_SIZE, ksize, CONF_PARSED);
  evidence_add(&e2.ev, &is2);
  struct observation ram = crash;
  ram.region = REGION_RAM;
  evidence_add(&e2.ev, &ram);
  engine_run(&e2, rules, 1);
  assert(!has_phys_exclude(&e2));
#endif
}

/* ram_map_phys_exclude: the non-RAM gaps in an authoritative complete System
 * RAM map are forbidden bands. Carves each whole-map origin (firmware_memmap +
 * device-tree); a partial-leak origin, or adjacent extents with no gap, emit
 * nothing. */
int rule_ram_map_phys_exclude(const struct evidence_set *ev,
                              const struct estimate *est,
                              struct constraint *out, int out_max);

static struct observation mk_ram(unsigned long lo, unsigned long hi,
                                 const char *origin) {
  struct observation o;
  memset(&o, 0, sizeof(o));
  o.value_kind = OBS_ADDRESS;
  o.type = KASLD_TYPE_PHYS;
  o.region = REGION_RAM;
  o.lo = lo;
  o.hi = hi;
  o.set_mask = LO_SET | HI_SET;
  o.conf = CONF_PARSED;
  snprintf(o.origin, ORIGIN_LEN, "%s", origin);
  return o;
}

static void test_ram_map_phys_exclude(void) {
#if !TEXT_TRACKS_DIRECTMAP
  const rule_fn rules[] = {rule_ram_map_phys_exclude};
  unsigned long ksize = 0x1000000ul; /* 16 MiB image */
  /* Two RAM extents with a real non-RAM gap (256 MiB .. 288 MiB). */
  unsigned long r1lo = PHYS_OFFSET + 0x1000000ul;  /* +16 MiB  */
  unsigned long r1hi = PHYS_OFFSET + 0x10000000ul; /* +256 MiB */
  unsigned long r2lo = PHYS_OFFSET + 0x12000000ul; /* +288 MiB */
  unsigned long r2hi = PHYS_OFFSET + 0x40000000ul; /* +1 GiB   */

  /* Positive: gap carved, slot count drops. */
  struct engine e;
  engine_init(&e);
  struct observation is = mk_scalar(SF_IMAGE_SIZE, ksize, CONF_PARSED);
  evidence_add(&e.ev, &is);
  struct observation a = mk_ram(r1lo, r1hi, "firmware_memmap");
  struct observation b = mk_ram(r2lo, r2hi, "firmware_memmap");
  evidence_add(&e.ev, &a);
  evidence_add(&e.ev, &b);
  engine_run(&e, rules, 1);
  assert(has_phys_exclude(&e));
  const struct estimate *est = &e.est[Q_PHYS_TEXT_BASE];
  assert(quantity_slots(Q_PHYS_TEXT_BASE, est, e.constraints, e.n_constraints,
                        KASLR_PHYS_ALIGN) <
         quantity_slots(Q_PHYS_TEXT_BASE, est, NULL, 0, KASLR_PHYS_ALIGN));

  /* Negative 1: same gap but a partial-leak origin (not the authoritative map)
   * — the "gap" could be unobserved RAM, so nothing is excluded. */
  struct engine e2;
  engine_init(&e2);
  struct observation is2 = mk_scalar(SF_IMAGE_SIZE, ksize, CONF_PARSED);
  evidence_add(&e2.ev, &is2);
  struct observation a2 = mk_ram(r1lo, r1hi, "proc_iomem");
  struct observation b2 = mk_ram(r2lo, r2hi, "proc_iomem");
  evidence_add(&e2.ev, &a2);
  evidence_add(&e2.ev, &b2);
  engine_run(&e2, rules, 1);
  assert(!has_phys_exclude(&e2));

  /* Negative 2: adjacent extents (no gap) emit nothing. */
  struct engine e3;
  engine_init(&e3);
  struct observation is3 = mk_scalar(SF_IMAGE_SIZE, ksize, CONF_PARSED);
  evidence_add(&e3.ev, &is3);
  struct observation a3 = mk_ram(r1lo, r1hi, "firmware_memmap");
  struct observation b3 = mk_ram(r1hi + 1, r2hi, "firmware_memmap");
  evidence_add(&e3.ev, &a3);
  evidence_add(&e3.ev, &b3);
  engine_run(&e3, rules, 1);
  assert(!has_phys_exclude(&e3));

  /* Positive 2: arch-general — a device-tree /memory map (arches with no
   * /sys/firmware/memmap) carves the same gap. */
  struct engine e4;
  engine_init(&e4);
  struct observation is4 = mk_scalar(SF_IMAGE_SIZE, ksize, CONF_PARSED);
  evidence_add(&e4.ev, &is4);
  struct observation a4 = mk_ram(r1lo, r1hi, "sysfs_devicetree_memory");
  struct observation b4 = mk_ram(r2lo, r2hi, "sysfs_devicetree_memory");
  evidence_add(&e4.ev, &a4);
  evidence_add(&e4.ev, &b4);
  engine_run(&e4, rules, 1);
  assert(has_phys_exclude(&e4));

  /* Positive 3: the hotplug memory-block map (online runs) carves the same
   * gap — the runtime view, arch-general. */
  struct engine e5;
  engine_init(&e5);
  struct observation is5 = mk_scalar(SF_IMAGE_SIZE, ksize, CONF_PARSED);
  evidence_add(&e5.ev, &is5);
  struct observation a5 = mk_ram(r1lo, r1hi, "sysfs_memory_blocks");
  struct observation b5 = mk_ram(r2lo, r2hi, "sysfs_memory_blocks");
  evidence_add(&e5.ev, &a5);
  evidence_add(&e5.ev, &b5);
  engine_run(&e5, rules, 1);
  assert(has_phys_exclude(&e5));
#endif
}

/* cmdline_mem_phys_ceiling: `mem=N` + SF_IMAGE_SIZE → C_UPPER_BOUND
 * on Q_PHYS_TEXT_BASE at (mem - ksize), aligned down. Decoupled arches. */
int rule_cmdline_mem_phys_ceiling(const struct evidence_set *ev,
                                  const struct estimate *est,
                                  struct constraint *out, int out_max);

static void test_cmdline_mem_phys_ceiling(void) {
#if !TEXT_TRACKS_DIRECTMAP
  struct engine e;
  engine_init(&e);
  unsigned long ksize = 0x1000000ul; /* 16 MiB image */
  unsigned long mem = 0x40000000ul;  /* 1 GiB mem= cap */
  struct observation k = mk_scalar(SF_IMAGE_SIZE, ksize, CONF_PARSED);
  struct observation m = mk_scalar(SF_PHYS_CMDLINE_MEM, mem, CONF_PARSED);
  evidence_add(&e.ev, &k);
  evidence_add(&e.ev, &m);

  const rule_fn rules[] = {rule_cmdline_mem_phys_ceiling};
  engine_run(&e, rules, 1);

  unsigned long expect = (mem - ksize) & ~(KASLR_PHYS_ALIGN - 1);
  struct estimate top;
  quantities[Q_PHYS_TEXT_BASE].init_top(&top);
  if (expect > (unsigned long)KASLR_PHYS_MIN)
    assert(e.est[Q_PHYS_TEXT_BASE].hi == min_ul(expect, top.hi));
  else
    assert(e.est[Q_PHYS_TEXT_BASE].hi == top.hi); /* below floor: inert */
#endif
}

/* No mem= → no constraint emitted (rule is signal-gated). */
static void test_cmdline_mem_phys_ceiling_no_signal(void) {
#if !TEXT_TRACKS_DIRECTMAP
  struct engine e;
  engine_init(&e);
  struct observation k = mk_scalar(SF_IMAGE_SIZE, 0x1000000ul, CONF_PARSED);
  evidence_add(&e.ev, &k);

  const rule_fn rules[] = {rule_cmdline_mem_phys_ceiling};
  engine_run(&e, rules, 1);

  struct estimate top;
  quantities[Q_PHYS_TEXT_BASE].init_top(&top);
  assert(e.est[Q_PHYS_TEXT_BASE].hi == top.hi);
#endif
}

/* cmdline_memmap_phys_exclude: each PHYS REGION_CMDLINE_MEMMAP extent
 * + SF_IMAGE_SIZE → C_EXCLUDE on Q_PHYS_TEXT_BASE over the inclusive hole.
 * Iterates ALL reservations (up to engine cap). */
int rule_cmdline_memmap_phys_exclude(const struct evidence_set *ev,
                                     const struct estimate *est,
                                     struct constraint *out, int out_max);

static void test_cmdline_memmap_phys_exclude(void) {
#if !TEXT_TRACKS_DIRECTMAP
  struct engine e;
  engine_init(&e);
  unsigned long ksize = 0x1000000ul;
  struct observation k = mk_scalar(SF_IMAGE_SIZE, ksize, CONF_PARSED);
  evidence_add(&e.ev, &k);

  /* Two reservations: cmdline_memmap_phys_exclude should emit two excludes. */
  for (int i = 0; i < 2; i++) {
    unsigned long lo =
        PHYS_OFFSET + 0x10000000ul + (unsigned long)i * 0x4000000ul;
    unsigned long hi = lo + 0x1000000ul - 1; /* 16 MiB each */
    struct observation o;
    memset(&o, 0, sizeof(o));
    o.value_kind = OBS_ADDRESS;
    o.type = KASLD_TYPE_PHYS;
    o.region = REGION_CMDLINE_MEMMAP;
    o.lo = lo;
    o.hi = hi;
    o.set_mask = LO_SET | HI_SET;
    o.conf = CONF_PARSED;
    evidence_add(&e.ev, &o);
  }

  const rule_fn rules[] = {rule_cmdline_memmap_phys_exclude};
  engine_run(&e, rules, 1);

  /* At least two C_EXCLUDE constraints on Q_PHYS_TEXT_BASE. */
  int n_excl = 0;
  for (int i = 0; i < e.n_constraints; i++)
    if (e.constraints[i].q == Q_PHYS_TEXT_BASE &&
        e.constraints[i].op == C_EXCLUDE)
      n_excl++;
  assert(n_excl >= 2);

  /* Interior holes: hole-aware slot count strictly lower than bare. */
  const struct estimate *est = &e.est[Q_PHYS_TEXT_BASE];
  unsigned long with = quantity_slots(Q_PHYS_TEXT_BASE, est, e.constraints,
                                      e.n_constraints, KASLR_PHYS_ALIGN);
  unsigned long bare =
      quantity_slots(Q_PHYS_TEXT_BASE, est, NULL, 0, KASLR_PHYS_ALIGN);
  assert(with < bare);
#endif
}

/* No SF_IMAGE_SIZE → no exclusion possible (rule needs both inputs). */
static void test_cmdline_memmap_no_image_size(void) {
#if !TEXT_TRACKS_DIRECTMAP
  struct engine e;
  engine_init(&e);
  struct observation o;
  memset(&o, 0, sizeof(o));
  o.value_kind = OBS_ADDRESS;
  o.type = KASLD_TYPE_PHYS;
  o.region = REGION_CMDLINE_MEMMAP;
  o.lo = PHYS_OFFSET + 0x10000000ul;
  o.hi = o.lo + 0x1000000ul - 1;
  o.set_mask = LO_SET | HI_SET;
  o.conf = CONF_PARSED;
  evidence_add(&e.ev, &o);

  const rule_fn rules[] = {rule_cmdline_memmap_phys_exclude};
  engine_run(&e, rules, 1);

  int n_excl = 0;
  for (int i = 0; i < e.n_constraints; i++)
    if (e.constraints[i].op == C_EXCLUDE)
      n_excl++;
  assert(n_excl == 0);
#endif
}

/* x86_64_efi_phys_seed_zero: when EFI is present AND the cmdline
 * carries a memory-rewriting trigger (mem= / memmap= / hugepages=) AND a PHYS
 * kernel_image observation is in evidence (single-Loader-Code-entry path),
 * pin Q_PHYS_TEXT_BASE to the kernel_image lo. x86_64-only. */
int rule_x86_64_efi_phys_seed_zero(const struct evidence_set *ev,
                                   const struct estimate *est,
                                   struct constraint *out, int out_max);

#if defined(__x86_64__)
/* Helper: build evidence with EFI present + a kernel_image at `base` +
 * optional cmdline triggers, run the rule, return the est. */
static void seed_zero_setup(struct engine *e, unsigned long base, int with_mem,
                            int with_memmap, int with_hugepages) {
  engine_init(e);
  struct observation efi = mk_scalar(SF_EFI_PRESENT, 1, CONF_PARSED);
  evidence_add(&e->ev, &efi);
  /* kernel_image at the EFI Loader Code lo (aligned to KASLR_PHYS_ALIGN). */
  struct observation img = mk_obs(KASLD_TYPE_PHYS, REGION_KERNEL_IMAGE, base,
                                  LO_SET | SAMPLE_SET, POS_BASE, CONF_PARSED);
  evidence_add(&e->ev, &img);
  if (with_mem) {
    struct observation m =
        mk_scalar(SF_PHYS_CMDLINE_MEM, 0x40000000ul, CONF_PARSED);
    evidence_add(&e->ev, &m);
  }
  if (with_memmap) {
    struct observation mm;
    memset(&mm, 0, sizeof(mm));
    mm.value_kind = OBS_ADDRESS;
    mm.type = KASLD_TYPE_PHYS;
    mm.region = REGION_CMDLINE_MEMMAP;
    mm.lo = PHYS_OFFSET + 0x20000000ul;
    mm.hi = mm.lo + 0xffffful;
    mm.set_mask = LO_SET | HI_SET;
    mm.conf = CONF_PARSED;
    evidence_add(&e->ev, &mm);
  }
  if (with_hugepages) {
    struct observation hp = mk_scalar(SF_CMDLINE_HUGEPAGES, 1, CONF_PARSED);
    evidence_add(&e->ev, &hp);
  }
}
#endif

static void test_x86_64_efi_phys_seed_zero_mem(void) {
#if defined(__x86_64__)
  unsigned long base =
      (unsigned long)KASLR_PHYS_MIN + 0x4000000ul; /* 16+64 MiB */
  /* Align to KASLR_PHYS_ALIGN (the rule rejects misaligned candidates). */
  base &= ~((unsigned long)KASLR_PHYS_ALIGN - 1);
  if (base < (unsigned long)KASLR_PHYS_MIN)
    return; /* arch parameters degenerate; skip */
  struct engine e;
  seed_zero_setup(&e, base, 1, 0, 0); /* mem= trigger only */
  const rule_fn rules[] = {rule_x86_64_efi_phys_seed_zero};
  engine_run(&e, rules, 1);
  /* Bilateral pin at base. */
  assert(e.est[Q_PHYS_TEXT_BASE].lo == base);
  assert(e.est[Q_PHYS_TEXT_BASE].hi == base);
#endif
}

static void test_x86_64_efi_phys_seed_zero_memmap(void) {
#if defined(__x86_64__)
  unsigned long base = (unsigned long)KASLR_PHYS_MIN + 0x4000000ul;
  base &= ~((unsigned long)KASLR_PHYS_ALIGN - 1);
  if (base < (unsigned long)KASLR_PHYS_MIN)
    return;
  struct engine e;
  seed_zero_setup(&e, base, 0, 1, 0); /* memmap= trigger only */
  const rule_fn rules[] = {rule_x86_64_efi_phys_seed_zero};
  engine_run(&e, rules, 1);
  assert(e.est[Q_PHYS_TEXT_BASE].lo == base);
  assert(e.est[Q_PHYS_TEXT_BASE].hi == base);
#endif
}

static void test_x86_64_efi_phys_seed_zero_hugepages(void) {
#if defined(__x86_64__)
  unsigned long base = (unsigned long)KASLR_PHYS_MIN + 0x4000000ul;
  base &= ~((unsigned long)KASLR_PHYS_ALIGN - 1);
  if (base < (unsigned long)KASLR_PHYS_MIN)
    return;
  struct engine e;
  seed_zero_setup(&e, base, 0, 0, 1); /* hugepages= trigger only */
  const rule_fn rules[] = {rule_x86_64_efi_phys_seed_zero};
  engine_run(&e, rules, 1);
  assert(e.est[Q_PHYS_TEXT_BASE].lo == base);
  assert(e.est[Q_PHYS_TEXT_BASE].hi == base);
#endif
}

/* No cmdline trigger → no pin (seed remains random). */
static void test_x86_64_efi_phys_seed_zero_no_trigger(void) {
#if defined(__x86_64__)
  unsigned long base = (unsigned long)KASLR_PHYS_MIN + 0x4000000ul;
  base &= ~((unsigned long)KASLR_PHYS_ALIGN - 1);
  if (base < (unsigned long)KASLR_PHYS_MIN)
    return;
  struct engine e;
  seed_zero_setup(&e, base, 0, 0, 0); /* EFI + kernel_image, no trigger */
  const rule_fn rules[] = {rule_x86_64_efi_phys_seed_zero};
  engine_run(&e, rules, 1);
  /* Window stays wider than the bilateral pin. */
  assert(!(e.est[Q_PHYS_TEXT_BASE].lo == base &&
           e.est[Q_PHYS_TEXT_BASE].hi == base));
#endif
}

/* No EFI → no pin (the trigger only matters via the EFI stub). */
static void test_x86_64_efi_phys_seed_zero_no_efi(void) {
#if defined(__x86_64__)
  struct engine e;
  engine_init(&e);
  unsigned long base = (unsigned long)KASLR_PHYS_MIN + 0x4000000ul;
  base &= ~((unsigned long)KASLR_PHYS_ALIGN - 1);
  if (base < (unsigned long)KASLR_PHYS_MIN)
    return;
  /* kernel_image + mem= trigger, but no SF_EFI_PRESENT. */
  struct observation img = mk_obs(KASLD_TYPE_PHYS, REGION_KERNEL_IMAGE, base,
                                  LO_SET | SAMPLE_SET, POS_BASE, CONF_PARSED);
  struct observation m =
      mk_scalar(SF_PHYS_CMDLINE_MEM, 0x40000000ul, CONF_PARSED);
  evidence_add(&e.ev, &img);
  evidence_add(&e.ev, &m);
  const rule_fn rules[] = {rule_x86_64_efi_phys_seed_zero};
  engine_run(&e, rules, 1);
  assert(!(e.est[Q_PHYS_TEXT_BASE].lo == base &&
           e.est[Q_PHYS_TEXT_BASE].hi == base));
#endif
}

/* No kernel_image observation → fallback case (deferred); no pin emitted. */
static void test_x86_64_efi_phys_seed_zero_no_kernel_image(void) {
#if defined(__x86_64__)
  struct engine e;
  engine_init(&e);
  struct observation efi = mk_scalar(SF_EFI_PRESENT, 1, CONF_PARSED);
  struct observation m =
      mk_scalar(SF_PHYS_CMDLINE_MEM, 0x40000000ul, CONF_PARSED);
  evidence_add(&e.ev, &efi);
  evidence_add(&e.ev, &m);
  const rule_fn rules[] = {rule_x86_64_efi_phys_seed_zero};
  engine_run(&e, rules, 1);
  struct estimate top;
  quantities[Q_PHYS_TEXT_BASE].init_top(&top);
  /* No pin: window unchanged. */
  assert(e.est[Q_PHYS_TEXT_BASE].lo == top.lo);
  assert(e.est[Q_PHYS_TEXT_BASE].hi == top.hi);
#endif
}

/* highmem_32bit_bound (coupled 32-bit) + ppc64_firmware_ceiling (ppc64):
 * batch of in-process parity ceilings. Active paths run when cross-built for
 * the relevant arch; inert (no-op) on the x86_64 host. */
int rule_highmem_32bit_bound(const struct evidence_set *ev,
                             const struct estimate *est, struct constraint *out,
                             int out_max);
int rule_ppc64_firmware_ceiling(const struct evidence_set *ev,
                                const struct estimate *est,
                                struct constraint *out, int out_max);

static void test_highmem_32bit_bound(void) {
  struct engine e;
  engine_init(&e);
  struct estimate potop;
  quantities[Q_PAGE_OFFSET].init_top(&potop);
  unsigned long po = potop.lo + 0x10000000ul;
  struct observation pl = mk_obs(KASLD_TYPE_VIRT, REGION_PAGE_OFFSET, po,
                                 LO_SET, POS_BASE, CONF_PARSED);
  evidence_add(&e.ev, &pl);
  struct observation lm = mk_scalar(SF_PHYS_LOWMEM, 0x20000000ul, CONF_PARSED);
  evidence_add(&e.ev, &lm);

  const rule_fn rules[] = {rule_page_offset_from_landmark,
                           rule_highmem_32bit_bound};
  engine_run(&e, rules, 2);
  struct estimate vtop;
  quantities[Q_VIRT_TEXT_BASE].init_top(&vtop);
#if !TEXT_TRACKS_DIRECTMAP
  assert(e.est[Q_VIRT_TEXT_BASE].hi == vtop.hi); /* inert on decoupled */
#else
  if (sizeof(unsigned long) == 4) {
    unsigned long expect = (po + 0x20000000ul - (4ul << 20) + TEXT_OFFSET) &
                           ~(KASLR_VIRT_ALIGN - 1);
    if (expect > KASLR_VIRT_TEXT_MIN && expect < vtop.hi)
      assert(e.est[Q_VIRT_TEXT_BASE].hi == expect);
  } else {
    assert(e.est[Q_VIRT_TEXT_BASE].hi == vtop.hi); /* inert on 64-bit coupled */
  }
#endif
}

static void test_ppc64_firmware_ceiling(void) {
  struct engine e;
  engine_init(&e);
  unsigned long fw = 0x10000000ul; /* 256 MiB firmware base */
  struct observation o = mk_scalar(SF_PHYS_FW_RESERVED_BASE, fw, CONF_PARSED);
  evidence_add(&e.ev, &o);

  const rule_fn rules[] = {rule_ppc64_firmware_ceiling};
  engine_run(&e, rules, 1);
  struct estimate vtop;
  quantities[Q_VIRT_TEXT_BASE].init_top(&vtop);
#if defined(__powerpc64__)
  unsigned long expect =
      (KASLR_VIRT_TEXT_MIN + fw - (16ul << 20)) & ~(KASLR_VIRT_ALIGN - 1);
  if (expect > KASLR_VIRT_TEXT_MIN && expect < vtop.hi)
    assert(e.est[Q_VIRT_TEXT_BASE].hi == expect);
#else
  assert(e.est[Q_VIRT_TEXT_BASE].hi == vtop.hi); /* inert off ppc64 */
#endif
}

/* x86_32_vmsplit_ceiling: cross-quantity ceiling = virt_page_offset + 512 MiB.
 */
int rule_x86_32_vmsplit_ceiling(const struct evidence_set *ev,
                                const struct estimate *est,
                                struct constraint *out, int out_max);

static void test_x86_32_vmsplit_ceiling(void) {
  struct engine e;
  engine_init(&e);
  struct estimate potop;
  quantities[Q_PAGE_OFFSET].init_top(&potop);
  unsigned long po = potop.lo + 0x10000000ul;
  struct observation pl = mk_obs(KASLD_TYPE_VIRT, REGION_PAGE_OFFSET, po,
                                 LO_SET, POS_BASE, CONF_PARSED);
  evidence_add(&e.ev, &pl);

  const rule_fn rules[] = {rule_page_offset_from_landmark,
                           rule_x86_32_vmsplit_ceiling};
  engine_run(&e, rules, 2);
  struct estimate vtop;
  quantities[Q_VIRT_TEXT_BASE].init_top(&vtop);
#if defined(__i386__)
  unsigned long expect = po + (512UL * 1024 * 1024);
  if (expect > KASLR_VIRT_TEXT_MIN && expect < vtop.hi)
    assert(e.est[Q_VIRT_TEXT_BASE].hi == expect);
#else
  assert(e.est[Q_VIRT_TEXT_BASE].hi == vtop.hi); /* inert off i386 */
#endif
}

/* x86_64 RANDOMIZE_MEMORY region-base bounds (blind-spot quantities). The
 * vmalloc floor chains virt_page_offset + max_pfn -> Q_VMALLOC_BASE lower
 * bound; the vmemmap rule chains that -> Q_VMEMMAP_BASE lower bound and adds an
 * upper bound from max_pfn. Cross-quantity, multi-pass. x86_64 only; inert (no
 * constraint) elsewhere. */
int rule_x86_64_vmalloc_base_bound(const struct evidence_set *ev,
                                   const struct estimate *est,
                                   struct constraint *out, int out_max);
int rule_x86_64_vmemmap_base_bound(const struct evidence_set *ev,
                                   const struct estimate *est,
                                   struct constraint *out, int out_max);

/* 64-bit-only block: these model x86_64 RANDOMIZE_MEMORY (vmalloc/vmemmap) and
 * 64-bit VA-bits/paging layouts with addresses that do not fit a 32-bit
 * `unsigned long`. Guarded so the suite still builds + runs on 32-bit arches
 * (where it exercises the 32-bit-gated rules); the bodies are empty there and
 * pass trivially. Matches the test_xkphys_decode guard. */
#if __SIZEOF_LONG__ >= 8
static void test_x86_64_vmalloc_vmemmap_chain(void) {
  struct engine e;
  engine_init(&e);

  struct estimate potop;
  quantities[Q_PAGE_OFFSET].init_top(&potop);
  /* po above the L4 VAS floor -> L4 paging (VMALLOC_SIZE_TB = 32). */
  unsigned long po = potop.lo + 0x88000000000ul;
  struct observation pl = mk_obs(KASLD_TYPE_VIRT, REGION_PAGE_OFFSET, po,
                                 LO_SET, POS_BASE, CONF_PARSED);
  evidence_add(&e.ev, &pl);
  unsigned long max_pfn = 0x100000ul; /* 1M pages = 4 GiB */
  struct observation mp = mk_scalar(SF_PHYS_MAX_PFN, max_pfn, CONF_PARSED);
  evidence_add(&e.ev, &mp);

  const rule_fn rules[] = {rule_page_offset_from_landmark,
                           rule_x86_64_vmalloc_base_bound,
                           rule_x86_64_vmemmap_base_bound};
  engine_run(&e, rules, 3);

#if defined(__x86_64__)
  unsigned long one_tb = 1ul << 40;
  unsigned long pud = 1ul << 30;
  unsigned long page_bytes = max_pfn << 12;
  unsigned long memory_tb = (page_bytes + one_tb - 1) / one_tb + 10ul;
  unsigned long directmap_tb = memory_tb < 4096ul ? memory_tb : 4096ul;

  unsigned long vmalloc_lo = po + directmap_tb * one_tb + pud;
  assert(e.est[Q_VMALLOC_BASE].lo == vmalloc_lo);
  assert(e.est[Q_VMALLOC_BASE].lo_binding != 0);

  /* VMALLOC_SIZE_TB: L5 (12800) if virt_page_offset sits below the L4 VAS
   * floor, else L4 (32) — same test the rule applies. */
  unsigned long vmalloc_size_tb = (po < 0xffff800000000000ul) ? 12800ul : 32ul;
  unsigned long vmemmap_lo = vmalloc_lo + vmalloc_size_tb * one_tb + pud;
  assert(e.est[Q_VMEMMAP_BASE].lo == vmemmap_lo);

  /* vmemmap_size = directmap_tb * 16 GiB, rounded up to TiB (>= 1). */
  unsigned long vmemmap_size_tb =
      (directmap_tb * (1ul << 34) + one_tb - 1) / one_tb;
  if (vmemmap_size_tb == 0)
    vmemmap_size_tb = 1;
  unsigned long vmemmap_hi = 0xfffffe0000000000ul - vmemmap_size_tb * one_tb;
  assert(e.est[Q_VMEMMAP_BASE].hi == vmemmap_hi);

  /* vmalloc gets an UPPER bound back from vmemmap's ceiling:
   * virt_vmalloc_base <= vmemmap_hi - VMALLOC_SIZE_TB*1TiB - PUD_SIZE. */
  unsigned long vmalloc_hi = vmemmap_hi - vmalloc_size_tb * one_tb - pud;
  assert(e.est[Q_VMALLOC_BASE].hi == vmalloc_hi);
  assert(e.est[Q_VMALLOC_BASE].hi_binding != 0);
  assert(e.est[Q_VMALLOC_BASE].hi >
         e.est[Q_VMALLOC_BASE].lo); /* valid window */
#else
  struct estimate vmtop;
  quantities[Q_VMALLOC_BASE].init_top(&vmtop);
  assert(e.est[Q_VMALLOC_BASE].lo == vmtop.lo); /* inert off x86_64 */
  assert(e.est[Q_VMEMMAP_BASE].lo == vmtop.lo);
#endif
}

/* No SF_PHYS_MAX_PFN -> the vmalloc floor emits nothing, so the vmemmap rule
 * (which needs a constrained vmalloc base) also stays at honest top. */
static void test_x86_64_vmalloc_no_max_pfn(void) {
  struct engine e;
  engine_init(&e);
  struct estimate potop;
  quantities[Q_PAGE_OFFSET].init_top(&potop);
  unsigned long po = potop.lo + 0x88000000000ul;
  struct observation pl = mk_obs(KASLD_TYPE_VIRT, REGION_PAGE_OFFSET, po,
                                 LO_SET, POS_BASE, CONF_PARSED);
  evidence_add(&e.ev, &pl);

  const rule_fn rules[] = {rule_page_offset_from_landmark,
                           rule_x86_64_vmalloc_base_bound,
                           rule_x86_64_vmemmap_base_bound};
  engine_run(&e, rules, 3);

  struct estimate vmtop;
  quantities[Q_VMALLOC_BASE].init_top(&vmtop);
  assert(e.est[Q_VMALLOC_BASE].lo == vmtop.lo);
  assert(e.est[Q_VMALLOC_BASE].lo_binding == 0);
  quantities[Q_VMEMMAP_BASE].init_top(&vmtop);
  assert(e.est[Q_VMEMMAP_BASE].lo == vmtop.lo);
}

/* x86_64_page_offset_from_vmalloc_vmemmap, backward chain): a leaked
 * VMALLOC virtual address bounds Q_PAGE_OFFSET from above by the directmap
 * size + PUD gap. */
int rule_x86_64_page_offset_from_vmalloc_vmemmap(const struct evidence_set *ev,
                                                 const struct estimate *est,
                                                 struct constraint *out,
                                                 int out_max);

static void test_x86_64_po_from_vmalloc(void) {
#if defined(__x86_64__)
  struct engine e;
  engine_init(&e);
  unsigned long max_pfn = 0x100000ul; /* 4 GiB */
  evidence_add(&e.ev, &(struct observation){.value_kind = OBS_SCALAR,
                                            .scalar_fact = SF_PHYS_MAX_PFN,
                                            .scalar_value = max_pfn,
                                            .conf = CONF_PARSED,
                                            .valid = 1});

  /* directmap_size = (4 GiB rounded-to-1-TiB) + 10 TiB padding = 11 TiB. */
  unsigned long one_tb = 1ul << 40;
  unsigned long pud = 1ul << 30;
  unsigned long directmap_size = 11ul * one_tb;
  /* Pick a vmalloc witness that yields a non-trivial bound: base + 100 MiB. */
  unsigned long po_truth = 0xffff888000000000ul;
  unsigned long va_witness = po_truth + directmap_size + pud + 0x6400000ul;
  struct observation va = mk_obs(KASLD_TYPE_VIRT, REGION_VMALLOC, va_witness,
                                 LO_SET | SAMPLE_SET, POS_BASE, CONF_PARSED);
  evidence_add(&e.ev, &va);

  const rule_fn rules[] = {rule_x86_64_page_offset_from_vmalloc_vmemmap};
  engine_run(&e, rules, 1);

  /* The upper bound on Q_PAGE_OFFSET should be ≤ va_witness - directmap_size -
   * PUD. */
  unsigned long expect = va_witness - directmap_size - pud;
  assert(e.est[Q_PAGE_OFFSET].hi <= expect);
  /* And it must still admit the truth. */
  assert(e.est[Q_PAGE_OFFSET].hi >= po_truth);
#endif
}

/* VMEMMAP observation alone: tighter bound, additional vmalloc+pud subtraction.
 */
static void test_x86_64_po_from_vmemmap(void) {
#if defined(__x86_64__)
  struct engine e;
  engine_init(&e);
  unsigned long max_pfn = 0x100000ul;
  evidence_add(&e.ev, &(struct observation){.value_kind = OBS_SCALAR,
                                            .scalar_fact = SF_PHYS_MAX_PFN,
                                            .scalar_value = max_pfn,
                                            .conf = CONF_PARSED,
                                            .valid = 1});

  unsigned long one_tb = 1ul << 40;
  unsigned long pud = 1ul << 30;
  unsigned long directmap_size = 11ul * one_tb;
  unsigned long vmalloc_size = 32ul * one_tb; /* L4 default */
  unsigned long po_truth = 0xffff888000000000ul;
  unsigned long mm_witness =
      po_truth + directmap_size + vmalloc_size + 2ul * pud + 0x6400000ul;
  struct observation mm = mk_obs(KASLD_TYPE_VIRT, REGION_VMEMMAP, mm_witness,
                                 LO_SET | SAMPLE_SET, POS_BASE, CONF_PARSED);
  evidence_add(&e.ev, &mm);

  const rule_fn rules[] = {rule_x86_64_page_offset_from_vmalloc_vmemmap};
  engine_run(&e, rules, 1);

  unsigned long expect = mm_witness - vmalloc_size - directmap_size - 2ul * pud;
  assert(e.est[Q_PAGE_OFFSET].hi <= expect);
  assert(e.est[Q_PAGE_OFFSET].hi >= po_truth);
#endif
}

/* No SF_PHYS_MAX_PFN → no bound (the rule needs directmap_size). */
static void test_x86_64_po_from_vmalloc_no_max_pfn(void) {
#if defined(__x86_64__)
  struct engine e;
  engine_init(&e);
  unsigned long va_witness = 0xffffc90000000000ul;
  struct observation va = mk_obs(KASLD_TYPE_VIRT, REGION_VMALLOC, va_witness,
                                 LO_SET | SAMPLE_SET, POS_BASE, CONF_PARSED);
  evidence_add(&e.ev, &va);

  const rule_fn rules[] = {rule_x86_64_page_offset_from_vmalloc_vmemmap};
  engine_run(&e, rules, 1);

  struct estimate top;
  quantities[Q_PAGE_OFFSET].init_top(&top);
  assert(e.est[Q_PAGE_OFFSET].hi == top.hi);
#endif
}

/* x86_64_page_offset_from_vmalloc_vmemmap reads est[Q_PAGE_OFFSET] to choose
 * the L4/L5 VMALLOC_SIZE that determines the upper bound it writes back on
 * Q_PAGE_OFFSET.
 * It commits to L5 (the larger subtraction, tighter bound) only when
 * Q_PAGE_OFFSET is pinned (lo==hi) below the L4 VAS floor. When it is, the L5
 * branch must fire and must never emit a bound below the pinned truth. The pin
 * dominates the resolved estimate, so the L5 selection is asserted on the
 * EMITTED constraint rather than the resolved interval. */
static void test_x86_64_po_from_vmemmap_pinned_l5(void) {
#if defined(__x86_64__)
  struct engine e;
  engine_init(&e);
  unsigned long max_pfn = 0x100000ul; /* 4 GiB -> directmap_size 11 TiB */
  evidence_add(&e.ev, &(struct observation){.value_kind = OBS_SCALAR,
                                            .scalar_fact = SF_PHYS_MAX_PFN,
                                            .scalar_value = max_pfn,
                                            .conf = CONF_PARSED,
                                            .valid = 1});

  unsigned long one_tb = 1ul << 40;
  unsigned long pud = 1ul << 30;
  unsigned long directmap_size = 11ul * one_tb;
  unsigned long vmalloc_size_l5 = 12800ul * one_tb;

  /* Pin Q_PAGE_OFFSET (lo==hi) to an L5-territory base, below the L4 VAS floor
   * 0xffff800000000000. */
  unsigned long po_l5 = 0xff11000000000000ul;
  struct observation pin = mk_obs(KASLD_TYPE_VIRT, REGION_PAGE_OFFSET, po_l5,
                                  LO_SET, POS_BASE, CONF_DERIVED);
  evidence_add(&e.ev, &pin);

  unsigned long slack = 0x6400000ul; /* 100 MiB */
  unsigned long mm_witness =
      po_l5 + directmap_size + vmalloc_size_l5 + 2ul * pud + slack;
  struct observation mm = mk_obs(KASLD_TYPE_VIRT, REGION_VMEMMAP, mm_witness,
                                 LO_SET | SAMPLE_SET, POS_BASE, CONF_PARSED);
  evidence_add(&e.ev, &mm);

  /* Pin runs alongside the consumer; the fixpoint pins Q_PAGE_OFFSET, then the
   * consumer re-runs seeing the L5-territory pin and switches to L5. */
  const rule_fn rules[] = {rule_x86_64_page_offset_from_vmalloc_vmemmap,
                           rule_pin_page_offset};
  engine_run(&e, rules, 2);

  /* L5 subtraction; equals po_l5 + slack. (The L4 value the rule emits on the
   * first, un-pinned pass is ~12768 TiB larger, so this value is uniquely L5.)
   */
  unsigned long expect_l5 =
      mm_witness - vmalloc_size_l5 - directmap_size - 2ul * pud;

  int found_l5 = 0;
  for (int i = 0; i < e.n_constraints; i++) {
    const struct constraint *c = &e.constraints[i];
    if (strcmp(c->origin, "x86_64_page_offset_from_vmalloc_vmemmap") != 0 ||
        c->op != C_UPPER_BOUND)
      continue;
    assert(c->value >= po_l5); /* over-narrowing guard: never below the truth */
    if (c->value == expect_l5)
      found_l5 = 1; /* the L5 branch fired */
  }
  assert(found_l5);

  /* The pin dominates the resolved estimate. */
  assert(e.est[Q_PAGE_OFFSET].lo == po_l5);
  assert(e.est[Q_PAGE_OFFSET].hi == po_l5);
#endif
}

/* The other half of the same self-edge gate: pinned lo==hi but in L4 territory
 * (at/above the L4 VAS floor). The `< X86_64_L4_VAS_START` condition must keep
 * the rule on L4 — committing to the tighter L5 subtraction here would push the
 * upper bound far below the truth. The soundness assertion (every emitted bound
 * >= the pinned truth) fails if the territory check is dropped and L5 is used.
 */
static void test_x86_64_po_from_vmemmap_pinned_l4_keeps_l4(void) {
#if defined(__x86_64__)
  struct engine e;
  engine_init(&e);
  unsigned long max_pfn = 0x100000ul;
  evidence_add(&e.ev, &(struct observation){.value_kind = OBS_SCALAR,
                                            .scalar_fact = SF_PHYS_MAX_PFN,
                                            .scalar_value = max_pfn,
                                            .conf = CONF_PARSED,
                                            .valid = 1});

  unsigned long one_tb = 1ul << 40;
  unsigned long pud = 1ul << 30;
  unsigned long directmap_size = 11ul * one_tb;
  unsigned long vmalloc_size_l4 = 32ul * one_tb;

  /* Pin at the canonical L4 base: lo==hi, but ABOVE the L4 VAS floor. */
  unsigned long po_l4 = 0xffff888000000000ul;
  struct observation pin = mk_obs(KASLD_TYPE_VIRT, REGION_PAGE_OFFSET, po_l4,
                                  LO_SET, POS_BASE, CONF_DERIVED);
  evidence_add(&e.ev, &pin);

  unsigned long slack = 0x6400000ul;
  unsigned long mm_witness =
      po_l4 + directmap_size + vmalloc_size_l4 + 2ul * pud + slack;
  struct observation mm = mk_obs(KASLD_TYPE_VIRT, REGION_VMEMMAP, mm_witness,
                                 LO_SET | SAMPLE_SET, POS_BASE, CONF_PARSED);
  evidence_add(&e.ev, &mm);

  const rule_fn rules[] = {rule_x86_64_page_offset_from_vmalloc_vmemmap,
                           rule_pin_page_offset};
  engine_run(&e, rules, 2);

  unsigned long expect_l4 =
      mm_witness - vmalloc_size_l4 - directmap_size - 2ul * pud;

  int found_l4 = 0;
  for (int i = 0; i < e.n_constraints; i++) {
    const struct constraint *c = &e.constraints[i];
    if (strcmp(c->origin, "x86_64_page_offset_from_vmalloc_vmemmap") != 0 ||
        c->op != C_UPPER_BOUND)
      continue;
    /* Over-narrowing guard: a wrongful L5 pick here lands ~12768 TiB below
     * po_l4, tripping this. */
    assert(c->value >= po_l4);
    if (c->value == expect_l4)
      found_l4 = 1;
  }
  assert(found_l4);

  assert(e.est[Q_PAGE_OFFSET].lo == po_l4);
  assert(e.est[Q_PAGE_OFFSET].hi == po_l4);
#endif
}

/* x86_64_vmalloc_vmemmap_invariant: a too-close vmalloc/vmemmap pair
 * → both observations invalidated. The required gap is VMALLOC_SIZE_TB·1TB
 * + PUD_SIZE = ≥33 TiB on L4. */
int rule_x86_64_vmalloc_vmemmap_invariant(const struct evidence_set *ev,
                                          struct verdict *out, int out_max);

static void test_x86_64_vmalloc_vmemmap_invariant_violation(void) {
#if defined(__x86_64__)
  struct engine e;
  engine_init(&e);
  /* L4 territory; gap of only 1 TiB — far below required 33 TiB. */
  unsigned long va = 0xffffc90000000000ul;
  unsigned long mm = va + (1ul << 40);
  struct observation o_va = mk_obs(KASLD_TYPE_VIRT, REGION_VMALLOC, va,
                                   LO_SET | SAMPLE_SET, POS_BASE, CONF_PARSED);
  struct observation o_mm = mk_obs(KASLD_TYPE_VIRT, REGION_VMEMMAP, mm,
                                   LO_SET | SAMPLE_SET, POS_BASE, CONF_PARSED);
  evidence_add(&e.ev, &o_va);
  evidence_add(&e.ev, &o_mm);

  const verdict_fn vrules[] = {rule_x86_64_vmalloc_vmemmap_invariant};
  engine_run_full(&e, NULL, 0, vrules, 1);

  /* Both observations should be invalidated. */
  int va_valid = 1, mm_valid = 1;
  for (int i = 0; i < e.ev.n_obs; i++) {
    if (e.ev.obs[i].region == REGION_VMALLOC)
      va_valid = e.ev.obs[i].valid;
    else if (e.ev.obs[i].region == REGION_VMEMMAP)
      mm_valid = e.ev.obs[i].valid;
  }
  assert(!va_valid);
  assert(!mm_valid);
#endif
}

/* Compliant pair (vmemmap is 34 TiB above vmalloc) — neither invalidated. */
static void test_x86_64_vmalloc_vmemmap_invariant_ok(void) {
#if defined(__x86_64__)
  struct engine e;
  engine_init(&e);
  unsigned long va = 0xffffc90000000000ul;
  unsigned long mm = va + 34ul * (1ul << 40); /* 34 TiB above */
  struct observation o_va = mk_obs(KASLD_TYPE_VIRT, REGION_VMALLOC, va,
                                   LO_SET | SAMPLE_SET, POS_BASE, CONF_PARSED);
  struct observation o_mm = mk_obs(KASLD_TYPE_VIRT, REGION_VMEMMAP, mm,
                                   LO_SET | SAMPLE_SET, POS_BASE, CONF_PARSED);
  evidence_add(&e.ev, &o_va);
  evidence_add(&e.ev, &o_mm);

  const verdict_fn vrules[] = {rule_x86_64_vmalloc_vmemmap_invariant};
  engine_run_full(&e, NULL, 0, vrules, 1);

  int va_valid = 1, mm_valid = 1;
  for (int i = 0; i < e.ev.n_obs; i++) {
    if (e.ev.obs[i].region == REGION_VMALLOC)
      va_valid = e.ev.obs[i].valid;
    else if (e.ev.obs[i].region == REGION_VMEMMAP)
      mm_valid = e.ev.obs[i].valid;
  }
  assert(va_valid);
  assert(mm_valid);
#endif
}

/* arm64_va_bits_from_vmemmap: a VIRT/VMEMMAP observation below the
 * VA_BITS=48 VMEMMAP_START floor (0xfffffdffc0000000) cannot lie in VA48's
 * vmemmap → pin Q_VA_BITS=52 + the matching PAGE_OFFSET ceiling. */
int rule_arm64_va_bits_from_vmemmap(const struct evidence_set *ev,
                                    const struct estimate *est,
                                    struct constraint *out, int out_max);

static void test_arm64_va_bits_from_vmemmap_pins_52(void) {
  struct engine e;
  engine_init(&e);
  /* Below the VA48 VMEMMAP_START floor → VA52-only witness. */
  unsigned long v_mm = 0xfff8000000000000ul;
  struct observation o = mk_obs(KASLD_TYPE_VIRT, REGION_VMEMMAP, v_mm,
                                LO_SET | SAMPLE_SET, POS_BASE, CONF_PARSED);
  evidence_add(&e.ev, &o);

  const rule_fn rules[] = {rule_arm64_va_bits_from_vmemmap};
  engine_run(&e, rules, 1);

#if defined(__aarch64__)
  /* Q_VA_BITS pinned to 52. */
  int va_eq = 0;
  for (int i = 0; i < e.n_constraints; i++)
    if (e.constraints[i].q == Q_VA_BITS && e.constraints[i].op == C_EQUALS &&
        e.constraints[i].value == 52)
      va_eq = 1;
  assert(va_eq);
  /* Q_PAGE_OFFSET ceiling at 0xfff0000000000000. */
  assert(e.est[Q_PAGE_OFFSET].hi == 0xfff0000000000000ul);
#else
  /* Inert off arm64. */
  (void)v_mm;
  struct estimate top;
  quantities[Q_PAGE_OFFSET].init_top(&top);
  assert(e.est[Q_PAGE_OFFSET].hi == top.hi);
#endif
}

/* VMEMMAP observation at or above the VA48 floor: no discrimination. */
static void test_arm64_va_bits_from_vmemmap_above_floor_inert(void) {
  struct engine e;
  engine_init(&e);
  /* Inside VA48's vmemmap window — consistent with either mode. */
  unsigned long v_mm = 0xfffffe0000000000ul;
  struct observation o = mk_obs(KASLD_TYPE_VIRT, REGION_VMEMMAP, v_mm,
                                LO_SET | SAMPLE_SET, POS_BASE, CONF_PARSED);
  evidence_add(&e.ev, &o);

  const rule_fn rules[] = {rule_arm64_va_bits_from_vmemmap};
  engine_run(&e, rules, 1);

  struct estimate top;
  quantities[Q_PAGE_OFFSET].init_top(&top);
  assert(e.est[Q_PAGE_OFFSET].hi == top.hi);
  /* Q_VA_BITS: no constraint emitted. */
  for (int i = 0; i < e.n_constraints; i++)
    assert(e.constraints[i].q != Q_VA_BITS);
}

/* s390_text_from_vmalloc: a VIRT/VMALLOC observation pushes the text
 * base lower bound up by exactly MODULES_LEN (= SZ_2G) + 1. */
int rule_s390_text_from_belows(const struct evidence_set *ev,
                               const struct estimate *est,
                               struct constraint *out, int out_max);

static void test_s390_text_from_vmalloc_lo_bound(void) {
  struct engine e;
  engine_init(&e);
  unsigned long v_va = 0x3FF0000000000ul; /* arbitrary VMALLOC address */
  struct observation o = mk_obs(KASLD_TYPE_VIRT, REGION_VMALLOC, v_va,
                                LO_SET | SAMPLE_SET, POS_BASE, CONF_PARSED);
  evidence_add(&e.ev, &o);

  const rule_fn rules[] = {rule_s390_text_from_belows};
  engine_run(&e, rules, 1);

#if defined(__s390__) || defined(__s390x__)
  unsigned long expect = v_va + 0x80000000ul + 1ul;
  /* Q_VIRT_TEXT_BASE lo is at least expect. */
  assert(e.est[Q_VIRT_TEXT_BASE].lo >= expect);
#else
  struct estimate top;
  quantities[Q_VIRT_TEXT_BASE].init_top(&top);
  assert(e.est[Q_VIRT_TEXT_BASE].lo == top.lo);
#endif
}

/* No VMALLOC observation → no constraint emitted. */
static void test_s390_text_from_vmalloc_no_obs(void) {
  struct engine e;
  engine_init(&e);
  const rule_fn rules[] = {rule_s390_text_from_belows};
  engine_run(&e, rules, 1);
  struct estimate top;
  quantities[Q_VIRT_TEXT_BASE].init_top(&top);
  assert(e.est[Q_VIRT_TEXT_BASE].lo == top.lo);
}

/* s390_text_from_vmemmap, VMEMMAP rung of the below-text cascade):
 * a VIRT/VMEMMAP observation pushes Q_VIRT_TEXT_BASE.lo up by at least
 * vmemmap_size + MODULES_LEN + 1, where vmemmap_size is derived from
 * SF_PHYS_MAX_PFN × 64 (upstream default struct page bytes). */
static void test_s390_text_from_vmemmap_with_max_pfn(void) {
  struct engine e;
  engine_init(&e);
  unsigned long v_mm = 0x3FE0000000000ul; /* arbitrary VMEMMAP address */
  unsigned long max_pfn = 0x100000ul;     /* 1 M pages → 64 MiB vmemmap */
  struct observation o = mk_obs(KASLD_TYPE_VIRT, REGION_VMEMMAP, v_mm,
                                LO_SET | SAMPLE_SET, POS_BASE, CONF_PARSED);
  struct observation s = mk_scalar(SF_PHYS_MAX_PFN, max_pfn, CONF_PARSED);
  evidence_add(&e.ev, &o);
  evidence_add(&e.ev, &s);

  const rule_fn rules[] = {rule_s390_text_from_belows};
  engine_run(&e, rules, 1);

#if defined(__s390__) || defined(__s390x__)
  /* expect ≥ V_mm + vmemmap_size + MODULES_LEN + 1
   *        = V_mm + 64 MiB + 2 GiB + 1 */
  unsigned long expect = v_mm + (max_pfn * 64ul) + 0x80000000ul + 1ul;
  assert(e.est[Q_VIRT_TEXT_BASE].lo >= expect);
#else
  struct estimate top;
  quantities[Q_VIRT_TEXT_BASE].init_top(&top);
  assert(e.est[Q_VIRT_TEXT_BASE].lo == top.lo);
#endif
}

/* No SF_PHYS_MAX_PFN: rule still fires with vmemmap_size=0, giving the looser
 * (still sound) bound V_mm + MODULES_LEN + 1. */
static void test_s390_text_from_vmemmap_no_max_pfn(void) {
  struct engine e;
  engine_init(&e);
  unsigned long v_mm = 0x3FE0000000000ul;
  struct observation o = mk_obs(KASLD_TYPE_VIRT, REGION_VMEMMAP, v_mm,
                                LO_SET | SAMPLE_SET, POS_BASE, CONF_PARSED);
  evidence_add(&e.ev, &o);
  const rule_fn rules[] = {rule_s390_text_from_belows};
  engine_run(&e, rules, 1);
#if defined(__s390__) || defined(__s390x__)
  unsigned long expect = v_mm + 0x80000000ul + 1ul;
  assert(e.est[Q_VIRT_TEXT_BASE].lo >= expect);
#else
  struct estimate top;
  quantities[Q_VIRT_TEXT_BASE].init_top(&top);
  assert(e.est[Q_VIRT_TEXT_BASE].lo == top.lo);
#endif
}

/* No VMEMMAP observation → no constraint. */
static void test_s390_text_from_vmemmap_no_obs(void) {
  struct engine e;
  engine_init(&e);
  const rule_fn rules[] = {rule_s390_text_from_belows};
  engine_run(&e, rules, 1);
  struct estimate top;
  quantities[Q_VIRT_TEXT_BASE].init_top(&top);
  assert(e.est[Q_VIRT_TEXT_BASE].lo == top.lo);
}

/* s390_text_segment_mod: a PHYS/KERNEL_IMAGE observation pins
 * Q_VIRT_TEXT_BASE's stride class to (phys mod 1 MiB). */
int rule_s390_text_segment_mod(const struct evidence_set *ev,
                               const struct estimate *est,
                               struct constraint *out, int out_max);

static void test_s390_text_segment_mod_fires(void) {
  struct engine e;
  engine_init(&e);
  unsigned long phys_anchor = 0x12340000ul; /* low 20 bits = 0x40000 */
  struct observation img =
      mk_obs(KASLD_TYPE_PHYS, REGION_KERNEL_IMAGE, phys_anchor,
             LO_SET | SAMPLE_SET, POS_BASE, CONF_PARSED);
  evidence_add(&e.ev, &img);
  const rule_fn rules[] = {rule_s390_text_segment_mod};
  engine_run(&e, rules, 1);
#if defined(__s390__) || defined(__s390x__)
  assert(e.est[Q_VIRT_TEXT_BASE].stride == 0x100000ul);
  assert(e.est[Q_VIRT_TEXT_BASE].stride_offset == (phys_anchor % 0x100000ul));
  assert(!estimate_is_bottom(&e.est[Q_VIRT_TEXT_BASE],
                             &quantities[Q_VIRT_TEXT_BASE]));
#else
  /* Inert off s390 — the rule's #if guard returns 0 and the estimate's
   * stride stays at its top (= 0). */
  assert(e.est[Q_VIRT_TEXT_BASE].stride == 0);
#endif
}

static void test_s390_text_segment_mod_no_anchor(void) {
  struct engine e;
  engine_init(&e);
  /* No PHYS/KERNEL_IMAGE observation — rule should not fire. */
  const rule_fn rules[] = {rule_s390_text_segment_mod};
  engine_run(&e, rules, 1);
  assert(e.est[Q_VIRT_TEXT_BASE].stride == 0);
}

/* s390_text_no_random: when SF_PHYS_KASLR_RANDOMIZATION_FAILED is present on
 * s390, the boot stub places the kernel image at low physical memory
 * (TEXT_OFFSET on pre-v6.8, or ALIGN(mem_safe_offset, 1MiB) on v6.8+).
 * The rule emits a 256 MiB upper bound at CONF_HEURISTIC. */
int rule_s390_text_no_random(const struct evidence_set *ev,
                             const struct estimate *est, struct constraint *out,
                             int out_max);

static void test_s390_text_no_random_fires_with_signal(void) {
#if defined(__s390__) || defined(__s390x__)
  struct engine e;
  engine_init(&e);
  struct observation s =
      mk_scalar(SF_PHYS_KASLR_RANDOMIZATION_FAILED, 1, CONF_PARSED);
  evidence_add(&e.ev, &s);

  const rule_fn rules[] = {rule_s390_text_no_random};
  engine_run(&e, rules, 1);
  /* Upper bound at 256 MiB; lower bound stays at the honest floor. */
  assert(e.est[Q_PHYS_TEXT_BASE].hi == 256ul * 1024ul * 1024ul);
#endif
}

/* Without the signal, the rule must not fire — guards against a
 * regression that emits the bound on every s390 run. */
static void test_s390_text_no_random_inert_without_signal(void) {
#if defined(__s390__) || defined(__s390x__)
  struct engine e;
  engine_init(&e);
  /* No SF_PHYS_KASLR_RANDOMIZATION_FAILED. */
  struct estimate top;
  quantities[Q_PHYS_TEXT_BASE].init_top(&top);

  const rule_fn rules[] = {rule_s390_text_no_random};
  engine_run(&e, rules, 1);
  assert(e.est[Q_PHYS_TEXT_BASE].hi == top.hi);
#endif
}

/* The s390 no-PRNG empirical fixture (t_phys = 0xaa0000 = ~10.6 MiB):
 * with the new rule firing, the resolved window still admits the true
 * displaced text base. Regression guard tying the chosen constant to
 * the empirical case. */
static void test_s390_text_no_random_admits_empirical_phys(void) {
#if defined(__s390__) || defined(__s390x__)
  struct engine e;
  engine_init(&e);
  struct observation s =
      mk_scalar(SF_PHYS_KASLR_RANDOMIZATION_FAILED, 1, CONF_PARSED);
  evidence_add(&e.ev, &s);

  const rule_fn rules[] = {rule_s390_text_no_random};
  engine_run(&e, rules, 1);
  const unsigned long empirical_phys = 0xaa0000ul;
  assert(empirical_phys <= e.est[Q_PHYS_TEXT_BASE].hi);
  assert(empirical_phys >= e.est[Q_PHYS_TEXT_BASE].lo);
#endif
}

/* cmdline_memmap_too_large_phys_pin: cmdline carries 5+ memmap=
 * tokens with offset → SF_CMDLINE_MEMMAP_COUNT > 4 + a PHYS kernel_image
 * observation pins Q_PHYS_TEXT_BASE bilaterally. */
int rule_cmdline_memmap_too_large_phys_pin(const struct evidence_set *ev,
                                           const struct estimate *est,
                                           struct constraint *out, int out_max);

static void test_cmdline_memmap_too_large_phys_pin(void) {
#if defined(__x86_64__)
  unsigned long base = (unsigned long)KASLR_PHYS_MIN + 0x4000000ul;
  base &= ~((unsigned long)KASLR_PHYS_ALIGN - 1);
  if (base < (unsigned long)KASLR_PHYS_MIN)
    return;
  struct engine e;
  engine_init(&e);
  /* Trigger: count = 5 (> MAX_MEMMAP_REGIONS = 4). */
  struct observation cnt = mk_scalar(SF_CMDLINE_MEMMAP_COUNT, 5, CONF_PARSED);
  evidence_add(&e.ev, &cnt);
  /* Anchor: PHYS kernel_image observation. */
  struct observation img = mk_obs(KASLD_TYPE_PHYS, REGION_KERNEL_IMAGE, base,
                                  LO_SET | SAMPLE_SET, POS_BASE, CONF_PARSED);
  evidence_add(&e.ev, &img);

  const rule_fn rules[] = {rule_cmdline_memmap_too_large_phys_pin};
  engine_run(&e, rules, 1);
  /* Bilateral pin. */
  assert(e.est[Q_PHYS_TEXT_BASE].lo == base);
  assert(e.est[Q_PHYS_TEXT_BASE].hi == base);
#endif
}

/* Count ≤ 4 → no pin (kernel honours the entries; KASLR continues). */
static void test_cmdline_memmap_too_large_phys_pin_under_threshold(void) {
#if defined(__x86_64__)
  unsigned long base = (unsigned long)KASLR_PHYS_MIN + 0x4000000ul;
  base &= ~((unsigned long)KASLR_PHYS_ALIGN - 1);
  if (base < (unsigned long)KASLR_PHYS_MIN)
    return;
  struct engine e;
  engine_init(&e);
  struct observation cnt = mk_scalar(SF_CMDLINE_MEMMAP_COUNT, 4, CONF_PARSED);
  struct observation img = mk_obs(KASLD_TYPE_PHYS, REGION_KERNEL_IMAGE, base,
                                  LO_SET | SAMPLE_SET, POS_BASE, CONF_PARSED);
  evidence_add(&e.ev, &cnt);
  evidence_add(&e.ev, &img);
  const rule_fn rules[] = {rule_cmdline_memmap_too_large_phys_pin};
  engine_run(&e, rules, 1);
  /* Window not narrowed to a point. */
  assert(!(e.est[Q_PHYS_TEXT_BASE].lo == base &&
           e.est[Q_PHYS_TEXT_BASE].hi == base));
#endif
}

/* physical_start_lower_bound (1.1 fix): when SF_PHYSICAL_START is learned,
 * push Q_VIRT_TEXT_BASE.lo + Q_PHYS_TEXT_BASE.lo to the precise floor at
 * CONF_PARSED; without the scalar, fall back to compile-time
 * KASLR_VIRT_TEXT_MIN at CONF_HEURISTIC (overridable by any real evidence). */
int rule_physical_start_lower_bound(const struct evidence_set *ev,
                                    const struct estimate *est,
                                    struct constraint *out, int out_max);

static void test_physical_start_lower_bound_learned(void) {
#if defined(__x86_64__)
  struct engine e;
  engine_init(&e);
  unsigned long learned = 0x800000ul; /* 8 MiB; below the default 16 MiB */
  struct observation o = mk_scalar(SF_PHYSICAL_START, learned, CONF_PARSED);
  evidence_add(&e.ev, &o);
  const rule_fn rules[] = {rule_physical_start_lower_bound};
  engine_run(&e, rules, 1);
  /* Q_VIRT_TEXT_BASE.lo raised to KERNEL_VIRT_TEXT_MIN + learned. */
  assert(e.est[Q_VIRT_TEXT_BASE].lo ==
         (unsigned long)KERNEL_VIRT_TEXT_MIN + learned);
  /* Q_PHYS_TEXT_BASE.lo raised to learned. */
  assert(e.est[Q_PHYS_TEXT_BASE].lo == learned);
#endif
}

/* No SF_PHYSICAL_START → heuristic falls back to compile-time
 * KASLR_VIRT_TEXT_MIN (same value the pre-widening top had). Default-config
 * kernels keep their tight window. */
static void test_physical_start_lower_bound_heuristic(void) {
#if defined(__x86_64__)
  struct engine e;
  engine_init(&e);
  const rule_fn rules[] = {rule_physical_start_lower_bound};
  engine_run(&e, rules, 1);
  assert(e.est[Q_VIRT_TEXT_BASE].lo == (unsigned long)KASLR_VIRT_TEXT_MIN);
  assert(e.est[Q_PHYS_TEXT_BASE].lo == (unsigned long)KASLR_PHYS_MIN);
#endif
}

/* The heuristic floor is overridable: a real text leak BELOW
 * KASLR_VIRT_TEXT_MIN survives (compile-time floor is a heuristic, the leak is
 * parsed and wins via the resolver's confidence priority). */
static void test_physical_start_lower_bound_leak_below_heuristic(void) {
#if defined(__x86_64__)
  struct engine e;
  engine_init(&e);
  /* Sample below the default KASLR_VIRT_TEXT_MIN — simulates a kernel built
   * with CONFIG_PHYSICAL_START < default. */
  unsigned long below = (unsigned long)KASLR_VIRT_TEXT_MIN -
                        0x10000ul; /* one 64 KiB step below */
  struct observation o = mk_obs(KASLD_TYPE_VIRT, REGION_KERNEL_IMAGE, below,
                                SAMPLE_SET, POS_INTERIOR, CONF_PARSED);
  evidence_add(&e.ev, &o);
  const rule_fn rules[] = {rule_physical_start_lower_bound,
                           rule_range_from_interior};
  engine_run(&e, rules, 2);
  /* The CONF_PARSED leak upper bound (text ≤ below) must coexist with the
   * window — i.e. the resolved window admits `below`. */
  assert(e.est[Q_VIRT_TEXT_BASE].lo <= below);
  assert(e.est[Q_VIRT_TEXT_BASE].hi == below);
#endif
}

/* arm64_coupling_validate: VIRT observations whose tagged region
 * disagrees with the address band are invalidated. */
int rule_arm64_coupling_validate(const struct evidence_set *ev,
                                 struct verdict *out, int out_max);

static void test_arm64_coupling_validate_module_outside_band(void) {
  struct engine e;
  engine_init(&e);
  /* Tag a kernel-text address as MODULE. Bad: not in [MODULES_START,END]. */
  struct observation bad =
      mk_obs(KASLD_TYPE_VIRT, REGION_MODULE, 0xffff8000c0000000ul,
             LO_SET | SAMPLE_SET, POS_BASE, CONF_PARSED);
  evidence_add(&e.ev, &bad);
  const verdict_fn vrules[] = {rule_arm64_coupling_validate};
  engine_run_full(&e, NULL, 0, vrules, 1);
#if defined(__aarch64__)
  assert(!e.ev.obs[0].valid);
#else
  (void)e; /* inert off arm64 */
#endif
}

/* Tag inside the module band: valid. */
static void test_arm64_coupling_validate_module_inside_band(void) {
  struct engine e;
  engine_init(&e);
  struct observation ok =
      mk_obs(KASLD_TYPE_VIRT, REGION_MODULE, 0xffff800040000000ul,
             LO_SET | SAMPLE_SET, POS_BASE, CONF_PARSED);
  evidence_add(&e.ev, &ok);
  const verdict_fn vrules[] = {rule_arm64_coupling_validate};
  engine_run_full(&e, NULL, 0, vrules, 1);
  assert(e.ev.obs[0].valid);
}

/* Regression: a KERNEL_TEXT observation inside the validation range
 * [KERNEL_VIRT_TEXT_MIN, KERNEL_VIRT_TEXT_MAX] but outside the narrower KASLR
 * window [KASLR_VIRT_TEXT_MIN, KASLR_VIRT_TEXT_MAX) must NOT be invalidated.
 * The rule's job is region-band misclassification, not enforcement of one
 * specific kernel version's KASLR formula — text leaks from kernels whose
 * kaslr_early.c produces slots outside the modelled window are legitimate. */
static void
test_arm64_coupling_validate_text_in_validation_outside_kaslr(void) {
#if defined(__aarch64__)
  /* Construction: only exercise this gap if it exists on the host build
   * (validation range strictly wider than the KASLR window on the lower
   * edge). Pick an address one image-alignment above KERNEL_VIRT_TEXT_MIN — if
   * that lands below KASLR_VIRT_TEXT_MIN, it's in the previously-rejected gap.
   */
  unsigned long a = (unsigned long)KERNEL_VIRT_TEXT_MIN + 0x10000ul;
  if (a >= (unsigned long)KASLR_VIRT_TEXT_MIN ||
      a > (unsigned long)KERNEL_VIRT_TEXT_MAX)
    return; /* no gap to test on this header */
  struct engine e;
  engine_init(&e);
  struct observation ok = mk_obs(KASLD_TYPE_VIRT, REGION_KERNEL_TEXT, a,
                                 LO_SET | SAMPLE_SET, POS_BASE, CONF_PARSED);
  evidence_add(&e.ev, &ok);
  const verdict_fn vrules[] = {rule_arm64_coupling_validate};
  engine_run_full(&e, NULL, 0, vrules, 1);
  assert(e.ev.obs[0].valid); /* must NOT be invalidated */
#endif
}

/* Regression: a KERNEL_TEXT observation outside even the validation range
 * IS still invalidated (the rule continues to catch genuinely misclassified
 * observations — we widened the band, not abolished it). */
static void test_arm64_coupling_validate_text_outside_validation(void) {
#if defined(__aarch64__)
  /* Pick an address below KERNEL_VIRT_VAS_START (arch-low end of kernel VAS) so
   * the rule's KERNEL_VIRT_TEXT_MIN floor strictly excludes it. */
  unsigned long below = (unsigned long)KERNEL_VIRT_TEXT_MIN - 0x1000ul;
  if (below >= (unsigned long)KERNEL_VIRT_TEXT_MIN)
    return; /* underflow on this header, skip */
  struct engine e;
  engine_init(&e);
  struct observation bad = mk_obs(KASLD_TYPE_VIRT, REGION_KERNEL_TEXT, below,
                                  LO_SET | SAMPLE_SET, POS_BASE, CONF_PARSED);
  evidence_add(&e.ev, &bad);
  const verdict_fn vrules[] = {rule_arm64_coupling_validate};
  engine_run_full(&e, NULL, 0, vrules, 1);
  assert(!e.ev.obs[0].valid); /* still caught */
#endif
}

/* Regression for coupling_validate (x86_64): KERNEL_TEXT inside
 * [KERNEL_VIRT_TEXT_MIN, KASLR_VIRT_TEXT_MIN) must NOT be invalidated. On
 * x86_64 the gap is the 16 MiB between KERNEL_VIRT_TEXT_MIN (=
 * __START_KERNEL_map) and KASLR_VIRT_TEXT_MIN (= __START_KERNEL_map +
 * PHYSICAL_START), which a kernel built with non-default CONFIG_PHYSICAL_START
 * legitimately populates. */
static void test_coupling_validate_text_in_validation_outside_kaslr(void) {
#if defined(__x86_64__)
  unsigned long a =
      (unsigned long)KERNEL_VIRT_TEXT_MIN + 0x200000ul; /* +2 MiB */
  if (a >= (unsigned long)KASLR_VIRT_TEXT_MIN ||
      a > (unsigned long)KERNEL_VIRT_TEXT_MAX)
    return;
  struct engine e;
  engine_init(&e);
  struct observation ok = mk_obs(KASLD_TYPE_VIRT, REGION_KERNEL_TEXT, a,
                                 LO_SET | SAMPLE_SET, POS_BASE, CONF_PARSED);
  evidence_add(&e.ev, &ok);
  const verdict_fn vrules[] = {rule_coupling_validate};
  engine_run_full(&e, NULL, 0, vrules, 1);
  assert(e.ev.obs[0].valid); /* must NOT be invalidated */
#endif
}

/* riscv64_coupling_validate: per-region VA-band verdict, sibling of
 * coupling_validate / arm64_coupling_validate. */
int rule_riscv64_coupling_validate(const struct evidence_set *ev,
                                   struct verdict *out, int out_max);

static void test_riscv64_coupling_validate_module_outside_band(void) {
#if (defined(__riscv) || defined(__riscv__)) && __riscv_xlen == 64
  struct engine e;
  engine_init(&e);
  /* A clearly-non-module addr (low kernel VAS) tagged as MODULE: bad. */
  unsigned long bad_a = (unsigned long)KERNEL_VIRT_VAS_START + 0x1000ul;
  if (bad_a >= (unsigned long)MODULES_START)
    return; /* arch geometry edge */
  struct observation bad = mk_obs(KASLD_TYPE_VIRT, REGION_MODULE, bad_a,
                                  LO_SET | SAMPLE_SET, POS_BASE, CONF_PARSED);
  evidence_add(&e.ev, &bad);
  const verdict_fn vrules[] = {rule_riscv64_coupling_validate};
  engine_run_full(&e, NULL, 0, vrules, 1);
  assert(!e.ev.obs[0].valid);
#endif
}

static void test_riscv64_coupling_validate_text_inside_validation(void) {
#if (defined(__riscv) || defined(__riscv__)) && __riscv_xlen == 64
  struct engine e;
  engine_init(&e);
  /* Modern KERNEL_LINK_ADDR + small slide — inside [KERNEL_VIRT_TEXT_MIN, MAX].
   */
  unsigned long a = (unsigned long)KERNEL_VIRT_TEXT_MAX - 0x200000ul;
  struct observation ok = mk_obs(KASLD_TYPE_VIRT, REGION_KERNEL_TEXT, a,
                                 LO_SET | SAMPLE_SET, POS_BASE, CONF_PARSED);
  evidence_add(&e.ev, &ok);
  const verdict_fn vrules[] = {rule_riscv64_coupling_validate};
  engine_run_full(&e, NULL, 0, vrules, 1);
  assert(e.ev.obs[0].valid);
#endif
}

/* loongarch64_coupling_validate: per-region VA-band verdict, sibling of
 * the other coupling_validate rules. */
int rule_loongarch64_coupling_validate(const struct evidence_set *ev,
                                       struct verdict *out, int out_max);

static void test_loongarch64_coupling_validate_directmap_in_xkprange(void) {
#if defined(__loongarch__) && __loongarch_grlen == 64
  struct engine e;
  engine_init(&e);
  /* A clearly-DMW directmap address: PAGE_OFFSET itself (XKPRANGE DMW1). */
  struct observation ok =
      mk_obs(KASLD_TYPE_VIRT, REGION_DIRECTMAP, (unsigned long)PAGE_OFFSET,
             LO_SET | SAMPLE_SET, POS_BASE, CONF_PARSED);
  evidence_add(&e.ev, &ok);
  const verdict_fn vrules[] = {rule_loongarch64_coupling_validate};
  engine_run_full(&e, NULL, 0, vrules, 1);
  assert(e.ev.obs[0].valid);
#endif
}

static void test_loongarch64_coupling_validate_directmap_in_xkvrange(void) {
#if defined(__loongarch__) && __loongarch_grlen == 64
  struct engine e;
  engine_init(&e);
  /* A clearly-XKVRANGE address (vmalloc/module territory) tagged as
   * DIRECTMAP: bad — DMW windows end at 0xa000_..., XKVRANGE starts at
   * 0xc000_... */
  struct observation bad =
      mk_obs(KASLD_TYPE_VIRT, REGION_DIRECTMAP, 0xffff000000000000ul,
             LO_SET | SAMPLE_SET, POS_BASE, CONF_PARSED);
  evidence_add(&e.ev, &bad);
  const verdict_fn vrules[] = {rule_loongarch64_coupling_validate};
  engine_run_full(&e, NULL, 0, vrules, 1);
  assert(!e.ev.obs[0].valid);
#endif
}

/* riscv64_page_offset_from_vmalloc_vmemmap: VMALLOC observation
 * → virt_page_offset > V_va (no mode dependency); VMEMMAP observation →
 * virt_page_offset > V_mm + VMALLOC_SIZE, gated on Q_VA_BITS pinned. */
int rule_riscv64_page_offset_from_vmalloc_vmemmap(const struct evidence_set *ev,
                                                  const struct estimate *est,
                                                  struct constraint *out,
                                                  int out_max);

static void test_riscv64_po_from_vmalloc(void) {
  struct engine e;
  engine_init(&e);
  unsigned long v_va = 0xffffffd000000000ul; /* somewhere in vmalloc */
  struct observation o = mk_obs(KASLD_TYPE_VIRT, REGION_VMALLOC, v_va,
                                LO_SET | SAMPLE_SET, POS_BASE, CONF_PARSED);
  evidence_add(&e.ev, &o);

  const rule_fn rules[] = {rule_riscv64_page_offset_from_vmalloc_vmemmap};
  engine_run(&e, rules, 1);

#if (defined(__riscv) || defined(__riscv__)) && __riscv_xlen == 64
  /* Q_PAGE_OFFSET lower bound at v_va + 1. */
  assert(e.est[Q_PAGE_OFFSET].lo >= v_va + 1ul);
#else
  (void)v_va;
  struct estimate top;
  quantities[Q_PAGE_OFFSET].init_top(&top);
  assert(e.est[Q_PAGE_OFFSET].lo == top.lo);
#endif
}

/* VMEMMAP branch fires under default (un-pinned) Q_PAGE_OFFSET by choosing
 * the SMALLEST plausible VMALLOC_SIZE — SV39's 80 GiB. Sound under any mode
 * ambiguity (undersizing only loosens the derived lower bound). */
static void test_riscv64_po_from_vmemmap_default_window_uses_sv39(void) {
  struct engine e;
  engine_init(&e);
  /* V_mm in the SV39 vmemmap band; arbitrary, picked to land in-window. */
  unsigned long v_mm = 0xffffffc000000000ul;
  struct observation o = mk_obs(KASLD_TYPE_VIRT, REGION_VMEMMAP, v_mm,
                                LO_SET | SAMPLE_SET, POS_BASE, CONF_PARSED);
  evidence_add(&e.ev, &o);

  const rule_fn rules[] = {rule_riscv64_page_offset_from_vmalloc_vmemmap};
  engine_run(&e, rules, 1);

#if (defined(__riscv) || defined(__riscv__)) && __riscv_xlen == 64
  /* SV39 VMALLOC_SIZE = 0x1400000000 (80 GiB). */
  assert(e.est[Q_PAGE_OFFSET].lo >= v_mm + 0x1400000000ul + 1ul);
#else
  (void)v_mm;
  struct estimate top;
  quantities[Q_PAGE_OFFSET].init_top(&top);
  assert(e.est[Q_PAGE_OFFSET].lo == top.lo);
#endif
}

/* VMEMMAP branch — Q_PAGE_OFFSET upper-bounded at the SV48 value rules out
 * SV39 (SV39's window is far above SV48's). The rule must therefore pick
 * SV48's VMALLOC_SIZE (~44 TiB) — not the default SV39 size that would fire
 * under the un-narrowed window. Uses the test-local cap helper to set hi
 * without pinning lo, so the derived C_LOWER_BOUND on Q_PAGE_OFFSET is
 * observable. */
static void test_riscv64_po_from_vmemmap_pinned_sv48(void) {
  struct engine e;
  engine_init(&e);

  unsigned long sv48_po = 0xffffaf8000000000ul;
  struct observation cap = mk_obs(KASLD_TYPE_VIRT, REGION_PAGE_OFFSET, sv48_po,
                                  LO_SET, POS_BASE, CONF_DERIVED);
  evidence_add(&e.ev, &cap);

  /* V_mm chosen so:
   *   - V_mm + SV48_SIZE + 1 ≤ sv48_po  (consistent with the upper bound)
   *   - V_mm + SV48_SIZE + 1 > top.lo   (visibly tightens the lower bound)
   * V_mm = sv48_po - SV48_SIZE - 0x10000000 puts V_mm just inside the SV48
   * vmemmap region. */
  unsigned long sv48_size = 0x2840000000000ul;
  unsigned long v_mm = sv48_po - sv48_size - 0x10000000ul;
  struct observation o = mk_obs(KASLD_TYPE_VIRT, REGION_VMEMMAP, v_mm,
                                LO_SET | SAMPLE_SET, POS_BASE, CONF_PARSED);
  evidence_add(&e.ev, &o);

  /* Cap runs alongside the consumer rule — fixpoint propagates the cap into
   * Q_PAGE_OFFSET, then the consumer re-runs with the narrowed window. */
  const rule_fn rules[] = {rule_riscv64_page_offset_from_vmalloc_vmemmap,
                           rule_cap_page_offset};
  engine_run(&e, rules, 2);

#if (defined(__riscv) || defined(__riscv__)) && __riscv_xlen == 64
  /* SV48 VMALLOC_SIZE = 0x2840000000000 (~44 TiB).
   * Mistakenly using SV39 size (0x1400000000 = 80 GiB) would leave po.lo at
   * the SV57 floor (top.lo = 0xff60000000000000) because V_mm + SV39_SIZE is
   * far below it. Assert the EXACT SV48-derived value to prove mode pick. */
  assert(e.est[Q_PAGE_OFFSET].lo == v_mm + sv48_size + 1ul);
  /* The cap upper-bounds Q_PAGE_OFFSET. */
  assert(e.est[Q_PAGE_OFFSET].hi == sv48_po);
#else
  (void)v_mm;
  (void)sv48_po;
  (void)sv48_size;
  struct estimate top;
  quantities[Q_PAGE_OFFSET].init_top(&top);
  /* Non-riscv64: rule body inert; cap helper still fires for any arch since
   * it is test-local. After cap: po.lo == top.lo (cap only sets hi). The
   * sv48_po landmark is a riscv64-shaped address; on arches whose VAS sits
   * below it (e.g. s390x), the cap is redundant against the honest top —
   * assert hi <= sv48_po rather than equality. */
  assert(e.est[Q_PAGE_OFFSET].lo == top.lo);
  if (sv48_po <= top.hi)
    assert(e.est[Q_PAGE_OFFSET].hi == sv48_po);
  else
    assert(e.est[Q_PAGE_OFFSET].hi == top.hi);
#endif
}

/* No observations: no constraint. */
static void test_riscv64_po_from_vmalloc_vmemmap_no_obs(void) {
  struct engine e;
  engine_init(&e);
  const rule_fn rules[] = {rule_riscv64_page_offset_from_vmalloc_vmemmap};
  engine_run(&e, rules, 1);
  struct estimate top;
  quantities[Q_PAGE_OFFSET].init_top(&top);
  assert(e.est[Q_PAGE_OFFSET].lo == top.lo);
}
#endif /* __SIZEOF_LONG__ >= 8 (x86_64 vmalloc/vmemmap) */

/* VA_BITS / paging-mode discrimination from DIRECTMAP leak ranges. Each rule
 * pins Q_VA_BITS (C_EQUALS) and tightens the Q_PAGE_OFFSET window to match
 * legacy. x86_64 (L4/L5) is active on the host; arm64 (VA48/VA52) is inert
 * here and exercised only when cross-built. */
int rule_x86_64_la57_from_directmap(const struct evidence_set *ev,
                                    const struct estimate *est,
                                    struct constraint *out, int out_max);
int rule_arm64_va_bits_from_directmap(const struct evidence_set *ev,
                                      const struct estimate *est,
                                      struct constraint *out, int out_max);

/* Emit a single DIRECTMAP virtual leak at `addr`. */
static void add_directmap(struct engine *e, unsigned long addr) {
  struct observation o = mk_obs(KASLD_TYPE_VIRT, REGION_DIRECTMAP, addr,
                                LO_SET | SAMPLE_SET, POS_BASE, CONF_PARSED);
  evidence_add(&e->ev, &o);
}

/* True if the finite-set estimate holds exactly the single candidate `value`.
 */
static int finset_is(const struct estimate *est, unsigned long value) {
  const struct quantity_def *qd = &quantities[Q_VA_BITS];
  unsigned long want = 0;
  for (int i = 0; i < qd->n_candidates; i++)
    if (qd->candidates[i] == value)
      want = 1ul << i;
  return want != 0 && est->lo == want;
}

#if __SIZEOF_LONG__ >=                                                         \
    8 /* 64-bit-only: LA57 / arm64 VA-bits directmap layouts */
static void test_va_bits_la57_l5(void) {
  struct engine e;
  engine_init(&e);
  /* DIRECTMAP address below the L4 VAS floor -> L5 paging. */
  add_directmap(&e, 0xff11000000001000ul);
  const rule_fn rules[] = {rule_x86_64_la57_from_directmap};
  engine_run(&e, rules, 1);

#if defined(__x86_64__)
  assert(finset_is(&e.est[Q_VA_BITS], 57));
  assert(e.est[Q_PAGE_OFFSET].lo == 0xff11000000000000ul);
  assert(e.est[Q_PAGE_OFFSET].hi == 0xffff800000000000ul - 1);
#else
  struct estimate po;
  quantities[Q_PAGE_OFFSET].init_top(&po);
  assert(e.est[Q_PAGE_OFFSET].lo == po.lo); /* inert off x86_64 */
#endif
}

static void test_va_bits_la57_l4(void) {
  struct engine e;
  engine_init(&e);
  /* DIRECTMAP at/above the L4 VAS floor -> L4 paging. */
  add_directmap(&e, 0xffff888000001000ul);
  const rule_fn rules[] = {rule_x86_64_la57_from_directmap};
  engine_run(&e, rules, 1);

#if defined(__x86_64__)
  assert(finset_is(&e.est[Q_VA_BITS], 48));
  assert(e.est[Q_PAGE_OFFSET].lo == 0xffff800000000000ul);
#else
  (void)e;
#endif
}

/* Contradictory leaks (both ranges) -> no constraint emitted. */
static void test_va_bits_la57_contradictory(void) {
  struct engine e;
  engine_init(&e);
  add_directmap(&e, 0xff11000000001000ul); /* L5 range */
  add_directmap(&e, 0xffff888000001000ul); /* L4 range */
  const rule_fn rules[] = {rule_x86_64_la57_from_directmap};
  engine_run(&e, rules, 1);

  struct estimate vtop, po;
  quantities[Q_VA_BITS].init_top(&vtop);
  quantities[Q_PAGE_OFFSET].init_top(&po);
  assert(e.est[Q_VA_BITS].lo == vtop.lo);   /* all candidates still live */
  assert(e.est[Q_PAGE_OFFSET].lo == po.lo); /* window untouched */
  assert(e.est[Q_PAGE_OFFSET].hi == po.hi);
}

/* arm64 VA_BITS rule: active under cross-build, inert (no change) on host. */
static void test_va_bits_arm64(void) {
  struct engine e;
  engine_init(&e);
  /* Address in [VA52_PO, VA48_PO) -> VA_BITS=52. */
  add_directmap(&e, 0xfff0000000001000ul);
  const rule_fn rules[] = {rule_arm64_va_bits_from_directmap};
  engine_run(&e, rules, 1);

#if defined(__aarch64__)
  assert(finset_is(&e.est[Q_VA_BITS], 52));
  /* VA52 pins the virt_page_offset ceiling to the window floor. */
  assert(e.est[Q_PAGE_OFFSET].hi == 0xfff0000000000000ul);
#else
  struct estimate po;
  quantities[Q_PAGE_OFFSET].init_top(&po);
  assert(e.est[Q_PAGE_OFFSET].hi == po.hi); /* inert off arm64 */
#endif
}
#endif /* __SIZEOF_LONG__ >= 8 (la57 / arm64 va_bits) */

/* KASLR alignment quantities (LK_MAXALIGN). The arch-default baseline pins the
 * minimum granularity; boot_params (x86_64) and EFI_KIMG_ALIGN (arm64) raise it
 * from config/page_size evidence. */
int rule_kaslr_align_arch_default(const struct evidence_set *ev,
                                  const struct estimate *est,
                                  struct constraint *out, int out_max);
int rule_boot_params_kaslr_align(const struct evidence_set *ev,
                                 const struct estimate *est,
                                 struct constraint *out, int out_max);
int rule_arm64_efi_kimg_align(const struct evidence_set *ev,
                              const struct estimate *est,
                              struct constraint *out, int out_max);

static void test_kaslr_align_arch_default(void) {
  struct engine e;
  engine_init(&e);
  const rule_fn rules[] = {rule_kaslr_align_arch_default};
  engine_run(&e, rules, 1);
  /* Baseline equals the arch KASLR_VIRT_ALIGN floor. */
  assert(e.est[Q_KASLR_ALIGN].lo == (unsigned long)KASLR_VIRT_ALIGN);
#if defined(KASLR_PHYS_MIN)
  assert(e.est[Q_PHYS_KASLR_ALIGN].lo == (unsigned long)KASLR_PHYS_ALIGN);
#endif
}

static void test_boot_params_kaslr_align(void) {
  struct engine e;
  engine_init(&e);
  unsigned long big = 16ul * 1024 * 1024; /* 16 MiB > 2 MiB default */
  struct observation a = mk_scalar(SF_PHYS_KERNEL_ALIGN, big, CONF_PARSED);
  evidence_add(&e.ev, &a);
  const rule_fn rules[] = {rule_kaslr_align_arch_default,
                           rule_boot_params_kaslr_align};
  engine_run(&e, rules, 2);
#if defined(__x86_64__) || defined(__i386__)
  /* Both x86_64 (boot_params live) and x86_32 (CONFIG_PHYSICAL_ALIGN from
   * /boot/config via the same SF_PHYS_KERNEL_ALIGN scalar) get the same
   * treatment — physical and virtual offsets are locked on both. */
  assert(e.est[Q_KASLR_ALIGN].lo == big);
  assert(e.est[Q_PHYS_KASLR_ALIGN].lo == big);
#else
  assert(e.est[Q_KASLR_ALIGN].lo ==
         (unsigned long)KASLR_VIRT_ALIGN); /* inert */
#endif
}

/* A sub-default alignment is dominated by the arch baseline (max-align). */
static void test_boot_params_kaslr_align_subdefault(void) {
  struct engine e;
  engine_init(&e);
  struct observation a = mk_scalar(SF_PHYS_KERNEL_ALIGN, 4096ul, CONF_PARSED);
  evidence_add(&e.ev, &a);
  const rule_fn rules[] = {rule_kaslr_align_arch_default,
                           rule_boot_params_kaslr_align};
  engine_run(&e, rules, 2);
  /* max-align never drops below the baseline. */
  assert(e.est[Q_KASLR_ALIGN].lo == (unsigned long)KASLR_VIRT_ALIGN);
}

static void test_arm64_efi_kimg_align(void) {
  struct engine e;
  engine_init(&e);
  struct observation p = mk_scalar(SF_PAGE_SIZE, 65536ul, CONF_PARSED);
  evidence_add(&e.ev, &p);
  const rule_fn rules[] = {rule_kaslr_align_arch_default,
                           rule_arm64_efi_kimg_align};
  engine_run(&e, rules, 2);
#if defined(__aarch64__)
  assert(e.est[Q_PHYS_KASLR_ALIGN].lo == 131072ul); /* 128 KiB for 64K pages */
#else
  /* Inert off arm64: phys align stays at the arch baseline. */
#if defined(KASLR_PHYS_MIN)
  assert(e.est[Q_PHYS_KASLR_ALIGN].lo == (unsigned long)KASLR_PHYS_ALIGN);
#endif
#endif
}

/* ceiling_from_image_size aligns the ceiling to the RESOLVED Q_KASLR_ALIGN:
 * when boot_params raises the alignment to a coarser CONFIG_PHYSICAL_ALIGN, the
 * ceiling snaps to that boundary (matching legacy boot_params_align), tighter
 * than the compile-time KASLR_VIRT_ALIGN would give. Cross-quantity +
 * multi-pass. */
static void test_ceiling_uses_resolved_align(void) {
#if defined(__x86_64__)
  struct engine e;
  engine_init(&e);
  unsigned long init_size = 0x1ae7000ul; /* ~27 MiB (as in the fixture) */
  unsigned long kalign = 0x1000000ul;    /* 16 MiB CONFIG_PHYSICAL_ALIGN */
  struct observation a = mk_scalar(SF_INIT_SIZE, init_size, CONF_PARSED);
  struct observation b = mk_scalar(SF_PHYS_KERNEL_ALIGN, kalign, CONF_PARSED);
  evidence_add(&e.ev, &a);
  evidence_add(&e.ev, &b);

  const rule_fn rules[] = {rule_kaslr_align_arch_default,
                           rule_boot_params_kaslr_align,
                           rule_ceiling_from_image_size};
  engine_run(&e, rules, 3);

  struct estimate top;
  quantities[Q_VIRT_TEXT_BASE].init_top(&top);
  unsigned long expect =
      min_ul((KASLR_VIRT_TEXT_MAX - init_size) & ~(kalign - 1), top.hi);
  assert(e.est[Q_KASLR_ALIGN].lo == kalign);
  assert(e.est[Q_VIRT_TEXT_BASE].hi ==
         expect); /* snapped to 16 MiB, not 2 MiB */
  /* And strictly tighter than the compile-time-align ceiling would be. */
  assert(expect <= ((KASLR_VIRT_TEXT_MAX - init_size) &
                    ~((unsigned long)KASLR_VIRT_ALIGN - 1)));
#endif
}

/* config_max_offset_ceiling: CONFIG_RANDOMIZE_BASE_MAX_OFFSET (MIPS and
 * LoongArch) bounds virt_text_base to KASLR_VIRT_TEXT_MIN + max_offset +
 * ALIGN(kernel_length, 0xffff) — the +ALIGN(kl) term accounts for the
 * kernel's placement code bumping the slide past the original image
 * when it would otherwise overlap. File-derived scalar; inert where the
 * option is absent OR when no kernel_length signal is available
 * (without the width we can't size the bump). */
int rule_config_max_offset_ceiling(const struct evidence_set *ev,
                                   const struct estimate *est,
                                   struct constraint *out, int out_max);

static void test_config_max_offset_ceiling(void) {
  struct engine e;
  engine_init(&e);
  unsigned long max_offset = 0x1000000ul; /* 16 MiB */
  struct observation s =
      mk_scalar(SF_VIRT_RANDOMIZE_MAX_OFFSET, max_offset, CONF_PARSED);
  evidence_add(&e.ev, &s);
  /* Feed a kernel_length signal via PHYS iomem-style observations. */
  struct observation tx, bs;
  memset(&tx, 0, sizeof(tx));
  tx.value_kind = OBS_ADDRESS;
  tx.type = KASLD_TYPE_PHYS;
  tx.region = REGION_KERNEL_TEXT;
  tx.lo = 0x02860000ul;
  tx.hi = 0x0352ffffull;
  tx.set_mask = LO_SET | HI_SET;
  tx.pos = POS_BASE;
  tx.conf = CONF_PARSED;
  evidence_add(&e.ev, &tx);
  memset(&bs, 0, sizeof(bs));
  bs.value_kind = OBS_ADDRESS;
  bs.type = KASLD_TYPE_PHYS;
  bs.region = REGION_KERNEL_BSS;
  bs.lo = 0x04120e00ul;
  bs.hi = 0x0421b91full;
  bs.set_mask = LO_SET | HI_SET;
  bs.pos = POS_BASE;
  bs.conf = CONF_PARSED;
  evidence_add(&e.ev, &bs);

  const rule_fn rules[] = {rule_config_max_offset_ceiling};
  engine_run(&e, rules, 1);

  struct estimate top;
  quantities[Q_VIRT_TEXT_BASE].init_top(&top);
#if defined(__mips__) || defined(__loongarch__)
  unsigned long kl = bs.hi - tx.lo + 1;
  unsigned long aligned_kl = (kl + 0xffff) & ~0xfffful;
  unsigned long ceiling =
      (unsigned long)KASLR_VIRT_TEXT_MIN + max_offset + aligned_kl;
  if (ceiling < top.hi)
    assert(e.est[Q_VIRT_TEXT_BASE].hi == ceiling);
#else
  /* Inert off MIPS/LoongArch — estimate stays at top regardless of the
   * scalar. */
  assert(e.est[Q_VIRT_TEXT_BASE].hi == top.hi);
#endif
}

/* No SF_VIRT_RANDOMIZE_MAX_OFFSET -> inert (estimate stays at top). */
static void test_config_max_offset_absent(void) {
  struct engine e;
  engine_init(&e);
  const rule_fn rules[] = {rule_config_max_offset_ceiling};
  engine_run(&e, rules, 1);
  struct estimate top;
  quantities[Q_VIRT_TEXT_BASE].init_top(&top);
  assert(e.est[Q_VIRT_TEXT_BASE].hi == top.hi);
}

/* page_offset_invariant_pin: on arches where PAGE_OFFSET is architecturally
 * invariant (mips, ppc64) it pins Q_PAGE_OFFSET to PAGE_OFFSET; inert (honest
 * window kept) elsewhere. */
int rule_page_offset_invariant_pin(const struct evidence_set *ev,
                                   const struct estimate *est,
                                   struct constraint *out, int out_max);

static void test_page_offset_invariant_pin(void) {
  struct engine e;
  engine_init(&e);
  const rule_fn rules[] = {rule_page_offset_invariant_pin};
  engine_run(&e, rules, 1);

  struct estimate top;
  quantities[Q_PAGE_OFFSET].init_top(&top);
#if PAGE_OFFSET_INVARIANT
  assert(e.est[Q_PAGE_OFFSET].lo == (unsigned long)PAGE_OFFSET);
  assert(e.est[Q_PAGE_OFFSET].hi == (unsigned long)PAGE_OFFSET); /* pinned */
#else
  assert(e.est[Q_PAGE_OFFSET].lo == top.lo); /* honest window kept */
  assert(e.est[Q_PAGE_OFFSET].hi == top.hi);
#endif
}

/* page_offset_from_config: on VMSPLIT arches (PAGE_OFFSET_FROM_CONFIG) it pins
 * Q_PAGE_OFFSET to the parsed CONFIG_PAGE_OFFSET; inert elsewhere. */
int rule_page_offset_from_config(const struct evidence_set *ev,
                                 const struct estimate *est,
                                 struct constraint *out, int out_max);

static void test_page_offset_from_config(void) {
  struct engine e;
  engine_init(&e);
  struct estimate top;
  quantities[Q_PAGE_OFFSET].init_top(&top);
  /* Pick a value inside the arch's virt_page_offset window so the pin is
   * admitted.
   */
  unsigned long cfg = top.lo;
  struct observation o =
      mk_scalar(SF_VIRT_CONFIG_PAGE_OFFSET, cfg, CONF_PARSED);
  evidence_add(&e.ev, &o);

  const rule_fn rules[] = {rule_page_offset_from_config};
  engine_run(&e, rules, 1);

#if PAGE_OFFSET_FROM_CONFIG
  assert(e.est[Q_PAGE_OFFSET].lo == cfg);
  assert(e.est[Q_PAGE_OFFSET].hi == cfg); /* pinned to the config value */
#else
  assert(e.est[Q_PAGE_OFFSET].lo == top.lo); /* inert: honest window kept */
  assert(e.est[Q_PAGE_OFFSET].hi == top.hi);
#endif
}

/* virt_kaslr_disabled_pin: SF_VIRT_KASLR_DISABLED + the arch's compile-time
 * default text base pins Q_VIRT_TEXT_BASE on arches where
 * KASLR_DISABLED_PINS_VIRT_TEXT==1 (x86_64, arm64, riscv64); inert elsewhere.
 * The window-containment check guards against a computed default outside the
 * honest top. */
int rule_virt_kaslr_disabled_pin(const struct evidence_set *ev,
                                 const struct estimate *est,
                                 struct constraint *out, int out_max);
int rule_phys_kaslr_disabled_pin(const struct evidence_set *ev,
                                 const struct estimate *est,
                                 struct constraint *out, int out_max);

static void test_virt_kaslr_disabled_pin(void) {
  struct engine e;
  engine_init(&e);
  struct estimate top;
  quantities[Q_VIRT_TEXT_BASE].init_top(&top);
  unsigned long def = arch_default_text_base();

  struct observation sig = mk_scalar(SF_VIRT_KASLR_DISABLED, 1, CONF_PARSED);
  evidence_add(&e.ev, &sig);

  const rule_fn rules[] = {rule_virt_kaslr_disabled_pin};
  engine_run(&e, rules, 1);

#if KASLR_DISABLED_PINS_VIRT_TEXT
  /* Pinned to the per-arch default if it lies in the honest window. */
  if (def >= top.lo && def <= top.hi) {
    assert(e.est[Q_VIRT_TEXT_BASE].lo == def);
    assert(e.est[Q_VIRT_TEXT_BASE].hi == def);
  } else {
    /* Window-containment backstop: a default we cannot place leaves the
     * window intact rather than pinning to a wrong value. */
    assert(e.est[Q_VIRT_TEXT_BASE].lo == top.lo);
    assert(e.est[Q_VIRT_TEXT_BASE].hi == top.hi);
  }
#else
  (void)def;
  assert(e.est[Q_VIRT_TEXT_BASE].lo == top.lo); /* inert on relocating arches */
  assert(e.est[Q_VIRT_TEXT_BASE].hi == top.hi);
#endif
}

/* No signal -> no pin (the rule is off-detection-gated, not always-fire).
 * A VIRT KERNEL_TEXT observation at the default address alone does not
 * satisfy the rule — only SF_VIRT_KASLR_DISABLED does. Regression guard
 * for the "scalar fact is the virt KASLR-off signal" contract. */
static void test_virt_kaslr_disabled_pin_no_signal_no_pin(void) {
  struct engine e;
  engine_init(&e);
  struct estimate top;
  quantities[Q_VIRT_TEXT_BASE].init_top(&top);
  unsigned long def = top.lo;
  struct observation o = mk_obs(KASLD_TYPE_VIRT, REGION_KERNEL_TEXT, def,
                                LO_SET | SAMPLE_SET, POS_BASE, CONF_PARSED);
  evidence_add(&e.ev, &o);

  const rule_fn rules[] = {rule_virt_kaslr_disabled_pin};
  engine_run(&e, rules, 1);
  assert(e.est[Q_VIRT_TEXT_BASE].lo == top.lo);
  assert(e.est[Q_VIRT_TEXT_BASE].hi == top.hi);
}

/* directmap_kaslr_disabled_pin: KASAN (or nokaslr) leaves page_offset / vmalloc
 * / vmemmap at their compile-time L4/L5 defaults; the level comes from
 * SF_VIRT_ADDR_BITS. x86_64 only. */
int rule_directmap_kaslr_disabled_pin(const struct evidence_set *ev,
                                      const struct estimate *est,
                                      struct constraint *out, int out_max);

static void test_directmap_kaslr_disabled_pin(void) {
#if defined(__x86_64__)
  const rule_fn rules[] = {rule_directmap_kaslr_disabled_pin};
  struct estimate top;
  quantities[Q_PAGE_OFFSET].init_top(&top);

  /* KASAN + 4-level (VA 48): all three bases pinned to the L4 defaults. */
  struct engine e;
  engine_init(&e);
  struct observation k = mk_scalar(SF_KASAN_ENABLED, 1, CONF_PARSED);
  struct observation vb = mk_scalar(SF_VIRT_ADDR_BITS, 48, CONF_PARSED);
  evidence_add(&e.ev, &k);
  evidence_add(&e.ev, &vb);
  engine_run(&e, rules, 1);
  assert(e.est[Q_PAGE_OFFSET].lo == PAGE_OFFSET_BASE_L4 &&
         e.est[Q_PAGE_OFFSET].hi == PAGE_OFFSET_BASE_L4);
  assert(e.est[Q_VMALLOC_BASE].lo == VMALLOC_BASE_L4 &&
         e.est[Q_VMALLOC_BASE].hi == VMALLOC_BASE_L4);
  assert(e.est[Q_VMEMMAP_BASE].lo == VMEMMAP_BASE_L4 &&
         e.est[Q_VMEMMAP_BASE].hi == VMEMMAP_BASE_L4);

  /* nokaslr + 5-level (VA 57): page_offset pinned to the L5 default. */
  struct engine e2;
  engine_init(&e2);
  struct observation d = mk_scalar(SF_VIRT_KASLR_DISABLED, 1, CONF_PARSED);
  struct observation vb2 = mk_scalar(SF_VIRT_ADDR_BITS, 57, CONF_PARSED);
  evidence_add(&e2.ev, &d);
  evidence_add(&e2.ev, &vb2);
  engine_run(&e2, rules, 1);
  assert(e2.est[Q_PAGE_OFFSET].lo == PAGE_OFFSET_BASE_L5 &&
         e2.est[Q_PAGE_OFFSET].hi == PAGE_OFFSET_BASE_L5);

  /* Negative: VA width but no disable signal — no pin. */
  struct engine e3;
  engine_init(&e3);
  struct observation vb3 = mk_scalar(SF_VIRT_ADDR_BITS, 48, CONF_PARSED);
  evidence_add(&e3.ev, &vb3);
  engine_run(&e3, rules, 1);
  assert(e3.est[Q_PAGE_OFFSET].lo == top.lo &&
         e3.est[Q_PAGE_OFFSET].hi == top.hi);

  /* Negative: disable signal but no VA width — no pin (can't pick L4/L5). */
  struct engine e4;
  engine_init(&e4);
  struct observation k4 = mk_scalar(SF_KASAN_ENABLED, 1, CONF_PARSED);
  evidence_add(&e4.ev, &k4);
  engine_run(&e4, rules, 1);
  assert(e4.est[Q_PAGE_OFFSET].lo == top.lo &&
         e4.est[Q_PAGE_OFFSET].hi == top.hi);

  /* Fallback path: NO SF_VIRT_ADDR_BITS, but a directmap leak below the L4 VAS
   * floor resolves Q_VA_BITS=57 via la57_from_directmap; the pin then takes the
   * level from the estimate and still fires (here -> the L5 default). */
  struct engine e5;
  engine_init(&e5);
  struct observation k5 = mk_scalar(SF_KASAN_ENABLED, 1, CONF_PARSED);
  evidence_add(&e5.ev, &k5);
  struct observation dm =
      mk_obs(KASLD_TYPE_VIRT, REGION_DIRECTMAP, 0xff20000000000000ul,
             LO_SET | SAMPLE_SET, POS_INTERIOR, CONF_PARSED);
  evidence_add(&e5.ev, &dm);
  const rule_fn rules_la57[] = {rule_x86_64_la57_from_directmap,
                                rule_directmap_kaslr_disabled_pin};
  engine_run(&e5, rules_la57, 2);
  assert(e5.est[Q_PAGE_OFFSET].lo == PAGE_OFFSET_BASE_L5 &&
         e5.est[Q_PAGE_OFFSET].hi == PAGE_OFFSET_BASE_L5);
#endif
}

/* SF_PHYS_KASLR_DISABLED pins Q_PHYS_TEXT_BASE on arches where the kernel's
 * decompressor/relocator keeps the image at its compile-time physical default
 * under nokaslr (KASLR_DISABLED_PINS_PHYS=1). Per-quantity window-containment
 * applies independently. */
static void test_phys_kaslr_disabled_pin(void) {
  struct engine e;
  engine_init(&e);
  struct estimate top_p;
  quantities[Q_PHYS_TEXT_BASE].init_top(&top_p);

  struct observation sig = mk_scalar(SF_PHYS_KASLR_DISABLED, 1, CONF_PARSED);
  evidence_add(&e.ev, &sig);

  const rule_fn rules[] = {rule_phys_kaslr_disabled_pin};
  engine_run(&e, rules, 1);

#if KASLR_DISABLED_PINS_PHYS
  unsigned long def = arch_default_phys_text_base();
  if (def != 0 && def >= top_p.lo && def <= top_p.hi) {
    assert(e.est[Q_PHYS_TEXT_BASE].lo == def);
    assert(e.est[Q_PHYS_TEXT_BASE].hi == def);
  } else {
    /* Window-containment: a default outside the window leaves it intact. */
    assert(e.est[Q_PHYS_TEXT_BASE].lo == top_p.lo);
    assert(e.est[Q_PHYS_TEXT_BASE].hi == top_p.hi);
  }
#else
  /* Inert on arches where phys placement is bootloader/platform-determined
   * (arm64 memstart_addr, riscv64 DRAM_BASE, s390 __kaslr_offset_phys).
   * Even though SF_PHYS_KASLR_DISABLED is true, the rule refuses to pin
   * because arch_default_phys_text_base() doesn't model truth there. */
  assert(e.est[Q_PHYS_TEXT_BASE].lo == top_p.lo);
  assert(e.est[Q_PHYS_TEXT_BASE].hi == top_p.hi);
#endif
}

/* The phys pin uses the signal's confidence; with the signal at CONF_PARSED
 * and no competing constraint, the heuristic default fires. */
static void test_phys_kaslr_disabled_pin_defers_to_real_leak(void) {
#if KASLR_DISABLED_PINS_PHYS
  struct engine e;
  engine_init(&e);
  struct estimate top_p;
  quantities[Q_PHYS_TEXT_BASE].init_top(&top_p);
  unsigned long def = arch_default_phys_text_base();
  unsigned long real = def + 0x200000ul; /* one slot above the default */
  if (def == 0 || real > top_p.hi || real < top_p.lo)
    return; /* arch geometry doesn't support the synthesis cleanly */

  struct observation sig = mk_scalar(SF_PHYS_KASLR_DISABLED, 1, CONF_PARSED);
  evidence_add(&e.ev, &sig);

  const rule_fn rules[] = {rule_phys_kaslr_disabled_pin};
  engine_run(&e, rules, 1);
  assert(e.est[Q_PHYS_TEXT_BASE].lo == def);
  assert(e.est[Q_PHYS_TEXT_BASE].hi == def);
#endif
}

/* On arches where KASLR_DISABLED_PINS_PHYS=0 (arm64, riscv64, s390), the
 * phys pin rule is inert even when SF_PHYS_KASLR_DISABLED fires — phys
 * placement isn't predictable from compile-time data there. The virt
 * pin (a separate rule, separate fact) runs independently. */
static void test_phys_kaslr_disabled_pin_inert_on_decoupled(void) {
#if KASLR_DISABLED_PINS_VIRT_TEXT && !KASLR_DISABLED_PINS_PHYS
  struct engine e;
  engine_init(&e);
  struct estimate top_p;
  quantities[Q_PHYS_TEXT_BASE].init_top(&top_p);

  /* Emit BOTH facts (matches every current emitter) and run only the phys
   * rule to isolate its behavior. */
  struct observation sigv = mk_scalar(SF_VIRT_KASLR_DISABLED, 1, CONF_PARSED);
  struct observation sigp = mk_scalar(SF_PHYS_KASLR_DISABLED, 1, CONF_PARSED);
  evidence_add(&e.ev, &sigv);
  evidence_add(&e.ev, &sigp);

  const rule_fn rules[] = {rule_phys_kaslr_disabled_pin};
  engine_run(&e, rules, 1);

  /* Phys left wide — KASLR_DISABLED_PINS_PHYS=0 short-circuits the rule. */
  assert(e.est[Q_PHYS_TEXT_BASE].lo == top_p.lo);
  assert(e.est[Q_PHYS_TEXT_BASE].hi == top_p.hi);
#endif
}

/* --- Leak-derived phys rules (decoupled). Active on the x86_64 host; these
 * are dormant on the offline corpus (no leaks) and need live-host validation.
 */
int rule_mmio_floor_phys_ceiling(const struct evidence_set *ev,
                                 const struct estimate *est,
                                 struct constraint *out, int out_max);
int rule_phys_hole_filter(const struct evidence_set *ev,
                          const struct estimate *est, struct constraint *out,
                          int out_max);
int rule_kernel_image_phys_bound(const struct evidence_set *ev,
                                 const struct estimate *est,
                                 struct constraint *out, int out_max);

/* Emit a PHYS address observation with an explicit [lo,hi] extent. */
static void add_phys_extent(struct engine *e, enum kasld_region region,
                            unsigned long lo, unsigned long hi) {
  struct observation o;
  memset(&o, 0, sizeof(o));
  o.value_kind = OBS_ADDRESS;
  o.type = KASLD_TYPE_PHYS;
  o.region = region;
  o.lo = lo;
  o.hi = hi;
  o.set_mask = LO_SET | HI_SET;
  o.pos = POS_BASE;
  o.conf = CONF_PARSED;
  evidence_add(&e->ev, &o);
}

static void test_mmio_floor_phys_ceiling(void) {
  struct engine e;
  engine_init(&e);
  /* Anchor to PHYS_OFFSET (DRAM base) so the addresses are real physical RAM
   * on every arch (0 on x86_64, 2 GiB on riscv64) and the derived ceiling
   * lands inside the phys KASLR window rather than below it. */
  unsigned long P = (unsigned long)PHYS_OFFSET;
  add_phys_extent(&e, REGION_RAM, P + 0x40000000ul,
                  P + 0x7ffffffful); /* DRAM */
  add_phys_extent(&e, REGION_PCI_MMIO, P + 0x90000000ul,
                  P + 0x9fffffff); /* MMIO above */
  const rule_fn rules[] = {rule_mmio_floor_phys_ceiling};
  engine_run(&e, rules, 1);
#if !TEXT_TRACKS_DIRECTMAP
  assert(e.est[Q_PHYS_TEXT_BASE].hi == P + 0x90000000ul - 1);
#else
  (void)e;
#endif
}

static void test_phys_hole_filter(void) {
  struct engine e;
  engine_init(&e);
  /* Two DRAM extents with a hole; the honest-top ceiling sits above both.
   * PHYS_OFFSET-anchored (see test_mmio_floor_phys_ceiling). */
  unsigned long P = (unsigned long)PHYS_OFFSET;
  add_phys_extent(&e, REGION_RAM, P + 0x1000000ul, P + 0x2000000ul);
  add_phys_extent(&e, REGION_RAM, P + 0x3000000ul, P + 0x4000000ul);
  const rule_fn rules[] = {rule_phys_hole_filter};
  engine_run(&e, rules, 1);
#if !TEXT_TRACKS_DIRECTMAP
  assert(e.est[Q_PHYS_TEXT_BASE].hi == P + 0x4000000ul); /* highest DRAM hi */
#else
  (void)e;
#endif
}

static void test_kernel_image_phys_bound(void) {
  struct engine e;
  engine_init(&e);
  unsigned long w = (unsigned long)PHYS_OFFSET +
                    0x10000000ul; /* leaked phys kernel-text witness */
  struct observation o = mk_obs(KASLD_TYPE_PHYS, REGION_KERNEL_TEXT, w,
                                LO_SET | SAMPLE_SET, POS_BASE, CONF_PARSED);
  evidence_add(&e.ev, &o);
  const rule_fn rules[] = {rule_kernel_image_phys_bound};
  engine_run(&e, rules, 1);
  /* phys base ≤ witness, aligned down to the phys KASLR slot. The rule
   * emits Q_PHYS_TEXT_BASE on every arch now (the cross-side projection
   * lives in text_base_coupling_synth on coupled arches). */
  assert(e.est[Q_PHYS_TEXT_BASE].hi <= w);
  assert(e.est[Q_PHYS_TEXT_BASE].hi >= w - (unsigned long)KASLR_PHYS_ALIGN);
}

/* kernel_image_phys_bound's high-witness path: when the highest PHYS
 * kernel-image witness sits above MAX_KERNEL_IMAGE_SIZE, the rule emits
 * a LOWER bound on Q_PHYS_TEXT_BASE = hi - MAX + 1 (independent of arch
 * coupling — relies only on the image-size cap). The spread between
 * witnesses is kept well under MAX so both bounds coexist consistently. */
static void test_kernel_image_phys_bound_lower_from_high_witness(void) {
  struct engine e;
  engine_init(&e);
  unsigned long P = (unsigned long)PHYS_OFFSET;
  /* Spread = 80 MiB, well below the 256 MiB conflict cap. lo at 200 MiB,
   * hi at 280 MiB → pmin = 280 - 256 + 1 = 25 MiB (+ P). */
  unsigned long lo_w = P + (200ul * 1024 * 1024);
  unsigned long hi_w = P + (280ul * 1024 * 1024);
  struct observation o_lo = mk_obs(KASLD_TYPE_PHYS, REGION_KERNEL_TEXT, lo_w,
                                   LO_SET, POS_BASE, CONF_PARSED);
  struct observation o_hi = mk_obs(KASLD_TYPE_PHYS, REGION_KERNEL_BSS, hi_w,
                                   LO_SET, POS_BASE, CONF_PARSED);
  evidence_add(&e.ev, &o_lo);
  evidence_add(&e.ev, &o_hi);
  const rule_fn rules[] = {rule_kernel_image_phys_bound};
  engine_run(&e, rules, 1);
  unsigned long expected_pmin_raw = hi_w - (256ul * 1024 * 1024) + 1;
  assert(e.est[Q_PHYS_TEXT_BASE].lo >= expected_pmin_raw);
  assert(e.est[Q_PHYS_TEXT_BASE].hi <= lo_w);
  assert(e.est[Q_PHYS_TEXT_BASE].lo <= e.est[Q_PHYS_TEXT_BASE].hi);
}

int rule_efi_loader_kernel_pick(const struct evidence_set *ev,
                                const struct estimate *est,
                                struct constraint *out, int out_max);

/* Build a PHYS REGION_EFI_LOADER_IMAGE observation with both LO and HI set
 * (the shape dmesg_efi_memmap emits via kasld_result_sized). mk_obs() only
 * fills lo from the address argument, so patch hi explicitly. */
static struct observation mk_efi_loader_entry(unsigned long lo,
                                              unsigned long hi) {
  struct observation o = mk_obs(KASLD_TYPE_PHYS, REGION_EFI_LOADER_IMAGE, lo,
                                LO_SET | HI_SET, POS_BASE, CONF_PARSED);
  o.hi = hi;
  return o;
}

/* Single Loader Code entry, aligned at EFI_KIMG_ALIGN, size exactly
 * SF_IMAGE_SIZE → unique survivor → Q_PHYS_TEXT_BASE pinned to entry.lo. */
static void test_efi_loader_kernel_pick_single_aligned(void) {
#if defined(EFI_KIMG_ALIGN)
  const unsigned long P = (unsigned long)PHYS_OFFSET;
  const unsigned long ksize = 0x800000ul; /* 8 MiB */
  /* +1 GiB above PHYS_OFFSET is a multiple of every plausible
   * EFI_KIMG_ALIGN (64 KiB / 128 KiB / 2 MiB / …), keeps the candidate
   * inside every arch's Q_PHYS_TEXT_BASE honest top. */
  const unsigned long entry_lo = P + 0x40000000ul;
  const unsigned long entry_hi = entry_lo + ksize - 1;
  struct engine e;
  engine_init(&e);
  struct observation is = mk_scalar(SF_IMAGE_SIZE, ksize, CONF_PARSED);
  evidence_add(&e.ev, &is);
  struct observation o = mk_efi_loader_entry(entry_lo, entry_hi);
  evidence_add(&e.ev, &o);

  const rule_fn rules[] = {rule_efi_loader_kernel_pick};
  engine_run(&e, rules, 1);
  /* Window collapsed to the pin. */
  assert(e.est[Q_PHYS_TEXT_BASE].lo == entry_lo);
  assert(e.est[Q_PHYS_TEXT_BASE].hi == entry_lo);
#endif
}

/* Two Loader Code entries: one passes both filters, the other fails the
 * alignment filter. Exactly one survivor → C_EQUALS to the aligned entry. */
static void test_efi_loader_kernel_pick_multi_one_survives(void) {
#if defined(EFI_KIMG_ALIGN)
  const unsigned long P = (unsigned long)PHYS_OFFSET;
  const unsigned long ksize = 0x800000ul;
  const unsigned long kernel_lo = P + 0x40000000ul; /* aligned */
  const unsigned long bootldr_lo =
      P + 0x10000000ul + 0x1000ul; /* +4K → unaligned */
  struct engine e;
  engine_init(&e);
  struct observation is = mk_scalar(SF_IMAGE_SIZE, ksize, CONF_PARSED);
  evidence_add(&e.ev, &is);
  struct observation k = mk_efi_loader_entry(kernel_lo, kernel_lo + ksize - 1);
  struct observation b =
      mk_efi_loader_entry(bootldr_lo, bootldr_lo + ksize - 1);
  evidence_add(&e.ev, &k);
  evidence_add(&e.ev, &b);

  const rule_fn rules[] = {rule_efi_loader_kernel_pick};
  engine_run(&e, rules, 1);
  assert(e.est[Q_PHYS_TEXT_BASE].lo == kernel_lo);
  assert(e.est[Q_PHYS_TEXT_BASE].hi == kernel_lo);
#endif
}

/* Two Loader Code entries, both aligned, both within the size tolerance →
 * the rule cannot disambiguate → emit nothing (estimate untouched). The
 * conservative behaviour matches the old single-emit-on-loader_n==1 path. */
static void test_efi_loader_kernel_pick_multi_ambiguous_inert(void) {
#if defined(EFI_KIMG_ALIGN)
  const unsigned long P = (unsigned long)PHYS_OFFSET;
  const unsigned long ksize = 0x800000ul;
  /* Two entries widely separated, both aligned, both size==ksize. */
  const unsigned long a_lo = P + 0x40000000ul;
  const unsigned long b_lo = P + 0x80000000ul;
  struct engine e;
  engine_init(&e);
  struct observation is = mk_scalar(SF_IMAGE_SIZE, ksize, CONF_PARSED);
  evidence_add(&e.ev, &is);
  struct observation a = mk_efi_loader_entry(a_lo, a_lo + ksize - 1);
  struct observation b = mk_efi_loader_entry(b_lo, b_lo + ksize - 1);
  evidence_add(&e.ev, &a);
  evidence_add(&e.ev, &b);

  /* Capture honest top so we can confirm the rule was inert. */
  struct estimate top;
  quantities[Q_PHYS_TEXT_BASE].init_top(&top);

  const rule_fn rules[] = {rule_efi_loader_kernel_pick};
  engine_run(&e, rules, 1);
  /* Estimate stays at the honest top — no pin emitted. */
  assert(e.est[Q_PHYS_TEXT_BASE].lo == top.lo);
  assert(e.est[Q_PHYS_TEXT_BASE].hi == top.hi);
#endif
}

/* With SF_PHYS_KASLR_RANDOMIZATION_FAILED present, two surviving entries are
 * disambiguated by "firmware picks the lowest aligned slot" — the EFI stub
 * fell back from efi_random_alloc to a deterministic allocation that orders
 * memmap entries by physical address. Pin Q_PHYS_TEXT_BASE to the LOWER
 * survivor's lo at CONF_HEURISTIC (deferred to by any CONF_PARSED leak). */
static void test_efi_loader_kernel_pick_multi_rand_failed_picks_lowest(void) {
#if defined(EFI_KIMG_ALIGN)
  const unsigned long P = (unsigned long)PHYS_OFFSET;
  const unsigned long ksize = 0x800000ul;
  const unsigned long a_lo = P + 0x40000000ul; /* lower entry */
  const unsigned long b_lo = P + 0x80000000ul; /* higher entry */
  struct engine e;
  engine_init(&e);
  struct observation is = mk_scalar(SF_IMAGE_SIZE, ksize, CONF_PARSED);
  evidence_add(&e.ev, &is);
  struct observation rf =
      mk_scalar(SF_PHYS_KASLR_RANDOMIZATION_FAILED, 1, CONF_PARSED);
  evidence_add(&e.ev, &rf);
  /* Insert higher entry first so the rule cannot rely on iteration order. */
  struct observation b = mk_efi_loader_entry(b_lo, b_lo + ksize - 1);
  struct observation a = mk_efi_loader_entry(a_lo, a_lo + ksize - 1);
  evidence_add(&e.ev, &b);
  evidence_add(&e.ev, &a);

  const rule_fn rules[] = {rule_efi_loader_kernel_pick};
  engine_run(&e, rules, 1);
  /* Pinned to lower survivor, regardless of insertion order. */
  assert(e.est[Q_PHYS_TEXT_BASE].lo == a_lo);
  assert(e.est[Q_PHYS_TEXT_BASE].hi == a_lo);
#endif
}

/* Without the signal, the existing inert-on-ambiguity behaviour must be
 * preserved. Regression guard: a future change that picks the lowest
 * unconditionally would silently weaken soundness. */
static void test_efi_loader_kernel_pick_multi_without_signal_still_inert(void) {
#if defined(EFI_KIMG_ALIGN)
  const unsigned long P = (unsigned long)PHYS_OFFSET;
  const unsigned long ksize = 0x800000ul;
  const unsigned long a_lo = P + 0x40000000ul;
  const unsigned long b_lo = P + 0x80000000ul;
  struct engine e;
  engine_init(&e);
  struct observation is = mk_scalar(SF_IMAGE_SIZE, ksize, CONF_PARSED);
  evidence_add(&e.ev, &is);
  /* No SF_PHYS_KASLR_RANDOMIZATION_FAILED. */
  struct observation a = mk_efi_loader_entry(a_lo, a_lo + ksize - 1);
  struct observation b = mk_efi_loader_entry(b_lo, b_lo + ksize - 1);
  evidence_add(&e.ev, &a);
  evidence_add(&e.ev, &b);

  struct estimate top;
  quantities[Q_PHYS_TEXT_BASE].init_top(&top);

  const rule_fn rules[] = {rule_efi_loader_kernel_pick};
  engine_run(&e, rules, 1);
  assert(e.est[Q_PHYS_TEXT_BASE].lo == top.lo);
  assert(e.est[Q_PHYS_TEXT_BASE].hi == top.hi);
#endif
}

/* No SF_IMAGE_SIZE evidence → the size filter cannot apply → rule emits
 * nothing (sound by construction; we never want to pin on alignment alone
 * when the rule's contract requires both filters to succeed). */
static void test_efi_loader_kernel_pick_no_image_size_inert(void) {
#if defined(EFI_KIMG_ALIGN)
  const unsigned long P = (unsigned long)PHYS_OFFSET;
  const unsigned long ksize = 0x800000ul;
  const unsigned long entry_lo = P + 0x40000000ul;
  struct engine e;
  engine_init(&e);
  struct observation o = mk_efi_loader_entry(entry_lo, entry_lo + ksize - 1);
  evidence_add(&e.ev, &o);

  struct estimate top;
  quantities[Q_PHYS_TEXT_BASE].init_top(&top);

  const rule_fn rules[] = {rule_efi_loader_kernel_pick};
  engine_run(&e, rules, 1);
  assert(e.est[Q_PHYS_TEXT_BASE].lo == top.lo);
  assert(e.est[Q_PHYS_TEXT_BASE].hi == top.hi);
#endif
}

/* Entry size exceeds 2× SF_IMAGE_SIZE → size filter rejects → no survivor →
 * rule inert. */
static void test_efi_loader_kernel_pick_size_above_tolerance_inert(void) {
#if defined(EFI_KIMG_ALIGN)
  const unsigned long P = (unsigned long)PHYS_OFFSET;
  const unsigned long ksize = 0x800000ul;
  const unsigned long entry_lo = P + 0x40000000ul;
  const unsigned long entry_size = 3 * ksize; /* > 2× tolerance */
  struct engine e;
  engine_init(&e);
  struct observation is = mk_scalar(SF_IMAGE_SIZE, ksize, CONF_PARSED);
  evidence_add(&e.ev, &is);
  struct observation o =
      mk_efi_loader_entry(entry_lo, entry_lo + entry_size - 1);
  evidence_add(&e.ev, &o);

  struct estimate top;
  quantities[Q_PHYS_TEXT_BASE].init_top(&top);

  const rule_fn rules[] = {rule_efi_loader_kernel_pick};
  engine_run(&e, rules, 1);
  assert(e.est[Q_PHYS_TEXT_BASE].lo == top.lo);
  assert(e.est[Q_PHYS_TEXT_BASE].hi == top.hi);
#endif
}

int rule_image_size_text_data_gap(const struct evidence_set *ev,
                                  const struct estimate *est,
                                  struct constraint *out, int out_max);
int rule_directmap_page_offset_bounds(const struct evidence_set *ev,
                                      const struct estimate *est,
                                      struct constraint *out, int out_max);

static void test_image_size_text_data_gap(void) {
  struct engine e;
  engine_init(&e);
  struct estimate top;
  quantities[Q_VIRT_TEXT_BASE].init_top(&top);
  unsigned long text = top.lo;
  unsigned long gap = 0x800000ul; /* 8 MiB text..data */
  struct observation t = mk_obs(KASLD_TYPE_VIRT, REGION_KERNEL_TEXT, text,
                                LO_SET | SAMPLE_SET, POS_BASE, CONF_PARSED);
  struct observation d = mk_obs(KASLD_TYPE_VIRT, REGION_KERNEL_DATA, text + gap,
                                LO_SET | SAMPLE_SET, POS_BASE, CONF_PARSED);
  evidence_add(&e.ev, &t);
  evidence_add(&e.ev, &d);
  const rule_fn rules[] = {rule_image_size_text_data_gap};
  engine_run(&e, rules, 1);
  unsigned long expect = ((unsigned long)KASLR_VIRT_TEXT_MAX - gap) &
                         ~((unsigned long)KASLR_VIRT_ALIGN - 1);
  if (expect < top.hi)
    assert(e.est[Q_VIRT_TEXT_BASE].hi == expect);
}

/* 64-bit-only: these model a randomized direct map with TiB-scale offsets and
 * >4 GiB of RAM — the 1 TiB leak offset and the 13 GiB span do not fit a 32-bit
 * `unsigned long`. Runs on all 64-bit arches; skipped on 32-bit (where the
 * direct-map base is fixed, not randomized). */
#if __SIZEOF_LONG__ >= 8
static void test_directmap_page_offset_bounds(void) {
  struct engine e;
  engine_init(&e);
  struct estimate top;
  quantities[Q_PAGE_OFFSET].init_top(&top);
  unsigned long vd = top.lo + 0x11000000000ul; /* a directmap leak in-window */
  struct observation o = mk_obs(KASLD_TYPE_VIRT, REGION_DIRECTMAP, vd,
                                LO_SET | SAMPLE_SET, POS_BASE, CONF_PARSED);
  evidence_add(&e.ev, &o);
  const rule_fn rules[] = {rule_directmap_page_offset_bounds};
  engine_run(&e, rules, 1);
  assert(e.est[Q_PAGE_OFFSET].hi ==
         vd); /* virt_page_offset <= lowest directmap */
}

/* With SF_PHYS_MAX_PFN the directmap leak also yields a sound lower bound:
 * virt_page_offset >= V - (max_pfn*PAGE_SIZE - PHYS_OFFSET). This is what
 * narrows the randomized direct-map base to ~RAM/1GiB candidates from a single
 * leak. */
static void test_directmap_page_offset_lower_bound_from_max_pfn(void) {
  struct engine e;
  engine_init(&e);
  struct estimate top;
  quantities[Q_PAGE_OFFSET].init_top(&top);
  unsigned long vd = top.lo + 0x11000000000ul; /* a directmap leak in-window */
  struct observation o = mk_obs(KASLD_TYPE_VIRT, REGION_DIRECTMAP, vd,
                                LO_SET | SAMPLE_SET, POS_BASE, CONF_PARSED);
  unsigned long max_pfn = 0x340000ul; /* ~13 GiB of direct-mapped RAM */
  struct observation mp = mk_scalar(SF_PHYS_MAX_PFN, max_pfn, CONF_PARSED);
  evidence_add(&e.ev, &o);
  evidence_add(&e.ev, &mp);
  const rule_fn rules[] = {rule_directmap_page_offset_bounds};
  engine_run(&e, rules, 1);
  unsigned long reach = max_pfn * PAGE_SIZE - (unsigned long)PHYS_OFFSET;
  unsigned long expect_lo = vd - reach;
  assert(e.est[Q_PAGE_OFFSET].hi == vd); /* base <= leak */
  assert(e.est[Q_PAGE_OFFSET].lo ==
         expect_lo); /* base >= leak - directmap span */
  /* The window must be exactly the direct-map span — no wider, no narrower. */
  assert(e.est[Q_PAGE_OFFSET].hi - e.est[Q_PAGE_OFFSET].lo == reach);
}

/* virt_page_offset_base on x86_64 RANDOMIZE_MEMORY is PUD-aligned (1 GiB) by
 * the kernel's own KASLR placement (arch/x86/mm/kaslr.c uses round_up(...,
 * PUD_SIZE)). Bounds derived from a *non-aligned* directmap leak address
 * must therefore align DOWN on the upper edge and UP on the lower edge —
 * the unaligned raw values are provably non-bases. */
static void test_directmap_page_offset_bounds_pud_aligned(void) {
#if RANDOMIZE_MEMORY_ALIGN > 0
  struct engine e;
  engine_init(&e);
  struct estimate top;
  quantities[Q_PAGE_OFFSET].init_top(&top);
  /* Leak deliberately NOT on a PUD boundary: top.lo + 1 TiB + 0x397b000
   * (a typical sub-PUD offset). Without the alignment fix the rule would
   * emit raw bounds with the same sub-PUD offset; with it the upper
   * aligns down to the nearest PUD and the lower aligns up. */
  const unsigned long pud = (unsigned long)RANDOMIZE_MEMORY_ALIGN;
  const unsigned long sub_pud_offset = 0x397b000ul; /* < PUD_SIZE */
  unsigned long vd = top.lo + (1ul << 40) + sub_pud_offset;
  struct observation o = mk_obs(KASLD_TYPE_VIRT, REGION_DIRECTMAP, vd,
                                LO_SET | SAMPLE_SET, POS_BASE, CONF_PARSED);
  unsigned long max_pfn = 0x340000ul; /* ~13 GiB direct-mapped RAM */
  struct observation mp = mk_scalar(SF_PHYS_MAX_PFN, max_pfn, CONF_PARSED);
  evidence_add(&e.ev, &o);
  evidence_add(&e.ev, &mp);
  const rule_fn rules[] = {rule_directmap_page_offset_bounds};
  engine_run(&e, rules, 1);
  /* Upper aligned DOWN: low PUD bits cleared. */
  assert((e.est[Q_PAGE_OFFSET].hi & (pud - 1)) == 0);
  assert(e.est[Q_PAGE_OFFSET].hi <= vd);
  assert(e.est[Q_PAGE_OFFSET].hi >= vd - sub_pud_offset);
  /* Lower aligned UP: low PUD bits cleared, AND no less restrictive than raw.
   */
  assert((e.est[Q_PAGE_OFFSET].lo & (pud - 1)) == 0);
  unsigned long reach = max_pfn * PAGE_SIZE - (unsigned long)PHYS_OFFSET;
  unsigned long raw_lower = vd - reach;
  assert(e.est[Q_PAGE_OFFSET].lo >= raw_lower);
  assert(e.est[Q_PAGE_OFFSET].lo <= raw_lower + (pud - 1));
#else
  /* Arches without RANDOMIZE_MEMORY_ALIGN — no-op. */
#endif
}
#endif /* __SIZEOF_LONG__ >= 8 (randomized direct-map bounds) */

int rule_base_align_cross_validate(const struct evidence_set *ev,
                                   const struct estimate *est,
                                   struct constraint *out, int out_max);
int rule_randomize_memory_page_offset(const struct evidence_set *ev,
                                      const struct estimate *est,
                                      struct constraint *out, int out_max);

static void test_base_align_cross_validate(void) {
  struct engine e;
  engine_init(&e);
  struct observation o;
  memset(&o, 0, sizeof(o));
  o.value_kind = OBS_ADDRESS;
  o.type = KASLD_TYPE_VIRT;
  o.region = REGION_KERNEL_TEXT;
  o.lo = (unsigned long)KASLR_VIRT_TEXT_MIN;
  o.base_align = 0x400000ul; /* 4 MiB observed alignment */
  o.set_mask = LO_SET | BASE_ALIGN_SET;
  o.pos = POS_BASE;
  o.conf = CONF_PARSED;
  evidence_add(&e.ev, &o);
  const rule_fn rules[] = {rule_base_align_cross_validate};
  engine_run(&e, rules, 1);
  assert(e.est[Q_KASLR_ALIGN].lo >= 0x400000ul);
}

static void test_randomize_memory_page_offset(void) {
  /* x86_64-only rule (RANDOMIZE_MEMORY); the synthetic direct-map base sits
   * 8.8 TiB above the floor, beyond a 32-bit `unsigned long`. */
#if defined(__x86_64__)
  struct engine e;
  engine_init(&e);
  struct estimate top;
  quantities[Q_PAGE_OFFSET].init_top(&top);
  unsigned long po = (top.lo + 0x88000000000ul) & ~((2ul << 20) - 1);
  unsigned long phys = 0x4000000ul;
  /* same-origin VIRT directmap + PHYS, differing by `po`. */
  struct observation v = mk_obs(KASLD_TYPE_VIRT, REGION_DIRECTMAP, po + phys,
                                LO_SET | SAMPLE_SET, POS_BASE, CONF_PARSED);
  snprintf(v.origin, ORIGIN_LEN, "pair");
  struct observation p = mk_obs(KASLD_TYPE_PHYS, REGION_DIRECTMAP, phys,
                                LO_SET | SAMPLE_SET, POS_BASE, CONF_PARSED);
  snprintf(p.origin, ORIGIN_LEN, "pair");
  evidence_add(&e.ev, &v);
  evidence_add(&e.ev, &p);
  const rule_fn rules[] = {rule_randomize_memory_page_offset};
  engine_run(&e, rules, 1);
  if (po >= top.lo && po <= top.hi) {
    assert(e.est[Q_PAGE_OFFSET].lo == po);
    assert(e.est[Q_PAGE_OFFSET].hi == po);
  }
#endif
}

int rule_firmware_memmap_holes(const struct evidence_set *ev,
                               struct verdict *out, int out_max);

static void test_firmware_memmap_holes(void) {
#if defined(__x86_64__)
  struct engine e;
  engine_init(&e);
  /* Authoritative System RAM extent [16M, 2G]. */
  struct observation ram;
  memset(&ram, 0, sizeof(ram));
  ram.value_kind = OBS_ADDRESS;
  ram.type = KASLD_TYPE_PHYS;
  ram.region = REGION_RAM;
  ram.lo = 0x1000000ul;
  ram.hi = 0x80000000ul;
  ram.set_mask = LO_SET | HI_SET;
  ram.pos = POS_BASE;
  ram.conf = CONF_PARSED;
  snprintf(ram.origin, ORIGIN_LEN, "firmware_memmap");
  evidence_add(&e.ev, &ram);
  /* Candidate inside RAM (kept) and one above RAM (dropped). */
  struct observation in =
      mk_obs(KASLD_TYPE_PHYS, REGION_KERNEL_TEXT, 0x10000000ul,
             LO_SET | SAMPLE_SET, POS_BASE, CONF_PARSED);
  uint32_t in_id = evidence_add(&e.ev, &in);
  struct observation out_c =
      mk_obs(KASLD_TYPE_PHYS, REGION_KERNEL_TEXT, 0x90000000ul,
             LO_SET | SAMPLE_SET, POS_BASE, CONF_PARSED);
  uint32_t out_id = evidence_add(&e.ev, &out_c);

  const verdict_fn vrules[] = {rule_firmware_memmap_holes};
  engine_run_full(&e, NULL, 0, vrules, 1);

  for (int i = 0; i < e.ev.n_obs; i++) {
    if (e.ev.obs[i].id == in_id)
      assert(e.ev.obs[i].valid == 1); /* inside System RAM: kept */
    if (e.ev.obs[i].id == out_id)
      assert(e.ev.obs[i].valid == 0); /* outside System RAM: dropped */
  }
#endif
}

/* randomize_memory_page_offset Path 2: cross-origin directmap - RAM base. */
static void test_randomize_memory_page_offset_path2(void) {
  /* x86_64-only rule; the PUD-aligned base literal exceeds a 32-bit long. */
#if defined(__x86_64__)
  struct engine e;
  engine_init(&e);
  unsigned long po = 0xff11000000000000ul; /* PUD-aligned, in x86_64 window */
  unsigned long pram = 0x100000ul;
  struct observation d =
      mk_obs(KASLD_TYPE_VIRT, REGION_DIRECTMAP, po + pram, LO_SET | SAMPLE_SET,
             POS_INTERIOR, CONF_PARSED); /* no origin */
  struct observation r;
  memset(&r, 0, sizeof(r));
  r.value_kind = OBS_ADDRESS;
  r.type = KASLD_TYPE_PHYS;
  r.region = REGION_RAM;
  r.lo = pram;
  r.set_mask = LO_SET;
  r.pos = POS_BASE;
  r.conf = CONF_PARSED;
  evidence_add(&e.ev, &d);
  evidence_add(&e.ev, &r);
  const rule_fn rules[] = {rule_randomize_memory_page_offset};
  engine_run(&e, rules, 1);
  assert(e.est[Q_PAGE_OFFSET].lo == po);
  assert(e.est[Q_PAGE_OFFSET].hi == po); /* reconstructed exact base, pinned */
#endif                                   /* __x86_64__ */
}

/* phys_virt_synth: same-origin directmap + DRAM leaks reconstruct
 * virt_page_offset = virt - phys + PHYS_OFFSET, pinned when origins agree. */
int rule_phys_virt_synth(const struct evidence_set *ev,
                         const struct estimate *est, struct constraint *out,
                         int out_max);

static void test_phys_virt_synth(void) {
  struct engine e;
  engine_init(&e);
  struct estimate top;
  quantities[Q_PAGE_OFFSET].init_top(&top);
  /* virt_page_offset base in-window for any arch (a window-scaled bump above
   * the floor, PMD-aligned so it can be a real directmap base), and a phys
   * address >= PHYS_OFFSET (the rule skips phys below the DRAM base). The
   * direct-map VA of phys p is po + (p - PHYS_OFFSET); the rule reconstructs
   * virt_page_offset = v - p + PHYS_OFFSET = po. */
  const unsigned long pmd_size = 2ul * 1024 * 1024;
  unsigned long po = top.lo + (po_window_bump(&top) & ~(pmd_size - 1));
  unsigned long p = (unsigned long)PHYS_OFFSET + 0x4000000ul;
  unsigned long v = po + (p - (unsigned long)PHYS_OFFSET);
  struct observation vo =
      mk_obs(KASLD_TYPE_VIRT, REGION_DIRECTMAP, v, LO_SET | SAMPLE_SET,
             POS_INTERIOR, CONF_PARSED);
  snprintf(vo.origin, ORIGIN_LEN, "synth");
  struct observation d;
  memset(&d, 0, sizeof(d));
  d.value_kind = OBS_ADDRESS;
  d.type = KASLD_TYPE_PHYS;
  d.region = REGION_RAM;
  d.lo = p;
  d.set_mask = LO_SET;
  d.pos = POS_BASE;
  d.conf = CONF_PARSED;
  snprintf(d.origin, ORIGIN_LEN, "synth");
  evidence_add(&e.ev, &vo);
  evidence_add(&e.ev, &d);
  const rule_fn rules[] = {rule_phys_virt_synth};
  engine_run(&e, rules, 1);
  if (po >= top.lo && po <= top.hi) {
    assert(e.est[Q_PAGE_OFFSET].lo == po);
    assert(e.est[Q_PAGE_OFFSET].hi == po);
  }
}

/* A directmap virt leak and a phys leak that are NOT the same physical page
 * (different objects from the same origin — e.g. a generic directmap register
 * value vs. a CR3/BSS leak) produce a v-p that is not large-page aligned, so it
 * cannot be the real virt_page_offset base. The rule must reject it rather than
 * pin virt_page_offset to a bogus value. Regression test for the alignment
 * guard. */
static void test_phys_virt_synth_rejects_misaligned_pair(void) {
  struct engine e;
  engine_init(&e);
  struct estimate top;
  quantities[Q_PAGE_OFFSET].init_top(&top);
  /* v - p = (po_floor + 0x101000) - 0x100000 = po_floor + 0x1000 — page
   * aligned but NOT PMD (2 MiB) aligned: a provably-impossible base. Anchor to
   * the arch's (large-page-aligned) virt_page_offset floor so the test is
   * portable across widths — the alignment guard is width-independent. */
  unsigned long po_floor = top.lo;
  unsigned long p = (unsigned long)PHYS_OFFSET + 0x100000ul;
  unsigned long v = po_floor + 0x101000ul;
  struct observation vo =
      mk_obs(KASLD_TYPE_VIRT, REGION_DIRECTMAP, v, LO_SET | SAMPLE_SET,
             POS_INTERIOR, CONF_PARSED);
  snprintf(vo.origin, ORIGIN_LEN, "mixed");
  struct observation po_obs;
  memset(&po_obs, 0, sizeof(po_obs));
  po_obs.value_kind = OBS_ADDRESS;
  po_obs.type = KASLD_TYPE_PHYS;
  po_obs.region = REGION_RAM;
  po_obs.lo = p;
  po_obs.set_mask = LO_SET;
  po_obs.pos = POS_BASE;
  po_obs.conf = CONF_PARSED;
  snprintf(po_obs.origin, ORIGIN_LEN, "mixed");
  evidence_add(&e.ev, &vo);
  evidence_add(&e.ev, &po_obs);
  const rule_fn rules[] = {rule_phys_virt_synth};
  engine_run(&e, rules, 1);
  /* Estimate must be untouched — no pin to the misaligned candidate. */
  assert(e.est[Q_PAGE_OFFSET].lo == top.lo);
  assert(e.est[Q_PAGE_OFFSET].hi == top.hi);
}

/* Two origins whose candidates agree within one KASLR alignment slot but are
 * not identical (a 2 MiB-spread, both PMD-aligned, the lower one at-least-as
 * aligned). On a fixed-PAGE_OFFSET arch the rule must PIN to the
 * cleanest/lowest candidate (virt_page_offset is a single architectural
 * constant — the spread is pairing noise); on x86_64 (randomized base) it
 * reports the [lo, hi] window. Exercised per-arch under tests/test-cross, which
 * is where the fixed-arch pin path actually runs. */
static void test_phys_virt_synth_spread_within_align(void) {
  struct engine e;
  engine_init(&e);
  struct estimate top;
  quantities[Q_PAGE_OFFSET].init_top(&top);

  const unsigned long pmd = 2ul * 1024 * 1024;
  /* Window-scaled bump, aligned to at least 2*pmd so po_true has strictly
   * higher trailing-zero count than po_alt = po_true + pmd — the rule picks
   * the most-aligned candidate via trailing_zeros_ul, and this test asserts
   * po_true wins. Lands strictly inside the floor..top window on every
   * arch / address width. */
  unsigned long po_true = top.lo + (po_window_bump(&top) & ~((2 * pmd) - 1));
  unsigned long po_alt = po_true + pmd; /* +2 MiB: less aligned */
  unsigned long p = (unsigned long)PHYS_OFFSET + 0x4000000ul; /* >= DRAM base */

  /* Origin A reconstructs po_true; origin B reconstructs po_alt. */
  struct observation va =
      mk_obs(KASLD_TYPE_VIRT, REGION_DIRECTMAP,
             po_true + (p - (unsigned long)PHYS_OFFSET), LO_SET | SAMPLE_SET,
             POS_INTERIOR, CONF_PARSED);
  snprintf(va.origin, ORIGIN_LEN, "origA");
  struct observation pa =
      mk_obs(KASLD_TYPE_PHYS, REGION_RAM, p, LO_SET, POS_BASE, CONF_PARSED);
  snprintf(pa.origin, ORIGIN_LEN, "origA");
  struct observation vb =
      mk_obs(KASLD_TYPE_VIRT, REGION_DIRECTMAP,
             po_alt + (p - (unsigned long)PHYS_OFFSET), LO_SET | SAMPLE_SET,
             POS_INTERIOR, CONF_PARSED);
  snprintf(vb.origin, ORIGIN_LEN, "origB");
  struct observation pb =
      mk_obs(KASLD_TYPE_PHYS, REGION_RAM, p, LO_SET, POS_BASE, CONF_PARSED);
  snprintf(pb.origin, ORIGIN_LEN, "origB");
  evidence_add(&e.ev, &va);
  evidence_add(&e.ev, &pa);
  evidence_add(&e.ev, &vb);
  evidence_add(&e.ev, &pb);

  const rule_fn rules[] = {rule_phys_virt_synth};
  engine_run(&e, rules, 1);

  /* The rule's agreement tolerance is max(resolved virt_kaslr_align,
   * KASLR_VIRT_ALIGN); Q_KASLR_ALIGN is unset in this isolated run, so it is
   * KASLR_VIRT_ALIGN. */
  unsigned long align = (unsigned long)KASLR_VIRT_ALIGN;
  if (po_alt <= top.hi && pmd <= align) {
#if PAGE_OFFSET_FIXED
    assert(e.est[Q_PAGE_OFFSET].lo == po_true); /* pinned to cleanest/lowest */
    assert(e.est[Q_PAGE_OFFSET].hi == po_true);
#else
    assert(e.est[Q_PAGE_OFFSET].lo == po_true); /* proven window */
    assert(e.est[Q_PAGE_OFFSET].hi == po_alt);
#endif
  } else {
    /* spread exceeds the arch's align (or out of window): rule bails, untouched
     */
    assert(e.est[Q_PAGE_OFFSET].lo == top.lo);
    assert(e.est[Q_PAGE_OFFSET].hi == top.hi);
  }
}

/* MIPS64 XKPHYS decode (applied at the observation boundary on mips64): an
 * address with bits [63:62] == 0b10 is a direct physical mapping; bits [58:0]
 * are the physical address. A normal kernel VA (bits 11) must NOT match. */
static void test_xkphys_decode(void) {
#if __SIZEOF_LONG__ >= 8
  /* XKPHYS is a 64-bit address-space concept (mips64); `unsigned long` on a
   * 32-bit arch can't represent these literals (they'd truncate), and the
   * decode is mips64-gated in the product, so this only runs where long is
   * 64-bit. */
  /* XKPHYS, CCA=0: 0x9000... */
  assert(kasld_addr_is_xkphys(0x9000000012345678ul));
  assert(kasld_xkphys_to_phys(0x9000000012345678ul) == 0x12345678ul);
  /* XKPHYS, CCA=3 (cached): 0xb800... — CCA bits must be stripped too. */
  assert(kasld_addr_is_xkphys(0xb800000000abc000ul));
  assert(kasld_xkphys_to_phys(0xb800000000abc000ul) == 0xabc000ul);
  /* CKSEG/normal kernel VA (bits [63:62] == 0b11) is NOT XKPHYS. */
  assert(!kasld_addr_is_xkphys(0xffffffff80000000ul));
  /* User/low address (bits 00) is not XKPHYS. */
  assert(!kasld_addr_is_xkphys(0x0000000012345000ul));
#endif /* __SIZEOF_LONG__ >= 8 */
}

/* s390_paging_level: SF_VIRT_ADDR_BITS (from the mmap probe) -> text-base
 * ceiling at 1<<va_bits. On s390 a 3-level probe (va_bits=42) drops the ceiling
 * to 4 TiB; inert on other arches (the quantity stays at its honest top). */
int rule_s390_paging_level(const struct evidence_set *ev,
                           const struct estimate *est, struct constraint *out,
                           int out_max);

static void test_s390_paging_level(void) {
  struct engine e;
  engine_init(&e);
  struct observation v =
      mk_scalar(SF_VIRT_ADDR_BITS, 42ul, CONF_PARSED); /* 3-level */
  evidence_add(&e.ev, &v);
  const rule_fn rules[] = {rule_kaslr_align_arch_default,
                           rule_s390_paging_level};
  engine_run(&e, rules, 2);

  struct estimate top;
  quantities[Q_VIRT_TEXT_BASE].init_top(&top);
#if defined(__s390x__) || defined(__zarch__)
  unsigned long align = e.est[Q_KASLR_ALIGN].lo;
  if (align < (unsigned long)KASLR_VIRT_ALIGN)
    align = (unsigned long)KASLR_VIRT_ALIGN;
  unsigned long ceiling = (1ul << 42) & ~(align - 1);
  if (ceiling < top.hi)
    assert(e.est[Q_VIRT_TEXT_BASE].hi == ceiling); /* dropped to ~4 TiB */
#else
  assert(e.est[Q_VIRT_TEXT_BASE].hi == top.hi); /* inert off s390 */
#endif
}

/* ========================================================================
 * Arch-gated rules: dedicated coverage. On the host (wrong arch) each is inert
 * (estimate stays at its honest top); the active assertion executes when this
 * test is compiled for the rule's arch (see `make test-cross`). Completes the
 * per-rule matrix so every rule has a named test.
 * ======================================================================== */
int rule_arm64_memstart_align(const struct evidence_set *,
                              const struct estimate *, struct constraint *,
                              int);
int rule_min_offset_from_image_size(const struct evidence_set *,
                                    const struct estimate *,
                                    struct constraint *, int);
int rule_module_text_bound(const struct evidence_set *, const struct estimate *,
                           struct constraint *, int);
int rule_ppc32_phys_ceiling(const struct evidence_set *,
                            const struct estimate *, struct constraint *, int);
int rule_riscv64_fdt_kaslr_seed(const struct evidence_set *,
                                const struct estimate *, struct constraint *,
                                int);
int rule_riscv64_non_efi_phys_base(const struct evidence_set *,
                                   const struct estimate *, struct constraint *,
                                   int);

/* arm64: SF_PAGE_SIZE + a directmap leak -> Q_PAGE_OFFSET upper bound, snapped
 * down to the MEMSTART alignment (1 GiB for 4 KiB pages). */
static void test_arm64_memstart_align(void) {
  struct engine e;
  engine_init(&e);
  struct estimate top;
  quantities[Q_PAGE_OFFSET].init_top(&top);
  unsigned long v =
      top.lo + 0x40123000ul; /* a directmap addr above the floor */
  struct observation ps = mk_scalar(SF_PAGE_SIZE, 4096ul, CONF_PARSED);
  struct observation d = mk_obs(KASLD_TYPE_VIRT, REGION_DIRECTMAP, v,
                                LO_SET | SAMPLE_SET, POS_INTERIOR, CONF_PARSED);
  evidence_add(&e.ev, &ps);
  evidence_add(&e.ev, &d);
  const rule_fn rules[] = {rule_arm64_memstart_align};
  engine_run(&e, rules, 1);
#if defined(__aarch64__)
  unsigned long expect = v & ~((1024ul * 1024 * 1024) - 1);
  if (expect > top.lo && expect < top.hi)
    assert(e.est[Q_PAGE_OFFSET].hi == expect);
#else
  assert(e.est[Q_PAGE_OFFSET].hi == top.hi &&
         e.est[Q_PAGE_OFFSET].lo == top.lo);
#endif
}

/* mips/loongarch: VIRT text + data leaks -> Q_VIRT_TEXT_BASE lower bound at
 * KASLR_VIRT_TEXT_MIN + (max_data - min_text). */
static void test_min_offset_from_image_size(void) {
  struct engine e;
  engine_init(&e);
  struct estimate top;
  quantities[Q_VIRT_TEXT_BASE].init_top(&top);
  unsigned long gap = 0x100000ul;
  struct observation t = mk_obs(KASLD_TYPE_VIRT, REGION_KERNEL_TEXT, 0x100000ul,
                                LO_SET | SAMPLE_SET, POS_INTERIOR, CONF_PARSED);
  struct observation d =
      mk_obs(KASLD_TYPE_VIRT, REGION_KERNEL_DATA, 0x100000ul + gap,
             LO_SET | SAMPLE_SET, POS_INTERIOR, CONF_PARSED);
  evidence_add(&e.ev, &t);
  evidence_add(&e.ev, &d);
  const rule_fn rules[] = {rule_min_offset_from_image_size};
  engine_run(&e, rules, 1);
#if defined(__mips__) || defined(__loongarch__)
  unsigned long expect = (unsigned long)KASLR_VIRT_TEXT_MIN + gap;
  if (expect > top.lo && expect <= top.hi)
    assert(e.est[Q_VIRT_TEXT_BASE].lo == expect);
#else
  assert(e.est[Q_VIRT_TEXT_BASE].lo == top.lo &&
         e.est[Q_VIRT_TEXT_BASE].hi == top.hi);
#endif
}

/* MODULES_RELATIVE_TO_TEXT (riscv64/s390): a VIRT module leak bounds the text
 * base. The exact value is arch-specific (two cases); assert the monotone
 * invariant — the rule narrows within the window and never widens. */
static void test_module_text_bound(void) {
  struct engine e;
  engine_init(&e);
  struct estimate top;
  quantities[Q_VIRT_TEXT_BASE].init_top(&top);
  unsigned long vmod = top.lo + 0x100000ul;
  struct observation m = mk_obs(KASLD_TYPE_VIRT, REGION_MODULE, vmod,
                                LO_SET | SAMPLE_SET, POS_INTERIOR, CONF_PARSED);
  evidence_add(&e.ev, &m);
  const rule_fn rules[] = {rule_kaslr_align_arch_default,
                           rule_module_text_bound};
  engine_run(&e, rules, 2);
#if MODULES_RELATIVE_TO_TEXT
  assert(e.est[Q_VIRT_TEXT_BASE].lo >= top.lo &&
         e.est[Q_VIRT_TEXT_BASE].hi <=
             top.hi); /* narrowed-or-equal, never wider */
#else
  assert(e.est[Q_VIRT_TEXT_BASE].lo == top.lo &&
         e.est[Q_VIRT_TEXT_BASE].hi == top.hi); /* inert */
#endif
}

/* text_pin_from_observation: a POS_BASE VIRT/KERNEL_TEXT observation pins
 * Q_VIRT_TEXT_BASE; a POS_BASE PHYS/KERNEL_TEXT observation pins
 * Q_PHYS_TEXT_BASE. Arch-independent. */
int rule_text_pin_from_observation(const struct evidence_set *ev,
                                   const struct estimate *est,
                                   struct constraint *out, int out_max);

static void test_text_pin_from_observation_virt(void) {
  struct engine e;
  engine_init(&e);
  struct estimate top;
  quantities[Q_VIRT_TEXT_BASE].init_top(&top);
  unsigned long stext = top.lo + 0x2680000ul; /* inside the window */
  struct observation o = mk_obs(KASLD_TYPE_VIRT, REGION_KERNEL_TEXT, stext,
                                LO_SET, POS_BASE, CONF_PARSED);
  evidence_add(&e.ev, &o);
  const rule_fn rules[] = {rule_text_pin_from_observation};
  engine_run(&e, rules, 1);
  assert(e.est[Q_VIRT_TEXT_BASE].lo == stext);
  assert(e.est[Q_VIRT_TEXT_BASE].hi == stext);
}

static void test_text_pin_from_observation_phys(void) {
  struct engine e;
  engine_init(&e);
  struct estimate top;
  quantities[Q_PHYS_TEXT_BASE].init_top(&top);
  unsigned long ptext = top.lo + 0x2660000ul;
  struct observation o = mk_obs(KASLD_TYPE_PHYS, REGION_KERNEL_TEXT, ptext,
                                LO_SET, POS_BASE, CONF_PARSED);
  evidence_add(&e.ev, &o);
  const rule_fn rules[] = {rule_text_pin_from_observation};
  engine_run(&e, rules, 1);
  assert(e.est[Q_PHYS_TEXT_BASE].lo == ptext);
  assert(e.est[Q_PHYS_TEXT_BASE].hi == ptext);
}

static void test_text_pin_from_observation_kernel_image_region(void) {
  /* REGION_KERNEL_IMAGE qualifies just like REGION_KERNEL_TEXT. */
  struct engine e;
  engine_init(&e);
  struct estimate top;
  quantities[Q_VIRT_TEXT_BASE].init_top(&top);
  unsigned long stext = top.lo + 0x800000ul;
  struct observation o = mk_obs(KASLD_TYPE_VIRT, REGION_KERNEL_IMAGE, stext,
                                LO_SET, POS_BASE, CONF_PARSED);
  evidence_add(&e.ev, &o);
  const rule_fn rules[] = {rule_text_pin_from_observation};
  engine_run(&e, rules, 1);
  assert(e.est[Q_VIRT_TEXT_BASE].lo == stext);
  assert(e.est[Q_VIRT_TEXT_BASE].hi == stext);
}

static void test_text_pin_from_observation_pos_interior_inert(void) {
  /* POS_INTERIOR is not a base witness — rule must not pin. */
  struct engine e;
  engine_init(&e);
  struct estimate top;
  quantities[Q_VIRT_TEXT_BASE].init_top(&top);
  unsigned long sample = top.lo + 0x100000ul;
  struct observation o = mk_obs(KASLD_TYPE_VIRT, REGION_KERNEL_TEXT, sample,
                                LO_SET | SAMPLE_SET, POS_INTERIOR, CONF_PARSED);
  evidence_add(&e.ev, &o);
  const rule_fn rules[] = {rule_text_pin_from_observation};
  engine_run(&e, rules, 1);
  assert(e.est[Q_VIRT_TEXT_BASE].lo == top.lo); /* unchanged */
  assert(e.est[Q_VIRT_TEXT_BASE].hi == top.hi);
}

static void test_text_pin_from_observation_data_region_ignored(void) {
  /* REGION_KERNEL_DATA / KERNEL_BSS iomem entries are not text bases. */
  struct engine e;
  engine_init(&e);
  struct estimate top;
  quantities[Q_PHYS_TEXT_BASE].init_top(&top);
  unsigned long data_lo = top.lo + 0x3530000ul;
  struct observation o = mk_obs(KASLD_TYPE_PHYS, REGION_KERNEL_DATA, data_lo,
                                LO_SET, POS_BASE, CONF_PARSED);
  evidence_add(&e.ev, &o);
  const rule_fn rules[] = {rule_text_pin_from_observation};
  engine_run(&e, rules, 1);
  assert(e.est[Q_PHYS_TEXT_BASE].lo == top.lo); /* unchanged */
  assert(e.est[Q_PHYS_TEXT_BASE].hi == top.hi);
}

static void test_text_pin_from_observation_no_obs_inert(void) {
  struct engine e;
  engine_init(&e);
  struct estimate top;
  quantities[Q_VIRT_TEXT_BASE].init_top(&top);
  const rule_fn rules[] = {rule_text_pin_from_observation};
  engine_run(&e, rules, 1);
  assert(e.est[Q_VIRT_TEXT_BASE].lo == top.lo);
  assert(e.est[Q_VIRT_TEXT_BASE].hi == top.hi);
}

/* text_base_coupling_synth: on TEXT_TRACKS_DIRECTMAP arches with
 * Q_PAGE_OFFSET pinned, propagates each text-base side onto the other.
 * Inert on decoupled arches (asserts a no-op on the host build path). */
int rule_text_base_coupling_synth(const struct evidence_set *ev,
                                  const struct estimate *est,
                                  struct constraint *out, int out_max);
/* rule_page_offset_invariant_pin prototype already declared above. */

static void test_text_base_coupling_synth_virt_to_phys(void) {
  /* Pin Q_VIRT_TEXT_BASE via text_pin_from_observation, pin Q_PAGE_OFFSET
   * via page_offset_invariant_pin, and assert Q_PHYS_TEXT_BASE is now
   * narrowed by the coupling. */
  struct engine e;
  engine_init(&e);
  struct estimate vtop, ptop;
  quantities[Q_VIRT_TEXT_BASE].init_top(&vtop);
  quantities[Q_PHYS_TEXT_BASE].init_top(&ptop);
  /* Pick a vtext known to be inside the arch's KASLR window. */
  unsigned long vtext = vtop.lo + 0x2680000ul;
  struct observation v = mk_obs(KASLD_TYPE_VIRT, REGION_KERNEL_TEXT, vtext,
                                LO_SET, POS_BASE, CONF_PARSED);
  evidence_add(&e.ev, &v);
  const rule_fn rules[] = {rule_page_offset_invariant_pin,
                           rule_text_pin_from_observation,
                           rule_text_base_coupling_synth};
  engine_run(&e, rules, 3);
#if TEXT_TRACKS_DIRECTMAP && PAGE_OFFSET_INVARIANT
  /* Coupling fires. The phys estimate must have narrowed from its top. */
  assert(e.est[Q_PHYS_TEXT_BASE].lo > ptop.lo ||
         e.est[Q_PHYS_TEXT_BASE].hi < ptop.hi);
#else
  /* Inert on decoupled or non-invariant-PAGE_OFFSET arches. The host
   * build is x86_64 (decoupled), so this is the actively-tested branch. */
  assert(e.est[Q_PHYS_TEXT_BASE].lo == ptop.lo);
  assert(e.est[Q_PHYS_TEXT_BASE].hi == ptop.hi);
#endif
}

static void test_text_base_coupling_synth_phys_to_virt(void) {
  struct engine e;
  engine_init(&e);
  struct estimate vtop, ptop;
  quantities[Q_VIRT_TEXT_BASE].init_top(&vtop);
  quantities[Q_PHYS_TEXT_BASE].init_top(&ptop);
  unsigned long ptext = ptop.lo + 0x2660000ul;
  struct observation p = mk_obs(KASLD_TYPE_PHYS, REGION_KERNEL_TEXT, ptext,
                                LO_SET, POS_BASE, CONF_PARSED);
  evidence_add(&e.ev, &p);
  const rule_fn rules[] = {rule_page_offset_invariant_pin,
                           rule_text_pin_from_observation,
                           rule_text_base_coupling_synth};
  engine_run(&e, rules, 3);
#if TEXT_TRACKS_DIRECTMAP && PAGE_OFFSET_INVARIANT
  assert(e.est[Q_VIRT_TEXT_BASE].lo > vtop.lo ||
         e.est[Q_VIRT_TEXT_BASE].hi < vtop.hi);
#else
  assert(e.est[Q_VIRT_TEXT_BASE].lo == vtop.lo);
  assert(e.est[Q_VIRT_TEXT_BASE].hi == vtop.hi);
#endif
}

static void test_text_base_coupling_synth_no_page_offset_pin_inert(void) {
  /* Without a pinned Q_PAGE_OFFSET the rule cannot project anything,
   * even when virt text is pinned. */
  struct engine e;
  engine_init(&e);
  struct estimate ptop;
  quantities[Q_PHYS_TEXT_BASE].init_top(&ptop);
  unsigned long vtext = (unsigned long)KASLR_VIRT_TEXT_MIN + 0x800000ul;
  struct observation v = mk_obs(KASLD_TYPE_VIRT, REGION_KERNEL_TEXT, vtext,
                                LO_SET, POS_BASE, CONF_PARSED);
  evidence_add(&e.ev, &v);
  /* Note: NOT including page_offset_invariant_pin. */
  const rule_fn rules[] = {rule_text_pin_from_observation,
                           rule_text_base_coupling_synth};
  engine_run(&e, rules, 2);
  assert(e.est[Q_PHYS_TEXT_BASE].lo == ptop.lo);
  assert(e.est[Q_PHYS_TEXT_BASE].hi == ptop.hi);
}

static void test_text_base_coupling_synth_no_obs_soundness(void) {
  /* With no text observations the rule may still project the architectural
   * honest tops across the coupling (sound — the arch's KASLR window IS a
   * constraint), but it must never resolve a quantity to bottom. */
  struct engine e;
  engine_init(&e);
  struct estimate vtop, ptop;
  quantities[Q_VIRT_TEXT_BASE].init_top(&vtop);
  quantities[Q_PHYS_TEXT_BASE].init_top(&ptop);
  const rule_fn rules[] = {rule_page_offset_invariant_pin,
                           rule_text_base_coupling_synth};
  engine_run(&e, rules, 2);
  /* Either side is allowed to narrow (when coupled), but neither may go
   * bottom and the resulting range must remain valid (lo <= hi). */
  assert(e.est[Q_VIRT_TEXT_BASE].lo <= e.est[Q_VIRT_TEXT_BASE].hi);
  assert(e.est[Q_PHYS_TEXT_BASE].lo <= e.est[Q_PHYS_TEXT_BASE].hi);
#if !(TEXT_TRACKS_DIRECTMAP && PAGE_OFFSET_INVARIANT)
  /* On decoupled or non-invariant-PAGE_OFFSET host build, no projection
   * occurs; estimates stay at their honest tops. */
  assert(e.est[Q_VIRT_TEXT_BASE].lo == vtop.lo);
  assert(e.est[Q_VIRT_TEXT_BASE].hi == vtop.hi);
  assert(e.est[Q_PHYS_TEXT_BASE].lo == ptop.lo);
  assert(e.est[Q_PHYS_TEXT_BASE].hi == ptop.hi);
#endif
}

/* ppc32 (BookE model): SF_PHYS_MEMTOTAL above the KASLR-enable threshold caps
 * the text ceiling. Assert it narrowed (exact ceiling is arch-macro-derived).
 */
static void test_ppc32_phys_ceiling(void) {
  struct engine e;
  engine_init(&e);
  struct estimate top;
  quantities[Q_VIRT_TEXT_BASE].init_top(&top);
  struct observation m =
      mk_scalar(SF_PHYS_MEMTOTAL, 0x40000000ul, CONF_PARSED); /* 1 GiB */
  evidence_add(&e.ev, &m);
  const rule_fn rules[] = {rule_ppc32_phys_ceiling};
  engine_run(&e, rules, 1);
#if defined(__powerpc__) && !defined(__powerpc64__)
  assert(e.est[Q_VIRT_TEXT_BASE].lo >= top.lo &&
         e.est[Q_VIRT_TEXT_BASE].hi <= top.hi); /* narrowed-or-equal */
#else
  assert(e.est[Q_VIRT_TEXT_BASE].lo == top.lo &&
         e.est[Q_VIRT_TEXT_BASE].hi == top.hi); /* inert */
#endif
}

/* riscv64 non-EFI: FDT kaslr-seed + image size pins the text base (Path 1).
 * Assert it pins within [KERNEL_LINK_ADDR, +1 GiB). */
static void test_riscv64_fdt_kaslr_seed(void) {
  struct engine e;
  engine_init(&e);
  struct estimate top;
  quantities[Q_VIRT_TEXT_BASE].init_top(&top);
  /* Any nonzero seed pins the base (the test asserts lo==hi, not a value); use
   * a 32-bit-safe constant so it does not truncate on 32-bit builds. */
  struct observation seed =
      mk_scalar(SF_FDT_KASLR_SEED, 0x12345678ul, CONF_PARSED);
  struct observation efi = mk_scalar(SF_EFI_PRESENT, 0ul, CONF_PARSED);
  struct observation isz =
      mk_scalar(SF_IMAGE_SIZE, 0x1800000ul, CONF_PARSED); /* 24 MiB */
  evidence_add(&e.ev, &seed);
  evidence_add(&e.ev, &efi);
  evidence_add(&e.ev, &isz);
  const rule_fn rules[] = {rule_riscv64_fdt_kaslr_seed};
  engine_run(&e, rules, 1);
#if (defined(__riscv) || defined(__riscv__)) && __riscv_xlen == 64
  assert(e.est[Q_VIRT_TEXT_BASE].lo == e.est[Q_VIRT_TEXT_BASE].hi); /* pinned */
#else
  assert(e.est[Q_VIRT_TEXT_BASE].lo == top.lo &&
         e.est[Q_VIRT_TEXT_BASE].hi == top.hi); /* inert */
#endif
}

/* riscv64 non-EFI: a PHYS DRAM floor + EFI-absent pins the physical text
 * base to pdram_lo + TEXT_OFFSET + RISCV64_HEAD_TEXT_OFFSET — the
 * +RISCV64_HEAD_TEXT_OFFSET term is what makes the pin land at `_stext`
 * (per the kasld convention that Q_PHYS_TEXT_BASE names `_stext`-phys)
 * rather than `_start` / image base. Omitting it lands the pin 0x2000
 * below the iomem "Kernel code" entry and the resolved window excludes
 * the actual phys text base. */
static void test_riscv64_non_efi_phys_base(void) {
  struct engine e;
  engine_init(&e);
#if defined(KASLR_PHYS_MIN)
  struct estimate top;
  quantities[Q_PHYS_TEXT_BASE].init_top(&top);
  unsigned long pdram = (unsigned long)KASLR_PHYS_MIN;
  struct observation efi = mk_scalar(SF_EFI_PRESENT, 0ul, CONF_PARSED);
  struct observation ram =
      mk_obs(KASLD_TYPE_PHYS, REGION_RAM, pdram, LO_SET, POS_BASE, CONF_PARSED);
  evidence_add(&e.ev, &efi);
  evidence_add(&e.ev, &ram);
  const rule_fn rules[] = {rule_riscv64_non_efi_phys_base};
  engine_run(&e, rules, 1);
#if (defined(__riscv) || defined(__riscv__)) && __riscv_xlen == 64
  unsigned long expect = pdram + (unsigned long)TEXT_OFFSET +
                         (unsigned long)RISCV64_HEAD_TEXT_OFFSET;
  if (expect >= (unsigned long)KASLR_PHYS_MIN && expect >= top.lo &&
      expect <= top.hi) {
    assert(e.est[Q_PHYS_TEXT_BASE].lo == expect);
    assert(e.est[Q_PHYS_TEXT_BASE].hi == expect);
  }
#else
  assert(e.est[Q_PHYS_TEXT_BASE].lo == top.lo &&
         e.est[Q_PHYS_TEXT_BASE].hi == top.hi); /* inert */
#endif
#else
  (void)e; /* arch has no physical KASLR quantity */
#endif
}

int main(void) {
  TEST_SUITE("test_engine");

  BEGIN_CATEGORY("Engine core (pilot, convergence, saturation)");
  RUN(test_engine_interior_ceiling);
#if __SIZEOF_LONG__ >= 8
  RUN(test_engine_cross_quantity_fixpoint); /* 64-bit-only (see definition) */
#endif
  RUN(test_engine_converges_and_is_stable);
  RUN(test_engine_saturation_clean);
  RUN(test_engine_saturation_constraints_full);
  RUN(test_engine_saturation_rule_emit_overflow);
  RUN(test_engine_saturation_vrule_emit_overflow);
  RUN(test_engine_saturation_estimate_work_full);
  RUN(test_engine_saturation_conflicts_full);

  BEGIN_CATEGORY("Address helpers (XKPHYS / s390 paging)");
  RUN(test_xkphys_decode);
  RUN(test_s390_paging_level);

  BEGIN_CATEGORY("Image-size ceilings");
  RUN(test_ceiling_from_image_size);
  RUN(test_ceiling_prefers_exact_init_size);
  RUN(test_ceiling_no_evidence);
  RUN(test_ceiling_oversized_image);
  RUN(test_phys_ceiling_from_memtotal);
  RUN(test_phys_ceiling_prefers_dram_top_over_memtotal);
  RUN(test_phys_ceiling_no_dram_floor);
  RUN(test_virt_ceiling_from_memtotal);
  RUN(test_phys_bits_ceiling);
  RUN(test_phys_bits_absent);
  RUN(test_image_size_text_data_gap);
  RUN(test_min_offset_from_image_size);

  BEGIN_CATEGORY("DRAM bounds");
  RUN(test_dram_floor_bound);
  RUN(test_dram_floor_ignores_non_ram_dram_regions);
  RUN(test_dram_floor_no_dram);
  RUN(test_dram_ceiling);
  RUN(test_mmio_floor_phys_ceiling);
  RUN(test_phys_hole_filter);
  RUN(test_kernel_image_phys_bound);
  RUN(test_kernel_image_phys_bound_lower_from_high_witness);
  RUN(test_highmem_32bit_bound);
  RUN(test_firmware_memmap_holes);

  BEGIN_CATEGORY("virt_page_offset rules");
  RUN(test_page_offset_pin);
  RUN(test_page_offset_conflict);
  RUN(test_page_offset_none);
  RUN(test_page_offset_invariant_pin);
  RUN(test_page_offset_from_config);
#if __SIZEOF_LONG__ >= 8
  RUN(test_directmap_page_offset_bounds);
  RUN(test_directmap_page_offset_lower_bound_from_max_pfn);
  RUN(test_directmap_page_offset_bounds_pud_aligned);
  RUN(test_randomize_memory_page_offset);
  RUN(test_randomize_memory_page_offset_path2);
#endif

  BEGIN_CATEGORY("Coupling / cluster verdicts");
  RUN(test_coupling_validate);
  RUN(test_text_cluster_filter);
  /* The remaining coupling tests are defined inside the file-level
   * `#if __SIZEOF_LONG__ >= 8` block (line ~1412) — their bodies model
   * 64-bit-only kernel layouts (arm64 / loongarch / riscv64 VA, x86_64 KASLR
   * gaps). The function definitions vanish on 32-bit targets, so the RUN
   * sites need the matching gate to keep the build clean across i686 /
   * armv7 / mips / mips64 / powerpc-linux-musl. */
#if __SIZEOF_LONG__ >= 8
  RUN(test_coupling_validate_text_in_validation_outside_kaslr);
  RUN(test_arm64_coupling_validate_module_outside_band);
  RUN(test_arm64_coupling_validate_module_inside_band);
  RUN(test_arm64_coupling_validate_text_in_validation_outside_kaslr);
  RUN(test_arm64_coupling_validate_text_outside_validation);
  RUN(test_riscv64_coupling_validate_module_outside_band);
  RUN(test_riscv64_coupling_validate_text_inside_validation);
  RUN(test_loongarch64_coupling_validate_directmap_in_xkprange);
  RUN(test_loongarch64_coupling_validate_directmap_in_xkvrange);
#endif

  BEGIN_CATEGORY("Cmdline rules (mem= / memmap= / initrd / nokaslr)");
  RUN(test_initrd_phys_exclude);
  RUN(test_phys_reservation_exclude);
  RUN(test_ram_map_phys_exclude);
  RUN(test_cmdline_phys_exclude);
  RUN(test_cmdline_mem_phys_ceiling);
  RUN(test_cmdline_mem_phys_ceiling_no_signal);
  RUN(test_cmdline_memmap_phys_exclude);
  RUN(test_cmdline_memmap_no_image_size);
#if defined(__x86_64__)
  RUN(test_cmdline_memmap_too_large_phys_pin);
  RUN(test_cmdline_memmap_too_large_phys_pin_under_threshold);
#endif

  BEGIN_CATEGORY("KASLR alignment");
  RUN(test_kaslr_align_arch_default);
  RUN(test_boot_params_kaslr_align);
  RUN(test_boot_params_kaslr_align_subdefault);
  RUN(test_arm64_efi_kimg_align);
  RUN(test_ceiling_uses_resolved_align);
  RUN(test_config_max_offset_ceiling);
  RUN(test_config_max_offset_absent);
  RUN(test_base_align_cross_validate);

  BEGIN_CATEGORY("KASLR-off pin");
  RUN(test_virt_kaslr_disabled_pin);
  RUN(test_virt_kaslr_disabled_pin_no_signal_no_pin);
  RUN(test_directmap_kaslr_disabled_pin);
  RUN(test_phys_kaslr_disabled_pin);
  RUN(test_phys_kaslr_disabled_pin_defers_to_real_leak);
  RUN(test_phys_kaslr_disabled_pin_inert_on_decoupled);
#if defined(__x86_64__)
  RUN(test_physical_start_lower_bound_learned);
  RUN(test_physical_start_lower_bound_heuristic);
  RUN(test_physical_start_lower_bound_leak_below_heuristic);
#endif

  BEGIN_CATEGORY("Module-relative text bounds");
  RUN(test_module_text_bound);

  BEGIN_CATEGORY("EFI Loader Code disambiguation");
  RUN(test_efi_loader_kernel_pick_single_aligned);
  RUN(test_efi_loader_kernel_pick_multi_one_survives);
  RUN(test_efi_loader_kernel_pick_multi_ambiguous_inert);
  RUN(test_efi_loader_kernel_pick_multi_rand_failed_picks_lowest);
  RUN(test_efi_loader_kernel_pick_multi_without_signal_still_inert);
  RUN(test_efi_loader_kernel_pick_no_image_size_inert);
  RUN(test_efi_loader_kernel_pick_size_above_tolerance_inert);

  BEGIN_CATEGORY("Text-base pin from observation");
  RUN(test_text_pin_from_observation_virt);
  RUN(test_text_pin_from_observation_phys);
  RUN(test_text_pin_from_observation_kernel_image_region);
  RUN(test_text_pin_from_observation_pos_interior_inert);
  RUN(test_text_pin_from_observation_data_region_ignored);
  RUN(test_text_pin_from_observation_no_obs_inert);

  BEGIN_CATEGORY("Text-base coupling synth (phys↔virt)");
  RUN(test_text_base_coupling_synth_virt_to_phys);
  RUN(test_text_base_coupling_synth_phys_to_virt);
  RUN(test_text_base_coupling_synth_no_page_offset_pin_inert);
  RUN(test_text_base_coupling_synth_no_obs_soundness);

  BEGIN_CATEGORY("phys_virt_synth");
  RUN(test_phys_virt_synth);
  RUN(test_phys_virt_synth_rejects_misaligned_pair);
  RUN(test_phys_virt_synth_spread_within_align);

  BEGIN_CATEGORY("x86_64-specific rules");
  RUN(test_x86_32_vmsplit_ceiling);
#if defined(__x86_64__)
  RUN(test_x86_64_efi_phys_seed_zero_mem);
  RUN(test_x86_64_efi_phys_seed_zero_memmap);
  RUN(test_x86_64_efi_phys_seed_zero_hugepages);
  RUN(test_x86_64_efi_phys_seed_zero_no_trigger);
  RUN(test_x86_64_efi_phys_seed_zero_no_efi);
  RUN(test_x86_64_efi_phys_seed_zero_no_kernel_image);
#endif
#if __SIZEOF_LONG__ >= 8 /* 64-bit-only block (vmalloc/vmemmap + va_bits) */
  RUN(test_x86_64_vmalloc_vmemmap_chain);
  RUN(test_x86_64_vmalloc_no_max_pfn);
#if defined(__x86_64__)
  RUN(test_x86_64_po_from_vmalloc);
  RUN(test_x86_64_po_from_vmemmap);
  RUN(test_x86_64_po_from_vmalloc_no_max_pfn);
  RUN(test_x86_64_po_from_vmemmap_pinned_l5);
  RUN(test_x86_64_po_from_vmemmap_pinned_l4_keeps_l4);
  RUN(test_x86_64_vmalloc_vmemmap_invariant_violation);
  RUN(test_x86_64_vmalloc_vmemmap_invariant_ok);
#endif

  BEGIN_CATEGORY("arm64-specific rules");
  RUN(test_arm64_memstart_align);
  RUN(test_arm64_va_bits_from_vmemmap_pins_52);
  RUN(test_arm64_va_bits_from_vmemmap_above_floor_inert);
  RUN(test_va_bits_la57_l5);
  RUN(test_va_bits_la57_l4);
  RUN(test_va_bits_la57_contradictory);
  RUN(test_va_bits_arm64);

  BEGIN_CATEGORY("riscv64-specific rules");
  RUN(test_riscv64_fdt_kaslr_seed);
  RUN(test_riscv64_non_efi_phys_base);
  RUN(test_riscv64_po_from_vmalloc);
  RUN(test_riscv64_po_from_vmemmap_default_window_uses_sv39);
  RUN(test_riscv64_po_from_vmemmap_pinned_sv48);
  RUN(test_riscv64_po_from_vmalloc_vmemmap_no_obs);

  BEGIN_CATEGORY("s390-specific rules");
  RUN(test_s390_text_from_vmalloc_lo_bound);
  RUN(test_s390_text_from_vmalloc_no_obs);
  RUN(test_s390_text_from_vmemmap_with_max_pfn);
  RUN(test_s390_text_from_vmemmap_no_max_pfn);
  RUN(test_s390_text_from_vmemmap_no_obs);
  RUN(test_s390_text_segment_mod_fires);
  RUN(test_s390_text_segment_mod_no_anchor);
  RUN(test_s390_text_no_random_fires_with_signal);
  RUN(test_s390_text_no_random_inert_without_signal);
  RUN(test_s390_text_no_random_admits_empirical_phys);
#endif

  BEGIN_CATEGORY("ppc-specific rules");
  RUN(test_ppc32_phys_ceiling);
  RUN(test_ppc64_firmware_ceiling);

  return TEST_DONE();
}
