// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Full-engine integration test: feed a realistic, mutually-consistent set of
// leaked observations + scalar facts through the ENTIRE production rule
// registry (engine_rules / engine_verdict_rules — the same lists the
// orchestrator runs) and assert the resolved estimates are SOUND:
//   - non-bottom (lo <= hi) for every interval quantity;
//   - the planted ground-truth value stays inside each resolved range
//     (the critical invariant — no rule may over-tighten past the truth);
//   - the engine actually narrowed from the honest top (the rules fired and
//     interacted through the fixpoint, not just sat inert).
//
// The per-rule unit tests exercise rules in isolation; this exercises their
// interaction + cross-quantity dependencies on leak-bearing input the offline
// replay corpus cannot provide. x86_64 host only (the registry is compiled for
// the build arch); the planted scenario is an x86_64 layout.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine.h"
#include "include/kasld/engine_rules.h"
#include "include/kasld/regions.h"
#include "test_harness.h"
#include "test_po_access.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static uint32_t add_addr(struct engine *e, enum kasld_addr_type type,
                         enum kasld_region region, unsigned long lo,
                         unsigned long hi, const char *name) {
  struct observation o;
  memset(&o, 0, sizeof(o));
  o.value_kind = OBS_ADDRESS;
  o.type = type;
  o.region = region;
  o.lo = lo;
  o.sample = lo;
  o.set_mask = LO_SET | SAMPLE_SET;
  if (hi) {
    o.hi = hi;
    o.set_mask |= HI_SET;
  }
  o.pos = POS_BASE;
  o.conf = CONF_PARSED;
  if (name)
    snprintf(o.name, NAME_LEN, "%s", name);
  return evidence_add(&e->ev, &o);
}

/* add_addr with an explicit confidence — for exercising confidence-ordered
 * conflict resolution (a parsed source must beat an inferred one regardless of
 * which is captured first). Used only by arch-gated tests, so unused on hosts
 * whose arch compiles none of them out. */
__attribute__((unused)) static void
add_addr_conf(struct engine *e, enum kasld_addr_type type,
              enum kasld_region region, unsigned long lo, unsigned long hi,
              enum kasld_confidence conf, const char *name) {
  struct observation o;
  memset(&o, 0, sizeof(o));
  o.value_kind = OBS_ADDRESS;
  o.type = type;
  o.region = region;
  o.lo = lo;
  o.sample = lo;
  o.set_mask = LO_SET | SAMPLE_SET;
  if (hi) {
    o.hi = hi;
    o.set_mask |= HI_SET;
  }
  o.pos = POS_BASE;
  o.conf = conf;
  if (name)
    snprintf(o.name, NAME_LEN, "%s", name);
  evidence_add(&e->ev, &o);
}

/* Top-edge twin of add_addr: emits an observation with pos=top and only the
 * upper extent set (HI_SET, no LO/SAMPLE). Used to model firmware-style
 * ceiling signals — linux,kernel-end and linux,memory-limit. Used only by
 * arch-gated tests (ppc64/riscv64), so unused on other hosts. */
__attribute__((unused)) static void add_addr_top(struct engine *e,
                                                 enum kasld_addr_type type,
                                                 enum kasld_region region,
                                                 unsigned long hi) {
  struct observation o;
  memset(&o, 0, sizeof(o));
  o.value_kind = OBS_ADDRESS;
  o.type = type;
  o.region = region;
  o.hi = hi;
  o.set_mask = HI_SET;
  o.pos = POS_TOP;
  o.conf = CONF_PARSED;
  evidence_add(&e->ev, &o);
}

/* An interior-position sample: a leaked pointer inside a region, not its base.
 * Models the several kernel-text function-pointer leaks a real run gathers
 * alongside the _stext base. Used only by the x86_64 curation test. */
__attribute__((unused)) static void add_interior(struct engine *e,
                                                 enum kasld_addr_type type,
                                                 enum kasld_region region,
                                                 unsigned long addr) {
  struct observation o;
  memset(&o, 0, sizeof(o));
  o.value_kind = OBS_ADDRESS;
  o.type = type;
  o.region = region;
  o.sample = addr;
  o.set_mask = SAMPLE_SET;
  o.pos = POS_INTERIOR;
  o.conf = CONF_PARSED;
  evidence_add(&e->ev, &o);
}

static void add_scalar(struct engine *e, enum kasld_scalar_fact f,
                       unsigned long v) {
  struct observation o;
  memset(&o, 0, sizeof(o));
  o.value_kind = OBS_SCALAR;
  o.scalar_fact = f;
  o.scalar_value = v;
  o.conf = CONF_PARSED;
  evidence_add(&e->ev, &o);
}

/* A direct bound on a quantity (the constraint input channel). Used only by the
 * x86_64-gated perf-bracket test. */
__attribute__((unused)) static void
add_constraint(struct engine *e, enum kasld_quantity q, enum constraint_op op,
               unsigned long value, enum kasld_confidence conf) {
  struct observation o;
  memset(&o, 0, sizeof(o));
  o.value_kind = OBS_CONSTRAINT;
  o.c_quantity = q;
  o.c_op = op;
  o.scalar_value = value;
  o.conf = conf;
  evidence_add(&e->ev, &o);
}

/* Used only by the x86_64-gated tests, so unused on hosts that compile none of
 * them (same reason as add_addr_conf / add_addr_top above). */
__attribute__((unused)) static int contains(const struct estimate *e,
                                            unsigned long v) {
  return e->lo <= v && v <= e->hi;
}

/* Arches with a whole-engine containment property test below. Decoupled arches
 * (x86_64/arm64/riscv64/s390) draw virt and phys text bases independently;
 * coupled arches (x86_32) draw one and derive the other via the linear map. The
 * shared containment core applies to both. */
#if defined(__x86_64__) || defined(__aarch64__) ||                             \
    ((defined(__riscv) || defined(__riscv__)) && __riscv_xlen == 64) ||        \
    defined(__s390x__) || defined(__i386__) || defined(__mips64) ||            \
    defined(__mips64__) || defined(__loongarch64) ||                           \
    (defined(__loongarch__) && __loongarch_grlen == 64) ||                     \
    (defined(__mips__) && !defined(__mips64) && !defined(__mips64__)) ||       \
    (defined(__arm__) && !defined(__aarch64__)) ||                             \
    ((defined(__powerpc__) || defined(__PPC__)) && !defined(__powerpc64__) &&  \
     !defined(__ppc64__)) ||                                                   \
    ((defined(__riscv) || defined(__riscv__)) && __riscv_xlen == 32) ||        \
    defined(__powerpc64__) || defined(__ppc64__)
#define KASLD_PROP_ARCH 1
#endif

#ifdef KASLD_PROP_ARCH
/* ---- Soundness property test support ----------------------------------------
 * Deterministic SplitMix64 PRNG + generators, used by the per-arch property
 * tests below. Determinism is mandatory (the suite bans wall-clock / rand()): a
 * seed reproduces the exact case, so any failure this finds is promoted
 * verbatim into a fixed unit test. */
struct prop_rng {
  unsigned long long s;
};
static unsigned long long prop_rand(struct prop_rng *r) {
  r->s += 0x9E3779B97F4A7C15ull;
  unsigned long long z = r->s;
  z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
  z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
  return z ^ (z >> 31);
}
/* An `align`-multiple in [lo, hi) (lo assumed already align-aligned). */
static unsigned long prop_aligned(struct prop_rng *r, unsigned long lo,
                                  unsigned long hi, unsigned long align) {
  unsigned long slots = (hi - lo) / align;
  if (slots == 0)
    return lo;
  return lo + (unsigned long)(prop_rand(r) % slots) * align;
}
static int prop_coin(struct prop_rng *r) { return (int)(prop_rand(r) & 1u); }

/* Draw a module-region base in [lo, hi] and offer the engine the two witnesses
 * a real kernel gives for it. The window is the caller's to compute, because
 * how the allocator is confined is the arch's own fact — a bounding box around
 * the image on arm64, a fixed span below it on the text-anchored arches.
 *
 * The region base is a SECOND truth, drawn rather than derived: on every one of
 * these arches the allocator makes its own choice at boot, so a generator that
 * computed the base from the text slide would be asserting a formula the kernel
 * does not follow. Returns the drawn base for the containment check.
 *
 * Both witnesses are emitted under their own coin, so the property also covers
 * the runs where one or neither is present. The tags are not interchangeable:
 * the interior address is REGION_MODULE, which claims the address really
 * belongs to a module, while the region start is REGION_MODULE_BAND paired with
 * POS_BASE, which is the layout-block landmark's pair and the only form the pin
 * reads. Emitting the start as REGION_MODULE leaves the estimate spanning the
 * declared band — wide enough that containment holds far from the truth, which
 * is a check that cannot fail. */
__attribute__((unused)) static unsigned long
prop_module_region(struct prop_rng *r, struct engine *e, unsigned long lo,
                   unsigned long hi, unsigned long top) {
  unsigned long mbase = prop_aligned(r, lo, hi, 0x10000ul);
  /* `top` is the highest address the region can hand out, which is not the
   * same question as where its base may fall: the text-anchored arches end
   * their region AT the image base, so a module address above _text is one
   * their allocator could never return. Emitting one anyway does not merely
   * weaken the test — module_text_bound reads the lowest module address as a
   * bound on the text base, so an impossible module address teaches the engine
   * a false thing about text and the failure surfaces on a different quantity
   * than the one being added. */
  if (prop_coin(r) && top > mbase)
    add_interior(e, KASLD_TYPE_VIRT, REGION_MODULE,
                 mbase + (unsigned long)(prop_rand(r) % (top - mbase)));
  if (prop_coin(r))
    add_addr(e, KASLD_TYPE_VIRT, REGION_MODULE_BAND, mbase, 0, "module_base");
  return mbase;
}

/* Containment via the value-access seam: truth must lie in one of q's resolved
 * ranges (interval minus any C_EXCLUDE holes carved at `floor`). Returns 1 for
 * a non-interval quantity (its containment is the [lo,hi] / finset check). */
static int truth_in_ranges(enum kasld_quantity q, const struct estimate *est,
                           const struct engine *e, enum kasld_confidence floor,
                           unsigned long truth) {
  struct range rs[ESTIMATE_MAX_WORK];
  int n = quantity_ranges(q, est, floor, e->constraints, e->n_constraints, rs,
                          ESTIMATE_MAX_WORK);
  if (n == 0)
    return 1;
  for (int i = 0; i < n; i++)
    if (rs[i].lo <= truth && truth <= rs[i].hi)
      return 1;
  return 0;
}

struct prop_check {
  enum kasld_quantity q;
  unsigned long truth;
};

/* Shared containment core for the per-arch whole-engine property tests. `e`
 * holds the faithful evidence for one generated truth (unchanged across the two
 * resolves). Asserts, in BOTH the likely (all-signals) and guaranteed
 * (sound-floor) windows, that every checked quantity is non-bottom and still
 * contains its truth (interval + C_EXCLUDE holes via truth_in_ranges). Aborts
 * with the reproducing seed on the first violation. */
/* Distinct rule origins the property suite has exercised (any constraint it
 * emitted, at any confidence). A coverage guard asserts this stays healthy, so
 * the generators can't silently stop triggering rules and leave the suite
 * validating nothing. */
static char prop_seen[128][ORIGIN_LEN];
static int prop_seen_n;
static void prop_note_origin(const char *o) {
  if (o[0] == '\0')
    return;
  for (int i = 0; i < prop_seen_n; i++)
    if (strcmp(prop_seen[i], o) == 0)
      return;
  if (prop_seen_n < 128)
    snprintf(prop_seen[prop_seen_n++], ORIGIN_LEN, "%s", o);
}

/* Does the truth satisfy this constraint? A constraint is a claim about its
 * quantity; on faithful evidence a sound rule only emits claims the truth
 * meets. An at-floor constraint the truth violates is a rule over-narrowing
 * (Phase 3 per-constraint soundness). */
static int prop_constraint_holds(const struct constraint *c,
                                 unsigned long truth) {
  switch (c->op) {
  case C_LOWER_BOUND:
    return c->value <= truth;
  case C_UPPER_BOUND:
    return c->value >= truth;
  case C_EQUALS:
    return c->value == truth;
  case C_AT_LEAST_ALIGN:
    return c->value == 0 || (truth % c->value) == 0;
  case C_EXCLUDE:
    return truth < c->value || truth > c->value2;
  case C_STRIDE:
    return c->value2 == 0 || (truth % c->value2) == (c->value % c->value2);
  }
  return 1;
}

/* Curation invariant: every observation a run invalidated must be one the
 * fixture deliberately made faulty. Curation removing anything else is a
 * curator over-reaching — a region-blind outlier filter rejecting a sound
 * non-text leak (the text_cluster_filter / directmap bug) — which silently
 * drops evidence and collapses a quantity. That is a COMPLETENESS failure:
 * sound but less resolved, and invisible to the containment check, which an
 * absent or widened window still trivially "contains" the truth for.
 *
 * Stated over faulty sets rather than only faithful ones because collateral is
 * the realistic shape. A faithful set has nothing to curate, so a curator that
 * fires at all is already wrong and any assertion catches it; the harder case
 * is a set where curation SHOULD fire, and takes a sound observation with it.
 * The directmap bug needed exactly that mixture — a text cluster and a sound
 * directmap leak — to trigger.
 *
 * Subset, not equality: a curator that fails to detect an injected fault has
 * lost precision, not soundness, and some decline by design (below CLUSTER_MIN
 * the outlier filter does not fire at all). Demanding equality would oblige
 * every curator to catch every fault. A fixture wanting to assert detection
 * says so itself. */
static void assert_curation_subset(struct engine *e, const uint32_t *faulty,
                                   int n_faulty, const char *arch,
                                   const char *ctx, unsigned long seed) {
  for (int i = 0; i < e->ev.n_obs; i++) {
    if (e->ev.obs[i].valid)
      continue;
    int deliberate = 0;
    for (int j = 0; j < n_faulty; j++)
      if (e->ev.obs[i].id == faulty[j]) {
        deliberate = 1;
        break;
      }
    if (deliberate)
      continue;
    /* Name the curator. The verdict that targeted this observation carries the
     * emitting rule in `origin`, so the failure localizes itself instead of
     * leaving the reader to work out which of the seven rules fired. */
    const char *by = "(no verdict found)";
    for (int v = 0; v < e->ev.n_verdicts; v++)
      if (e->ev.verdicts[v].observation_id == e->ev.obs[i].id) {
        by = e->ev.verdicts[v].origin;
        break;
      }
    fprintf(stderr,
            "\nCURATION FAIL %s (%s) seed=%lu: %s invalidated a "
            "truth-consistent obs id=%u type=%d region=%d\n",
            arch, ctx, seed, by, e->ev.obs[i].id, (int)e->ev.obs[i].type,
            (int)e->ev.obs[i].region);
    assert(0 && "curation: a verdict invalidated a truth-consistent obs");
  }
}

/* The faithful case: nothing is faulty, so nothing may be curated. */
static void assert_no_curation(struct engine *e, const char *arch,
                               const char *ctx, unsigned long seed) {
  assert_curation_subset(e, NULL, 0, arch, ctx, seed);
}

static void prop_check_containment(struct engine *e, const rule_fn *rules,
                                   int nr, const verdict_fn *vrules, int nv,
                                   const struct prop_check *chk, int nchk,
                                   const char *arch, unsigned long seed) {
  const struct quantity_def *qd = quantities;
  for (int pass = 0; pass < 2; pass++) {
    enum kasld_confidence floor;
    const char *wname;
    if (pass == 0) {
      engine_run_full(e, rules, nr, vrules, nv);
      floor = CONF_BRUTE;
      wname = "likely";
    } else {
      engine_run_full_floored(e, CONF_INFERRED, rules, nr, vrules, nv);
      floor = CONF_INFERRED;
      wname = "guaranteed";
    }
    /* The generated set is faithful, so no verdict may curate any observation
     * out (a completeness guard the containment check below cannot see). */
    assert_no_curation(e, arch, wname, seed);
    /* Phase 3: per-constraint soundness on the all-signals store. Every
     * at-floor constraint on a checked quantity must be a true claim about the
     * truth; one that is not is a rule over-narrowing, named by its origin.
     * Checked first (before the window check below) because it is the sharper
     * diagnostic — it localizes the culprit rule and catches even an unsound
     * constraint the resolver ended up rejecting (which the window check,
     * seeing only the resolved edges, would miss). Sub-floor constraints are
     * exempt: the likely window admits guesses. */
    if (pass == 0) {
      for (int ci = 0; ci < e->n_constraints; ci++) {
        const struct constraint *c = &e->constraints[ci];
        prop_note_origin(c->origin); /* coverage: this rule fired */
        if ((int)c->conf < (int)CONF_INFERRED)
          continue;
        int ti = -1;
        for (int k = 0; k < nchk; k++)
          if (chk[k].q == c->q) {
            ti = k;
            break;
          }
        if (ti < 0)
          continue; /* no truth generated for this quantity */
        if (!prop_constraint_holds(c, chk[ti].truth)) {
          fprintf(stderr,
                  "\nPROPERTY CONSTRAINT %s: rule '%s' emitted an at-floor "
                  "constraint excluding the truth seed=%lu q=%d op=%d "
                  "value=0x%lx value2=0x%lx truth=0x%lx\n",
                  arch, c->origin, seed, (int)c->q, (int)c->op, c->value,
                  c->value2, chk[ti].truth);
          assert(0 && "constraint: at-floor rule output excludes the truth");
        }
      }
    }

    /* Containment is asserted on the GUARANTEED window only. The likely window
     * admits guesses by construction, and a guess that is sound as a model can
     * still be wrong about a particular target: ppc32_phys_ceiling models the
     * BookE placement window, correctly, at CONF_HEURISTIC — and a BookS kernel
     * placed above that window is a configuration the arch admits and that
     * heuristic misses. Demanding the likely window contain the truth would
     * assert more than the two-window design promises, and would make a rule
     * that models one platform of a multi-platform arch unwritable. The
     * per-constraint check above still runs on the all-signals store, where it
     * exempts sub-floor constraints for the same reason and catches anything
     * that turns such a guess into an at-floor claim. */
    if (pass == 0)
      continue;

    for (int k = 0; k < nchk; k++) {
      const struct estimate *est = &e->est[chk[k].q];
      /* quantity_admits() rather than a bare edge comparison: on a finite-set
       * quantity `lo` is a bitmask of live candidates, so comparing a truth
       * against it asks a question the lattice does not answer — Q_VA_BITS
       * reads as excluded on every run. The accessor knows which lattice the
       * quantity uses; truth_in_ranges still carries the interval-only
       * C_EXCLUDE holes it cannot see. */
      if (estimate_is_bottom(est, &qd[chk[k].q]) ||
          !quantity_admits(chk[k].q, est, chk[k].truth) ||
          !truth_in_ranges(chk[k].q, est, e, floor, chk[k].truth)) {
        fprintf(stderr,
                "\nPROPERTY FAIL %s (%s) seed=%lu q=%d truth=0x%lx "
                "window=[0x%lx,0x%lx]\n",
                arch, wname, seed, (int)chk[k].q, chk[k].truth, est->lo,
                est->hi);
        assert(0 && "property: window excluded the truth");
      }
    }
  }
}

/* A phys-only baseline that leaves both text-base windows multi-slot (no exact
 * text pin), so the floor property can inject a distinct in-window value. RAM +
 * MemTotal + image-size lower bound ceiling the phys base; the virt base stays
 * near its honest top (x86_64 decouples the two). Faithful: contains the truth
 * this seed generated (memtotal >= phys + image). Used only by the x86_64 floor
 * property, so unused on an arm64 host. */
__attribute__((unused)) static void prop_build_baseline(struct engine *e,
                                                        unsigned long memtotal,
                                                        unsigned long image) {
  engine_init(e);
  add_addr(e, KASLD_TYPE_PHYS, REGION_RAM, 0, memtotal - 1, NULL);
  add_scalar(e, SF_PHYS_MEMTOTAL, memtotal);
  add_scalar(e, SF_IMAGE_SIZE_MIN, image);
  add_scalar(e, SF_PHYS_ADDR_BITS, 46);
}

struct prop_axis {
  enum kasld_addr_type type;
  enum kasld_quantity q;
  unsigned long truth;
  unsigned long align;
  /* Realistic window to draw the wrong-but-valid pin value from (the arch KASLR
   * window). On arches whose honest top is a wide VA-config union, drawing from
   * the whole guaranteed window could pick an address a band-check verdict
   * invalidates, which would break the positive control; the KASLR window is
   * where a real _stext can land. */
  unsigned long pick_lo, pick_hi;
};

/* Shared floor-invariant core. Over the phys-only baseline (which leaves the
 * text windows multi-slot), a below-floor wrong base pin on each axis must move
 * NO guaranteed quantity, while the SAME pin at CONF_PARSED must (per-axis
 * positive control proves the pin is live). Generalizes
 * test_full_engine_floor_invariant to random truths/windows; per-arch callers
 * supply the generated truth + axes. `r` draws the wrong value; memtotal/image
 * rebuild the baseline for each injection. */
__attribute__((unused)) static void
prop_check_floor(const rule_fn *rules, int nr, const verdict_fn *vrules, int nv,
                 unsigned long memtotal, unsigned long image,
                 const struct prop_axis *axes, int naxes, struct prop_rng *r,
                 const char *arch, unsigned long seed) {
  static const enum kasld_confidence subfloor[] = {CONF_HEURISTIC, CONF_TIMING,
                                                   CONF_BRUTE};
  static struct engine e0;
  prop_build_baseline(&e0, memtotal, image);
  engine_run_full_floored(&e0, CONF_INFERRED, rules, nr, vrules, nv);
  struct estimate g0[Q__COUNT];
  memcpy(g0, e0.est, sizeof(g0));

  for (int a = 0; a < naxes; a++) {
    assert(contains(&g0[axes[a].q], axes[a].truth)); /* faithful baseline */
    unsigned long lo = g0[axes[a].q].lo, hi = g0[axes[a].q].hi;
    unsigned long align = axes[a].align;
    /* Draw the wrong value from the KASLR window intersected with the
     * guaranteed window, so it is both in-window (won't bottom the meet) and
     * valid. */
    unsigned long plo = axes[a].pick_lo > lo ? axes[a].pick_lo : lo;
    unsigned long phi = axes[a].pick_hi < hi ? axes[a].pick_hi : hi;
    if (phi <= plo || (phi - plo) / align < 4)
      continue; /* window too narrow to plant a distinct in-window value */

    unsigned long wrong = 0;
    int ok = 0;
    for (int t = 0; t < 8 && !ok; t++) {
      unsigned long cand = prop_aligned(r, plo + align, phi, align);
      if (cand > plo && cand < phi && cand != axes[a].truth) {
        wrong = cand;
        ok = 1;
      }
    }
    if (!ok)
      continue;

    /* Positive control: at CONF_PARSED the pin MUST move guaranteed. */
    {
      static struct engine e;
      prop_build_baseline(&e, memtotal, image);
      add_addr_conf(&e, axes[a].type, REGION_KERNEL_TEXT, wrong, 0, CONF_PARSED,
                    "_stext");
      engine_run_full_floored(&e, CONF_INFERRED, rules, nr, vrules, nv);
      const struct estimate *g = &e.est[axes[a].q];
      if (g->lo == lo && g->hi == hi) {
        fprintf(stderr,
                "\nPROPERTY FLOOR %s: parsed pin inert seed=%lu axis=%d "
                "wrong=0x%lx window=[0x%lx,0x%lx]\n",
                arch, seed, a, wrong, lo, hi);
        assert(0 &&
               "floor: CONF_PARSED pin did not move guaranteed (not live)");
      }
    }

    /* Invariance: at every sub-floor level the pin moves NO guaranteed quantity
     * (the whole g[] is byte-identical to the baseline g0). */
    for (size_t c = 0; c < sizeof(subfloor) / sizeof(subfloor[0]); c++) {
      static struct engine e;
      prop_build_baseline(&e, memtotal, image);
      add_addr_conf(&e, axes[a].type, REGION_KERNEL_TEXT, wrong, 0, subfloor[c],
                    "_stext");
      engine_run_full_floored(&e, CONF_INFERRED, rules, nr, vrules, nv);
      for (int q = 0; q < Q__COUNT; q++) {
        if (e.est[q].lo != g0[q].lo || e.est[q].hi != g0[q].hi ||
            e.est[q].stride != g0[q].stride ||
            e.est[q].stride_offset != g0[q].stride_offset) {
          fprintf(
              stderr,
              "\nPROPERTY FLOOR %s: sub-floor pin MOVED guaranteed seed=%lu "
              "axis=%d conf=%d q=%d wrong=0x%lx\n",
              arch, seed, a, (int)subfloor[c], q, wrong);
          assert(0 && "floor: below-floor signal moved the guaranteed window");
        }
      }
    }
  }
}
#endif /* KASLD_PROP_ARCH */

/* A consistent x86_64 KASLR placement and the leaks a real run might gather. */
static void test_full_engine_x86_64_leaky(void) {
#if defined(__x86_64__)
  const unsigned long T = 0xffffffff8a000000ul;  /* true virt text base   */
  const unsigned long P = 0x10000000ul;          /* true phys base (256M) */
  const unsigned long PO = 0xffff888000000000ul; /* L4 virt_page_offset_base */
  const unsigned long gap = 0x1400000ul;         /* 20 MiB text..data     */

  struct engine e;
  engine_init(&e);

  /* Leaks the rules consume (all consistent with T/P/PO). */
  add_addr(&e, KASLD_TYPE_PHYS, REGION_KERNEL_TEXT, P, 0, "_stext");
  add_addr(&e, KASLD_TYPE_VIRT, REGION_KERNEL_TEXT, T, 0, "_stext");
  add_addr(&e, KASLD_TYPE_VIRT, REGION_KERNEL_DATA, T + gap, 0, "_edata");
  add_addr(&e, KASLD_TYPE_VIRT, REGION_DIRECTMAP, PO + 0x10000000ul, 0, NULL);
  add_addr(&e, KASLD_TYPE_PHYS, REGION_RAM, 0x0ul, 0x7ffffffful, NULL);
  add_addr(&e, KASLD_TYPE_PHYS, REGION_PCI_MMIO, 0xfe000000ul, 0xfefffffful,
           NULL);
  add_scalar(&e, SF_PHYS_MEMTOTAL, 0x80000000ul); /* 2 GiB */
  add_scalar(&e, SF_IMAGE_SIZE_MIN, gap);         /* image ~ text..data span */
  add_scalar(&e, SF_PHYS_ADDR_BITS, 46);
  add_scalar(&e, SF_PHYS_KERNEL_ALIGN, 0x200000ul);

  int nr = 0, nv = 0;
  const rule_fn *rules = engine_rules(&nr);
  const verdict_fn *vrules = engine_verdict_rules(&nv);
  engine_run_full(&e, rules, nr, vrules, nv);

  const struct quantity_def *qd = quantities;

  /* Soundness: every interval quantity is non-bottom and still admits truth. */
  const struct estimate *vt = &e.est[Q_VIRT_IMAGE_BASE];
  const struct estimate *pt = &e.est[Q_PHYS_IMAGE_BASE];
  const struct estimate *po = &e.est[Q_PAGE_OFFSET];
  assert(!estimate_is_bottom(vt, &qd[Q_VIRT_IMAGE_BASE]));
  assert(!estimate_is_bottom(pt, &qd[Q_PHYS_IMAGE_BASE]));
  assert(!estimate_is_bottom(po, &qd[Q_PAGE_OFFSET]));
  assert(contains(vt, T)); /* must not over-tighten past the true text base */
  assert(contains(pt, P)); /* ... nor the true phys base */
  assert(contains(po, PO));

  /* Liveness: the rules fired and narrowed each quantity from its honest top.
   */
  struct estimate top;
  qd[Q_VIRT_IMAGE_BASE].init_top(&top);
  assert(vt->hi < top.hi); /* image_size_text_data_gap ceiling */
  qd[Q_PHYS_IMAGE_BASE].init_top(&top);
  assert(pt->hi < top.hi); /* kernel_image_phys_bound / mmio / memtotal */
  qd[Q_PAGE_OFFSET].init_top(&top);
  assert(po_hi(po) < top.hi); /* directmap_page_offset_bounds */
#endif
}

/* Regression for the text_cluster_filter / directmap collapse. A rich but fully
 * FAITHFUL x86_64 leak set — a kernel-text cluster PLUS a directmap leak — must
 * not curate the (sound) directmap out, and must still resolve page_offset. The
 * plain faithful test above carries only ~2 text leaks, below CLUSTER_MIN, so
 * the region-blind outlier filter never fired against the directmap; enough
 * text leaks form a cluster the directmap (terabytes away) is judged an outlier
 * of. Asserts no-curation, completeness, and monotonicity (the cluster must not
 * widen page_offset — adding sound evidence never makes a resolution worse). */
static void test_full_engine_faithful_cluster_keeps_directmap(void) {
#if defined(__x86_64__)
  const unsigned long T = 0xffffffff8a000000ul; /* true virt text base       */
  const unsigned long PO =
      0xffff8a4000000000ul;                     /* true page_offset (PUD-aln) */
  const unsigned long gap = 0x1400000ul;        /* 20 MiB image span         */
  const unsigned long dleak = PO + 0x8000000ul; /* directmap leak, +128 MiB  */
  int nr = 0, nv = 0;
  const rule_fn *rules = engine_rules(&nr);
  const verdict_fn *vrules = engine_verdict_rules(&nv);

  /* Baseline: the directmap leak WITHOUT a text cluster resolves page_offset.
   * static (BSS): two ~1.35 MiB engines would overflow the 2 MiB frame cap. */
  static struct engine base;
  engine_init(&base);
  add_addr(&base, KASLD_TYPE_VIRT, REGION_DIRECTMAP, dleak, 0, NULL);
  add_addr(&base, KASLD_TYPE_PHYS, REGION_RAM, 0x0ul, 0x7ffffffful, NULL);
  add_scalar(&base, SF_PHYS_MAX_PFN, 0x80000ul); /* ~2 GiB / 4 KiB */
  engine_run_full_floored(&base, CONF_INFERRED, rules, nr, vrules, nv);
  const struct estimate *pob = &base.est[Q_PAGE_OFFSET];
  assert(!estimate_is_bottom(pob, &quantities[Q_PAGE_OFFSET]));
  assert(contains(pob, PO));
  unsigned long base_lo = po_lo(pob), base_hi = po_hi(pob);

  /* Rich: the same directmap leak PLUS a faithful kernel-text cluster (>= 5).
   */
  static struct engine e;
  engine_init(&e);
  add_addr(&e, KASLD_TYPE_VIRT, REGION_KERNEL_TEXT, T, 0, "_stext");
  add_interior(&e, KASLD_TYPE_VIRT, REGION_KERNEL_TEXT, T + 0x100000ul);
  add_interior(&e, KASLD_TYPE_VIRT, REGION_KERNEL_TEXT, T + 0x400000ul);
  add_interior(&e, KASLD_TYPE_VIRT, REGION_KERNEL_TEXT, T + 0x800000ul);
  add_interior(&e, KASLD_TYPE_VIRT, REGION_KERNEL_TEXT, T + 0xc00000ul);
  add_interior(&e, KASLD_TYPE_VIRT, REGION_KERNEL_IMAGE, T + gap);
  add_addr(&e, KASLD_TYPE_VIRT, REGION_DIRECTMAP, dleak, 0, NULL);
  add_addr(&e, KASLD_TYPE_PHYS, REGION_RAM, 0x0ul, 0x7ffffffful, NULL);
  add_scalar(&e, SF_PHYS_MAX_PFN, 0x80000ul);
  engine_run_full_floored(&e, CONF_INFERRED, rules, nr, vrules, nv);

  /* (1) No-curation: every faithful obs — the directmap included — stays valid.
   */
  assert_no_curation(&e, "x86_64", "faithful-cluster", 0);
  /* (2) Completeness: page_offset still resolves and admits the truth. */
  const struct estimate *po = &e.est[Q_PAGE_OFFSET];
  assert(!estimate_is_bottom(po, &quantities[Q_PAGE_OFFSET]));
  assert(contains(po, PO));
  /* (3) Monotonicity: the text cluster did not widen page_offset. */
  assert(po_lo(po) >= base_lo && po_hi(po) <= base_hi);
#endif
}

/* Collateral: a misclassified pointer among sound evidence must cost only
 * itself. The faithful-set case above proves a curator stays quiet when there
 * is nothing to curate; this is the case where curation SHOULD fire, which is
 * where over-reach actually lives. A curator that removes the fault and a sound
 * observation alongside it passes every faithful-set assertion.
 *
 * The fault is the misclassification the curators exist for: a direct-map
 * address tagged REGION_KERNEL_TEXT, ~100 TiB from the text cluster. The
 * correctly-tagged direct-map leak sits at the same distance and must survive,
 * so the two differ only in the region they claim -- which is exactly the
 * distinction the region-blind version of the filter could not draw.
 *
 * Two curators independently rule on it: coupling_validate, because the address
 * is outside the VA band kernel text occupies, and text_cluster_filter, because
 * it is an outlier from the cluster. The assertion is on the observation being
 * removed rather than on which rule removed it -- either is a correct ruling,
 * and pinning one would fail the day the other reached it first. */
static void test_full_engine_curation_removes_only_the_fault(void) {
#if defined(__x86_64__)
  const unsigned long T = 0xffffffff8a000000ul;
  const unsigned long PO = 0xffff8a4000000000ul;
  const unsigned long gap = 0x1400000ul;
  const unsigned long dleak = PO + 0x8000000ul;
  int nr = 0, nv = 0;
  const rule_fn *rules = engine_rules(&nr);
  const verdict_fn *vrules = engine_verdict_rules(&nv);

  static struct engine e;
  engine_init(&e);
  add_addr(&e, KASLD_TYPE_VIRT, REGION_KERNEL_TEXT, T, 0, "_stext");
  add_interior(&e, KASLD_TYPE_VIRT, REGION_KERNEL_TEXT, T + 0x100000ul);
  add_interior(&e, KASLD_TYPE_VIRT, REGION_KERNEL_TEXT, T + 0x400000ul);
  add_interior(&e, KASLD_TYPE_VIRT, REGION_KERNEL_TEXT, T + 0x800000ul);
  add_interior(&e, KASLD_TYPE_VIRT, REGION_KERNEL_TEXT, T + 0xc00000ul);
  add_interior(&e, KASLD_TYPE_VIRT, REGION_KERNEL_IMAGE, T + gap);
  /* Sound, and far from the cluster: must survive. */
  add_addr(&e, KASLD_TYPE_VIRT, REGION_DIRECTMAP, dleak, 0, NULL);
  add_addr(&e, KASLD_TYPE_PHYS, REGION_RAM, 0x0ul, 0x7ffffffful, NULL);
  add_scalar(&e, SF_PHYS_MAX_PFN, 0x80000ul);
  /* The injected fault: the same neighbourhood, claiming to be kernel text. */
  uint32_t bad = add_addr(&e, KASLD_TYPE_VIRT, REGION_KERNEL_TEXT,
                          PO + 0x9000000ul, 0, NULL);

  engine_run_full_floored(&e, CONF_INFERRED, rules, nr, vrules, nv);

  /* Nothing but the injected fault was curated. */
  assert_curation_subset(&e, &bad, 1, "x86_64", "injected-fault", 0);

  /* And it WAS caught -- otherwise the subset assertion above holds vacuously
   * and this fixture would prove nothing about the filter firing. */
  int caught = 0;
  for (int i = 0; i < e.ev.n_obs; i++)
    if (e.ev.obs[i].id == bad && !e.ev.obs[i].valid)
      caught = 1;
  assert(caught);

  /* The sound direct-map leak survived the removal, so page_offset still
   * resolves and admits the truth. */
  const struct estimate *po = &e.est[Q_PAGE_OFFSET];
  assert(!estimate_is_bottom(po, &quantities[Q_PAGE_OFFSET]));
  assert(contains(po, PO));
  assert(contains(&e.est[Q_VIRT_IMAGE_BASE], T));
#endif
}

/* Two-window resolution (engine layer): a speculative (timing) base leak
 * tightens the LIKELY window (floor CONF_BRUTE, today's engine_run_full) but is
 * filtered out of the GUARANTEED window (floor CONF_INFERRED), which stays
 * sound. A POS_BASE claim pins the one slot it names (text_pin_from_observation
 * no longer widens a sub-floor pin into a slot window — a dense-probe emitter
 * that can miss by a slot declares that by emitting at CONF_TIMING, the weakest
 * pin). Demonstrates both the value (a correct guess pins likely to the right
 * slot) and the safety (a wrong guess can't poison guaranteed). */
static void test_full_engine_two_window(void) {
#if defined(__x86_64__)
  int nr = 0, nv = 0;
  const rule_fn *rules = engine_rules(&nr);
  const verdict_fn *vrules = engine_verdict_rules(&nv);
  const unsigned long T =
      0xffffffff8a000000ul; /* a valid, 2 MiB-aligned base */

  /* (1) Correct speculative leak -> likely pins T (the one slot it names);
   * guaranteed brackets it more loosely. */
  {
    struct engine e;
    engine_init(&e);
    add_addr_conf(&e, KASLD_TYPE_VIRT, REGION_KERNEL_TEXT, T, 0, CONF_TIMING,
                  "_stext");
    struct estimate g[Q__COUNT];
    engine_run_full_floored(&e, CONF_INFERRED, rules, nr, vrules, nv);
    memcpy(g, e.est, sizeof(g));
    engine_run_full(&e, rules, nr, vrules, nv); /* likely = floor CONF_BRUTE */
    const struct estimate *L = &e.est[Q_VIRT_IMAGE_BASE];
    const struct estimate *G = &g[Q_VIRT_IMAGE_BASE];
    assert(contains(G, T));           /* guaranteed holds the truth */
    assert(G->lo < G->hi);            /* timing leak filtered: unpinned */
    assert(L->lo == T && L->hi == T); /* likely pins the named slot */
    assert(contains(L, T));           /* ... which is the truth */
    assert(G->lo <= L->lo && L->hi <= G->hi); /* likely subset of guaranteed */
  }

  /* (2) WRONG speculative leak (a far slot) -> likely pins the wrong slot W and
   * so excludes the true T, but guaranteed holds it: safety. */
  {
    const unsigned long W = T + 0x2000000ul; /* a different valid slot */
    struct engine e;
    engine_init(&e);
    add_addr_conf(&e, KASLD_TYPE_VIRT, REGION_KERNEL_TEXT, W, 0, CONF_TIMING,
                  "_stext");
    struct estimate g[Q__COUNT];
    engine_run_full_floored(&e, CONF_INFERRED, rules, nr, vrules, nv);
    memcpy(g, e.est, sizeof(g));
    engine_run_full(&e, rules, nr, vrules, nv);
    const struct estimate *L = &e.est[Q_VIRT_IMAGE_BASE];
    const struct estimate *G = &g[Q_VIRT_IMAGE_BASE];
    assert(L->lo == W && L->hi == W); /* likely pins the (wrong) named slot */
    assert(!contains(L, T));          /* ... excluding the truth */
    assert(contains(G, T));           /* but guaranteed still holds it */
  }
#endif
}

/* The perf goal, end to end. A component that brackets the base from below (a
 * lower-bound constraint on Q_VIRT_IMAGE_BASE) plus its interior sample leaves
 * the LIKELY window a two-slot bracket; an independent exact pin inside the
 * bracket collapses it to that one slot, while the GUARANTEED window ignores
 * the sub-floor bound and stays sound. This is the shape perf (bracket) +
 * prefetch (pin) produce on a live x86_64 host. The bound rides the constraint
 * channel, so its below-_text value is never read as a text anchor. */
static void test_full_engine_constraint_bracket_and_corroborate(void) {
#if defined(__x86_64__)
  int nr = 0, nv = 0;
  const rule_fn *rules = engine_rules(&nr);
  const verdict_fn *vrules = engine_verdict_rules(&nv);
  const unsigned long A = (unsigned long)KASLR_VIRT_ALIGN;
  const unsigned long T = 0xffffffff8a000000ul; /* true base, grid-aligned */

  /* (1) The bracketing component alone: interior sample (base <= T) + the
   * lower-bound constraint (base >= T - A) -> likely brackets {T-A, T}. */
  {
    struct engine e;
    engine_init(&e);
    add_interior(&e, KASLD_TYPE_VIRT, REGION_KERNEL_TEXT, T); /* lowest IP */
    add_constraint(&e, Q_VIRT_IMAGE_BASE, C_LOWER_BOUND, T - A, CONF_HEURISTIC);

    struct estimate g[Q__COUNT];
    engine_run_full_floored(&e, CONF_INFERRED, rules, nr, vrules, nv);
    memcpy(g, e.est, sizeof(g));
    engine_run_full(&e, rules, nr, vrules, nv); /* likely = floor CONF_BRUTE */
    const struct estimate *L = &e.est[Q_VIRT_IMAGE_BASE];
    const struct estimate *G = &g[Q_VIRT_IMAGE_BASE];
    assert(contains(G, T));               /* guaranteed holds the truth */
    assert(L->lo == T - A && L->hi == T); /* likely: the two-slot bracket */
    assert(contains(L, T));
    assert(G->lo <= L->lo && L->hi <= G->hi); /* likely subset of guaranteed */
  }

  /* (2) Add an independent exact pin at T (prefetch-shaped, CONF_TIMING) inside
   * the bracket: the likely window collapses to the single true slot. */
  {
    struct engine e;
    engine_init(&e);
    add_interior(&e, KASLD_TYPE_VIRT, REGION_KERNEL_TEXT, T);
    add_constraint(&e, Q_VIRT_IMAGE_BASE, C_LOWER_BOUND, T - A, CONF_HEURISTIC);
    add_addr_conf(&e, KASLD_TYPE_VIRT, REGION_KERNEL_IMAGE, T, 0, CONF_TIMING,
                  NULL);

    struct estimate g[Q__COUNT];
    engine_run_full_floored(&e, CONF_INFERRED, rules, nr, vrules, nv);
    memcpy(g, e.est, sizeof(g));
    engine_run_full(&e, rules, nr, vrules, nv);
    const struct estimate *L = &e.est[Q_VIRT_IMAGE_BASE];
    const struct estimate *G = &g[Q_VIRT_IMAGE_BASE];
    assert(L->lo == T && L->hi == T); /* corroboration collapses to one slot */
    assert(contains(G, T));           /* guaranteed still sound */
  }
#endif
}

#if defined(__x86_64__)
/* A bounded-but-not-located x86_64 scenario: phys DRAM + MMIO + scalars narrow
 * the physical base and page_offset, and no kernel-text leak is present, so the
 * virtual image base stays at its honest top. This is the realistic
 * post-leak-drought shape, and it leaves each localizing quantity with room for
 * an injected signal to (try to) narrow it. */
static void build_x86_64_floor_baseline(struct engine *e) {
  engine_init(e);
  add_addr(e, KASLD_TYPE_PHYS, REGION_RAM, 0x0ul, 0x7ffffffful, NULL);
  add_addr(e, KASLD_TYPE_PHYS, REGION_PCI_MMIO, 0xfe000000ul, 0xfefffffful,
           NULL);
  add_addr(e, KASLD_TYPE_VIRT, REGION_DIRECTMAP,
           0xffff888000000000ul + 0x10000000ul, 0, NULL);
  add_scalar(e, SF_PHYS_MEMTOTAL, 0x80000000ul);
  add_scalar(e, SF_IMAGE_SIZE_MIN, 0x1400000ul);
  add_scalar(e, SF_PHYS_ADDR_BITS, 46);
  add_scalar(e, SF_PHYS_KERNEL_ALIGN, 0x200000ul);
}
#endif

/* Registry-wide floor invariant. Generalizes test_full_engine_two_window from
 * one planted timing leak to a property over the WHOLE rule registry: NO
 * below-floor signal may move the GUARANTEED window. Guaranteed resolves at
 * CONF_INFERRED, so a sub-floor observation is out of scope there — a wrong
 * guess can shrink LIKELY toward the wrong slot but must never touch
 * guaranteed. For a battery of adversarial image-base pins (one per axis),
 * injected at every sub-floor confidence, the guaranteed estimate of EVERY
 * quantity is byte- identical (value fields) to the no-injection baseline. A
 * positive control asserts the SAME signal at CONF_PARSED DOES move guaranteed,
 * proving each injection is live (not vacuously ignored for an unrelated
 * reason). Catches a rule that reads a below-floor observation into an
 * at-or-above-floor constraint — e.g. a forgotten `if (!o->valid) continue`
 * guard. x86_64 host only (the planted layout is x86_64); the gating mechanism
 * it exercises is arch-agnostic. */
static void test_full_engine_floor_invariant(void) {
#if defined(__x86_64__)
  int nr = 0, nv = 0;
  const rule_fn *rules = engine_rules(&nr);
  const verdict_fn *vrules = engine_verdict_rules(&nv);

  /* Baseline guaranteed window (floor CONF_INFERRED), no injection. */
  struct estimate g0[Q__COUNT];
  {
    struct engine e;
    build_x86_64_floor_baseline(&e);
    engine_run_full_floored(&e, CONF_INFERRED, rules, nr, vrules, nv);
    memcpy(g0, e.est, sizeof(g0));
  }

  /* Wrong-but-in-window _stext pins on each axis: values inside the baseline
   * window, so at CONF_PARSED they narrow it (they do not bottom-force). */
  struct inj {
    enum kasld_addr_type type;
    unsigned long value;
    enum kasld_quantity q;
  };
  static const struct inj injs[] = {
      {KASLD_TYPE_VIRT, 0xffffffff8a000000ul, Q_VIRT_IMAGE_BASE},
      {KASLD_TYPE_PHYS, 0x10000000ul, Q_PHYS_IMAGE_BASE},
  };
  static const enum kasld_confidence subfloor[] = {CONF_HEURISTIC, CONF_TIMING,
                                                   CONF_BRUTE};

  for (size_t i = 0; i < sizeof(injs) / sizeof(injs[0]); i++) {
    /* Positive control: at CONF_PARSED the same signal MUST move guaranteed,
     * proving the injection is live. */
    {
      struct engine e;
      build_x86_64_floor_baseline(&e);
      add_addr_conf(&e, injs[i].type, REGION_KERNEL_TEXT, injs[i].value, 0,
                    CONF_PARSED, "_stext");
      engine_run_full_floored(&e, CONF_INFERRED, rules, nr, vrules, nv);
      const struct estimate *g = &e.est[injs[i].q];
      const struct estimate *b = &g0[injs[i].q];
      assert(g->lo != b->lo || g->hi != b->hi); /* live: it moved guaranteed */
      assert(contains(g, injs[i].value)); /* ... toward the planted value */
    }
    /* Invariance: at every sub-floor level the whole guaranteed window equals
     * g0.
     */
    for (size_t c = 0; c < sizeof(subfloor) / sizeof(subfloor[0]); c++) {
      struct engine e;
      build_x86_64_floor_baseline(&e);
      add_addr_conf(&e, injs[i].type, REGION_KERNEL_TEXT, injs[i].value, 0,
                    subfloor[c], "_stext");
      engine_run_full_floored(&e, CONF_INFERRED, rules, nr, vrules, nv);
      for (int q = 0; q < Q__COUNT; q++) {
        assert(e.est[q].lo == g0[q].lo);
        assert(e.est[q].hi == g0[q].hi);
        assert(e.est[q].stride == g0[q].stride);
        assert(e.est[q].stride_offset == g0[q].stride_offset);
      }
    }
  }
#endif
}

/* A hardened ppc64le system with KASLR disabled and no /proc/iomem leak:
 * the only phys observation is `P initrd pos=base lo=0x2c90000` (from
 * devicetree). The kernel sits at phys 0 (well below the initrd) —
 * the lowest-address dram-section observation does NOT mark the RAM
 * floor when it comes from a non-RAM region. dram_floor_bound must
 * scope its floor scan to REGION_RAM observations only; widening it to
 * is_phys_dram_region(...) would pin Q_PHYS_IMAGE_BASE.lo to 0x2c90000
 * and exclude the actual kernel-at-phys-0 placement. */
static void test_full_engine_ppc64_hardened_shape(void) {
#if defined(__powerpc64__) || defined(__ppc64__)
  struct engine e;
  engine_init(&e);
  add_scalar(&e, SF_VIRT_KASLR_DISABLED, 0x1);
  add_scalar(&e, SF_PHYS_KASLR_DISABLED, 0x1);
  add_scalar(&e, SF_VIRT_CONFIG_PAGE_OFFSET, 0xc000000000000000ul);
  add_scalar(&e, SF_EFI_PRESENT, 0x0);
  add_scalar(&e, SF_PHYS_MEMTOTAL, 0x7a04d000ul);
  add_scalar(&e, SF_PHYS_MAX_PFN, 0x80000ul);
  add_scalar(&e, SF_PAGE_SIZE, 0x1000ul);
  add_addr(&e, KASLD_TYPE_VIRT, REGION_PAGE_OFFSET, 0xc000000000000000ul, 0,
           NULL);
  add_addr(&e, KASLD_TYPE_PHYS, REGION_INITRD, 0x2c90000ul, 0x4a4f1d6ul, NULL);

  int nr = 0, nv = 0;
  const rule_fn *rules = engine_rules(&nr);
  const verdict_fn *vrules = engine_verdict_rules(&nv);
  engine_run_full(&e, rules, nr, vrules, nv);

  /* Default ppc64le layout: text at phys 0 (image base) / virt
   * 0xc000000000000000; virt_page_offset at 0xc000000000000000. */
  const unsigned long t_virt = 0xc000000000000000ul;
  const unsigned long t_phys = 0x0ul;
  const unsigned long t_po = 0xc000000000000000ul;

  const struct estimate *vt = &e.est[Q_VIRT_IMAGE_BASE];
  const struct estimate *pt = &e.est[Q_PHYS_IMAGE_BASE];
  const struct estimate *po = &e.est[Q_PAGE_OFFSET];

  assert(!estimate_is_bottom(vt, &quantities[Q_VIRT_IMAGE_BASE]));
  assert(!estimate_is_bottom(pt, &quantities[Q_PHYS_IMAGE_BASE]));
  assert(!estimate_is_bottom(po, &quantities[Q_PAGE_OFFSET]));

  assert(vt->lo <= t_virt && t_virt <= vt->hi);
  assert(pt->lo <= t_phys && t_phys <= pt->hi);
  assert(po_lo(po) <= t_po && t_po <= po_hi(po));
#endif
}

/* An s390 system whose dmesg contains `boot: KASLR disabled: CPU has no
 * PRNG`. That message means the s390 boot stub skipped the random offset,
 * but the image is still relocated to a runtime-determined virt position
 * derived from physical memory layout — it does NOT imply text sits at
 * KERNEL_VIRT_TEXT_DEFAULT. dmesg_kaslr_disabled emits this as
 * SF_VIRT_KASLR_RANDOMIZATION_FAILED (distinct from SF_VIRT_KASLR_DISABLED,
 * which the virt_/phys_kaslr_disabled_pin rule would honour);
 * virt_/phys_kaslr_disabled_pin therefore does NOT fire, and the engine
 * resolves Q_VIRT_IMAGE_BASE to a wide window that admits the runtime-relocated
 * _stext. Were the no-PRNG line miscategorised as SF_VIRT_KASLR_DISABLED, the
 * engine would pin to KERNEL_VIRT_TEXT_DEFAULT (0x3FFE0100000) and exclude any
 * _stext displaced by the runtime relocation (e.g. 0x3FFFE6A0000, ~8 GiB above
 * the default).
 *
 * The test plants the scalars a low-priv s390 system would emit when
 * dmesg contains the no-PRNG line (notably without SF_VIRT_KASLR_DISABLED)
 * and asserts the resolved windows admit the displaced text base. */
static void test_full_engine_s390_no_prng_shape(void) {
#if defined(__s390__) || defined(__s390x__)
  struct engine e;
  engine_init(&e);
  add_scalar(&e, SF_EFI_PRESENT, 0x0);
  add_scalar(&e, SF_IMAGE_SIZE_MIN, 0x126046cul);
  add_scalar(&e, SF_PHYS_MEMTOTAL, 0x7bd9e000ul);
  add_scalar(&e, SF_PHYS_MAX_PFN, 0x80000ul);
  add_scalar(&e, SF_PAGE_SIZE, 0x1000ul);
  add_scalar(&e, SF_VIRT_ADDR_BITS, 0x35ul); /* 53 = s390 4-level paging */

  int nr = 0, nv = 0;
  const rule_fn *rules = engine_rules(&nr);
  const verdict_fn *vrules = engine_verdict_rules(&nv);
  engine_run_full(&e, rules, nr, vrules, nv);

  /* Sample displaced text base derived from runtime layout; the engine's
   * resolved window must admit it (and any other plausible displaced
   * value within the s390 KASLR window). */
  const unsigned long t_virt = 0x3fffe6a0000ul;
  const unsigned long t_phys = 0xaa0000ul;

  const struct estimate *vt = &e.est[Q_VIRT_IMAGE_BASE];
  const struct estimate *pt = &e.est[Q_PHYS_IMAGE_BASE];

  assert(!estimate_is_bottom(vt, &quantities[Q_VIRT_IMAGE_BASE]));
  assert(!estimate_is_bottom(pt, &quantities[Q_PHYS_IMAGE_BASE]));
  /* With SF_VIRT_KASLR_DISABLED erroneously emitted, vt would collapse to
   * [KERNEL_VIRT_TEXT_DEFAULT, KERNEL_VIRT_TEXT_DEFAULT] and t_virt would fall
   * outside. The exemption keeps the signal off and the window admits
   * the displaced text base. */
  assert(vt->lo <= t_virt && t_virt <= vt->hi);
  assert(pt->lo <= t_phys && t_phys <= pt->hi);
#endif
}

/* A no-KASLR arm32 system (CONFIG_RANDOMIZE_BASE is not available on
 * arm32; the kernel always loads at PAGE_OFFSET + IMAGE_BASE_OFFSET + head).
 * On any 32-bit arch, expressions like `4 * GB` in the arch header
 * overflow an `unsigned long` to 0 and collapse Q_PHYS_IMAGE_BASE's
 * honest-top to a bottom interval (lo > hi). The bottom then propagates
 * via text_base_coupling_synth onto Q_VIRT_IMAGE_BASE on coupled arches.
 *
 * The test plants the scalars a low-priv arm32 system emits when only
 * boot_config (PAGE_OFFSET, KASLR off) and meminfo are readable, and
 * asserts the resolved windows are non-bottom and admit the true text
 * placement. Pinned the moment any arch header introduces a 32-bit
 * overflow in its KERNEL_PHYS_MAX (or any rule that depends on it). */
static void test_full_engine_arm32_no_kaslr_shape(void) {
#if defined(__arm__) && !defined(__aarch64__)
  struct engine e;
  engine_init(&e);
  add_scalar(&e, SF_EFI_PRESENT, 0x0);
  add_scalar(&e, SF_PHYS_MEMTOTAL, 0xf4e4000ul); /* ~ 250 MiB */
  add_scalar(&e, SF_PHYS_MAX_PFN, 0x10000ul);
  add_scalar(&e, SF_PAGE_SIZE, 0x1000ul);
  add_scalar(&e, SF_VIRT_KASLR_DISABLED, 0x1);
  add_scalar(&e, SF_PHYS_KASLR_DISABLED, 0x1);
  add_addr(&e, KASLD_TYPE_VIRT, REGION_PAGE_OFFSET, 0xc0000000ul, 0, NULL);

  int nr = 0, nv = 0;
  const rule_fn *rules = engine_rules(&nr);
  const verdict_fn *vrules = engine_verdict_rules(&nv);
  engine_run_full(&e, rules, nr, vrules, nv);

  /* Default arm32 layout: _stext sits at PAGE_OFFSET + IMAGE_BASE_OFFSET + head
   * (a small head-asm offset), phys text at IMAGE_BASE_OFFSET above RAM_BASE
   * (= 0x8000 on the standard layout). The resolved windows must remain
   * non-bottom and admit these. */
  const unsigned long t_virt = 0xc0008220ul;
  const unsigned long t_phys = 0x8000ul;
  const unsigned long t_po = 0xc0000000ul;

  const struct estimate *vt = &e.est[Q_VIRT_IMAGE_BASE];
  const struct estimate *pt = &e.est[Q_PHYS_IMAGE_BASE];
  const struct estimate *po = &e.est[Q_PAGE_OFFSET];

  assert(!estimate_is_bottom(vt, &quantities[Q_VIRT_IMAGE_BASE]));
  assert(!estimate_is_bottom(pt, &quantities[Q_PHYS_IMAGE_BASE]));
  assert(!estimate_is_bottom(po, &quantities[Q_PAGE_OFFSET]));

  assert(vt->lo <= t_virt && t_virt <= vt->hi);
  assert(pt->lo <= t_phys && t_phys <= pt->hi);
  assert(po_lo(po) <= t_po && t_po <= po_hi(po));
#endif
}

/* A typical i686 system: KASLR enabled, virt_page_offset and
 * CONFIG_PHYSICAL_START readable from /boot/config, BIOS e820 readable from
 * /sys/kernel/boot_params, zoneinfo + firmware/memmap readable. x86_32 is
 * coupled (TEXT_TRACKS_DIRECTMAP = 1) so the resolved Q_VIRT_IMAGE_BASE window
 * tracks the resolved Q_PHYS_IMAGE_BASE window via the compile-time PAGE_OFFSET
 * / PHYS_OFFSET / IMAGE_BASE_OFFSET projection. The test plants the scalars +
 * phys extents an unprivileged i686 user reads and asserts the resolved windows
 * remain non-bottom and admit a representative KASLR slid placement
 * (phys text + 96 MiB above CONFIG_PHYSICAL_START = 16 MiB → 112 MiB
 * absolute, virt = virt_page_offset + same). */
static void test_full_engine_i686_kaslr_shape(void) {
#if defined(__i386__) || defined(__i686__)
  struct engine e;
  engine_init(&e);
  add_scalar(&e, SF_EFI_PRESENT, 0x0);
  add_scalar(&e, SF_VIRT_CONFIG_PAGE_OFFSET, 0xc0000000ul);
  add_scalar(&e, SF_PHYSICAL_START, 0x1000000ul);    /* 16 MiB */
  add_scalar(&e, SF_PHYS_KERNEL_ALIGN, 0x1000000ul); /* 16 MiB slot */
  add_scalar(&e, SF_IMAGE_SIZE_MIN, 0x10f4000ul); /* ~17 MiB (exact source: */
  add_scalar(&e, SF_IMAGE_SIZE_MAX, 0x10f4000ul); /* emits both MIN and MAX) */
  add_scalar(&e, SF_PHYS_MEMTOTAL, 0x3e4da000ul);
  add_scalar(&e, SF_PHYS_LOWMEM, 0x350f8000ul);
  add_scalar(&e, SF_PHYS_MAX_PFN, 0x3ffe0ul);
  add_scalar(&e, SF_PAGE_SIZE, 0x1000ul);
  add_scalar(&e, SF_PHYS_ADDR_BITS, 0x24ul);
  add_addr(&e, KASLD_TYPE_VIRT, REGION_PAGE_OFFSET, 0xc0000000ul, 0, NULL);
  add_addr(&e, KASLD_TYPE_PHYS, REGION_RAM, 0x100000ul, 0x3ffdfffful, NULL);
  add_addr(&e, KASLD_TYPE_PHYS, REGION_INITRD, 0x3e9f8000ul, 0x3ffdf9e0ul,
           NULL);

  int nr = 0, nv = 0;
  const rule_fn *rules = engine_rules(&nr);
  const verdict_fn *vrules = engine_verdict_rules(&nv);
  engine_run_full(&e, rules, nr, vrules, nv);

  /* Representative KASLR-slid placement. */
  const unsigned long t_virt = 0xc6000000ul; /* virt_page_offset + 96 MiB */
  const unsigned long t_phys =
      0x06000000ul; /* CONFIG_PHYSICAL_START + 80 MiB slide */
  const unsigned long t_po = 0xc0000000ul;

  const struct estimate *vt = &e.est[Q_VIRT_IMAGE_BASE];
  const struct estimate *pt = &e.est[Q_PHYS_IMAGE_BASE];
  const struct estimate *po = &e.est[Q_PAGE_OFFSET];

  assert(!estimate_is_bottom(vt, &quantities[Q_VIRT_IMAGE_BASE]));
  assert(!estimate_is_bottom(pt, &quantities[Q_PHYS_IMAGE_BASE]));
  assert(!estimate_is_bottom(po, &quantities[Q_PAGE_OFFSET]));

  assert(vt->lo <= t_virt && t_virt <= vt->hi);
  assert(pt->lo <= t_phys && t_phys <= pt->hi);
  assert(po_lo(po) <= t_po && t_po <= po_hi(po));
#endif
}

/* Same scenario but with a deliberately-bogus extra PHYS candidate far above
 * RAM: the engine must stay sound (truth still admitted, non-bottom). */
static void test_full_engine_robust_to_outlier(void) {
#if defined(__x86_64__)
  const unsigned long P = 0x10000000ul;
  struct engine e;
  engine_init(&e);
  add_addr(&e, KASLD_TYPE_PHYS, REGION_KERNEL_TEXT, P, 0, "_stext");
  add_addr(&e, KASLD_TYPE_PHYS, REGION_RAM, 0x0ul, 0x7ffffffful, NULL);
  /* Outlier far above DRAM — a bad leak. */
  add_addr(&e, KASLD_TYPE_PHYS, REGION_KERNEL_TEXT, 0x40000000000ul, 0, "bad");
  add_scalar(&e, SF_PHYS_MEMTOTAL, 0x80000000ul);

  int nr = 0, nv = 0;
  const rule_fn *rules = engine_rules(&nr);
  const verdict_fn *vrules = engine_verdict_rules(&nv);
  engine_run_full(&e, rules, nr, vrules, nv);

  const struct estimate *pt = &e.est[Q_PHYS_IMAGE_BASE];
  assert(!estimate_is_bottom(pt, &quantities[Q_PHYS_IMAGE_BASE]));
  assert(pt->lo <= P && P <= pt->hi); /* truth survives the outlier */
#endif
}

/* PowerPC firmware writes linux,kernel-end (phys address one byte past the
 * loaded kernel image). The sysfs_devicetree_kernel_end component emits it as
 * `P REGION_KERNEL_IMAGE pos=top hi=<kend>`; kernel_image_phys_bound then uses
 * obs_anchor() (which returns hi for a top-only observation) to tighten
 * Q_PHYS_IMAGE_BASE.hi.
 *
 * Plant a low kernel-end (24 MiB) on a ppc64 layout and assert the upper
 * bound lands at or below that — the engine's honest top for Q_PHYS_IMAGE_BASE
 * is far higher, so the rule firing on this signal is the only path that can
 * produce hi <= 24 MiB. */
static void test_full_engine_ppc_kernel_end_tightens(void) {
#if defined(__powerpc64__) || defined(__ppc64__)
  const unsigned long kend = 0x1800000ul; /* 24 MiB */
  struct engine e;
  engine_init(&e);
  add_scalar(&e, SF_VIRT_KASLR_DISABLED, 0x1);
  add_scalar(&e, SF_PHYS_KASLR_DISABLED, 0x1);
  add_scalar(&e, SF_VIRT_CONFIG_PAGE_OFFSET, 0xc000000000000000ul);
  add_addr(&e, KASLD_TYPE_VIRT, REGION_PAGE_OFFSET, 0xc000000000000000ul, 0,
           NULL);
  add_addr_top(&e, KASLD_TYPE_PHYS, REGION_KERNEL_IMAGE, kend);

  int nr = 0, nv = 0;
  const rule_fn *rules = engine_rules(&nr);
  const verdict_fn *vrules = engine_verdict_rules(&nv);
  engine_run_full(&e, rules, nr, vrules, nv);

  const struct estimate *pt = &e.est[Q_PHYS_IMAGE_BASE];
  assert(!estimate_is_bottom(pt, &quantities[Q_PHYS_IMAGE_BASE]));
  /* phys text base sits at or before the kernel image's last-byte witness. */
  assert(pt->hi <= kend);
  /* And the true placement (phys 0 for the ppc64 default layout) is admitted.
   */
  assert(pt->lo <= 0ul && 0ul <= pt->hi);
#endif
}

/* PowerPC firmware writes linux,memory-limit (the RAM ceiling honoured by the
 * kernel, set by mem= cmdline cap or firmware override). The
 * sysfs_devicetree_memory_limit component emits it as
 * `P REGION_RAM pos=top hi=limit-1`; dram_ceiling reads max(o->hi) across RAM
 * observations and projects it through SF_IMAGE_SIZE_MIN to tighten
 * Q_VIRT_IMAGE_BASE.hi on coupled arches (ppc64 is coupled).
 *
 * Plant a 128 MiB cap on a ppc64 layout and assert Q_VIRT_IMAGE_BASE.hi lands
 * below KERNEL_VIRT_TEXT_DEFAULT + the cap — i.e. dram_ceiling fired and
 * projected the cap. */
static void test_full_engine_ppc_memory_limit_caps_dram(void) {
#if defined(__powerpc64__) || defined(__ppc64__)
  const unsigned long limit = 0x08000000ul; /* 128 MiB */
  const unsigned long ksize = 0x00800000ul; /* 8 MiB image */
  struct engine e;
  engine_init(&e);
  add_scalar(&e, SF_VIRT_KASLR_DISABLED, 0x1);
  add_scalar(&e, SF_PHYS_KASLR_DISABLED, 0x1);
  add_scalar(&e, SF_VIRT_CONFIG_PAGE_OFFSET, 0xc000000000000000ul);
  add_scalar(&e, SF_IMAGE_SIZE_MIN, ksize);
  add_addr(&e, KASLD_TYPE_VIRT, REGION_PAGE_OFFSET, 0xc000000000000000ul, 0,
           NULL);
  /* The memory-limit emission as the component shapes it. */
  add_addr_top(&e, KASLD_TYPE_PHYS, REGION_RAM, limit - 1);

  int nr = 0, nv = 0;
  const rule_fn *rules = engine_rules(&nr);
  const verdict_fn *vrules = engine_verdict_rules(&nv);
  engine_run_full(&e, rules, nr, vrules, nv);

  const struct estimate *vt = &e.est[Q_VIRT_IMAGE_BASE];
  assert(!estimate_is_bottom(vt, &quantities[Q_VIRT_IMAGE_BASE]));
  /* dram_ceiling: phys_ceiling = (limit-1) - ksize; virt_ceiling = that +
   * PAGE_OFFSET + IMAGE_BASE_OFFSET. The resolved hi must be at or below that.
   */
  const unsigned long virt_ceiling = (limit - 1 - ksize) + 0xc000000000000000ul;
  assert(vt->hi <= virt_ceiling);
  /* And the true text base (phys 0 / virt 0xc00...000) is still admitted. */
  const unsigned long t_virt = 0xc000000000000000ul;
  assert(vt->lo <= t_virt && t_virt <= vt->hi);
#endif
}

/* The kernel-below-initrd ordering is a bootloader CONVENTION, not a fact:
 * physical KASLR (x86) can place the kernel above a low-loaded initrd. So
 * initrd_above_kernel's bound (phys_text_base + image_size <= initrd_start) is
 * CONF_HEURISTIC — it must shape the LIKELY window but NOT the guaranteed one.
 *
 * Plant a high SF_IMAGE_SIZE_MIN and a tight initrd_start on an x86_64 layout
 * with a DRAM extent but no kernel leak (initrd_above_kernel is the only rule
 * that produces the bound). Assert: the all-signals run applies it
 * (hi <= initrd_start - image_size), the sound-floor run does NOT (the bound is
 * below CONF_INFERRED, so the DRAM ceiling — not the convention — binds, and
 * the true base may legitimately sit above initrd_start). (Gated to x86_64
 * since this is where the integration harness compiles by default.) */
static void test_full_engine_initrd_above_kernel_upper_bound(void) {
#if defined(__x86_64__)
  const unsigned long istart = 0x40000000ul; /*  1 GiB */
  const unsigned long ksize = 0x01000000ul;  /* 16 MiB */
  int nr = 0, nv = 0;
  const rule_fn *rules = engine_rules(&nr);
  const verdict_fn *vrules = engine_verdict_rules(&nv);

  /* One engine, re-resolved twice on the same evidence (a second on-stack
   * engine blows the frame-size limit). */
  struct engine e;
  engine_init(&e);
  add_scalar(&e, SF_IMAGE_SIZE_MIN, ksize);
  add_addr(&e, KASLD_TYPE_PHYS, REGION_INITRD, istart, 0, NULL);
  add_addr(&e, KASLD_TYPE_PHYS, REGION_RAM, 0x0ul, 0x7ffffffful, NULL);

  /* LIKELY (all signals): the convention bound applies. */
  engine_run_full(&e, rules, nr, vrules, nv);
  assert(!estimate_is_bottom(&e.est[Q_PHYS_IMAGE_BASE],
                             &quantities[Q_PHYS_IMAGE_BASE]));
  assert(e.est[Q_PHYS_IMAGE_BASE].hi <= istart - ksize);

  /* GUARANTEED (sound floor): the convention bound is out of scope, so it does
   * NOT cap the base below initrd_start - image_size — a kernel physical KASLR
   * placed above the initrd stays inside the window. The DRAM ceiling binds. */
  e.ev.n_verdicts =
      0; /* clear curation between runs, as the orchestrator does */
  engine_run_full_floored(&e, CONF_INFERRED, rules, nr, vrules, nv);
  assert(!estimate_is_bottom(&e.est[Q_PHYS_IMAGE_BASE],
                             &quantities[Q_PHYS_IMAGE_BASE]));
  assert(e.est[Q_PHYS_IMAGE_BASE].hi > istart - ksize);
#endif
}

/* riscv64 legacy (pre-v5.13) no-KASLR: text in the linear map at PAGE_OFFSET
 * (MAXPHYSMEM_128GB = 0xffffffe000000000). Replicates MilkV board behavior:
 * CONFIG_PAGE_OFFSET landmark, modern sv39 cpuinfo PAGE_OFFSET range (which the
 * resolver must reject in favour of the higher CONFIG landmark), module leak,
 * DRAM extents, disabled markers. Real _stext = 0xffffffe000229000. */
static void test_full_engine_riscv64_legacy_no_kaslr(void) {
#if (defined(__riscv) || defined(__riscv__)) && __riscv_xlen == 64
  struct engine e;
  engine_init(&e);
  add_scalar(&e, SF_EFI_PRESENT, 0x0);
  add_scalar(&e, SF_PHYS_MEMTOTAL, 0x13cd4000ul);
  add_scalar(&e, SF_PHYS_MAX_PFN, 0x9fe00ul);
  add_scalar(&e, SF_PAGE_SIZE, 0x1000ul);
  add_scalar(&e, SF_VIRT_ADDR_BITS, 39ul);
  add_scalar(&e, SF_VIRT_KASLR_DISABLED, 0x1);
  add_scalar(&e, SF_PHYS_KASLR_DISABLED, 0x1);
  /* PAGE_OFFSET evidence, in the order parallel execution produces on the
   * board: proc_cpuinfo (fast) lands its DERIVED modern-sv39 range FIRST
   * (CONF_INFERRED), then proc_config (slow gzip) lands the authoritative
   * CONFIG_PAGE_OFFSET (CONF_PARSED). The two contradict; confidence — not
   * capture order — must decide, so the legacy parsed value has to win despite
   * being added second. Reverting proc_cpuinfo's confidence to parsed would
   * make this resolve to the wrong (modern) value, failing the po_lo(po)
   * assertion below. */
  add_addr_conf(&e, KASLD_TYPE_VIRT, REGION_PAGE_OFFSET, 0xffffffd600000000ul,
                0xffffffd800000000ul, CONF_INFERRED, NULL);
  add_addr(&e, KASLD_TYPE_VIRT, REGION_PAGE_OFFSET, 0xffffffe000000000ul, 0,
           NULL);
  /* Module leaks (~2 GiB below text), REGION_MODULE as proc_modules and
   * sysfs_module_sections emit them: module_text_bound requires structural
   * provenance, since on this arch the module band contains the whole text
   * range and a range-classified address is indistinguishable from a module. */
  add_addr(&e, KASLD_TYPE_VIRT, REGION_MODULE, 0xffffffdf80922000ul, 0, NULL);
  add_addr(&e, KASLD_TYPE_VIRT, REGION_MODULE, 0xffffffdf80d99000ul, 0, NULL);
  /* DRAM. */
  add_addr(&e, KASLD_TYPE_PHYS, REGION_RAM, 0x80000000ul, 0, NULL);
  add_addr_top(&e, KASLD_TYPE_PHYS, REGION_RAM, 0x9fe00000ul);

  int nr = 0, nv = 0;
  const rule_fn *rules = engine_rules(&nr);
  const verdict_fn *vrules = engine_verdict_rules(&nv);
  engine_run_full(&e, rules, nr, vrules, nv);

  const struct estimate *vt = &e.est[Q_VIRT_IMAGE_BASE];
  const struct estimate *po = &e.est[Q_PAGE_OFFSET];
  unsigned long t_virt = 0xffffffe000229000ul; /* real _stext on the board */

  assert(!estimate_is_bottom(vt, &quantities[Q_VIRT_IMAGE_BASE]));
  /* PAGE_OFFSET resolves to the legacy value (the higher CONFIG landmark beats
   * the modern cpuinfo range). */
  assert(po_lo(po) == 0xffffffe000000000ul);
  /* The window contains the real _stext, is in the legacy linear-map region
   * (NOT the 128 GiB-high modern KERNEL_LINK default), and module_text_bound
   * makes it tight. */
  assert(vt->lo <= t_virt && t_virt <= vt->hi);
  /* rule_riscv64_text_base's legacy branch raises lo to PAGE_OFFSET + the head
   * gap (sound: _text sits above _start = PAGE_OFFSET). */
  assert(vt->lo == 0xffffffe000000000ul + IMAGE_BASE_OFFSET);
  assert(vt->hi < 0xffffffe040000000ul); /* tight (< PAGE_OFFSET + 1 GiB) */
  assert(vt->lo != vt->hi ||             /* not falsely pinned... */
         vt->lo == t_virt);              /* ...unless exactly at truth */
  assert(vt->hi < (unsigned long)KERNEL_LINK_ADDR); /* not the modern default */
#endif
}

/* riscv64 legacy MAXPHYSMEM_2GB (CMODEL_MEDLOW): text in the linear map at
 * PAGE_OFFSET = 0xffffffff80000000 — which coincides with the modern
 * KERNEL_LINK_ADDR. No loadable modules (medlow), hence no module leak. The
 * resolved window must use the (high) legacy PAGE_OFFSET as its floor, not the
 * lowest-legacy WIDE floor — the case the `== legacy` match used to miss. */
static void test_full_engine_riscv64_legacy_2gb(void) {
#if (defined(__riscv) || defined(__riscv__)) && __riscv_xlen == 64
  struct engine e;
  engine_init(&e);
  add_scalar(&e, SF_EFI_PRESENT, 0x0);
  add_scalar(&e, SF_PAGE_SIZE, 0x1000ul);
  add_scalar(&e, SF_VIRT_ADDR_BITS, 39ul);
  add_scalar(&e, SF_VIRT_KASLR_DISABLED, 0x1);
  /* cpuinfo's DERIVED modern sv39 range (CONF_INFERRED) captured first, then
   * the authoritative CONFIG_PAGE_OFFSET (CONF_PARSED): the resolver must
   * reject the modern range in favour of the higher parsed CONFIG landmark by
   * confidence, not capture order. */
  add_addr_conf(&e, KASLD_TYPE_VIRT, REGION_PAGE_OFFSET, 0xffffffd600000000ul,
                0xffffffd800000000ul, CONF_INFERRED, NULL);
  add_addr(&e, KASLD_TYPE_VIRT, REGION_PAGE_OFFSET, 0xffffffff80000000ul, 0,
           NULL);
  add_addr(&e, KASLD_TYPE_PHYS, REGION_RAM, 0x80000000ul, 0, NULL);

  int nr = 0, nv = 0;
  const rule_fn *rules = engine_rules(&nr);
  const verdict_fn *vrules = engine_verdict_rules(&nv);
  engine_run_full(&e, rules, nr, vrules, nv);

  const struct estimate *vt = &e.est[Q_VIRT_IMAGE_BASE];
  unsigned long t_virt = 0xffffffff80202000ul; /* representative 2 GiB _stext */
  assert(!estimate_is_bottom(vt, &quantities[Q_VIRT_IMAGE_BASE]));
  /* Floor is the RESOLVED (high) PAGE_OFFSET + head — the `== 0xffffffe0...`
   * match would have left lo at the lowest-legacy WIDE floor (a 2 GiB-too-low,
   * useless window). */
  assert(vt->lo == 0xffffffff80000000ul + (unsigned long)IMAGE_BASE_OFFSET);
  assert(vt->lo <= t_virt && t_virt <= vt->hi);
#endif
}

/* arm64 sub-48 VA_BITS soundness (B Phase 1). A 4K-3level (VA_BITS=39, common
 * on Android) kernel: PAGE_OFFSET and KIMAGE_VADDR are HIGHER than the 48-bit
 * defaults. One test guards all three Phase-1 fixes:
 *   - arm64_coupling_validate must ADMIT the sub-48 directmap leak (its old
 *     ceiling _PAGE_END(48) rejected anything >= 0xffff800000000000);
 *   - arm64_va_bits_from_directmap must classify it as VA_BITS=39 and pin the
 *     exact PAGE_OFFSET (it used to collapse everything >= 0xffff000000000000
 *     to VA_BITS=48);
 *   - the widened Q_VIRT_IMAGE_BASE honest top must ADMIT the sub-48 text base
 *     (the old KASLR_VIRT_TEXT_MAX ceiling excluded it).
 * Reverting any one of the three fails an assertion below. */
static void test_full_engine_arm64_va39_sub48(void) {
#if defined(__aarch64__)
  struct engine e;
  engine_init(&e);
  add_scalar(&e, SF_EFI_PRESENT, 0x0);
  unsigned long po39 = arm64_page_offset_for(39ul); /* 0xffffff8000000000 */
  /* A 39-bit DIRECTMAP leak (within [PAGE_OFFSET(39), _PAGE_END(39))). */
  add_addr(&e, KASLD_TYPE_VIRT, REGION_DIRECTMAP, po39 + 0x1000000ul, 0, NULL);
  /* A real 39-bit kernel-text leak (_stext), KASLR on (no disabled signal).
   * The engine solves the image base _text = _stext - STEXT_OFFSET. */
  /* 64 KiB-aligned, as a real arm64 _stext is: KIMAGE_VADDR and the KASLR
   * slide are both multiples of the 64 KiB granule, so _text and _stext land
   * on it too. An unaligned value here is unreachable on hardware and only
   * survived while the witness pinned, which skips the grid check. */
  unsigned long t_stext = arm64_page_end_for(39ul) + 0x80000000ul + 0x200000ul;
  unsigned long t_text = t_stext - (unsigned long)STEXT_OFFSET;
  add_addr(&e, KASLD_TYPE_VIRT, REGION_KERNEL_TEXT, t_stext, 0, "_stext");

  int nr = 0, nv = 0;
  const rule_fn *rules = engine_rules(&nr);
  const verdict_fn *vrules = engine_verdict_rules(&nv);
  engine_run_full(&e, rules, nr, vrules, nv);

  const struct estimate *vt = &e.est[Q_VIRT_IMAGE_BASE];
  const struct estimate *po = &e.est[Q_PAGE_OFFSET];
  /* PAGE_OFFSET resolves to the exact 39-bit value (admitted + classified). */
  assert(po_lo(po) == po39 && po_hi(po) == po39);
  /* The image base resolves to the sub-48 _text — which sits ABOVE the old
   * 48-bit honest-top ceiling (KASLR_VIRT_TEXT_MAX), so only the widened
   * KASLR_VIRT_TEXT_MAX_WIDE admits it. */
  assert(t_text > (unsigned long)KASLR_VIRT_TEXT_MAX);
  /* The witness is _stext with no _text alongside it, so the base is pinned
   * only where the arch fixes the head gap. arm64's SEGMENT_ALIGN was SZ_2M
   * under the pre-5.7 CONFIG_DEBUG_ALIGN_RODATA, so it declares a ceiling and
   * the same witness bounds instead -- the upper edge is still exactly _text,
   * which is what this case is about: the sub-48 base sits above the old
   * ceiling and only the widened one admits it. */
  assert(vt->hi == t_text);
  if (STEXT_GAP_EXACT) {
    assert(vt->lo == t_text);
  } else {
    assert(vt->lo <= t_text);
    assert(vt->lo >= t_stext - (unsigned long)STEXT_OFFSET_MAX);
  }
#endif
}

/* B Phase 2: rule_arm64_text_base brackets the no-KASLR base across the
 * module-region spread for the resolved VA_BITS_MIN. A 39-bit (4K 3-level)
 * no-KASLR kernel's KIMAGE_VADDR(39) is one of {_PAGE_END(39)+128M, +256M,
 * +2G}; the size is unknown, so the window is the tight range [+128M, +2G], NOT
 * the 48-bit default the generic pin used to force. */
static void test_full_engine_arm64_va39_no_kaslr(void) {
#if defined(__aarch64__)
  struct engine e;
  engine_init(&e);
  add_scalar(&e, SF_EFI_PRESENT, 0x0);
  add_scalar(&e, SF_VIRT_KASLR_DISABLED, 0x1);
  /* PAGE_OFFSET as the probe / a directmap leak resolves it (39-bit). */
  add_addr_conf(&e, KASLD_TYPE_VIRT, REGION_PAGE_OFFSET,
                arm64_page_offset_for(39ul), 0, CONF_INFERRED, NULL);

  int nr = 0, nv = 0;
  const rule_fn *rules = engine_rules(&nr);
  const verdict_fn *vrules = engine_verdict_rules(&nv);
  engine_run_full(&e, rules, nr, vrules, nv);

  const struct estimate *vt = &e.est[Q_VIRT_IMAGE_BASE];
  unsigned long pe39 = arm64_page_end_for(39ul);
  assert(vt->lo == pe39 + 0x8000000ul);  /* +128M (smallest region) */
  assert(vt->hi == pe39 + 0x80000000ul); /* +2G   (largest region)  */
  /* Admits both a 128M-region (5.4..6.1) and a 2G-region no-KASLR text base. */
  assert(vt->lo <= pe39 + 0x8000000ul && pe39 + 0x80000000ul <= vt->hi);
#endif
}

/* 48-bit no-KASLR: the base is KIMAGE_VADDR(48), one of {_PAGE_END+128M, +256M,
 * +2G}. The window brackets the spread to [_PAGE_END+128M, _PAGE_END+2G] =
 * [0xffff800008000000, 0xffff800080000000]. The lower edge admits a 5.4..6.1
 * (128M-region) kernel's text — the bug this guards against pinned to the 2G
 * value (KERNEL_VIRT_TEXT_DEFAULT) and excluded the real low base. */
static void test_full_engine_arm64_va48_no_kaslr(void) {
#if defined(__aarch64__)
  struct engine e;
  engine_init(&e);
  add_scalar(&e, SF_EFI_PRESENT, 0x0);
  add_scalar(&e, SF_VIRT_KASLR_DISABLED, 0x1);
  add_addr_conf(&e, KASLD_TYPE_VIRT, REGION_PAGE_OFFSET,
                arm64_page_offset_for(48ul), 0, CONF_INFERRED, NULL);

  int nr = 0, nv = 0;
  const rule_fn *rules = engine_rules(&nr);
  const verdict_fn *vrules = engine_verdict_rules(&nv);
  engine_run_full(&e, rules, nr, vrules, nv);

  const struct estimate *vt = &e.est[Q_VIRT_IMAGE_BASE];
  assert(vt->lo == 0xffff800008000000ul); /* _PAGE_END(48) + 128M */
  assert(vt->hi == (unsigned long)KERNEL_VIRT_TEXT_DEFAULT); /* +2G */
  /* Both the 128M-region truth and the 2G default sit inside the window. */
  assert(vt->lo <= 0xffff800008000000ul && 0xffff800008000000ul <= vt->hi);
  assert(vt->lo <= (unsigned long)KERNEL_VIRT_TEXT_DEFAULT &&
         (unsigned long)KERNEL_VIRT_TEXT_DEFAULT <= vt->hi);
#endif
}

/* 48-bit KASLR-ON with no text leak: rule_arm64_text_base re-narrows the
 * (union, Phase-1-widened) honest top back to the 48-bit KASLR band once
 * PAGE_OFFSET resolves. The floor uses the smallest module region
 * (_PAGE_END(48)+128M) so a 5.4..6.1 kernel's lower text base is admitted; the
 * ceiling is still the 2G-region KASLR-window top (KASLR_VIRT_TEXT_MAX). */
static void test_full_engine_arm64_va48_kaslr_window(void) {
#if defined(__aarch64__)
  struct engine e;
  engine_init(&e);
  add_scalar(&e, SF_EFI_PRESENT, 0x0); /* KASLR on: no disabled signal */
  add_addr_conf(&e, KASLD_TYPE_VIRT, REGION_PAGE_OFFSET,
                arm64_page_offset_for(48ul), 0, CONF_INFERRED, NULL);

  int nr = 0, nv = 0;
  const rule_fn *rules = engine_rules(&nr);
  const verdict_fn *vrules = engine_verdict_rules(&nv);
  engine_run_full(&e, rules, nr, vrules, nv);

  const struct estimate *vt = &e.est[Q_VIRT_IMAGE_BASE];
  assert(vt->lo == arm64_page_end_for(48ul) + 0x8000000ul); /* +128M floor */
  assert(vt->hi == (unsigned long)KASLR_VIRT_TEXT_MAX);
  /* Proves the narrowing happened: the union ceiling is strictly higher. */
  assert(vt->hi < (unsigned long)KASLR_VIRT_TEXT_MAX_WIDE);
#endif
}

/* A sub-48 (39-bit) KASLR-on kernel resolves to its own text band — floor at
 * the smallest-region KIMAGE_VADDR(39) (_PAGE_END(39)+128M), ceiling at the
 * largest-region base plus the max KASLR offset — narrower than and disjoint
 * from the 48-bit window. compute_kaslr_info derives the entropy/slot count
 * from this resolved band, so reporting is VA_BITS-correct for free; this
 * guards that the band itself is right. */
static void test_full_engine_arm64_va39_kaslr_window(void) {
#if defined(__aarch64__)
  struct engine e;
  engine_init(&e);
  add_scalar(&e, SF_EFI_PRESENT, 0x0); /* KASLR on: no disabled signal */
  add_addr_conf(&e, KASLD_TYPE_VIRT, REGION_PAGE_OFFSET,
                arm64_page_offset_for(39ul), 0, CONF_INFERRED, NULL);

  int nr = 0, nv = 0;
  const rule_fn *rules = engine_rules(&nr);
  const verdict_fn *vrules = engine_verdict_rules(&nv);
  engine_run_full(&e, rules, nr, vrules, nv);

  unsigned long pe39 = arm64_page_end_for(39ul);
  unsigned long ceiling39 = pe39 + 0x80000000ul + (1ul << 36) + (1ul << 37);
  const struct estimate *vt = &e.est[Q_VIRT_IMAGE_BASE];
  assert(vt->lo == pe39 + 0x8000000ul); /* +128M floor */
  assert(vt->hi == ceiling39);          /* +2G base + max offset */
  /* Disjoint from the 48-bit window — its own narrower band. */
  assert(vt->lo > (unsigned long)KASLR_VIRT_TEXT_MAX);
#endif
}

/* Pre-v5.4 arm64 layout (e.g. v4.14): the kernel image sits LOW, below
 * _PAGE_END, at VA_START(48) + 128 MiB module region; _text a TEXT_OFFSET above
 * (real v4.14 value 0xffff000008080000). On the unprivileged/hardened profile
 * no leak resolves PAGE_OFFSET, so rule_arm64_text_base does not re-narrow and
 * Q_VIRT_IMAGE_BASE stays at its honest top — which must admit the real low
 * text base. Guards the KASLR_VIRT_TEXT_MIN_WIDE floor end-to-end through the
 * full registry; without the widened floor the window starts at KIMAGE_VADDR
 * (0xffff800080000000) and excludes the truth. */
static void test_full_engine_arm64_old_layout_sound(void) {
#if defined(__aarch64__)
  struct engine e;
  engine_init(&e);
  add_scalar(&e, SF_EFI_PRESENT, 0x0); /* file-only floor: no narrowing leak */

  int nr = 0, nv = 0;
  const rule_fn *rules = engine_rules(&nr);
  const verdict_fn *vrules = engine_verdict_rules(&nv);
  engine_run_full(&e, rules, nr, vrules, nv);

  const unsigned long t_text = 0xffff000008080000ul; /* v4.14 _text */
  const struct estimate *vt = &e.est[Q_VIRT_IMAGE_BASE];
  assert(!estimate_is_bottom(vt, &quantities[Q_VIRT_IMAGE_BASE]));
  assert(vt->lo <= t_text && t_text <= vt->hi);
#endif
}

/* Pre-v6.8 s390 runs identity-mapped: kernel text near address 0 (image base at
 * the bottom of RAM, _stext at IMAGE_BASE_OFFSET = 0x100000). With no text /
 * module leak (the hardened file-only floor) Q_VIRT_IMAGE_BASE and
 * Q_PHYS_IMAGE_BASE stay at their honest tops, which must admit that low base.
 * Guards both s390 identity-map floors: KASLR_VIRT_TEXT_MIN_WIDE=0 on the
 * virtual side (else the window floors at the modern ~4 TiB
 * KASLR_VIRT_TEXT_MIN) and KASLR_PHYS_MIN_WIDE=KERNEL_PHYS_MIN on the physical
 * side (else it floors at the derived KASLR_PHYS_MIN = _stext floor 0x100000
 * and excludes the true image base, rejecting the parsed low-base pin). */
static void test_full_engine_s390_old_identity_map_sound(void) {
#if defined(__s390__) || defined(__s390x__)
  struct engine e;
  engine_init(&e);
  add_scalar(&e, SF_EFI_PRESENT, 0x0); /* file-only floor: no narrowing leak */

  int nr = 0, nv = 0;
  const rule_fn *rules = engine_rules(&nr);
  const verdict_fn *vrules = engine_verdict_rules(&nv);
  engine_run_full(&e, rules, nr, vrules, nv);

  const struct estimate *vt = &e.est[Q_VIRT_IMAGE_BASE];
  assert(!estimate_is_bottom(vt, &quantities[Q_VIRT_IMAGE_BASE]));
  /* _text near 0 (real v4.14 value 0x200) and _stext at IMAGE_BASE_OFFSET. */
  assert(vt->lo <= 0x200ul && 0x200ul <= vt->hi);
  assert(vt->lo <= (unsigned long)IMAGE_BASE_OFFSET &&
         (unsigned long)IMAGE_BASE_OFFSET <= vt->hi);

  /* Physical image base (_text = __kaslr_offset_phys) is identity-mapped low
   * too: a real v4.14 boot shows iomem "Kernel code" starting at phys 0x200. */
  const struct estimate *pt = &e.est[Q_PHYS_IMAGE_BASE];
  assert(!estimate_is_bottom(pt, &quantities[Q_PHYS_IMAGE_BASE]));
  assert(pt->lo <= 0x200ul && 0x200ul <= pt->hi);
  assert(pt->lo <= (unsigned long)KERNEL_PHYS_MIN &&
         (unsigned long)KERNEL_PHYS_MIN <= pt->hi);
#endif
}

/* Property test: over a seeded family of valid x86_64 layouts and a random
 * subset of the faithful leaks each would produce, the resolved window of every
 * quantity must still contain the truth — in the all-signals (likely) window
 * AND the sound-floor (guaranteed) window. Generalizes
 * test_full_engine_x86_64_leaky from one hand-picked truth to thousands.
 * Soundness only: a rule that emits nothing passes (precision is the per-rule
 * unit tests' job). A failure prints the seed, which reproduces the case
 * exactly for promotion to a fixed test. */
static void test_full_engine_property_x86_64(void) {
#if defined(__x86_64__)
  int nr = 0, nv = 0;
  const rule_fn *rules = engine_rules(&nr);
  const verdict_fn *vrules = engine_verdict_rules(&nv);
  const unsigned long ITERS = 2000;
  for (unsigned long seed = 0; seed < ITERS; seed++) {
    struct prop_rng r = {seed * 0x100000001B3ull + 0xCBF29CE484222325ull};

    /* --- a valid, aligned x86_64 truth (real KASLR windows) --- */
    /* Image geometry first: the base ceilings (base + image <= window max, a
     * real kernel's image fits inside the KASLR window) depend on it. */
    unsigned long gap =
        (1ul + prop_rand(&r) % 16ul) * 0x100000ul; /* 1..16 MiB */
    unsigned long image =
        gap + (prop_rand(&r) % 16ul) * 0x100000ul; /* >= gap */
    unsigned long virt =
        prop_aligned(&r, (unsigned long)KASLR_VIRT_TEXT_MIN,
                     (unsigned long)KASLR_VIRT_TEXT_MAX - image,
                     (unsigned long)KASLR_VIRT_ALIGN);
    unsigned long phys = prop_aligned(&r, (unsigned long)KASLR_PHYS_MIN,
                                      (unsigned long)KASLR_PHYS_MAX - image,
                                      (unsigned long)KASLR_PHYS_ALIGN);
    /* L4 direct-map base: 1 GiB-aligned, a bounded random offset above it. */
    unsigned long po = (unsigned long)PAGE_OFFSET_BASE_L4 +
                       (unsigned long)(prop_rand(&r) % 0x1000ull) *
                           (unsigned long)RANDOMIZE_MEMORY_ALIGN;
    unsigned long memtotal = phys + image +
                             (unsigned long)(prop_rand(&r) % 0x40000000ull) +
                             0x10000000ul;

    struct engine e;
    engine_init(&e);

    /* --- a random subset of faithful leaks (all consistent with the truth) ---
     */
    if (prop_coin(&r))
      add_addr(&e, KASLD_TYPE_VIRT, REGION_KERNEL_TEXT,
               virt + (unsigned long)STEXT_OFFSET, 0, "_stext");
    if (prop_coin(&r))
      add_addr(&e, KASLD_TYPE_VIRT, REGION_KERNEL_DATA, virt + gap, 0,
               "_edata");
    if (prop_coin(&r))
      add_addr(&e, KASLD_TYPE_PHYS, REGION_KERNEL_TEXT, phys, 0, "_stext");
    if (prop_coin(&r))
      add_addr(&e, KASLD_TYPE_VIRT, REGION_DIRECTMAP,
               po + (unsigned long)(prop_rand(&r) % 0x10000000ull), 0, NULL);
    if (prop_coin(&r))
      add_addr(&e, KASLD_TYPE_PHYS, REGION_RAM, 0, memtotal - 1, NULL);
    if (prop_coin(&r))
      add_scalar(&e, SF_IMAGE_SIZE_MIN,
                 image); /* lower bound on the footprint */
    if (prop_coin(&r))
      add_scalar(&e, SF_PHYS_MEMTOTAL, memtotal);
    if (prop_coin(&r))
      add_scalar(&e, SF_PHYS_ADDR_BITS, 46);
    if (prop_coin(&r))
      add_scalar(&e, SF_PHYS_KERNEL_ALIGN, (unsigned long)KASLR_PHYS_ALIGN);

    struct prop_check chk[] = {
        {Q_VIRT_IMAGE_BASE, virt},
        {Q_PHYS_IMAGE_BASE, phys},
        {Q_PAGE_OFFSET, po},
    };
    prop_check_containment(&e, rules, nr, vrules, nv, chk,
                           (int)(sizeof(chk) / sizeof(chk[0])), "x86_64", seed);
  }
#endif
}

/* Property test (adversarial / floor invariant). Generalizes
 * test_full_engine_floor_invariant from one fixed baseline + two fixed
 * injection values to a seeded family: over random truths and windows, a
 * below-floor wrong base pin must NEVER move the guaranteed window (which
 * resolves at CONF_INFERRED), while the SAME pin at CONF_PARSED MUST (the
 * per-iteration positive control proves the injection is live, not vacuously
 * ignored). This is the property whose failure is the guaranteed-window
 * hole-carving / size-pin bug class — a rule reading a below-floor observation
 * into an at-floor constraint. */
static void test_full_engine_property_x86_64_floor(void) {
#if defined(__x86_64__)
  int nr = 0, nv = 0;
  const rule_fn *rules = engine_rules(&nr);
  const verdict_fn *vrules = engine_verdict_rules(&nv);

  const unsigned long ITERS = 1500;
  for (unsigned long seed = 0; seed < ITERS; seed++) {
    struct prop_rng r = {seed * 0x100000001B3ull + 0x1234567ull};

    unsigned long gap = (1ul + prop_rand(&r) % 16ul) * 0x100000ul;
    unsigned long image = gap + (prop_rand(&r) % 16ul) * 0x100000ul;
    unsigned long virt =
        prop_aligned(&r, (unsigned long)KASLR_VIRT_TEXT_MIN,
                     (unsigned long)KASLR_VIRT_TEXT_MAX - image,
                     (unsigned long)KASLR_VIRT_ALIGN);
    unsigned long phys = prop_aligned(&r, (unsigned long)KASLR_PHYS_MIN,
                                      (unsigned long)KASLR_PHYS_MAX - image,
                                      (unsigned long)KASLR_PHYS_ALIGN);
    unsigned long memtotal = phys + image +
                             (unsigned long)(prop_rand(&r) % 0x40000000ull) +
                             0x10000000ul;

    struct prop_axis axes[] = {
        {KASLD_TYPE_VIRT, Q_VIRT_IMAGE_BASE, virt,
         (unsigned long)KASLR_VIRT_ALIGN, (unsigned long)KASLR_VIRT_TEXT_MIN,
         (unsigned long)KASLR_VIRT_TEXT_MAX},
        {KASLD_TYPE_PHYS, Q_PHYS_IMAGE_BASE, phys,
         (unsigned long)KASLR_PHYS_ALIGN, (unsigned long)KASLR_PHYS_MIN,
         (unsigned long)KASLR_PHYS_MAX},
    };
    prop_check_floor(rules, nr, vrules, nv, memtotal, image, axes, 2, &r,
                     "x86_64", seed);
  }
#endif
}

/* Property test: arm64 whole-engine containment. arm64 is decoupled like x86_64
 * (virt/phys text randomize independently) but with a 64 KiB granule, a nonzero
 * .head.text gap (STEXT_OFFSET), and a honest top spanning the VA_BITS configs
 * — so it drives a distinct set of arch rules over the same invariant. Default
 * (48-bit) placements: with no VA_BITS signal, Q_VA_BITS stays the full
 * candidate set and the virt honest top is the config union (which contains a
 * 48-bit base); the faithful leaks must narrow toward the truth, not past it.
 */
static void test_full_engine_property_arm64(void) {
#if defined(__aarch64__)
  int nr = 0, nv = 0;
  const rule_fn *rules = engine_rules(&nr);
  const verdict_fn *vrules = engine_verdict_rules(&nv);
  const unsigned long ITERS = 2000;
  for (unsigned long seed = 0; seed < ITERS; seed++) {
    struct prop_rng r = {seed * 0x100000001B3ull + 0xA5A5A5A5ull};

    /* The head gap from _text to _stext. Written out rather than read from
     * STEXT_OFFSET / STEXT_OFFSET_MAX, since a generator drawing from the
     * constant under test cannot contradict it: 64 KiB is the granule the head
     * is rounded to, and 2 MiB the segment alignment a kernel that aligns
     * rodata to a section boundary produces. */
    const unsigned long heads[] = {0x10000ul, 0x200000ul};
    unsigned long head =
        heads[prop_rand(&r) % (sizeof(heads) / sizeof(heads[0]))];
    unsigned long gap =
        (1ul + prop_rand(&r) % 16ul) * 0x100000ul; /* 1..16 MiB */
    unsigned long image =
        gap + (prop_rand(&r) % 16ul) * 0x100000ul; /* >= gap */
    /* _stext lies inside the image, so a declared minimum size below the head
     * gap would be evidence contradicting itself. */
    if (image < head + 0x100000ul)
      image = head + 0x100000ul;
    /* arm64 couples the virt/phys text residues mod MIN_KIMG_ALIGN (2 MiB) —
     * the granule the kernel image is mapped with; arm64_text_phys_residue pins
     * virt's residue to phys's. Generate both 2 MiB-aligned (residue 0): a
     * faithful placement (real arm64 bases are MIN_KIMG_ALIGN-aligned) that
     * satisfies the coupling. A finer-aligned truth violates that C_STRIDE —
     * invisible to the interval containment check, caught by Phase 3. (phys
     * floor at 2 MiB rather than 0: a phys base of 0 is not realistic.) */
    const unsigned long kimg = 0x200000ul; /* MIN_KIMG_ALIGN */
    unsigned long virt =
        prop_aligned(&r, (unsigned long)KASLR_VIRT_TEXT_MIN,
                     (unsigned long)KASLR_VIRT_TEXT_MAX - image, kimg);
    unsigned long phys =
        prop_aligned(&r, kimg, (unsigned long)KASLR_PHYS_MAX - image, kimg);
    unsigned long memtotal = phys + image +
                             (unsigned long)(prop_rand(&r) % 0x40000000ull) +
                             0x10000000ul;

    struct engine e;
    engine_init(&e);

    if (prop_coin(&r))
      add_addr(&e, KASLD_TYPE_VIRT, REGION_KERNEL_TEXT, virt + head, 0,
               "_stext");
    if (prop_coin(&r))
      add_addr(&e, KASLD_TYPE_VIRT, REGION_KERNEL_DATA, virt + gap, 0,
               "_edata");
    /* Faithful phys _stext = phys image base + the .head.text gap (the same
     * image-internal offset in virt and phys space). */
    if (prop_coin(&r))
      add_addr(&e, KASLD_TYPE_PHYS, REGION_KERNEL_TEXT, phys + head, 0,
               "_stext");
    /* The image base itself, on both axes. A witness at _text is exact whatever
     * the head gap turns out to be, so it resolves through a different path in
     * the pin rule than the _stext witnesses above — where the gap is a range
     * rather than a single value, the equality is reached only from here. */
    if (prop_coin(&r))
      add_addr(&e, KASLD_TYPE_VIRT, REGION_KERNEL_IMAGE, virt, 0, "_text");
    if (prop_coin(&r))
      add_addr(&e, KASLD_TYPE_PHYS, REGION_KERNEL_IMAGE, phys, 0, "_text");
    if (prop_coin(&r))
      add_addr(&e, KASLD_TYPE_PHYS, REGION_RAM, 0, memtotal - 1, NULL);
    if (prop_coin(&r))
      add_scalar(&e, SF_IMAGE_SIZE_MIN, image);
    if (prop_coin(&r))
      add_scalar(&e, SF_PHYS_MEMTOTAL, memtotal);
    if (prop_coin(&r))
      add_scalar(&e, SF_PHYS_ADDR_BITS, 48);

    /* arm64's allocator draws a bounding box that must contain [_text, _end]
     * and is at most MODULES_BRACKET_TEXT wide, so its base lies in
     * [_end - W, _text] — clamped to the band the arch declares. */
    unsigned long mod_lo = virt + image - (unsigned long)MODULES_BRACKET_TEXT;
    if (mod_lo < (unsigned long)MODULES_START)
      mod_lo = (unsigned long)MODULES_START;
    /* The box contains [_text, _end], so it reaches above the image; it is at
     * most W wide and cannot leave the declared band. */
    unsigned long mod_top = mod_lo + (unsigned long)MODULES_BRACKET_TEXT;
    if (mod_top > (unsigned long)MODULES_END)
      mod_top = (unsigned long)MODULES_END;
    unsigned long mbase = prop_module_region(&r, &e, mod_lo, virt, mod_top);

    struct prop_check chk[] = {
        {Q_VIRT_IMAGE_BASE, virt},
        {Q_PHYS_IMAGE_BASE, phys},
        {Q_MODULE_BASE, mbase},
    };
    prop_check_containment(&e, rules, nr, vrules, nv, chk,
                           (int)(sizeof(chk) / sizeof(chk[0])), "arm64", seed);
  }
#endif
}

/* Property test: riscv64 whole-engine containment. Decoupled KASLR, 2 MiB
 * granule, STEXT_OFFSET 0 (the KASLD image base is the _stext value here). Same
 * faithful-leak set as the other decoupled arches. */
static void test_full_engine_property_riscv64(void) {
#if (defined(__riscv) || defined(__riscv__)) && __riscv_xlen == 64
  int nr = 0, nv = 0;
  const rule_fn *rules = engine_rules(&nr);
  const verdict_fn *vrules = engine_verdict_rules(&nv);

  const unsigned long ITERS = 2000;
  for (unsigned long seed = 0; seed < ITERS; seed++) {
    struct prop_rng r = {seed * 0x100000001B3ull + 0x5C711Full};

    unsigned long gap = (1ul + prop_rand(&r) % 16ul) * 0x100000ul;
    unsigned long image = gap + (prop_rand(&r) % 16ul) * 0x100000ul;
    /* _text is not where the image starts. The linker emits _start, then the
     * head section rounded up to a page, and only then _text (vmlinux.lds.S:
     * `_start = .; HEAD_TEXT_SECTION; . = ALIGN(PAGE_SIZE); ... _text = .;`).
     * That head carries the EFI PE/COFF header, the SBI entry stub and the
     * paging-mode handoff, and measures 0x2000 on every riscv64 kernel booted.
     * A _text sitting exactly on the KASLR grid would mean a zero-length head,
     * which is not an image this arch can produce, so the truth is drawn as
     * grid + head. The literal is deliberate: reading the arch's own constant
     * here would make the generator agree with whatever that constant says
     * rather than test it. */
    const unsigned long head = 0x2000ul;
    unsigned long start =
        prop_aligned(&r, (unsigned long)KASLR_VIRT_TEXT_MIN,
                     (unsigned long)KASLR_VIRT_TEXT_MAX - image - head,
                     (unsigned long)KASLR_VIRT_ALIGN);
    unsigned long virt = start + head;
    unsigned long phys = prop_aligned(&r, (unsigned long)KASLR_PHYS_MIN,
                                      (unsigned long)KASLR_PHYS_MAX - image,
                                      (unsigned long)KASLR_PHYS_ALIGN);
    unsigned long memtotal = phys + image +
                             (unsigned long)(prop_rand(&r) % 0x40000000ull) +
                             0x10000000ul;

    struct engine e;
    engine_init(&e);
    if (prop_coin(&r))
      add_addr(&e, KASLD_TYPE_VIRT, REGION_KERNEL_TEXT,
               virt + (unsigned long)STEXT_OFFSET, 0, "_stext");
    if (prop_coin(&r))
      add_addr(&e, KASLD_TYPE_VIRT, REGION_KERNEL_DATA, virt + gap, 0,
               "_edata");
    if (prop_coin(&r))
      add_addr(&e, KASLD_TYPE_PHYS, REGION_KERNEL_TEXT,
               phys + (unsigned long)STEXT_OFFSET, 0, "_stext");
    if (prop_coin(&r))
      add_addr(&e, KASLD_TYPE_PHYS, REGION_RAM, 0, memtotal - 1, NULL);
    if (prop_coin(&r))
      add_scalar(&e, SF_IMAGE_SIZE_MIN, image);
    if (prop_coin(&r))
      add_scalar(&e, SF_PHYS_MEMTOTAL, memtotal);
    if (prop_coin(&r))
      add_scalar(&e, SF_PHYS_ADDR_BITS, 48);

    /* Text-anchored: the region sits below the image, within a fixed span of
     * it, so the window slides with the drawn text base. */
    unsigned long mod_lo = virt - (unsigned long)MODULES_END_TO_TEXT_OFFSET;
    if (mod_lo < (unsigned long)MODULES_START)
      mod_lo = (unsigned long)MODULES_START;
    /* The region ends where the image starts, and the image starts a head
     * below _text (IMAGE_BASE_OFFSET), so the last address the allocator can
     * hand out is below _start — not below _text. The gap between the two is
     * the image's own head, which belongs to no module. */
    unsigned long mbase = prop_module_region(&r, &e, mod_lo, virt, start);

    struct prop_check chk[] = {
        {Q_VIRT_IMAGE_BASE, virt},
        {Q_PHYS_IMAGE_BASE, phys},
        {Q_MODULE_BASE, mbase},
    };
    prop_check_containment(&e, rules, nr, vrules, nv, chk,
                           (int)(sizeof(chk) / sizeof(chk[0])), "riscv64",
                           seed);
  }
#endif
}

/* Property test: s390 whole-engine containment. Decoupled KASLR, 16 KiB virt /
 * 1 MiB phys granule, STEXT_OFFSET 0. Same faithful-leak set. */
static void test_full_engine_property_s390(void) {
#if defined(__s390x__)
  int nr = 0, nv = 0;
  const rule_fn *rules = engine_rules(&nr);
  const verdict_fn *vrules = engine_verdict_rules(&nv);

  const unsigned long ITERS = 2000;
  for (unsigned long seed = 0; seed < ITERS; seed++) {
    struct prop_rng r = {seed * 0x100000001B3ull + 0x53390ull};

    unsigned long gap = (1ul + prop_rand(&r) % 16ul) * 0x100000ul;
    unsigned long image = gap + (prop_rand(&r) % 16ul) * 0x100000ul;
    /* s390 couples text_virt ≡ phys_anchor mod _SEGMENT_SIZE (1 MiB). phys is
     * already 1 MiB-aligned (KASLR_PHYS_ALIGN), so generate virt 1 MiB-aligned
     * too (residue 0) to satisfy s390_text_segment_mod's C_STRIDE — which the
     * interval containment check can't see, but Phase 3 does. */
    const unsigned long seg = 0x100000ul; /* _SEGMENT_SIZE */
    unsigned long virt =
        prop_aligned(&r, (unsigned long)KASLR_VIRT_TEXT_MIN,
                     (unsigned long)KASLR_VIRT_TEXT_MAX - image, seg);
    unsigned long phys = prop_aligned(&r, (unsigned long)KASLR_PHYS_MIN,
                                      (unsigned long)KASLR_PHYS_MAX - image,
                                      (unsigned long)KASLR_PHYS_ALIGN);
    unsigned long memtotal = phys + image +
                             (unsigned long)(prop_rand(&r) % 0x40000000ull) +
                             0x10000000ul;

    struct engine e;
    engine_init(&e);
    if (prop_coin(&r))
      add_addr(&e, KASLD_TYPE_VIRT, REGION_KERNEL_TEXT,
               virt + (unsigned long)STEXT_OFFSET, 0, "_stext");
    if (prop_coin(&r))
      add_addr(&e, KASLD_TYPE_VIRT, REGION_KERNEL_DATA, virt + gap, 0,
               "_edata");
    if (prop_coin(&r))
      add_addr(&e, KASLD_TYPE_PHYS, REGION_KERNEL_TEXT,
               phys + (unsigned long)STEXT_OFFSET, 0, "_stext");
    if (prop_coin(&r))
      add_addr(&e, KASLD_TYPE_PHYS, REGION_RAM, 0, memtotal - 1, NULL);
    if (prop_coin(&r))
      add_scalar(&e, SF_IMAGE_SIZE_MIN, image);
    if (prop_coin(&r))
      add_scalar(&e, SF_PHYS_MEMTOTAL, memtotal);

    /* Text-anchored, as on riscv64: the region lies below the image within a
     * fixed span, so its window moves with the drawn base. */
    unsigned long mod_lo = virt - (unsigned long)MODULES_END_TO_TEXT_OFFSET;
    if (mod_lo < (unsigned long)MODULES_START)
      mod_lo = (unsigned long)MODULES_START;
    /* Same shape as riscv64: the region ends where the image starts, a head
     * below _text. */
    unsigned long mbase = prop_module_region(
        &r, &e, mod_lo, virt, virt - (unsigned long)IMAGE_BASE_OFFSET);

    struct prop_check chk[] = {
        {Q_VIRT_IMAGE_BASE, virt},
        {Q_PHYS_IMAGE_BASE, phys},
        {Q_MODULE_BASE, mbase},
    };
    prop_check_containment(&e, rules, nr, vrules, nv, chk,
                           (int)(sizeof(chk) / sizeof(chk[0])), "s390", seed);
  }
#endif
}

/* The coupled projection the x86_32 property fixtures need.
 *
 * api.h exposes phys_to_directmap_virt() only where the linear-map base is
 * known at build time, and x86_32's is a VMSPLIT choice, so the macro is
 * deliberately absent there. These fixtures are not analysing a target: they
 * CONSTRUCT a synthetic kernel and pin its page offset themselves (see the
 * REGION_PAGE_OFFSET landmark each adds). Projecting through that same chosen
 * base is therefore exact by construction, and keeping it in one place keeps
 * the projection and the landmark from drifting apart. */
#if defined(__i386__) /* both callers are x86_32-only */
static unsigned long fixture_coupled_virt(unsigned long phys) {
  return phys - (unsigned long)PHYS_OFFSET + (unsigned long)PAGE_OFFSET;
}
#endif

/* Property test: x86_32 whole-engine containment — a COUPLED arch. Kernel text
 * sits in the linear map, so virt and phys text bases share one KASLR slide:
 * virt = fixture_coupled_virt(phys). The generator draws phys and derives
 * virt; a random leak subset (sometimes phys-only or virt-only) forces
 * text_base_coupling_synth to reconstruct the other side, so this exercises the
 * coupling-rule family the decoupled tests never reach. STEXT_OFFSET 0. */
static void test_full_engine_property_x86_32(void) {
#if defined(__i386__)
  int nr = 0, nv = 0;
  const rule_fn *rules = engine_rules(&nr);
  const verdict_fn *vrules = engine_verdict_rules(&nv);

  const unsigned long ITERS = 2000;
  for (unsigned long seed = 0; seed < ITERS; seed++) {
    struct prop_rng r = {seed * 0x100000001B3ull + 0x86326ull};

    unsigned long gap = (1ul + prop_rand(&r) % 16ul) * 0x100000ul;
    unsigned long image = gap + (prop_rand(&r) % 16ul) * 0x100000ul;
    unsigned long phys = prop_aligned(&r, (unsigned long)KASLR_PHYS_ALIGN,
                                      (unsigned long)KASLR_PHYS_MAX - image,
                                      (unsigned long)KASLR_PHYS_ALIGN);
    /* Coupled: the virtual text base tracks phys in the linear map. */
    /* The linear-map base is DRAWN, not read from the compile-time constant.
     * x86_32's split is a Kconfig choice and the analysing build's value says
     * nothing about the target's — projecting through PAGE_OFFSET here would
     * make every iteration agree with this build by construction, which is the
     * one mistake on this arch the engine is written to avoid. */
    const unsigned long po_choices[] = PAGE_OFFSET_CANDIDATES;
    unsigned long po = po_choices[prop_rand(&r) %
                                  (sizeof(po_choices) / sizeof(po_choices[0]))];
    unsigned long virt = phys - (unsigned long)PHYS_OFFSET + po;
    unsigned long memtotal = phys + image +
                             (unsigned long)(prop_rand(&r) % 0x08000000ull) +
                             0x02000000ul;

    struct engine e;
    engine_init(&e);
    /* A page-offset landmark pins Q_PAGE_OFFSET to the (default vmsplit)
     * linear- map base — a real 32-bit kernel has a definite PAGE_OFFSET. This
     * is what enables text_base_coupling_synth (it projects only when
     * PAGE_OFFSET is pinned), so the phys-only / virt-only subsets below
     * exercise the coupling reconstruction rather than leaving the two bases
     * independent. */
    add_addr(&e, KASLD_TYPE_VIRT, REGION_PAGE_OFFSET, po, 0, "page_offset");
    if (prop_coin(&r))
      add_addr(&e, KASLD_TYPE_VIRT, REGION_KERNEL_TEXT,
               virt + (unsigned long)STEXT_OFFSET, 0, "_stext");
    if (prop_coin(&r))
      add_addr(&e, KASLD_TYPE_VIRT, REGION_KERNEL_DATA, virt + gap, 0,
               "_edata");
    if (prop_coin(&r))
      add_addr(&e, KASLD_TYPE_PHYS, REGION_KERNEL_TEXT,
               phys + (unsigned long)STEXT_OFFSET, 0, "_stext");
    if (prop_coin(&r))
      add_addr(&e, KASLD_TYPE_PHYS, REGION_RAM, 0, memtotal - 1, NULL);
    if (prop_coin(&r))
      add_scalar(&e, SF_IMAGE_SIZE_MIN, image);
    if (prop_coin(&r))
      add_scalar(&e, SF_PHYS_MEMTOTAL, memtotal);

    /* The module region starts where low memory ends, not at a constant:
     * MODULES_VADDR is VMALLOC_START, which is high_memory + VMALLOC_OFFSET,
     * and high_memory is the linear-map base plus however much low memory the
     * machine has (pgtable_32_areas.h, init_32.c). So the base moves with the
     * split AND with RAM, and it is COMPUTED here from the same memtotal the
     * evidence describes rather than drawn on its own — drawing it would put
     * the region somewhere this machine's memory does not place it. The arch's
     * MODULES_START_FOR(po) is the floor of that, the value at zero low
     * memory, which is what makes it a sound bound rather than the base. */
    unsigned long lowmem = memtotal;
    if (lowmem > po - (unsigned long)PHYS_OFFSET)
      lowmem = po - (unsigned long)PHYS_OFFSET;
    unsigned long mbase = prop_module_region(
        &r, &e, po + lowmem + 0x800000ul, po + lowmem + 0x800000ul,
        (unsigned long)MODULES_END_FOR(po));

    struct prop_check chk[] = {
        {Q_VIRT_IMAGE_BASE, virt},
        {Q_PHYS_IMAGE_BASE, phys},
        {Q_PAGE_OFFSET, po},
        {Q_MODULE_BASE, mbase},
    };
    prop_check_containment(&e, rules, nr, vrules, nv, chk,
                           (int)(sizeof(chk) / sizeof(chk[0])), "x86_32", seed);
  }
#endif
}

/* Property test: riscv32 whole-engine containment. KASLR is off and the split
 * is fixed by the build, so the image base does not move; what moves is the
 * board. The linear map is anchored to the base of DRAM, a runtime discovery,
 * so the same image sits at a different PHYSICAL address on every machine while
 * its virtual address stays put. The property is that a physical witness from
 * one board never narrows the virtual base off the one place it can be, and
 * that the physical base resolved from a DRAM extent tracks the board rather
 * than the analysing build. */
static void test_full_engine_property_riscv32(void) {
#if (defined(__riscv) || defined(__riscv__)) && __riscv_xlen == 32
  int nr = 0, nv = 0;
  const rule_fn *rules = engine_rules(&nr);
  const verdict_fn *vrules = engine_verdict_rules(&nv);
  const unsigned long ITERS = 2000;

  for (unsigned long seed = 0; seed < ITERS; seed++) {
    struct prop_rng r = {seed * 0x100000001B3ull + 0x52C332ull};

    unsigned long gap = (1ul + prop_rand(&r) % 8ul) * 0x100000ul;
    unsigned long image = gap + (prop_rand(&r) % 8ul) * 0x100000ul;
    /* The board's DRAM base, on the arch's own alignment grid. */
    unsigned long dram = (unsigned long)(prop_rand(&r) % 32ull) *
                         (unsigned long)KASLR_VIRT_ALIGN;
    unsigned long virt = (unsigned long)KERNEL_VIRT_TEXT_DEFAULT;
    unsigned long phys = dram + (unsigned long)IMAGE_BASE_OFFSET;
    unsigned long memtotal =
        image + 0x04000000ul + (unsigned long)(prop_rand(&r) % 0x10000000ull);

    struct engine e;
    engine_init(&e);

    if (prop_coin(&r))
      add_addr(&e, KASLD_TYPE_VIRT, REGION_KERNEL_TEXT,
               virt + (unsigned long)STEXT_OFFSET, 0, "_stext");
    if (prop_coin(&r))
      add_addr(&e, KASLD_TYPE_VIRT, REGION_KERNEL_DATA, virt + gap, 0,
               "_edata");
    if (prop_coin(&r))
      add_addr(&e, KASLD_TYPE_PHYS, REGION_RAM, dram, dram + memtotal - 1,
               NULL);
    if (prop_coin(&r))
      add_scalar(&e, SF_IMAGE_SIZE_MIN, image);
    if (prop_coin(&r))
      add_scalar(&e, SF_PHYS_MEMTOTAL, memtotal);

    struct prop_check chk[] = {
        {Q_VIRT_IMAGE_BASE, virt},
        {Q_PHYS_IMAGE_BASE, phys},
        {Q_PAGE_OFFSET, (unsigned long)PAGE_OFFSET},
    };
    prop_check_containment(&e, rules, nr, vrules, nv, chk,
                           (int)(sizeof(chk) / sizeof(chk[0])), "riscv32",
                           seed);
  }
#endif
}

/* Property test: ppc64 whole-engine containment. KASLR is off, but the kernel
 * is relocatable: firmware can place the image somewhere other than the bottom
 * of memory, which is the ordinary case under kdump. The linear map is anchored
 * at a compile-time PHYS_OFFSET, so that placement carries straight through to
 * the virtual base — one slide, no randomization. Drawing it is what keeps the
 * property about the coupling rather than about the default. */
static void test_full_engine_property_ppc64(void) {
#if defined(__powerpc64__) || defined(__ppc64__)
  int nr = 0, nv = 0;
  const rule_fn *rules = engine_rules(&nr);
  const verdict_fn *vrules = engine_verdict_rules(&nv);
  const unsigned long ITERS = 2000;

  for (unsigned long seed = 0; seed < ITERS; seed++) {
    struct prop_rng r = {seed * 0x100000001B3ull + 0x99C640ull};

    unsigned long gap = (1ul + prop_rand(&r) % 16ul) * 0x100000ul;
    unsigned long image = gap + (prop_rand(&r) % 16ul) * 0x100000ul;
    unsigned long phys = prop_aligned(&r, (unsigned long)KASLR_PHYS_MIN,
                                      (unsigned long)KASLR_PHYS_MAX - image,
                                      (unsigned long)KASLR_PHYS_ALIGN);
    unsigned long virt =
        phys - (unsigned long)PHYS_OFFSET + (unsigned long)PAGE_OFFSET;
    unsigned long memtotal = phys + image +
                             (unsigned long)(prop_rand(&r) % 0x40000000ull) +
                             0x10000000ul;

    struct engine e;
    engine_init(&e);

    if (prop_coin(&r))
      add_addr(&e, KASLD_TYPE_VIRT, REGION_KERNEL_TEXT,
               virt + (unsigned long)STEXT_OFFSET, 0, "_stext");
    if (prop_coin(&r))
      add_addr(&e, KASLD_TYPE_VIRT, REGION_KERNEL_DATA, virt + gap, 0,
               "_edata");
    if (prop_coin(&r))
      add_addr(&e, KASLD_TYPE_PHYS, REGION_RAM, 0, memtotal - 1, NULL);
    if (prop_coin(&r))
      add_scalar(&e, SF_IMAGE_SIZE_MIN, image);
    if (prop_coin(&r))
      add_scalar(&e, SF_PHYS_MEMTOTAL, memtotal);

    struct prop_check chk[] = {
        {Q_VIRT_IMAGE_BASE, virt},
        {Q_PHYS_IMAGE_BASE, phys},
        {Q_PAGE_OFFSET, (unsigned long)PAGE_OFFSET},
    };
    prop_check_containment(&e, rules, nr, vrules, nv, chk,
                           (int)(sizeof(chk) / sizeof(chk[0])), "ppc64", seed);
  }
#endif
}

/* Property test: ppc32 whole-engine containment — the DRAM-anchored arch.
 *
 * ppc32 is coupled like x86_32 and mips, but where its linear map starts is
 * neither a constant nor a menu choice this side can read: the anchor is the
 * base of DRAM, discovered at runtime, and the split is a free-form Kconfig
 * value, so the arch models a RANGE rather than a candidate list. The generator
 * draws across that range, because a rule quietly assuming one of the three
 * conventional splits would pass a generator that only ever produced them.
 *
 * KASLR is on here, so the image moves as well as the map, and the two move
 * together: one slide, projected through a base the run must infer. A moving
 * image over an inferred map is what no other covered arch presents.
 *
 * The physical base is drawn across the whole admissible window, past the
 * BookE placement cap. That is deliberate: BookE and BookS cannot be told apart
 * at compile time, so ppc32_phys_ceiling models the BookE window as a HEURISTIC
 * and a BookS kernel placed above it is a configuration the arch admits and
 * that heuristic legitimately misses. Generating only BookE-reachable bases
 * would hide every rule that turns that miss into a claim the sound floor
 * admits.
 *
 * No physical image-base witness is generated: powerpc declares no "Kernel
 * code" iomem resource, so the phys side is reached only through the coupling,
 * which is the vantage a real ppc32 run has.
 *
 * Q_MODULE_BASE is not checked — the region is placed relative to the linear
 * map and the declared band is a floor over kernel-version layouts rather than
 * the base itself, so there is no truth to state from this side. */
static void test_full_engine_property_ppc32(void) {
#if (defined(__powerpc__) || defined(__PPC__)) && !defined(__powerpc64__) &&   \
    !defined(__ppc64__)
  int nr = 0, nv = 0;
  const rule_fn *rules = engine_rules(&nr);
  const verdict_fn *vrules = engine_verdict_rules(&nv);
  const unsigned long ITERS = 2000;

  for (unsigned long seed = 0; seed < ITERS; seed++) {
    struct prop_rng r = {seed * 0x100000001B3ull + 0x9C3201ull};

    unsigned long gap = (1ul + prop_rand(&r) % 8ul) * 0x100000ul;
    unsigned long image = gap + (prop_rand(&r) % 8ul) * 0x100000ul;

    /* The split, across the whole admissible range at a granularity a real
     * CONFIG_PAGE_OFFSET keeps. */
    unsigned long po =
        prop_aligned(&r, (unsigned long)PAGE_OFFSET_MIN,
                     (unsigned long)PAGE_OFFSET_MAX + 0x1000000ul, 0x1000000ul);

    /* Coupled, so the physical base must leave the projected virtual base
     * inside the text window — and on the KASLR grid, which means drawing phys
     * at the VIRTUAL alignment: the split is coarser than both, so virt and
     * phys share a residue. */
    unsigned long vmax = (unsigned long)KASLR_VIRT_TEXT_MAX - image;
    if (po >= vmax)
      continue; /* this split leaves no room for an image */
    unsigned long pmax = vmax - po;
    if (pmax > (unsigned long)KASLR_PHYS_MAX)
      pmax = (unsigned long)KASLR_PHYS_MAX;
    unsigned long phys =
        prop_aligned(&r, 0ul, pmax, (unsigned long)KASLR_VIRT_ALIGN);
    unsigned long virt = phys - (unsigned long)PHYS_OFFSET + po;
    if (virt < (unsigned long)KASLR_VIRT_TEXT_MIN)
      continue;
    unsigned long memtotal = phys + image +
                             (unsigned long)(prop_rand(&r) % 0x10000000ull) +
                             0x04000000ul;

    struct engine e;
    engine_init(&e);

    /* The kernel states its own linear-map base in the layout block; without a
     * resolved split nothing can cross between the two address spaces, which is
     * what the anchor being a runtime discovery costs here. */
    add_addr(&e, KASLD_TYPE_VIRT, REGION_PAGE_OFFSET, po, 0, "page_offset");
    if (prop_coin(&r))
      add_addr(&e, KASLD_TYPE_VIRT, REGION_KERNEL_TEXT,
               virt + (unsigned long)STEXT_OFFSET, 0, "_stext");
    if (prop_coin(&r))
      add_addr(&e, KASLD_TYPE_VIRT, REGION_KERNEL_DATA, virt + gap, 0,
               "_edata");
    if (prop_coin(&r))
      add_addr(&e, KASLD_TYPE_PHYS, REGION_RAM, 0, memtotal - 1, NULL);
    if (prop_coin(&r))
      add_scalar(&e, SF_IMAGE_SIZE_MIN, image);
    if (prop_coin(&r))
      add_scalar(&e, SF_PHYS_MEMTOTAL, memtotal);

    struct prop_check chk[] = {
        {Q_VIRT_IMAGE_BASE, virt},
        {Q_PHYS_IMAGE_BASE, phys},
        {Q_PAGE_OFFSET, po},
    };
    prop_check_containment(&e, rules, nr, vrules, nv, chk,
                           (int)(sizeof(chk) / sizeof(chk[0])), "ppc32", seed);
  }
#endif
}

/* Property test: arm32 whole-engine containment — a drawn split over a runtime
 * DRAM base, with a head gap that only bounds.
 *
 * arm32 randomizes nothing: the image base is the compile-time default. What
 * varies instead is the machine. The split is a Kconfig choice this side cannot
 * read, the physical base of DRAM is a board fact discovered at boot, and the
 * gap from _text to _stext is an ALIGN over a section boundary rather than a
 * constant. So three quantities move per iteration and none of them is KASLR.
 *
 * That combination is what makes this arch worth a property despite the static
 * window: it is the only one where the guaranteed window was observed to
 * exclude the truth in the field, on a stock kernel that publishes _stext and
 * no _text. The _stext witness here is emitted at a gap the run cannot know,
 * which is exactly that vantage.
 *
 * The gaps are drawn from the two section sizes the arch builds with — 1 MiB
 * with 2-level paging, 2 MiB under LPAE — minus the head, which is where
 * _stext lands once ALIGN has rounded past it. They are written out rather than
 * read from STEXT_OFFSET_MAX, since a generator drawing from the constant under
 * test cannot contradict it. */
static void test_full_engine_property_arm32(void) {
#if defined(__arm__) && !defined(__aarch64__)
  int nr = 0, nv = 0;
  const rule_fn *rules = engine_rules(&nr);
  const verdict_fn *vrules = engine_verdict_rules(&nv);
  const unsigned long splits[] = PAGE_OFFSET_CANDIDATES;
  /* ALIGN(_text + head, SECTION_SIZE) - _text, for the two section sizes. */
  const unsigned long heads[] = {0x100000ul - 0x8000ul, 0x200000ul - 0x8000ul};
  const unsigned long ITERS = 2000;

  for (unsigned long seed = 0; seed < ITERS; seed++) {
    struct prop_rng r = {seed * 0x100000001B3ull + 0xA3B0011ull};

    unsigned long po =
        splits[prop_rand(&r) % (sizeof(splits) / sizeof(splits[0]))];
    unsigned long head =
        heads[prop_rand(&r) % (sizeof(heads) / sizeof(heads[0]))];
    unsigned long gap = (1ul + prop_rand(&r) % 8ul) * 0x100000ul;
    unsigned long image = gap + (prop_rand(&r) % 8ul) * 0x100000ul;

    /* The board's DRAM base: a runtime fact on this arch, not a constant. The
     * linear map puts it at the split, and the image sits IMAGE_BASE_OFFSET
     * above both. */
    unsigned long dram = (unsigned long)(prop_rand(&r) % 8ull) * 0x10000000ul;
    unsigned long virt = po + (unsigned long)IMAGE_BASE_OFFSET;
    unsigned long phys = dram + (unsigned long)IMAGE_BASE_OFFSET;
    unsigned long memtotal =
        image + 0x04000000ul + (unsigned long)(prop_rand(&r) % 0x10000000ull);

    struct engine e;
    engine_init(&e);

    add_addr(&e, KASLD_TYPE_VIRT, REGION_PAGE_OFFSET, po, 0, "page_offset");
    /* The vantage the field failure came from: _stext, at a gap this side can
     * only bound. */
    if (prop_coin(&r))
      add_addr(&e, KASLD_TYPE_VIRT, REGION_KERNEL_TEXT, virt + head, 0,
               "_stext");
    /* The other vantage: _text itself, which the boot-time layout line
     * publishes directly on this arch. A witness at the image base is exact
     * whatever the head gap turns out to be, so it resolves through a different
     * path in the pin rule than the _stext one above — bounded-gap arches reach
     * the equality only from here. Both are drawn independently so an iteration
     * may carry either, both, or neither. */
    if (prop_coin(&r))
      add_addr(&e, KASLD_TYPE_VIRT, REGION_KERNEL_IMAGE, virt, 0, "_text");
    if (prop_coin(&r))
      add_addr(&e, KASLD_TYPE_PHYS, REGION_KERNEL_IMAGE, phys, 0, "_text");
    if (prop_coin(&r))
      add_addr(&e, KASLD_TYPE_VIRT, REGION_KERNEL_DATA, virt + head + gap, 0,
               "_edata");
    if (prop_coin(&r))
      add_addr(&e, KASLD_TYPE_PHYS, REGION_RAM, dram, dram + memtotal - 1,
               NULL);
    if (prop_coin(&r))
      add_scalar(&e, SF_IMAGE_SIZE_MIN, image);
    if (prop_coin(&r))
      add_scalar(&e, SF_PHYS_MEMTOTAL, memtotal);

    struct prop_check chk[] = {
        {Q_VIRT_IMAGE_BASE, virt},
        {Q_PHYS_IMAGE_BASE, phys},
        {Q_PAGE_OFFSET, po},
    };
    prop_check_containment(&e, rules, nr, vrules, nv, chk,
                           (int)(sizeof(chk) / sizeof(chk[0])), "arm32", seed);
  }
#endif
}

/* Property test: mips32 whole-engine containment — mips64's axes at 32-bit
 * width. Same coupling, same fixed linear map, same two head-gap configs; what
 * differs is that every address, the RAM total and the projections between them
 * are 32 bits wide, and the machine can hold more memory than the linear map
 * can reach.
 *
 * That last part is the reason this arch is worth its own property rather than
 * being taken as read from mips64. KSEG0 covers 512 MiB, so a generated
 * memtotal above it describes a real configuration — a highmem machine — where
 * projecting a physical address through the linear map overflows the address
 * width and wraps to a low value. A wrapped phantom below the true base is the
 * dangerous direction, since a low bound is what carves truth out of the
 * guaranteed window, and no 64-bit arch can produce it.
 *
 * Q_PAGE_OFFSET and Q_MODULE_BASE are regression nets here, as on mips64: KSEG0
 * and the module region are both fixed by the ISA, so their truths are
 * constants the engine pins from the same headers this test reads. They catch a
 * rule that empties or moves one, and nothing more. */
static void test_full_engine_property_mips32(void) {
#if defined(__mips__) && !defined(__mips64) && !defined(__mips64__)
  int nr = 0, nv = 0;
  const rule_fn *rules = engine_rules(&nr);
  const verdict_fn *vrules = engine_verdict_rules(&nv);
  const unsigned long ITERS = 2000;

  for (unsigned long seed = 0; seed < ITERS; seed++) {
    struct prop_rng r = {seed * 0x100000001B3ull + 0x3D49B5ull};

    unsigned long gap = (1ul + prop_rand(&r) % 8ul) * 0x100000ul;
    unsigned long image = gap + (prop_rand(&r) % 8ul) * 0x100000ul;
    /* The image must land where the linear map can still reach its physical
     * base: KSEG0 is the smaller of the two windows on this arch. */
    unsigned long vmax =
        (unsigned long)PAGE_OFFSET + (unsigned long)KASLR_PHYS_MAX;
    if (vmax > (unsigned long)KASLR_VIRT_TEXT_MAX)
      vmax = (unsigned long)KASLR_VIRT_TEXT_MAX;
    unsigned long virt =
        prop_aligned(&r, (unsigned long)KASLR_VIRT_TEXT_MIN, vmax - image,
                     (unsigned long)KASLR_VIRT_ALIGN);
    unsigned long phys =
        virt - (unsigned long)PAGE_OFFSET + (unsigned long)PHYS_OFFSET;
    /* The two gaps the arch ships, stated from head.S rather than read from
     * STEXT_OFFSET/STEXT_OFFSET_MAX — a generator drawing from the constants
     * under test cannot contradict them. */
    unsigned long head = prop_coin(&r) ? 0x400ul : 0ul;
    /* Deliberately allowed past the linear map's reach: a machine with more
     * RAM than KSEG0 covers is the configuration this arch adds. */
    unsigned long memtotal = phys + image +
                             (unsigned long)(prop_rand(&r) % 0x20000000ull) +
                             0x04000000ul;

    struct engine e;
    engine_init(&e);

    if (prop_coin(&r))
      add_addr(&e, KASLD_TYPE_VIRT, REGION_KERNEL_TEXT, virt + head, 0,
               "_stext");
    if (prop_coin(&r))
      add_addr(&e, KASLD_TYPE_VIRT, REGION_KERNEL_DATA, virt + gap, 0,
               "_edata");
    /* iomem's "Kernel code" is __pa_symbol(&_text) on mips, so the physical
     * witness is the image base and carries no head gap. */
    if (prop_coin(&r))
      add_addr(&e, KASLD_TYPE_PHYS, REGION_KERNEL_IMAGE, phys, 0, "_text");
    if (prop_coin(&r))
      add_addr(&e, KASLD_TYPE_PHYS, REGION_RAM, 0, memtotal - 1, NULL);
    if (prop_coin(&r))
      add_scalar(&e, SF_IMAGE_SIZE_MIN, image);
    if (prop_coin(&r))
      add_scalar(&e, SF_PHYS_MEMTOTAL, memtotal);

    struct prop_check chk[] = {
        {Q_VIRT_IMAGE_BASE, virt},
        {Q_PHYS_IMAGE_BASE, phys},
        {Q_PAGE_OFFSET, (unsigned long)PAGE_OFFSET},
        {Q_MODULE_BASE, (unsigned long)MODULES_START},
    };
    prop_check_containment(&e, rules, nr, vrules, nv, chk,
                           (int)(sizeof(chk) / sizeof(chk[0])), "mips32", seed);
  }
#endif
}

/* Property test: loongarch64 whole-engine containment — the UNBOUNDED head-gap
 * arch. Coupled like mips64, with a linear map the build knows, so the shape of
 * the generator is the same; what only this arch reaches is the third state of
 * the head-gap contract.
 *
 * _stext is ALIGN(sizeof(.head.text), 64K) above _text, and nothing in the
 * linker script fixes how much head code a build has. The arch therefore states
 * no ceiling, and a _stext witness may only say _text <= _stext — no floor at
 * all. The generator draws the gap across several granules rather than fixing
 * it at the one value measured: a single value would pass just as well
 * against a rule that had invented a floor, since the invented floor would sit
 * exactly where that value put it. Varying it is what makes the absence of a
 * floor observable.
 *
 * The gap literals are deliberate. Reading STEXT_OFFSET_MAX would draw from the
 * unbounded sentinel, and reading STEXT_OFFSET would draw zero every time —
 * either way the generator would agree with the contract instead of testing it.
 *
 * Q_MODULE_BASE is not checked. The region is at a fixed address, but the band
 * the arch declares is a union over kernel-version layouts held at
 * MOD_BAND_BOUNDS, so this side has a bound on the base and not the base
 * itself — there is no truth to state without reading the target's own
 * MODULES_VADDR.
 *
 * What this arch does NOT do is collapse the virtual base to a point the way
 * mips64 does. With no head-gap ceiling the _stext witness gives an upper edge
 * only, and the physical witness projects across the coupling with an
 * IMAGE_BASE_OFFSET safety margin — 2 MiB here — so the resolved window is
 * about that wide rather than exact. That is the arch behaving as declared, and
 * it is worth knowing when reading a failure: a truth perturbed by less than
 * the margin still lies inside the window, so only a larger perturbation
 * demonstrates this property can fail. */
static void test_full_engine_property_loongarch64(void) {
#if defined(__loongarch64) ||                                                  \
    (defined(__loongarch__) && __loongarch_grlen == 64)
  int nr = 0, nv = 0;
  const rule_fn *rules = engine_rules(&nr);
  const verdict_fn *vrules = engine_verdict_rules(&nv);
  /* Head sizes a build can produce, each a whole 64 KiB granule. */
  const unsigned long heads[] = {0x10000ul, 0x20000ul, 0x30000ul};
  const unsigned long ITERS = 2000;

  for (unsigned long seed = 0; seed < ITERS; seed++) {
    struct prop_rng r = {seed * 0x100000001B3ull + 0x10A6C4ull};

    unsigned long gap = (1ul + prop_rand(&r) % 16ul) * 0x100000ul;
    unsigned long image = gap + (prop_rand(&r) % 16ul) * 0x100000ul;
    unsigned long virt =
        prop_aligned(&r, (unsigned long)KASLR_VIRT_TEXT_MIN,
                     (unsigned long)KASLR_VIRT_TEXT_MAX - image,
                     (unsigned long)KASLR_VIRT_ALIGN);
    /* Coupled: one slide moves both bases through a map the hardware fixes. */
    unsigned long phys =
        virt - (unsigned long)PAGE_OFFSET + (unsigned long)PHYS_OFFSET;
    unsigned long head =
        heads[prop_rand(&r) % (sizeof(heads) / sizeof(heads[0]))];
    unsigned long memtotal = phys + image +
                             (unsigned long)(prop_rand(&r) % 0x40000000ull) +
                             0x10000000ul;

    struct engine e;
    engine_init(&e);

    if (prop_coin(&r))
      add_addr(&e, KASLD_TYPE_VIRT, REGION_KERNEL_TEXT, virt + head, 0,
               "_stext");
    if (prop_coin(&r))
      add_addr(&e, KASLD_TYPE_VIRT, REGION_KERNEL_DATA, virt + gap, 0,
               "_edata");
    /* iomem's "Kernel code" is __pa_symbol(&_text) here, so the physical
     * witness is the image base and carries no head gap. */
    if (prop_coin(&r))
      add_addr(&e, KASLD_TYPE_PHYS, REGION_KERNEL_IMAGE, phys, 0, "_text");
    if (prop_coin(&r))
      add_addr(&e, KASLD_TYPE_PHYS, REGION_RAM, 0, memtotal - 1, NULL);
    if (prop_coin(&r))
      add_scalar(&e, SF_IMAGE_SIZE_MIN, image);
    if (prop_coin(&r))
      add_scalar(&e, SF_PHYS_MEMTOTAL, memtotal);

    struct prop_check chk[] = {
        {Q_VIRT_IMAGE_BASE, virt},
        {Q_PHYS_IMAGE_BASE, phys},
        {Q_PAGE_OFFSET, (unsigned long)PAGE_OFFSET},
    };
    prop_check_containment(&e, rules, nr, vrules, nv, chk,
                           (int)(sizeof(chk) / sizeof(chk[0])), "loongarch64",
                           seed);
  }
#endif
}

/* Property test: x86_64 RANDOMIZE_MEMORY region placement. Separate from the
 * x86_64 image property because it varies the OTHER randomization on this arch
 * — the one that moves the direct map, vmalloc and vmemmap rather than the
 * kernel image — and it is the only place Q_VMALLOC_BASE and Q_VMEMMAP_BASE are
 * checked at all.
 *
 * The three bases are not drawn independently. kernel_randomize_memory() walks
 * ONE shared entropy budget, in a fixed order, and each region's gap is bounded
 * by what the previous ones left (arch/x86/mm/kaslr.c):
 *
 *   remain = (vaddr_end - vaddr_start) - (dm_size + vmalloc_size +
 * vmemmap_size) for i in 0..2: e_i   = (rand % (remain/(3-i) + 1)) & PUD_MASK
 *       base_i = vaddr + e_i
 *       vaddr  = round_up(base_i + size_i + 1, PUD_SIZE)
 *       remain -= e_i
 *
 * The generator runs exactly that, so the three truths are correlated the way a
 * real boot correlates them. Drawing them independently would produce layouts
 * the kernel cannot emit and would test the rules against a fiction — and it is
 * the correlation, not the individual placement, that the budget bound rests
 * on.
 *
 * Two build-time inputs are drawn as well, since neither is fixed: the physical
 * padding (CONFIG_RANDOMIZE_MEMORY_PHYSICAL_PADDING, `range 0x0 0x40` in
 * arch/x86/Kconfig, defaulting to 0xa under MEMORY_HOTPLUG) and RAM. The
 * padding matters because it enlarges the direct map and so SHRINKS the budget
 * — a model that assumed the default would be tested only against the
 * configuration it assumed.
 *
 * The layout constants are written out from the kernel rather than read from
 * the arch header, for the reason every generator here does so: reading them
 * would make this agree with whatever the header says instead of testing it.
 *
 * The three checks do not have the same resolution, and that is inherent rather
 * than a weakness of the harness. The direct-map base and the vmemmap base are
 * held to roughly a gigabyte, but the vmalloc base only to about a terabyte:
 * its window is bounded through the direct map's SIZE, which moves in whole
 * terabytes and carries a padding this side cannot know. A perturbation smaller
 * than that stays inside the resolved window legitimately, so a control that
 * shifts the vmalloc truth by a page or a PUD will pass and prove nothing. */
static void test_full_engine_property_x86_64_randmem(void) {
#if defined(__x86_64__)
  int nr = 0, nv = 0;
  const rule_fn *rules = engine_rules(&nr);
  const verdict_fn *vrules = engine_verdict_rules(&nv);
  /* 4-level layout: __PAGE_OFFSET_BASE_L4, CPU_ENTRY_AREA_BASE,
   * VMALLOC_SIZE_TB, and the direct map's architectural cap at MAX_PHYSMEM_BITS
   * = 46. */
  const unsigned long vaddr_start = 0xffff888000000000ul;
  const unsigned long vaddr_end = 0xfffffe0000000000ul;
  const unsigned long one_tb = 1ul << 40;
  const unsigned long pud = 1ul << 30;
  const unsigned long vmalloc_tb = 32ul;
  const unsigned long dm_max_tb = 1ul << (46 - 40);
  const unsigned long ITERS = 2000;

  for (unsigned long seed = 0; seed < ITERS; seed++) {
    struct prop_rng r = {seed * 0x100000001B3ull + 0x5A4D0Full};

    /* RAM, and the padding a build may add to the direct map for hotplug. */
    unsigned long max_pfn =
        (1ul + (unsigned long)(prop_rand(&r) % 4096ull)) * (one_tb >> 22);
    unsigned long padding_tb = (unsigned long)(prop_rand(&r) % 0x41ull);

    unsigned long ram_bytes = max_pfn << 12;
    unsigned long dm_tb = (ram_bytes + one_tb - 1) / one_tb + padding_tb;
    if (dm_tb > dm_max_tb)
      dm_tb = dm_max_tb;
    /* vmemmap covers the direct map one struct page (64 bytes) per 4 KiB. */
    unsigned long vmemmap_tb = (dm_tb * 64ul + 4095ul) / 4096ul;
    if (vmemmap_tb == 0)
      vmemmap_tb = 1;

    unsigned long sizes[3] = {dm_tb * one_tb, vmalloc_tb * one_tb,
                              vmemmap_tb * one_tb};
    unsigned long span = vaddr_end - vaddr_start;
    if (sizes[0] + sizes[1] + sizes[2] >= span)
      continue; /* the fixed sizes already fill the span; no entropy to place */
    unsigned long remain = span - sizes[0] - sizes[1] - sizes[2];

    unsigned long vaddr = vaddr_start, base[3];
    for (int i = 0; i < 3; i++) {
      unsigned long cap = remain / (unsigned long)(3 - i);
      unsigned long e = (unsigned long)(prop_rand(&r) % (cap + 1)) & ~(pud - 1);
      vaddr += e;
      base[i] = vaddr;
      vaddr = (vaddr + sizes[i] + 1 + pud - 1) & ~(pud - 1);
      remain -= e;
    }

    struct engine e;
    engine_init(&e);
    add_scalar(&e, SF_VIRT_ADDR_BITS, 48);
    add_scalar(&e, SF_PHYS_MAX_PFN, max_pfn);
    /* A pointer into each region: what a leak of one of them actually is. */
    if (prop_coin(&r))
      add_interior(&e, KASLD_TYPE_VIRT, REGION_DIRECTMAP,
                   base[0] + (unsigned long)(prop_rand(&r) % 0x10000000ull));
    if (prop_coin(&r))
      add_interior(&e, KASLD_TYPE_VIRT, REGION_VMALLOC,
                   base[1] + (unsigned long)(prop_rand(&r) % 0x10000000ull));
    if (prop_coin(&r))
      add_interior(&e, KASLD_TYPE_VIRT, REGION_VMEMMAP,
                   base[2] + (unsigned long)(prop_rand(&r) % 0x10000000ull));

    struct prop_check chk[] = {
        {Q_PAGE_OFFSET, base[0]},
        {Q_VMALLOC_BASE, base[1]},
        {Q_VMEMMAP_BASE, base[2]},
    };
    prop_check_containment(&e, rules, nr, vrules, nv, chk,
                           (int)(sizeof(chk) / sizeof(chk[0])),
                           "x86_64-randmem", seed);
  }
#endif
}

/* Property test: arm64 linear map and paging config. Separate from the arm64
 * text property above because it varies a different axis — that one holds the
 * VA layout still and moves the image; this one moves the layout itself and
 * leaves the image out.
 *
 * arm64 is the only arch whose linear-map base is a function of a CONFIG rather
 * than a constant or a firmware value: PAGE_OFFSET = -(1 << VA_BITS), with the
 * map running to _PAGE_END = -(1 << (VA_BITS - 1)). Drawing VA_BITS from the
 * arch's own candidate list moves both together, which is what makes
 * containment of Q_PAGE_OFFSET a claim about inference rather than about a
 * constant — and it is the same draw that makes Q_VA_BITS meaningful, the one
 * finite-set quantity in the engine and so the only one whose containment runs
 * through a lattice other than the interval.
 *
 * No text base is generated. The kernel image region is anchored to
 * _PAGE_END(VA_BITS_MIN), and VA_BITS_MIN stays 48 under the 52-bit LVA configs
 * (asm/memory.h: MODULES_VADDR = _PAGE_END(VA_BITS_MIN), KIMAGE_VADDR =
 * MODULES_END), so each config admits its own narrow text window rather than
 * the union the wide bounds describe. Placing an image anywhere in that union
 * generates kernels arm64 does not build, and the text rules correctly reject
 * them. Modelling that window per config is what a text axis here would need;
 * until then the layout axis stands on its own, and the image is covered by the
 * property above under a fixed VA layout.
 */
static void test_full_engine_property_arm64_va(void) {
#if defined(__aarch64__)
  int nr = 0, nv = 0;
  const rule_fn *rules = engine_rules(&nr);
  const verdict_fn *vrules = engine_verdict_rules(&nv);
  const unsigned long vas[] = VA_BITS_CANDIDATES;
  const unsigned long ITERS = 2000;

  for (unsigned long seed = 0; seed < ITERS; seed++) {
    struct prop_rng r = {seed * 0x100000001B3ull + 0x5A4B3C2Dull};

    unsigned long va = vas[prop_rand(&r) % (sizeof(vas) / sizeof(vas[0]))];
    unsigned long po = arm64_page_offset_for(va);
    unsigned long page_end = arm64_page_end_for(va);

    struct engine e;
    engine_init(&e);

    /* A pointer into the linear map, which is what a direct-map leak is: it
     * says the map covers this address, not where the map begins. Working back
     * from it to the config, and from the config to the map's base, is the
     * inference under test.
     *
     * Only from ARM64_VA_BITS_VALIDATE_MIN up. Below it the arch deliberately
     * declines to corroborate: the accepting band's ceiling is _PAGE_END of
     * that width, so a narrower kernel's linear map runs above it and its
     * direct-map leak is ruled invalid by design — a documented completeness
     * trade on a config needing 16K pages and EXPERT, whose width still
     * resolves from the mmap probe. Generating a leak there would assert the
     * arch corroborates evidence it has decided not to. */
    if (va >= (unsigned long)ARM64_VA_BITS_VALIDATE_MIN && prop_coin(&r))
      add_interior(&e, KASLD_TYPE_VIRT, REGION_DIRECTMAP,
                   po + (unsigned long)(prop_rand(&r) % (page_end - po)));

    struct prop_check chk[] = {
        {Q_PAGE_OFFSET, po},
        {Q_VA_BITS, va},
    };
    prop_check_containment(&e, rules, nr, vrules, nv, chk,
                           (int)(sizeof(chk) / sizeof(chk[0])), "arm64-va",
                           seed);
  }
#endif
}

/* Property test: mips64 whole-engine containment — a COUPLED arch whose linear
 * map the ISA fixes. CKSEG0 makes PAGE_OFFSET a constant this build knows, so
 * unlike x86_32 no page-offset landmark is needed: the arch axiom pins it and
 * the coupling rules project from there. What mips64 brings that no other
 * covered arch does is that pairing — a build-known linear map, a module band
 * at a fixed address independent of both text and the map, and a head gap that
 * is a range rather than a constant.
 *
 * The head gap is DRAWN, not assumed. mips reserves a fill before _stext only
 * where the exception fill is compiled in, and several platforms select it out,
 * so a real _stext witness sits at +0x400 on some kernels and at +0 on others.
 * Generating one of the two would leave the property silent about the arch as
 * it ships; generating both is what makes this a claim about mips64 rather than
 * about one config of it.
 *
 * Q_PAGE_OFFSET and Q_MODULE_BASE are checked as a regression net rather than
 * as a discovery. Both truths are architectural constants the engine pins from
 * the same headers this test reads, so containment cannot fail here unless a
 * rule empties or moves one — which is the failure they are here to catch. */
static void test_full_engine_property_mips64(void) {
#if defined(__mips64) || defined(__mips64__)
  int nr = 0, nv = 0;
  const rule_fn *rules = engine_rules(&nr);
  const verdict_fn *vrules = engine_verdict_rules(&nv);

  const unsigned long ITERS = 2000;
  for (unsigned long seed = 0; seed < ITERS; seed++) {
    struct prop_rng r = {seed * 0x100000001B3ull + 0x6D49B5ull};

    unsigned long gap = (1ul + prop_rand(&r) % 16ul) * 0x100000ul;
    unsigned long image = gap + (prop_rand(&r) % 16ul) * 0x100000ul;
    unsigned long virt =
        prop_aligned(&r, (unsigned long)KASLR_VIRT_TEXT_MIN,
                     (unsigned long)KASLR_VIRT_TEXT_MAX - image,
                     (unsigned long)KASLR_VIRT_ALIGN);
    /* Coupled: text rides in a linear map the hardware places, so one slide
     * moves both bases and the projection is exact by construction. */
    unsigned long phys =
        virt - (unsigned long)PAGE_OFFSET + (unsigned long)PHYS_OFFSET;
    /* One of the two gaps the arch ships — never a value between them, and
     * NOT read from STEXT_OFFSET/STEXT_OFFSET_MAX. A generator that drew its
     * truth from the same constants the engine reads could not contradict
     * them: understate the range in the header and the generator quietly stops
     * producing the config that would expose it, so the property confirms the
     * header instead of testing it. These two are the arch's own facts —
     * head.S reserves 0x400 before _stext, except where the exception fill is
     * configured out and the gap is 0. */
    unsigned long head = prop_coin(&r) ? 0x400ul : 0ul;
    unsigned long memtotal = phys + image +
                             (unsigned long)(prop_rand(&r) % 0x20000000ull) +
                             0x08000000ul;

    struct engine e;
    engine_init(&e);

    /* A random subset of faithful leaks, all consistent with the truth. */
    if (prop_coin(&r))
      add_addr(&e, KASLD_TYPE_VIRT, REGION_KERNEL_TEXT, virt + head, 0,
               "_stext");
    if (prop_coin(&r))
      add_addr(&e, KASLD_TYPE_VIRT, REGION_KERNEL_DATA, virt + gap, 0,
               "_edata");
    /* iomem's "Kernel code" is __pa_symbol(&_text) on mips, so the physical
     * witness is the image base itself and carries no head gap. */
    if (prop_coin(&r))
      add_addr(&e, KASLD_TYPE_PHYS, REGION_KERNEL_IMAGE, phys, 0, "_text");
    if (prop_coin(&r))
      add_addr(&e, KASLD_TYPE_PHYS, REGION_RAM, 0, memtotal - 1, NULL);
    if (prop_coin(&r))
      add_scalar(&e, SF_IMAGE_SIZE_MIN, image);
    if (prop_coin(&r))
      add_scalar(&e, SF_PHYS_MEMTOTAL, memtotal);

    struct prop_check chk[] = {
        {Q_VIRT_IMAGE_BASE, virt},
        {Q_PHYS_IMAGE_BASE, phys},
        {Q_PAGE_OFFSET, (unsigned long)PAGE_OFFSET},
        {Q_MODULE_BASE, (unsigned long)MODULES_START},
    };
    prop_check_containment(&e, rules, nr, vrules, nv, chk,
                           (int)(sizeof(chk) / sizeof(chk[0])), "mips64", seed);
  }
#endif
}

/* Floor invariant on the other decoupled arches — same property as the x86_64
 * floor test, exercising each arch's own rule set (the arch-specific rules only
 * run on their arch, so a floor-gating bug in e.g. riscv64_text_base is only
 * caught here). */
static void test_full_engine_property_arm64_floor(void) {
#if defined(__aarch64__)
  int nr = 0, nv = 0;
  const rule_fn *rules = engine_rules(&nr);
  const verdict_fn *vrules = engine_verdict_rules(&nv);
  for (unsigned long seed = 0; seed < 1500; seed++) {
    struct prop_rng r = {seed * 0x100000001B3ull + 0xF100A64ull};
    unsigned long gap = (1ul + prop_rand(&r) % 16ul) * 0x100000ul;
    unsigned long image = gap + (prop_rand(&r) % 16ul) * 0x100000ul;
    unsigned long virt =
        prop_aligned(&r, (unsigned long)KASLR_VIRT_TEXT_MIN,
                     (unsigned long)KASLR_VIRT_TEXT_MAX - image,
                     (unsigned long)KASLR_VIRT_ALIGN);
    unsigned long phys = prop_aligned(&r, (unsigned long)KASLR_PHYS_ALIGN,
                                      (unsigned long)KASLR_PHYS_MAX - image,
                                      (unsigned long)KASLR_PHYS_ALIGN);
    unsigned long memtotal = phys + image +
                             (unsigned long)(prop_rand(&r) % 0x40000000ull) +
                             0x10000000ul;
    struct prop_axis axes[] = {
        {KASLD_TYPE_VIRT, Q_VIRT_IMAGE_BASE, virt,
         (unsigned long)KASLR_VIRT_ALIGN, (unsigned long)KASLR_VIRT_TEXT_MIN,
         (unsigned long)KASLR_VIRT_TEXT_MAX},
        {KASLD_TYPE_PHYS, Q_PHYS_IMAGE_BASE, phys,
         (unsigned long)KASLR_PHYS_ALIGN, (unsigned long)KASLR_PHYS_ALIGN,
         (unsigned long)KASLR_PHYS_MAX},
    };
    prop_check_floor(rules, nr, vrules, nv, memtotal, image, axes, 2, &r,
                     "arm64", seed);
  }
#endif
}

static void test_full_engine_property_riscv64_floor(void) {
#if (defined(__riscv) || defined(__riscv__)) && __riscv_xlen == 64
  int nr = 0, nv = 0;
  const rule_fn *rules = engine_rules(&nr);
  const verdict_fn *vrules = engine_verdict_rules(&nv);
  for (unsigned long seed = 0; seed < 1500; seed++) {
    struct prop_rng r = {seed * 0x100000001B3ull + 0xF105C71ull};
    unsigned long gap = (1ul + prop_rand(&r) % 16ul) * 0x100000ul;
    unsigned long image = gap + (prop_rand(&r) % 16ul) * 0x100000ul;
    unsigned long virt =
        prop_aligned(&r, (unsigned long)KASLR_VIRT_TEXT_MIN,
                     (unsigned long)KASLR_VIRT_TEXT_MAX - image,
                     (unsigned long)KASLR_VIRT_ALIGN);
    unsigned long phys = prop_aligned(&r, (unsigned long)KASLR_PHYS_MIN,
                                      (unsigned long)KASLR_PHYS_MAX - image,
                                      (unsigned long)KASLR_PHYS_ALIGN);
    unsigned long memtotal = phys + image +
                             (unsigned long)(prop_rand(&r) % 0x40000000ull) +
                             0x10000000ul;
    struct prop_axis axes[] = {
        {KASLD_TYPE_VIRT, Q_VIRT_IMAGE_BASE, virt,
         (unsigned long)KASLR_VIRT_ALIGN, (unsigned long)KASLR_VIRT_TEXT_MIN,
         (unsigned long)KASLR_VIRT_TEXT_MAX},
        {KASLD_TYPE_PHYS, Q_PHYS_IMAGE_BASE, phys,
         (unsigned long)KASLR_PHYS_ALIGN, (unsigned long)KASLR_PHYS_MIN,
         (unsigned long)KASLR_PHYS_MAX},
    };
    prop_check_floor(rules, nr, vrules, nv, memtotal, image, axes, 2, &r,
                     "riscv64", seed);
  }
#endif
}

static void test_full_engine_property_s390_floor(void) {
#if defined(__s390x__)
  int nr = 0, nv = 0;
  const rule_fn *rules = engine_rules(&nr);
  const verdict_fn *vrules = engine_verdict_rules(&nv);
  for (unsigned long seed = 0; seed < 1500; seed++) {
    struct prop_rng r = {seed * 0x100000001B3ull + 0xF10539ull};
    unsigned long gap = (1ul + prop_rand(&r) % 16ul) * 0x100000ul;
    unsigned long image = gap + (prop_rand(&r) % 16ul) * 0x100000ul;
    unsigned long virt =
        prop_aligned(&r, (unsigned long)KASLR_VIRT_TEXT_MIN,
                     (unsigned long)KASLR_VIRT_TEXT_MAX - image,
                     (unsigned long)KASLR_VIRT_ALIGN);
    unsigned long phys = prop_aligned(&r, (unsigned long)KASLR_PHYS_MIN,
                                      (unsigned long)KASLR_PHYS_MAX - image,
                                      (unsigned long)KASLR_PHYS_ALIGN);
    unsigned long memtotal = phys + image +
                             (unsigned long)(prop_rand(&r) % 0x40000000ull) +
                             0x10000000ul;
    struct prop_axis axes[] = {
        {KASLD_TYPE_VIRT, Q_VIRT_IMAGE_BASE, virt,
         (unsigned long)KASLR_VIRT_ALIGN, (unsigned long)KASLR_VIRT_TEXT_MIN,
         (unsigned long)KASLR_VIRT_TEXT_MAX},
        {KASLD_TYPE_PHYS, Q_PHYS_IMAGE_BASE, phys,
         (unsigned long)KASLR_PHYS_ALIGN, (unsigned long)KASLR_PHYS_MIN,
         (unsigned long)KASLR_PHYS_MAX},
    };
    prop_check_floor(rules, nr, vrules, nv, memtotal, image, axes, 2, &r,
                     "s390", seed);
  }
#endif
}

static void test_full_engine_property_x86_32_floor(void) {
#if defined(__i386__)
  int nr = 0, nv = 0;
  const rule_fn *rules = engine_rules(&nr);
  const verdict_fn *vrules = engine_verdict_rules(&nv);
  for (unsigned long seed = 0; seed < 1500; seed++) {
    struct prop_rng r = {seed * 0x100000001B3ull + 0xF108632ull};
    unsigned long gap = (1ul + prop_rand(&r) % 16ul) * 0x100000ul;
    unsigned long image = gap + (prop_rand(&r) % 16ul) * 0x100000ul;
    unsigned long phys = prop_aligned(&r, (unsigned long)KASLR_PHYS_ALIGN,
                                      (unsigned long)KASLR_PHYS_MAX - image,
                                      (unsigned long)KASLR_PHYS_ALIGN);
    unsigned long virt = fixture_coupled_virt(phys); /* coupled */
    unsigned long memtotal = phys + image +
                             (unsigned long)(prop_rand(&r) % 0x08000000ull) +
                             0x02000000ul;
    struct prop_axis axes[] = {
        {KASLD_TYPE_VIRT, Q_VIRT_IMAGE_BASE, virt,
         (unsigned long)KASLR_VIRT_ALIGN, (unsigned long)KASLR_VIRT_TEXT_MIN,
         (unsigned long)KASLR_VIRT_TEXT_MAX},
        {KASLD_TYPE_PHYS, Q_PHYS_IMAGE_BASE, phys,
         (unsigned long)KASLR_PHYS_ALIGN, (unsigned long)KASLR_PHYS_ALIGN,
         (unsigned long)KASLR_PHYS_MAX},
    };
    prop_check_floor(rules, nr, vrules, nv, memtotal, image, axes, 2, &r,
                     "x86_32", seed);
  }
#endif
}

/* Floor invariant on the arches whose containment properties are above but
 * whose floor invariant was never exercised. Same property as the x86_64 floor
 * test — a below-floor pin may shape `likely` and must move NO guaranteed
 * quantity, while the same pin at CONF_PARSED must — run against each arch's
 * own rule set, since an arch-specific rule that reads a below-floor signal
 * into an at-floor constraint is invisible everywhere else.
 *
 * All seven are coupled, so the truth is one slide: draw the physical base and
 * project it through the arch's own linear map. The phys draw is clamped so the
 * projection stays inside the virtual text window — on the 32-bit arches that
 * window is the smaller of the two, and an unclamped draw would wrap. */
__attribute__((unused)) static void prop_floor_coupled(const char *arch,
                                                       unsigned long salt,
                                                       unsigned long pmax_cap) {
#ifdef KASLD_PROP_ARCH
  int nr = 0, nv = 0;
  const rule_fn *rules = engine_rules(&nr);
  const verdict_fn *vrules = engine_verdict_rules(&nv);
  for (unsigned long seed = 0; seed < 1000; seed++) {
    struct prop_rng r = {seed * 0x100000001B3ull + salt};
    unsigned long gap = (1ul + prop_rand(&r) % 8ul) * 0x100000ul;
    unsigned long image = gap + (prop_rand(&r) % 8ul) * 0x100000ul;
    if (pmax_cap <= image + (unsigned long)KASLR_PHYS_ALIGN)
      continue;
    unsigned long phys =
        prop_aligned(&r, (unsigned long)KASLR_PHYS_ALIGN, pmax_cap - image,
                     (unsigned long)KASLR_PHYS_ALIGN);
    unsigned long virt =
        phys - (unsigned long)PHYS_OFFSET + (unsigned long)PAGE_OFFSET;
    unsigned long memtotal = phys + image +
                             (unsigned long)(prop_rand(&r) % 0x08000000ull) +
                             0x02000000ul;
    struct prop_axis axes[] = {
        {KASLD_TYPE_VIRT, Q_VIRT_IMAGE_BASE, virt,
         (unsigned long)KASLR_VIRT_ALIGN, (unsigned long)KASLR_VIRT_TEXT_MIN,
         (unsigned long)KASLR_VIRT_TEXT_MAX},
        {KASLD_TYPE_PHYS, Q_PHYS_IMAGE_BASE, phys,
         (unsigned long)KASLR_PHYS_ALIGN, (unsigned long)KASLR_PHYS_ALIGN,
         pmax_cap},
    };
    prop_check_floor(rules, nr, vrules, nv, memtotal, image, axes, 2, &r, arch,
                     seed);
  }
#else
  (void)arch;
  (void)salt;
  (void)pmax_cap;
#endif
}

/* The physical span whose projection stays inside the virtual text window. */
#ifdef KASLD_PROP_ARCH
__attribute__((unused)) static unsigned long prop_coupled_pmax(void) {
  unsigned long from_virt = (unsigned long)KASLR_VIRT_TEXT_MAX -
                            (unsigned long)PAGE_OFFSET +
                            (unsigned long)PHYS_OFFSET;
  unsigned long p = (unsigned long)KASLR_PHYS_MAX;
  return from_virt < p ? from_virt : p;
}
#endif

static void test_full_engine_property_mips64_floor(void) {
#if defined(__mips64) || defined(__mips64__)
  prop_floor_coupled("mips64", 0x6D49F1ull, prop_coupled_pmax());
#endif
}

static void test_full_engine_property_mips32_floor(void) {
#if defined(__mips__) && !defined(__mips64) && !defined(__mips64__)
  prop_floor_coupled("mips32", 0x3D49F1ull, prop_coupled_pmax());
#endif
}

static void test_full_engine_property_loongarch64_floor(void) {
#if defined(__loongarch64) ||                                                  \
    (defined(__loongarch__) && __loongarch_grlen == 64)
  prop_floor_coupled("loongarch64", 0x10A6F1ull, prop_coupled_pmax());
#endif
}

static void test_full_engine_property_ppc64_floor(void) {
#if defined(__powerpc64__) || defined(__ppc64__)
  prop_floor_coupled("ppc64", 0x99C6F1ull, prop_coupled_pmax());
#endif
}

static void test_full_engine_property_riscv32_floor(void) {
#if (defined(__riscv) || defined(__riscv__)) && __riscv_xlen == 32
  prop_floor_coupled("riscv32", 0x52C3F1ull, prop_coupled_pmax());
#endif
}

static void test_full_engine_property_ppc32_floor(void) {
#if (defined(__powerpc__) || defined(__PPC__)) && !defined(__powerpc64__) &&   \
    !defined(__ppc64__)
  prop_floor_coupled("ppc32", 0x9C32F1ull, prop_coupled_pmax());
#endif
}

static void test_full_engine_property_arm32_floor(void) {
#if defined(__arm__) && !defined(__aarch64__)
  prop_floor_coupled("arm32", 0xA3B0F1ull, prop_coupled_pmax());
#endif
}

/* Coverage guard: the property tests above must have exercised a healthy set of
 * distinct rules. Catches a generator regression that stops triggering rules
 * (which would leave the whole property suite validating almost nothing).
 * Threshold is conservative — every arch's property tests clear it. */
static void test_full_engine_property_coverage(void) {
#ifdef KASLD_PROP_ARCH
  /* Silent: any output here would interleave between the RUN macro's padded
   * test name and its status mark, breaking the aligned column. The assert is
   * the guard; on failure it names this file/line. */
  assert(prop_seen_n >= 8);
#endif
}

/* =========================================================================
 * Curation settles before any constraint is emitted
 *
 * A verdict rule reads the EFFECTIVE view (an observation's valid bit and its
 * effective region), so one ruling can enable another. The constraint store is
 * append-only with no retraction path, so a constraint emitted against a
 * half-curated set would outlive the observation it came from — the engine
 * would then narrow on evidence it had itself rejected.
 *
 * The planted cascade is built from arch macros, not from one arch's numbers,
 * because the ingredients are shared: every *_coupling_validate rule bands
 * REGION_KERNEL_TEXT against KERNEL_VIRT_TEXT_MIN/MAX, and none of them checks
 * REGION_KERNEL_DATA — while is_kernel_image_region(), which
 * text_cluster_filter judges against, does include it. So:
 *
 *   - five in-band text leaks, clustered;
 *   - five text claims below KERNEL_VIRT_TEXT_MIN, far enough below to form
 *     their own cluster. Equal counts leave text_cluster_filter without the
 *     strict majority it requires, so it refuses to act until they are gone;
 *   - one far KERNEL_DATA claim, which survives the band check but which the
 *     cluster filter rejects once the median moves onto the in-band cluster.
 *
 * The invariant asserted is the general one, not the scenario: after a run, no
 * constraint may name an invalidated observation in its lineage. An arch with
 * no band-checking curation rule simply keeps the whole planted set, and the
 * invariant holds with nothing to bite on.
 * ========================================================================= */
/* Confined to 64-bit layouts, and not for want of trying: the cascade needs an
 * outlier more than CLUSTER_OUTLIER_THRESHOLD (1 GiB) from the text cluster,
 * and on x86_32 / arm32 the whole address space below KERNEL_VIRT_TEXT_MIN is
 * 0x40000000 — exactly that threshold, with no room left to stay off zero.
 * Those arches also carry no band-checking curation rule, so there would be
 * nothing to cascade even if the geometry allowed it. */
#if __SIZEOF_LONG__ >= 8
#define CURATION_BAND_LO ((unsigned long)KERNEL_VIRT_TEXT_MIN)
#define CURATION_OUT_OF_BAND (CURATION_BAND_LO - 0x80000000ul)
#define CURATION_FAR (CURATION_BAND_LO - 0x100000000ul)

static void add_virt_at(struct engine *e, enum kasld_region region,
                        unsigned long addr) {
  struct observation o;
  memset(&o, 0, sizeof(o));
  o.value_kind = OBS_ADDRESS;
  o.type = KASLD_TYPE_VIRT;
  o.region = region;
  o.lo = addr;
  o.sample = addr;
  o.set_mask = LO_SET | SAMPLE_SET;
  o.pos = POS_BASE;
  o.conf = CONF_PARSED;
  snprintf(o.origin, ORIGIN_LEN, "curation_cascade");
  evidence_add(&e->ev, &o);
}

/* Count constraints whose lineage names an observation the run invalidated. */
static int stale_lineage_constraints(const struct engine *e) {
  int n = 0;
  for (int c = 0; c < e->n_constraints; c++)
    for (int l = 0; l < e->constraints[c].lineage_count; l++)
      for (int i = 0; i < e->ev.n_obs; i++)
        if (e->ev.obs[i].id == e->constraints[c].derived_from[l] &&
            !e->ev.obs[i].valid)
          n++;
  return n;
}

static int invalidated_obs(const struct engine *e) {
  int n = 0;
  for (int i = 0; i < e->ev.n_obs; i++)
    n += e->ev.obs[i].valid ? 0 : 1;
  return n;
}

static void plant_curation_cascade(struct engine *e) {
  engine_init(e);
  for (int i = 0; i < 5; i++)
    add_virt_at(e, REGION_KERNEL_TEXT,
                CURATION_BAND_LO + (unsigned long)(i + 1) * 0x100000ul);
  for (int i = 0; i < 5; i++)
    add_virt_at(e, REGION_KERNEL_TEXT,
                CURATION_OUT_OF_BAND + (unsigned long)i * 0x1000ul);
  add_virt_at(e, REGION_KERNEL_DATA, CURATION_FAR);
}

/* Does this arch carry a curation rule that bands kernel text? Probed rather
 * than enumerated from arch macros, so the day a fifth *_coupling_validate
 * lands this test strengthens itself instead of quietly going vacuous there. */
static int arch_bands_kernel_text(const verdict_fn *vrules, int n_vrules) {
  static struct engine probe;
  engine_init(&probe);
  add_virt_at(&probe, REGION_KERNEL_TEXT, CURATION_OUT_OF_BAND);
  engine_run_full(&probe, NULL, 0, vrules, n_vrules);
  return invalidated_obs(&probe) > 0;
}

static void check_no_stale_lineage(struct engine *e, int banded) {
  int invalid = invalidated_obs(e);
  /* Where text is banded the cascade must run to completion — five out-of-band
   * claims plus the far data claim the moved median then exposes. Asserting it
   * keeps the invariant below from passing on an evidence set curation never
   * touched. */
  if (banded)
    assert(invalid >= 6);
  else
    assert(invalid == 0);
  assert(stale_lineage_constraints(e) == 0);
}

#endif /* __SIZEOF_LONG__ >= 8 */

static void test_full_engine_curation_settles_before_constraints(void) {
#if __SIZEOF_LONG__ >= 8
  static struct engine e; /* ~1.3 MiB: BSS, never the stack */
  int n_rules = 0, n_vrules = 0;
  const rule_fn *rules = engine_rules(&n_rules);
  const verdict_fn *vrules = engine_verdict_rules(&n_vrules);

  int banded = arch_bands_kernel_text(vrules, n_vrules);

  plant_curation_cascade(&e);
  engine_run_full(&e, rules, n_rules, vrules, n_vrules);
  check_no_stale_lineage(&e, banded);

  /* Same invariant at the sound floor, where the guaranteed window is drawn. */
  plant_curation_cascade(&e);
  engine_run_full_floored(&e, CONF_INFERRED, rules, n_rules, vrules, n_vrules);
  check_no_stale_lineage(&e, banded);
#endif /* __SIZEOF_LONG__ >= 8 */
}

int main(void) {
  TEST_SUITE("test_engine_integration");

  BEGIN_CATEGORY("Full registry against planted leaks");
  RUN(test_full_engine_x86_64_leaky);
  RUN(test_full_engine_faithful_cluster_keeps_directmap);
  RUN(test_full_engine_curation_removes_only_the_fault);
  RUN(test_full_engine_two_window);
  RUN(test_full_engine_constraint_bracket_and_corroborate);
  RUN(test_full_engine_floor_invariant);
  RUN(test_full_engine_property_x86_64);
  RUN(test_full_engine_property_x86_64_floor);
  RUN(test_full_engine_property_arm64_floor);
  RUN(test_full_engine_property_riscv64_floor);
  RUN(test_full_engine_property_s390_floor);
  RUN(test_full_engine_property_x86_32_floor);
  RUN(test_full_engine_property_arm64);
  RUN(test_full_engine_property_riscv64);
  RUN(test_full_engine_property_s390);
  RUN(test_full_engine_property_x86_32);
  RUN(test_full_engine_property_mips64);
  RUN(test_full_engine_property_arm64_va);
  RUN(test_full_engine_property_x86_64_randmem);
  RUN(test_full_engine_property_loongarch64);
  RUN(test_full_engine_property_mips32);
  RUN(test_full_engine_property_ppc32);
  RUN(test_full_engine_property_arm32);
  RUN(test_full_engine_property_riscv32);
  RUN(test_full_engine_property_ppc64);
  RUN(test_full_engine_property_mips64_floor);
  RUN(test_full_engine_property_mips32_floor);
  RUN(test_full_engine_property_loongarch64_floor);
  RUN(test_full_engine_property_ppc64_floor);
  RUN(test_full_engine_property_riscv32_floor);
  RUN(test_full_engine_property_ppc32_floor);
  RUN(test_full_engine_property_arm32_floor);
  RUN(test_full_engine_property_coverage);
  RUN(test_full_engine_curation_settles_before_constraints);
  RUN(test_full_engine_ppc64_hardened_shape);
  RUN(test_full_engine_s390_no_prng_shape);
  RUN(test_full_engine_arm32_no_kaslr_shape);
  RUN(test_full_engine_riscv64_legacy_no_kaslr);
  RUN(test_full_engine_riscv64_legacy_2gb);
  RUN(test_full_engine_arm64_va39_sub48);
  RUN(test_full_engine_arm64_va39_no_kaslr);
  RUN(test_full_engine_arm64_va48_no_kaslr);
  RUN(test_full_engine_arm64_va48_kaslr_window);
  RUN(test_full_engine_arm64_va39_kaslr_window);
  RUN(test_full_engine_arm64_old_layout_sound);
  RUN(test_full_engine_s390_old_identity_map_sound);
  RUN(test_full_engine_i686_kaslr_shape);
  RUN(test_full_engine_robust_to_outlier);
  RUN(test_full_engine_ppc_kernel_end_tightens);
  RUN(test_full_engine_ppc_memory_limit_caps_dram);
  RUN(test_full_engine_initrd_above_kernel_upper_bound);

  return TEST_DONE();
}
