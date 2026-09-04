// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Tests for the report model builder (src/report.c).
//
// The builder is the only place that decides what a run reports, so what is
// asserted here is INVARIANTS -- properties that must hold of any model it
// produces -- not agreement with what some format currently prints. A test that
// pinned the model to today's output would cement every rendering decision the
// model exists to remove, including the ones already known to be wrong.
//
// Host-independent by construction: the estimates are built here from the
// quantity table's own tops and narrowed by hand, so nothing is read from the
// machine running the test and no sysroot is staged. The builder does no I/O,
// which is the property that makes that possible.
// ---
// <bcoles@gmail.com>

#define _GNU_SOURCE
#include "include/kasld/report.h"

#include "../src/estimate.c"
#include "../src/quantities.c"
#include "../src/report.c"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static int checks;
#define CHECK(cond)                                                            \
  do {                                                                         \
    checks++;                                                                  \
    if (!(cond)) {                                                             \
      fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);          \
      return 1;                                                                \
    }                                                                          \
  } while (0)

/* Every quantity at its architectural top: the state before any evidence. */
static void tops(struct estimate *est) {
  for (int q = 0; q < Q__COUNT; q++) {
    memset(&est[q], 0, sizeof(est[q]));
    if (quantities[q].init_top)
      quantities[q].init_top(&est[q]);
  }
}

/* The invariants every item must satisfy, whatever the inputs. */
static int check_item(const struct kasld_report_quantity *it) {
  /* A member without a name would render as a blank row in every format. */
  CHECK(it->key != NULL && it->key[0] != '\0');
  CHECK(it->label != NULL && it->label[0] != '\0');

  for (int g = 0; g < 2; g++) {
    const struct kasld_report_window *w = g ? &it->likely : &it->guaranteed;
    if (!w->present)
      continue;

    /* The listed holes are a bounded prefix of the carved ones, and every one
     * of them lies inside the hull it was carved from. */
    CHECK(w->excluded_listed <= w->n_excluded);
    CHECK(w->excluded_listed <= KASLD_REPORT_MAX_EXCLUDED);
    for (int i = 0; i < w->excluded_listed; i++) {
      CHECK(w->excluded[i].lo <= w->excluded[i].hi);
      CHECK(w->excluded[i].lo >= w->lo && w->excluded[i].hi <= w->hi);
    }

    if (w->shape == RSHAPE_SET) {
      /* A set has no endpoints and no grid. Reporting either would be the
       * flattening the shape tag exists to prevent. */
      CHECK(!w->has_lo && !w->has_hi);
      CHECK(w->n_values > 0);
      CHECK(w->candidates == (unsigned long)w->n_values);
      CHECK(it->align_min == 0);
    } else if (w->shape == RSHAPE_INTERVAL) {
      /* An interval is counted on a grid, so it must have one. */
      CHECK(it->align_min > 0);
      if (w->has_lo && w->has_hi)
        CHECK(w->lo <= w->hi);
      /* A count is claimed for a both-sided window and withheld for a
       * one-sided one, which is unbounded -- counting it from the lattice
       * floor would state a number the missing edge contradicts. */
      if (w->has_lo && w->has_hi)
        CHECK(w->candidates > 0);
      else
        CHECK(w->candidates == 0 && w->bits == 0);
    }

    /* The engine cannot resolve more possibilities than it was willing to
     * consider. Note the bound is against search_top, NOT entropy_top: the
     * engine deliberately searches wider than the kernel randomizes, so a count
     * exceeding entropy_top is legitimate and a format must cope with it rather
     * than print an incoherent ratio. */
    if (it->search_top > 0)
      CHECK(w->candidates <= it->search_top);
  }

  /* The likely window is the all-signals view of the same unknown: it may be
   * absent, but it can never admit more than the sound one. */
  if (it->guaranteed.present && it->likely.present)
    CHECK(it->likely.candidates <= it->guaranteed.candidates);

  /* The kernel's own window is never wider than the range the engine searches:
   * the whole reason the engine starts wider is to contain every kernel the
   * target might be running. A denominator larger than the search range would
   * mean the engine could not represent a base the kernel was free to pick. */
  if (it->entropy_top > 0 && it->search_top > 0)
    CHECK(it->entropy_top <= it->search_top);

  return 0;
}

int main(void) {
  struct estimate gest[Q__COUNT], lest[Q__COUNT];
  struct kasld_report r;
  struct kasld_resolution_view gv, lv;

  /* 1. Untouched tops: the model a run with no evidence at all produces. Every
   *    member is still reported -- membership is a property of the machine, not
   *    of how the run went -- and each states the architectural window. */
  tops(gest);
  gv.est = gest;
  gv.cs = NULL;
  gv.n_cs = 0;
  gv.floor = CONF_INFERRED;
  lv.est = NULL;
  lv.cs = NULL;
  lv.n_cs = 0;
  lv.floor = CONF_BRUTE;
  kasld_report_build(gv, lv, NULL, RPOSTURE_RANDOMIZED, 0, &r);

  CHECK(r.n_quantities > 0);
  for (int i = 0; i < r.n_quantities; i++) {
    if (check_item(&r.quantities[i]))
      return 1;
    /* No evidence: nothing can have narrowed below the machine's own offer. */
    if (r.quantities[i].search_top > 0)
      CHECK(r.quantities[i].guaranteed.candidates ==
            r.quantities[i].search_top);
    /* A likely view that was not supplied is absent, never fabricated. */
    CHECK(!r.quantities[i].likely.present);
  }

  /* 2. A narrowed guaranteed window, plus a likely view narrower still. The
   *    two windows are two statements about one unknown, so one item carries
   *    both -- there is no second item and no grade field. */
  tops(gest);
  tops(lest);
  {
    struct estimate *g = &gest[Q_VIRT_IMAGE_BASE];
    struct estimate *l = &lest[Q_VIRT_IMAGE_BASE];
    unsigned long span = g->hi - g->lo;
    g->hi = g->lo + span / 2;
    l->lo = g->lo;
    l->hi = g->lo + span / 4;
  }
  gv.est = gest;
  lv.est = lest;
  lv.cs = NULL;
  lv.n_cs = 0;
  kasld_report_build(gv, lv, NULL, RPOSTURE_RANDOMIZED, 0, &r);

  for (int i = 0; i < r.n_quantities; i++) {
    const struct kasld_report_quantity *it = &r.quantities[i];
    if (check_item(it))
      return 1;
    if (it->q != Q_VIRT_IMAGE_BASE)
      continue;
    CHECK(it->guaranteed.present && it->likely.present);
    /* Narrowing is read from the counts, not from a stored flag: a copy of a
     * derived fact is the kind of state that goes stale. */
    CHECK(it->guaranteed.candidates < it->search_top);
    CHECK(it->likely.candidates < it->guaranteed.candidates);
  }

  /* 3. An exclusion carved out of the interior. The estimate keeps only the
   *    hull, so the hole is recoverable from the constraints alone -- which is
   *    why the model lifts it, rather than leaving each format to rediscover
   *    that the range it is printing is not the candidate set. */
  tops(gest);
  {
    struct constraint cs[1];
    struct estimate *g = &gest[Q_VIRT_IMAGE_BASE];
    unsigned long a = g->lo + (g->hi - g->lo) / 4;
    unsigned long b = g->lo + (g->hi - g->lo) / 2;
    memset(cs, 0, sizeof(cs));
    cs[0].q = Q_VIRT_IMAGE_BASE;
    cs[0].op = C_EXCLUDE;
    cs[0].value = a;
    cs[0].value2 = b;
    cs[0].conf = CONF_PARSED;

    gv.est = gest;
    gv.cs = cs;
    gv.n_cs = 1;
    lv.est = NULL;
    kasld_report_build(gv, lv, NULL, RPOSTURE_RANDOMIZED, 0, &r);

    for (int i = 0; i < r.n_quantities; i++) {
      const struct kasld_report_quantity *it = &r.quantities[i];
      if (check_item(it))
        return 1;
      if (it->q != Q_VIRT_IMAGE_BASE)
        continue;
      CHECK(it->guaranteed.n_excluded == 1);
      CHECK(it->guaranteed.excluded_listed == 1);
      /* The hull is unchanged by an interior hole -- that is what makes the
       * count and the endpoints disagree, and why both must be reported. */
      CHECK(it->guaranteed.lo == gest[Q_VIRT_IMAGE_BASE].lo);
      CHECK(it->guaranteed.hi == gest[Q_VIRT_IMAGE_BASE].hi);
      CHECK(it->guaranteed.candidates < it->search_top);
    }
  }

  /* 4. A sub-floor exclusion must not carve a window resolved above it: it
   *    never reached that window's edges, and presenting it as carving the
   *    interior could drop the true value from a sound window. */
  tops(gest);
  {
    struct constraint cs[1];
    struct estimate *g = &gest[Q_VIRT_IMAGE_BASE];
    memset(cs, 0, sizeof(cs));
    cs[0].q = Q_VIRT_IMAGE_BASE;
    cs[0].op = C_EXCLUDE;
    cs[0].value = g->lo + (g->hi - g->lo) / 4;
    cs[0].value2 = g->lo + (g->hi - g->lo) / 2;
    cs[0].conf = CONF_TIMING; /* below CONF_INFERRED */

    gv.est = gest;
    gv.cs = cs;
    gv.n_cs = 1;
    gv.floor = CONF_INFERRED;
    lv.est = NULL;
    kasld_report_build(gv, lv, NULL, RPOSTURE_RANDOMIZED, 0, &r);

    for (int i = 0; i < r.n_quantities; i++) {
      const struct kasld_report_quantity *it = &r.quantities[i];
      if (it->q != Q_VIRT_IMAGE_BASE)
        continue;
      CHECK(it->guaranteed.n_excluded == 0);
      CHECK(it->guaranteed.candidates == it->search_top);
    }
  }

  /* 5. A set narrows by losing values, not by moving edges. The tighter-query
   *    is what every format asks before presenting a speculative window, so a
   *    shape it cannot compare is a shape whose likely view silently never
   *    appears -- which is how one quantity comes to be reported differently
   *    from its neighbours. */
  if (quantities[Q_VA_BITS].n_candidates > 1) {
    const struct kasld_report_quantity *it;
    tops(gest);
    tops(lest);
    gv.est = gest;
    gv.cs = NULL;
    gv.n_cs = 0;
    lv.est = lest;
    lv.cs = NULL;
    lv.n_cs = 0;

    /* Identical sets: the likely view reached the same answer, and saying so
     * twice would restate the proven one under a weaker grade. */
    kasld_report_build(gv, lv, NULL, RPOSTURE_RANDOMIZED, 0, &r);
    it = kasld_report_find(&r, Q_VA_BITS);
    CHECK(it != NULL);
    CHECK(it->guaranteed.shape == RSHAPE_SET);
    CHECK(!kasld_report_likely_is_tighter(it));

    /* Narrow the likely view through the lattice, not by clearing a bit: on
     * LK_FINSET `lo` is a live-candidate bitmask, and a test that edited it
     * directly would encode this quantity's current representation as though it
     * were the contract. */
    {
      struct constraint c;
      memset(&c, 0, sizeof(c));
      c.q = Q_VA_BITS;
      c.op = C_EXCLUDE;
      c.value = quantities[Q_VA_BITS].candidates[0];
      c.value2 = c.value;
      c.conf = CONF_PARSED;
      estimate_meet(&lest[Q_VA_BITS], &quantities[Q_VA_BITS], &c);
    }
    kasld_report_build(gv, lv, NULL, RPOSTURE_RANDOMIZED, 0, &r);
    it = kasld_report_find(&r, Q_VA_BITS);
    CHECK(it != NULL);
    CHECK(kasld_report_likely_is_tighter(it));
    CHECK(it->likely.candidates < it->guaranteed.candidates);
    CHECK(it->likely.n_values == (int)it->likely.candidates);
    if (check_item(it))
      return 1;
  } else {
    /* Stated rather than skipped silently: on an architecture admitting one
     * address-space size there is no set quantity to compare, and a run that
     * printed OK without saying so would look like coverage. */
    printf("test_report: set-narrowing case not exercised "
           "(this architecture admits one address-space size)\n");
  }

  /* 6. A concrete base is recorded only where a resolution agrees it is the
   *    answer. The caller picks it from the observations and cannot know what
   *    the engine made of them, so the model is what reconciles the two -- and
   *    a point offered unqualified is what lets a format present a bound as a
   *    value and count it as one candidate. */
  {
    struct kasld_report_point pts[Q__COUNT];
    const struct kasld_report_quantity *it;
    unsigned long lo, span;

    tops(gest);
    lo = gest[Q_VIRT_IMAGE_BASE].lo;
    span = gest[Q_VIRT_IMAGE_BASE].hi - lo;
    gv.est = gest;
    gv.cs = NULL;
    gv.n_cs = 0;
    gv.floor = CONF_INFERRED;
    lv.est = NULL;

    /* A point inside a window that admits many values: not the answer, so the
     * model does not offer it as one. */
    memset(pts, 0, sizeof(pts));
    pts[Q_VIRT_IMAGE_BASE].present = 1;
    pts[Q_VIRT_IMAGE_BASE].value = lo + span / 2;
    kasld_report_build(gv, lv, pts, RPOSTURE_RANDOMIZED, 0, &r);
    it = kasld_report_find(&r, Q_VIRT_IMAGE_BASE);
    CHECK(it != NULL);
    CHECK(it->guaranteed.candidates > 1);
    CHECK(!it->has_point);

    /* The same window narrowed to one value, with the point naming it: now it
     * is the answer, and the model says so. */
    tops(gest);
    gest[Q_VIRT_IMAGE_BASE].hi = gest[Q_VIRT_IMAGE_BASE].lo;
    memset(pts, 0, sizeof(pts));
    pts[Q_VIRT_IMAGE_BASE].present = 1;
    pts[Q_VIRT_IMAGE_BASE].value = gest[Q_VIRT_IMAGE_BASE].lo;
    kasld_report_build(gv, lv, pts, RPOSTURE_RANDOMIZED, 0, &r);
    it = kasld_report_find(&r, Q_VIRT_IMAGE_BASE);
    CHECK(it != NULL);
    CHECK(it->guaranteed.candidates == 1);
    CHECK(it->has_point && it->point == gest[Q_VIRT_IMAGE_BASE].lo);

    /* A pinned window and a point that names a DIFFERENT address: the two
     * disagree, so neither is presented as the answer. */
    memset(pts, 0, sizeof(pts));
    pts[Q_VIRT_IMAGE_BASE].present = 1;
    pts[Q_VIRT_IMAGE_BASE].value = gest[Q_VIRT_IMAGE_BASE].lo + 0x1000ul;
    kasld_report_build(gv, lv, pts, RPOSTURE_RANDOMIZED, 0, &r);
    it = kasld_report_find(&r, Q_VIRT_IMAGE_BASE);
    CHECK(it != NULL);
    CHECK(!it->has_point);
  }

  /* The tally run-all reads to decide whether a suite ran and what it found.
   * Emitted in the shared harness's shape -- "<pass>/<total> tests passed" on
   * stderr -- because that string is the contract between a suite and the
   * runner, and a suite that prints anything else is reported as having failed
   * to run at all. Every check here is a pass by the time this is reached: a
   * failing one returns above. */
  fprintf(stderr, "%d/%d tests passed\n", checks, checks);
  /* 7. A caller-supplied denominator wins over the architecture's own.
   *
   *    The direct map's residual is measured against the window the kernel
   *    draws page_offset_base from, which is sized from engine evidence the
   *    builder cannot see. Losing that supply changed a readout from
   *    "~4 of 15 bits" to "~4 bits" with nothing failing, because the render
   *    harness stages the denominator itself and never exercised the wiring. */
  {
    struct kasld_report_point pts[Q__COUNT];
    const struct kasld_report_quantity *it;
    unsigned long unsupplied;

    tops(gest);
    gv.est = gest;
    gv.cs = NULL;
    gv.n_cs = 0;
    gv.floor = CONF_INFERRED;
    lv.est = NULL;

    /* Nothing supplied: the builder's own answer stands, whatever it is. Kept
     * as the baseline the supplied case must differ from -- asserting only
     * that the supplied value arrives would pass on a builder that ignored the
     * supply and happened to compute the same figure. */
    memset(pts, 0, sizeof(pts));
    kasld_report_build(gv, lv, pts, RPOSTURE_RANDOMIZED, 0, &r);
    it = kasld_report_find(&r, Q_PAGE_OFFSET);
    CHECK(it != NULL);
    unsupplied = it->entropy_top;
    CHECK(unsupplied != 16384);

    memset(pts, 0, sizeof(pts));
    pts[Q_PAGE_OFFSET].entropy_top = 16384;
    kasld_report_build(gv, lv, pts, RPOSTURE_RANDOMIZED, 0, &r);
    it = kasld_report_find(&r, Q_PAGE_OFFSET);
    CHECK(it != NULL);
    CHECK(it->entropy_top == 16384);
    CHECK(it->top_bits == 14);
    /* Carried without a concrete value beside it: a denominator is known in
     * runs that resolved no base, so it must not be gated on `present`. */
    CHECK(!it->has_point);
  }

  /* 9. A quantity a constraint pinned at zero is reported, and one whose edge
   *    is merely the lattice floor is not.
   *
   *    Both edges of a pin at zero hold the value zero, so a presence test
   *    reading the value alone drops the whole quantity -- the engine resolves
   *    it exactly and the report says it knows nothing. This is not exotic: an
   *    s390 built without CONFIG_RANDOMIZE_IDENTITY_BASE has __identity_base ==
   *    0, so the stock configuration's linear-map base is zero.
   *
   *    Asserted against its own opposite. The same quantity left at a zero
   *    lattice floor, with nothing bound to it, must still read as unstated --
   *    otherwise the fix trades a dropped pin for a window counted from a floor
   *    no evidence established. */
  {
    const struct kasld_report_quantity *it;
    enum kasld_quantity zq = Q__COUNT;

    /* Any member whose top starts at a zero lower edge will do; picking it from
     * the table rather than naming one keeps this true of whichever quantities
     * the arch admits. */
    tops(gest);
    for (int q = 0; q < Q__COUNT; q++)
      if (q_is_member((enum kasld_quantity)q) && gest[q].kind == LK_INTERVAL &&
          gest[q].lo == 0 && gest[q].hi != 0) {
        zq = (enum kasld_quantity)q;
        break;
      }
    if (zq == Q__COUNT) {
      printf("test_report: (skipped: no member opens at a zero edge here)\n");
    } else {
      gv.est = gest;
      gv.cs = NULL;
      gv.n_cs = 0;
      gv.floor = CONF_INFERRED;
      lv.est = NULL;
      lv.cs = NULL;
      lv.n_cs = 0;
      lv.floor = CONF_BRUTE;

      /* Unbound zero floor: one-sided, and no count taken from it. */
      kasld_report_build(gv, lv, NULL, RPOSTURE_RANDOMIZED, 0, &r);
      it = kasld_report_find(&r, zq);
      CHECK(it != NULL);
      CHECK(!it->guaranteed.has_lo);
      CHECK(it->guaranteed.candidates == 0);

      /* Pinned at zero by a constraint. Ids start at 1, so a binding is what
       * separates this state from the one above -- the values are identical. */
      tops(gest);
      gest[zq].kind = LK_INTERVAL;
      gest[zq].lo = 0;
      gest[zq].hi = 0;
      gest[zq].lo_binding = 1;
      gest[zq].hi_binding = 1;
      gest[zq].lo_conf = CONF_PARSED;
      gest[zq].hi_conf = CONF_PARSED;
      kasld_report_build(gv, lv, NULL, RPOSTURE_RANDOMIZED, 0, &r);
      it = kasld_report_find(&r, zq);
      CHECK(it != NULL);
      CHECK(it->guaranteed.present);
      CHECK(it->guaranteed.has_lo && it->guaranteed.has_hi);
      CHECK(it->guaranteed.lo == 0 && it->guaranteed.hi == 0);
      CHECK(it->guaranteed.candidates == 1);
    }
  }

  /* Provenance is the caller's and survives the build verbatim. A replayed
   *    document names the captured kernel throughout, so the flag is the only
   *    thing separating it from a live one and it must not be inferred from,
   *    or overwritten by, anything the estimates say. */
  {
    tops(gest);
    gv.est = gest;
    gv.cs = NULL;
    gv.n_cs = 0;
    gv.floor = CONF_INFERRED;
    lv.est = NULL;
    lv.cs = NULL;
    lv.n_cs = 0;
    lv.floor = CONF_BRUTE;

    kasld_report_build(gv, lv, NULL, RPOSTURE_RANDOMIZED, 1, &r);
    CHECK(r.replay == 1);
    kasld_report_build(gv, lv, NULL, RPOSTURE_RANDOMIZED, 0, &r);
    CHECK(r.replay == 0);

    /* An empty resolution returns early from the builder; the flag is set
     * before that return, so a run that resolved nothing is still labelled. */
    gv.est = NULL;
    kasld_report_build(gv, lv, NULL, RPOSTURE_RANDOMIZED, 1, &r);
    CHECK(r.replay == 1);
    CHECK(r.n_quantities == 0);
  }

  /* 11. The grain a count stands on is a floor by default and the granularity
   *     itself once the alignment quantity is closed. The image base's
   *     granularity is a build option, so this is a property of the RUN, not of
   *     the architecture -- which is why the model reads it from the estimate
   *     rather than from a table keyed on the quantity.
   *
   *     Asserted in both directions from one staging, so a build that answered
   *     the same way regardless would fail: the same quantity, same window and
   *     same count, differing only in whether the alignment was closed. */
  {
    const struct kasld_report_quantity *it;
    unsigned long grain;

    tops(gest);
    gv.est = gest;
    gv.cs = NULL;
    gv.n_cs = 0;
    gv.floor = CONF_INFERRED;
    lv.est = NULL;
    lv.cs = NULL;
    lv.n_cs = 0;
    lv.floor = CONF_BRUTE;

    /* A floor alone: the architecture's minimum bounds the grain from below and
     * says nothing about the kernel this run is looking at. */
    kasld_report_build(gv, lv, NULL, RPOSTURE_RANDOMIZED, 0, &r);
    it = kasld_report_find(&r, Q_VIRT_IMAGE_BASE);
    CHECK(it != NULL);
    CHECK(!it->align_exact);
    grain = it->align_min;
    CHECK(grain > 0);

    /* The same run, with the granularity resolved to the grain already in use.
     * The count does not move -- only what the count is claimed to be. */
    gest[Q_VIRT_KASLR_ALIGN].lo = grain;
    gest[Q_VIRT_KASLR_ALIGN].hi = grain;
    kasld_report_build(gv, lv, NULL, RPOSTURE_RANDOMIZED, 0, &r);
    it = kasld_report_find(&r, Q_VIRT_IMAGE_BASE);
    CHECK(it != NULL);
    CHECK(it->align_min == grain);
    CHECK(it->align_exact);

    /* A granularity resolved to something FINER than the architecture's own
     * minimum qualifies a grain that is not the one being reported, so it must
     * not mark it exact. The arch minimum is what the model counts on there. */
    if (grain > 1) {
      gest[Q_VIRT_KASLR_ALIGN].lo = grain / 2;
      gest[Q_VIRT_KASLR_ALIGN].hi = grain / 2;
      kasld_report_build(gv, lv, NULL, RPOSTURE_RANDOMIZED, 0, &r);
      it = kasld_report_find(&r, Q_VIRT_IMAGE_BASE);
      CHECK(it != NULL);
      CHECK(it->align_min == grain);
      CHECK(!it->align_exact);
    }
  }

  /* 12. The module row is counted on the allocator's own step where the
   *     architecture states one, and marked exact because that step IS the
   *     pitch rather than a floor under it. Where no step is declared the
   *     page-granular floor stands and the count is a ceiling.
   *
   *     Asserted against the declaration rather than against a value, so this
   *     holds on every architecture `make test-cross` runs it on. */
  {
    const struct kasld_report_quantity *it;

    tops(gest);
    gv.est = gest;
    gv.cs = NULL;
    gv.n_cs = 0;
    gv.floor = CONF_INFERRED;
    lv.est = NULL;
    lv.cs = NULL;
    lv.n_cs = 0;
    lv.floor = CONF_BRUTE;
    kasld_report_build(gv, lv, NULL, RPOSTURE_RANDOMIZED, 0, &r);

    it = kasld_report_find(&r, Q_MODULE_BASE);
    if (it != NULL) {
#ifdef MODULES_BASE_RANDOM_STEP
      CHECK(it->align_min == (unsigned long)MODULES_BASE_RANDOM_STEP);
      CHECK(it->align_exact);
#else
      CHECK(it->align_min == (unsigned long)KASLD_LAYOUT_GRANULE);
      CHECK(!it->align_exact);
#endif
    }
  }

  printf("test_report: OK (%d checks)\n", checks);
  return 0;
}
