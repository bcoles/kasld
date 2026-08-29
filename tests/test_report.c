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
  kasld_report_build(gv, lv, NULL, RPOSTURE_RANDOMIZED, &r);

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
  kasld_report_build(gv, lv, NULL, RPOSTURE_RANDOMIZED, &r);

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
    kasld_report_build(gv, lv, NULL, RPOSTURE_RANDOMIZED, &r);

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
    kasld_report_build(gv, lv, NULL, RPOSTURE_RANDOMIZED, &r);

    for (int i = 0; i < r.n_quantities; i++) {
      const struct kasld_report_quantity *it = &r.quantities[i];
      if (it->q != Q_VIRT_IMAGE_BASE)
        continue;
      CHECK(it->guaranteed.n_excluded == 0);
      CHECK(it->guaranteed.candidates == it->search_top);
    }
  }

  printf("test_report: OK (%d checks)\n", checks);
  return 0;
}
