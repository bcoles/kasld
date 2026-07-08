// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Estimate resolution: per-lattice meet, bottom test, and the greedy
// conflict-aware resolver. Arch-independent — operates purely over the
// quantity definitions and a constraint array. See estimate.h for the
// model and the README "Inference engine" / "Cross-region derivation"
// sections for the layered architecture this fits into.
// ---
// <bcoles@gmail.com>

#include "include/kasld/estimate.h"

#include <limits.h>

/* Working cap on constraints considered for a single quantity in one
 * resolve. Far above realistic per-quantity constraint counts. */
/* ESTIMATE_MAX_WORK is declared in include/kasld/estimate.h alongside the
 * saturation enum, so callers can size their tests against the same cap. */

/* ------------------------------------------------------------------------
 * Modular helpers (C_STRIDE folding).
 *
 * Stride constraints take the form `q ≡ r (mod m)`. Folding two such
 * constraints (`q ≡ r1 mod m1`, `q ≡ r2 mod m2`) into one (`q ≡ R mod M`,
 * where M = lcm(m1, m2)) is the Chinese Remainder Theorem on a non-coprime
 * pair: unique solution iff (r1 - r2) is divisible by gcd(m1, m2).
 *
 * Moduli are capped by callers (estimate_meet sanity-checks) to fit the
 * extended-Euclidean math comfortably in unsigned long long.
 * ------------------------------------------------------------------------ */

/* Find (g, x, y) with g = gcd(a, b) and a*x + b*y = g. Signed math via
 * intptr_t so coefficients can be negative. */
static long long ext_gcd(long long a, long long b, long long *x, long long *y) {
  if (b == 0) {
    *x = 1;
    *y = 0;
    return a;
  }
  long long x1, y1;
  long long g = ext_gcd(b, a % b, &x1, &y1);
  *x = y1;
  *y = x1 - (a / b) * y1;
  return g;
}

/* Try to fold (r1 mod m1) and (r2 mod m2) into one (R mod M, where M =
 * lcm(m1, m2)). Returns 1 on success and sets *out_r, *out_m; returns 0
 * when the system is inconsistent (no R satisfies both). */
static int stride_crt(unsigned long r1, unsigned long m1, unsigned long r2,
                      unsigned long m2, unsigned long *out_r,
                      unsigned long *out_m) {
  if (m1 == 0 || m2 == 0)
    return 0;
  /* Normalise residues. */
  r1 %= m1;
  r2 %= m2;
  /* Same modulus: must just agree. */
  if (m1 == m2) {
    if (r1 != r2)
      return 0;
    *out_r = r1;
    *out_m = m1;
    return 1;
  }
  long long x, y;
  long long g = ext_gcd((long long)m1, (long long)m2, &x, &y);
  long long diff = (long long)r2 - (long long)r1;
  if (diff % g != 0)
    return 0; /* inconsistent — no solution */
  /* LCM = m1 * m2 / g. Check overflow before multiplying. */
  unsigned long long lcm =
      (unsigned long long)m1 / (unsigned long long)g * (unsigned long long)m2;
  if (lcm > (unsigned long long)ULONG_MAX)
    return 0;
  /* R = r1 + m1 * (diff/g * x)   mod lcm. */
  long long step = (diff / g) % (long long)(m2 / (unsigned long long)g);
  long long R = (long long)r1 + (long long)m1 * step * x;
  R %= (long long)lcm;
  if (R < 0)
    R += (long long)lcm;
  *out_r = (unsigned long)R;
  *out_m = (unsigned long)lcm;
  return 1;
}

/* The first stride-class element ≥ floor; or 0 if it would overflow.
 *
 * Sentinel-vs-value overlap: 0 is both the overflow sentinel AND a legitimate
 * return when floor=0 and offset≡0 (mod stride). Callers must disambiguate
 * before treating "0 means no element exists" — the only existing caller,
 * stride_intersects_interval, does this by re-checking the residue against the
 * floor modulo. If you add a second caller, do the same check or refactor to
 * a `bool overflowed` out-parameter. */
static unsigned long stride_first_at_or_above(unsigned long floor,
                                              unsigned long stride,
                                              unsigned long offset) {
  if (stride == 0)
    return floor;
  unsigned long off = offset % stride;
  unsigned long rem = floor % stride;
  if (rem == off)
    return floor;
  unsigned long add = (off >= rem) ? (off - rem) : (stride - (rem - off));
  if (floor > ULONG_MAX - add)
    return 0;
  return floor + add;
}

/* True iff the stride class has at least one element in [lo, hi]. */
static int stride_intersects_interval(unsigned long lo, unsigned long hi,
                                      unsigned long stride,
                                      unsigned long offset) {
  if (stride == 0)
    return 1;
  unsigned long first = stride_first_at_or_above(lo, stride, offset);
  /* Disambiguate sentinel-0 from legitimate-0: if the residue at lo does not
   * match offset's residue, then either (a) the next class member is at some
   * higher address but stride_first_at_or_above overflowed, or (b) `first`
   * was returned > 0 above. Case (a) -> no member in any [lo, hi]. */
  if (first == 0 && (lo % stride) != (offset % stride))
    return 0;
  return first <= hi;
}

/* ------------------------------------------------------------------------
 * Meet — narrow an estimate by one constraint.
 * ------------------------------------------------------------------------ */
void estimate_meet(struct estimate *e, const struct quantity_def *qd,
                   const struct constraint *c) {
  switch (qd->lattice) {
  case LK_INTERVAL:
    switch (c->op) {
    case C_LOWER_BOUND:
      if (c->value > e->lo) {
        e->lo = c->value;
        e->lo_binding = c->id;
      }
      break;
    case C_UPPER_BOUND:
      if (c->value < e->hi) {
        e->hi = c->value;
        e->hi_binding = c->id;
      }
      break;
    case C_EQUALS:
      if (c->value > e->lo) {
        e->lo = c->value;
        e->lo_binding = c->id;
      }
      if (c->value < e->hi) {
        e->hi = c->value;
        e->hi_binding = c->id;
      }
      break;
    case C_EXCLUDE:
      /* Single-interval lattice cannot represent a hole. Carve only when
       * the excluded range [value, value2] covers an end of [lo, hi]; an
       * interior hole is left uncarved (a known, documented limitation —
       * the value remains sound, just looser). */
      if (c->value <= e->lo && c->value2 >= e->lo && c->value2 < e->hi) {
        e->lo = c->value2 + 1;
        e->lo_binding = c->id;
      } else if (c->value2 >= e->hi && c->value <= e->hi && c->value > e->lo) {
        e->hi = c->value - 1;
        e->hi_binding = c->id;
      }
      break;
    case C_STRIDE: {
      /* Stride annotation: q ≡ value (mod value2). Reject moduli that
       * exceed the safe extended-Euclidean range or are zero. */
      unsigned long m = c->value2;
      unsigned long r = c->value;
      if (m == 0)
        break;
#if __SIZEOF_LONG__ >= 8
      /* Reject moduli beyond the safe extended-Euclidean range. Only reachable
       * on 64-bit: 0xf_ffff_ffff exceeds a 32-bit unsigned long. */
      if (m > 0xffffffffful)
        break;
#endif
      if (e->stride == 0) {
        e->stride = m;
        e->stride_offset = r % m;
        e->stride_binding = c->id;
      } else {
        unsigned long combined_r, combined_m;
        if (!stride_crt(e->stride_offset, e->stride, r % m, m, &combined_r,
                        &combined_m)) {
          /* Force bottom: the existing and new stride classes are disjoint,
           * so no q can satisfy both. Drive lo > hi to signal bottom via
           * the standard interval test. */
          e->lo = 1;
          e->hi = 0;
          e->stride_binding = c->id;
          break;
        }
        e->stride = combined_m;
        e->stride_offset = combined_r;
        e->stride_binding = c->id;
      }
      break;
    }
    default:
      break;
    }
    break;

  case LK_MAXALIGN:
    /* "q divisible by value": combining requires divisibility by both; for
     * powers of two that is the max. */
    if (c->op == C_AT_LEAST_ALIGN && c->value > e->lo) {
      e->lo = c->value;
      e->lo_binding = c->id;
    }
    break;

  case LK_FINSET:
    if (c->op == C_EQUALS) {
      /* Pin to the candidate whose value == c->value; if no candidate
       * matches, the intersection is empty (bottom). */
      unsigned long mask = 0;
      for (int i = 0; i < qd->n_candidates; i++)
        if (qd->candidates[i] == c->value)
          mask = 1ul << i;
      unsigned long narrowed = e->lo & mask;
      if (narrowed != e->lo) {
        e->lo = narrowed;
        e->lo_binding = c->id;
      }
    }
    break;
  }

  /* Propagate the binding constraint's confidence to whichever edge it just set
   * (ids are monotonic from 1, so this only matches an edge this call bound;
   * an edge left pointing at an earlier constraint keeps that one's conf).
   * Lets cross-quantity rules cap a derived constraint at its input's trust. */
  if (e->lo_binding == c->id)
    e->lo_conf = c->conf;
  if (e->hi_binding == c->id)
    e->hi_conf = c->conf;
}

int estimate_is_bottom(const struct estimate *e,
                       const struct quantity_def *qd) {
  switch (qd->lattice) {
  case LK_INTERVAL:
    if (e->lo > e->hi)
      return 1;
    /* With a stride annotation, also bottom when no element of the residue
     * class lies in the interval. */
    if (e->stride &&
        !stride_intersects_interval(e->lo, e->hi, e->stride, e->stride_offset))
      return 1;
    return 0;
  case LK_MAXALIGN:
    return 0; /* max of powers of two is always a valid alignment */
  case LK_FINSET:
    return e->lo == 0; /* no candidates remain */
  }
  return 0;
}

int estimate_finset_value(const struct quantity_def *qd,
                          const struct estimate *e, unsigned long *out) {
  if (qd->lattice != LK_FINSET)
    return 0;
  unsigned long mask =
      e->lo; /* live-candidate bitmask, one bit per candidate */
  if (mask == 0 || (mask & (mask - 1)) != 0)
    return 0; /* zero, or more than one, candidate still live */
  for (int i = 0; i < qd->n_candidates; i++) {
    if (mask == (1ul << i)) {
      *out = qd->candidates[i];
      return 1;
    }
  }
  return 0;
}

/* ------------------------------------------------------------------------
 * Greedy resolver.
 * ------------------------------------------------------------------------ */

/* Priority order for greedy acceptance: confidence DESC, then independent
 * corroboration (lineage_count) DESC, then intrinsic content (value ASC, op)
 * for capture-order-independent determinism, with id as the final tiebreak.
 * Returns <0 if a should come before b. */
static int prio_before(const struct constraint *a, const struct constraint *b) {
  if (a->conf != b->conf)
    return (int)b->conf - (int)a->conf; /* higher conf first */
  if (a->lineage_count != b->lineage_count)
    return (int)b->lineage_count - (int)a->lineage_count; /* more sources */
  /* Tie-break on intrinsic content, NOT emission id: id reflects component
   * capture order, which is non-deterministic under parallel execution — so an
   * equal-(conf,lineage) conflict would otherwise resolve differently between a
   * parallel run and a sequential (--verbose) one. value-then-op is a total,
   * capture-order-independent order; the direction is arbitrary (equal-
   * confidence conflicts have no more-correct side — confidence is the real
   * lever), but it makes the resolved estimate a pure function of the
   * constraint SET. id remains the final fallback for otherwise-identical
   * duplicates. */
  if (a->value != b->value)
    return (a->value < b->value) ? -1 : 1;
  if (a->op != b->op)
    return (int)a->op - (int)b->op;
  if (a->id != b->id)
    return (a->id < b->id) ? -1 : 1;
  return 0;
}

void estimate_resolve(enum kasld_quantity q, enum kasld_confidence floor,
                      const struct constraint *cs, int n_cs,
                      struct resolve_result *out) {
  const struct quantity_def *qd = &quantities[q];

  out->saturation = 0;

  /* Gather indices of in-scope constraints (this quantity, conf >= floor).
   * On overflow we silently keep the first ESTIMATE_MAX_WORK in INSERTION
   * order — the priority sort below would otherwise lose the higher-priority
   * candidates beyond the cap. Surface a saturation bit so --verbose can
   * report it. */
  int idx[ESTIMATE_MAX_WORK];
  int m = 0;
  int in_scope = 0;
  for (int i = 0; i < n_cs; i++) {
    if (cs[i].q != q || (int)cs[i].conf < (int)floor)
      continue;
    in_scope++;
    if (m < ESTIMATE_MAX_WORK)
      idx[m++] = i;
  }
  if (in_scope > m)
    out->saturation |= ESTIMATE_SAT_WORK_FULL;

  /* Insertion sort by priority (small m; stable, in place). */
  for (int i = 1; i < m; i++) {
    int cur = idx[i];
    int j = i - 1;
    while (j >= 0 && prio_before(&cs[idx[j]], &cs[cur]) > 0) {
      idx[j + 1] = idx[j];
      j--;
    }
    idx[j + 1] = cur;
  }

  /* Greedy: start from honest top, accept constraints strongest-first,
   * skipping any that would force bottom. */
  qd->init_top(&out->est);
  out->n_conflicts = 0;
  for (int k = 0; k < m; k++) {
    struct estimate trial = out->est;
    estimate_meet(&trial, qd, &cs[idx[k]]);
    if (estimate_is_bottom(&trial, qd)) {
      if (out->n_conflicts < ESTIMATE_MAX_CONFLICTS)
        out->conflicts[out->n_conflicts++] = cs[idx[k]].id;
      else
        out->saturation |= ESTIMATE_SAT_CONFLICTS_FULL;
    } else {
      out->est = trial;
    }
  }
}

/* ------------------------------------------------------------------------
 * quantity_ranges — interval-set value-access for consumers.
 * ------------------------------------------------------------------------ */
int quantity_ranges(enum kasld_quantity q, const struct estimate *e,
                    const struct constraint *cs, int n_cs, struct range *out,
                    int out_max) {
  const struct quantity_def *qd = &quantities[q];

  if (qd->lattice == LK_MAXALIGN)
    return 0; /* an alignment is not an address set */

  if (qd->lattice == LK_FINSET) {
    int n = 0;
    for (int i = 0; i < qd->n_candidates && n < out_max; i++)
      if (e->lo & (1ul << i)) {
        out[n].lo = qd->candidates[i];
        out[n].hi = qd->candidates[i];
        n++;
      }
    return n;
  }

  /* LK_INTERVAL: carve interior C_EXCLUDE holes out of [lo, hi]. Gather the
   * holes for q, clamp to the interval, sort by lo, then sweep emitting the
   * gaps between them. Edge holes were already applied by the lattice
   * (estimate_meet), so carving them here is an idempotent no-op. */
  struct range holes[ESTIMATE_MAX_WORK];
  int nh = 0;
  for (int i = 0; i < n_cs && nh < ESTIMATE_MAX_WORK; i++) {
    if (cs[i].q != q || cs[i].op != C_EXCLUDE)
      continue;
    unsigned long a = cs[i].value, b = cs[i].value2;
    if (b < e->lo || a > e->hi)
      continue; /* hole entirely outside the interval */
    if (a < e->lo)
      a = e->lo;
    if (b > e->hi)
      b = e->hi;
    holes[nh].lo = a;
    holes[nh].hi = b;
    nh++;
  }
  /* Sort holes by lo (insertion; small nh). */
  for (int i = 1; i < nh; i++) {
    struct range cur = holes[i];
    int j = i - 1;
    while (j >= 0 && holes[j].lo > cur.lo) {
      holes[j + 1] = holes[j];
      j--;
    }
    holes[j + 1] = cur;
  }
  /* Sweep [lo, hi], emitting gaps. `cur` tracks the next free address. */
  int n = 0;
  unsigned long cur = e->lo;
  for (int i = 0; i < nh; i++) {
    if (holes[i].lo > cur) {
      if (n >= out_max)
        return n;
      out[n].lo = cur;
      out[n].hi = holes[i].lo - 1;
      n++;
    }
    if (holes[i].hi == ULONG_MAX) {
      cur = ULONG_MAX;
      /* nothing above; mark exhausted */
      return n;
    }
    if (holes[i].hi + 1 > cur)
      cur = holes[i].hi + 1;
  }
  if (cur <= e->hi && n < out_max) {
    out[n].lo = cur;
    out[n].hi = e->hi;
    n++;
  }
  return n;
}

unsigned long quantity_slots(enum kasld_quantity q, const struct estimate *e,
                             const struct constraint *cs, int n_cs,
                             unsigned long align) {
  if (align == 0)
    return 0;
  struct range rs[ESTIMATE_MAX_WORK];
  int n = quantity_ranges(q, e, cs, n_cs, rs, ESTIMATE_MAX_WORK);

  /* Effective slot pitch: when a stride annotation is present and is a
   * multiple of the requested align, slots step by `stride` (each stride
   * class element is one allowed slot). Otherwise step by `align`. */
  unsigned long step = align;
  if (e->stride && e->stride > align && (e->stride % align) == 0)
    step = e->stride;

  unsigned long slots = 0;
  for (int i = 0; i < n; i++) {
    if (step == e->stride) {
      /* Stride-pitched: count residue-class members in [lo, hi]. */
      unsigned long first =
          stride_first_at_or_above(rs[i].lo, e->stride, e->stride_offset);
      if (first == 0 || first > rs[i].hi)
        continue;
      slots += (rs[i].hi - first) / e->stride + 1;
    } else {
      /* Whole-slot span. A non-empty range narrower than one slot still
       * occupies one slot (the base sits inside it) — so it counts as 1
       * candidate (0 bits), not 0. Without this a sub-slot window would report
       * "0 slots" and be indistinguishable from an empty result. */
      unsigned long w = (rs[i].hi - rs[i].lo) / step;
      if (w == 0 && rs[i].hi > rs[i].lo)
        w = 1;
      slots += w;
    }
  }
  return slots;
}
