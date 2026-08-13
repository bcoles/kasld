// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Lattice-agnostic access to the Q_PAGE_OFFSET estimate, for tests.
//
// src/ reads the quantities under the seam through the estimate accessors and
// never through `.lo` / `.hi` (check-lattice-seam enforces it); tests are under
// the same obligation for the same reason. Which lattice a quantity uses is
// declared once in the quantity table, and on a finite set `lo` is a
// live-candidate bitmask while `hi` is unused — a direct read is then a small
// integer that compares and arithmetics happily while meaning nothing.
//
// po_lo() / po_hi() report the window CONTAINING every admitted value.
//
// po_set() goes the other way: it applies the requested edges as BOUNDS rather
// than assigning them, so a fixture states "the split is somewhere in here" and
// the lattice decides how to hold it.
// ---
// <bcoles@gmail.com>

#ifndef KASLD_TEST_PO_ACCESS_H
#define KASLD_TEST_PO_ACCESS_H

#include "include/kasld/estimate.h"
#include "include/kasld/quantity.h"

#include <string.h>

static inline unsigned long po_lo(const struct estimate *e) {
  unsigned long v = 0;
  quantity_window(Q_PAGE_OFFSET, e, &v, NULL);
  return v;
}

static inline unsigned long po_hi(const struct estimate *e) {
  unsigned long v = 0;
  quantity_window(Q_PAGE_OFFSET, e, NULL, &v);
  return v;
}

/* Build a Q_PAGE_OFFSET estimate spanning [lo, hi], from the quantity's own
 * honest top. The constraint ids are arbitrary but non-zero, so the resulting
 * estimate reports a bound edge rather than an untouched axiom edge. */
static inline void po_set(struct estimate *e, unsigned long lo,
                          unsigned long hi) {
  const struct quantity_def *qd = &quantities[Q_PAGE_OFFSET];
  struct constraint c;

  qd->init_top(e);

  memset(&c, 0, sizeof(c));
  c.q = Q_PAGE_OFFSET;
  c.conf = CONF_PARSED;
  c.lineage_count = 1;

  c.op = C_LOWER_BOUND;
  c.value = lo;
  c.id = 1;
  estimate_meet(e, qd, &c);

  c.op = C_UPPER_BOUND;
  c.value = hi;
  c.id = 2;
  estimate_meet(e, qd, &c);
}

/* A linear-map base this architecture actually admits.
 *
 * A test that needs "some resolved PAGE_OFFSET" must ask for one rather than
 * invent it: where the architecture fixes the base its bracket holds a single
 * value, and pinning to anything else empties the estimate instead of resolving
 * it. The compile-time default is admissible on every arch — the axis
 * self-consistency test asserts exactly that.
 *
 * `n` selects among the admissible values, saturating at the last one, so
 * po_admissible(0) is always valid and po_admissible(1) differs from it
 * wherever the architecture has a second value to offer. Where the VMSPLIT
 * boundaries are enumerated, they are what a real kernel is built at, so a
 * fixture drawn from them is a placement that occurs rather than merely one
 * the window permits. */
static inline unsigned long po_admissible(int n) {
#if PAGE_OFFSET_IS_FINITE
  static const unsigned long c[] = PAGE_OFFSET_CANDIDATES;
  const int nc = (int)(sizeof(c) / sizeof(c[0]));
  return c[n < 0 ? 0 : (n >= nc ? nc - 1 : n)];
#else
  /* An interval admits everything between the edges. Anchor on the compile-time
   * base rather than on a window edge — the floor is 0 on s390, and a landmark
   * at 0 is not a base any rule will accept — then step toward whichever edge
   * has room. Both directions are needed: the compile-time base sits well below
   * the ceiling on x86_64 / arm64 / riscv64 / s390 but AT it on ppc32, where
   * stepping up alone returns the anchor again and a fixture asking for two
   * distinct bases silently gets one. */
  unsigned long lo = (unsigned long)PAGE_OFFSET_MIN;
  unsigned long hi = (unsigned long)PAGE_OFFSET_MAX;
  unsigned long v =
      (unsigned long)PAGE_OFFSET ? (unsigned long)PAGE_OFFSET : 0x40000000ul;
  unsigned long delta = (unsigned long)n * 0x40000000ul;
  if (n <= 0)
    return v;
  if (delta <= hi - v)
    return v + delta;
  if (delta <= v - lo)
    return v - delta;
  return v;
#endif
}

/* Is this architecture's PAGE_OFFSET resolved before any evidence arrives?
 * True where the bracket holds exactly one value, which makes "narrow it to a
 * different value" an impossible fixture rather than a failing one. */
static inline int po_is_fixed(void) { return PAGE_OFFSET_KNOWN_AT_BUILD; }

#endif /* KASLD_TEST_PO_ACCESS_H */
