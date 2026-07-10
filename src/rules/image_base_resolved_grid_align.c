// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: snap the guaranteed virtual image-base window to the RESOLVED KASLR
// grid.
//
// image_base_grid_align snaps the window to the COMPILE-TIME granule
// (KASLR_VIRT_ALIGN) — sound on every arch unconditionally. But when a parsed
// CONFIG_PHYSICAL_ALIGN / boot_params raises Q_VIRT_KASLR_ALIGN above that
// granule, the base actually steps by the coarser granule, so the sub-slots
// between two coarse grid points hold no valid base. Floor the upper bound and
// raise the lower bound to the resolved grid to carve them out.
//
// On a window whose only resolved-grid position is a single address this
// collapses [lo, hi] to a pin — the concrete base. That is the same
// "1 candidate / ~0 bits" state quantity_slots already reports from the coarse
// align, made nameable: the interval lattice cannot express "only one sub-slot
// in this span is a valid base", so the window stays a few compile-granule
// slots wide until this rule snaps it.
//
// Sound for the same reason as image_base_grid_align: _text is congruent to
// KERNEL_VIRT_TEXT_DEFAULT modulo the KASLR granule (the granule IS the
// randomization stride), so the largest resolved-grid point <= hi is still
// >= _text and the smallest resolved-grid point >= lo is still <= _text.
// Neither snap crosses _text. The resolved granule is only ever raised above
// the compile-time granule by a parsed alignment source — the true stride — so
// the residue modulo the coarser granule is exact. Mirrors
// ceiling_from_image_size, which already floors its image-size ceiling to this
// same resolved Q_VIRT_KASLR_ALIGN.
//
// Gated on the resolved granule being strictly coarser than the compile-time
// one: image_base_grid_align already covers the equal case, and this rule adds
// nothing there.
//
// Self-edge (reads est[Q_VIRT_IMAGE_BASE], writes the same quantity): reviewed
// in tests/check-self-edges; soundness test in tests/test_engine.c. Idempotent
// — snapping an already-grid bound is itself — so it reaches a fixpoint in one
// application.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"

#include <string.h>

static void emit_bound(struct constraint *c, enum constraint_op op,
                       unsigned long value, enum kasld_confidence conf,
                       uint32_t from) {
  memset(c, 0, sizeof(*c));
  c->q = Q_VIRT_IMAGE_BASE;
  c->op = op;
  c->value = value;
  c->conf = conf; /* as trustworthy as the bound it sharpens, no more */
  c->derived_from[0] = from;
  c->lineage_count = 1;
  snprintf(c->origin, ORIGIN_LEN, "image_base_resolved_grid_align");
}

int rule_image_base_resolved_grid_align(const struct evidence_set *ev,
                                        const struct estimate *est,
                                        struct constraint *out, int out_max) {
  (void)ev; /* reads only the resolved estimates, never raw evidence */

  const struct estimate *e = &est[Q_VIRT_IMAGE_BASE];
  if (e->kind != LK_INTERVAL)
    return 0;

  /* The resolved granule; only act when it is coarser than the compile-time
   * one (else image_base_grid_align already snapped to this grid). */
  unsigned long align = est[Q_VIRT_KASLR_ALIGN].lo;
  if (align <= (unsigned long)KASLR_VIRT_ALIGN)
    return 0;

  unsigned long def = (unsigned long)KERNEL_VIRT_TEXT_DEFAULT;
  int n = 0;

  /* Ceiling: floor a REAL upper bound down to the resolved grid. floored
   * >= _text always holds, so floored >= lo for any satisfiable estimate; the
   * lo guard is defensive against a window with no resolved-grid candidate. */
  if (e->hi_binding != 0 && n < out_max) {
    unsigned long floored = kasld_floor_aligned_suboffset(e->hi, align, def);
    if (floored < e->hi && floored >= e->lo)
      emit_bound(&out[n++], C_UPPER_BOUND, floored, e->hi_conf, e->hi_binding);
  }

  /* Floor: raise a REAL lower bound up to the resolved grid. Symmetric: ceiled
   * <= _text always holds, so ceiled <= hi for any satisfiable estimate; the hi
   * guard is the same defensive check against a candidate-free window. */
  if (e->lo_binding != 0 && n < out_max) {
    unsigned long ceiled = kasld_ceil_aligned_suboffset(e->lo, align, def);
    if (ceiled > e->lo && ceiled <= e->hi)
      emit_bound(&out[n++], C_LOWER_BOUND, ceiled, e->lo_conf, e->lo_binding);
  }

  return n;
}
