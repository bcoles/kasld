// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: snap the guaranteed virtual image-base window to the KASLR grid.
//
// _text is congruent to IMAGE_BASE_OFFSET modulo the compile-time
// KASLR_VIRT_ALIGN by construction (the residue is an exact architectural
// constant — linker script / boot protocol). So for a sound bound on _text:
//   - the largest grid point <= the upper bound is still >= _text, and
//   - the smallest grid point >= the lower bound is still <= _text.
// Flooring the ceiling and raising the floor to the grid are therefore SOUND
// sharpenings that never cross _text, even on the sub-offset arches (riscv64
// +0x2000, arm32 +0x8000, s390 +0x100000, mips +0x400) where a plain
// floor/ceil(v, align) would. Neither drops a candidate: the sub-slot slack
// outside the first/last grid point holds no valid base. The result is a
// candidate-exact window — min and max are the lowest and highest positions the
// base can actually occupy.
//
// This complements range_from_interior, whose raw interior-sample ceiling is
// deliberately left un-floored (a plain floor there once rejected the real
// riscv64 kallsyms pin). That rule's header defers "sound alignment-tightening
// [to] the aligned image base, not [...] _stext" — this rule is that step: it
// snaps the RESOLVED base bounds, not the raw sample. It bites where an
// unaligned bound is the tightest one (the interior-sample ceiling and the
// image-size-derived floor under the more restricted reader profiles).
//
// Compile-time KASLR_VIRT_ALIGN (via
// kasld_floor_text_base/kasld_ceil_text_base), NOT the resolved
// Q_VIRT_KASLR_ALIGN: the compile-time residue is valid modulo the compile-time
// granule on every arch unconditionally, whereas a runtime-raised alignment
// (only x86_64's boot_params_kaslr_align today) could invalidate the residue
// modulo the larger granule on a nonzero-residue arch. The source-specific
// ceiling rules already capture the escalation win where it is sound (x86_64,
// residue 0).
//
// Gated on IMAGE_BASE_RESIDUE_FIXED: the snap is sound only where _text's
// residue modulo KASLR_VIRT_ALIGN is an architectural constant. On arm32 the
// residue is config-dependent (variable TEXT_OFFSET / section-map padding), so
// the rule is inert there — snapping would floor a bound below the true base.
//
// Self-edge (reads est[Q_VIRT_IMAGE_BASE], writes the same quantity): reviewed
// in tests/check-self-edges; soundness test in tests/test_engine.c. Idempotent
// — floor/ceil of an already-grid value is itself — so it reaches a fixpoint in
// one application.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"

#include <string.h>

/* Only used on arches with a fixed _text residue; guarded so the inert-arch
 * build (which compiles out the caller below) does not warn it unused. */
#if IMAGE_BASE_RESIDUE_FIXED
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
  snprintf(c->origin, ORIGIN_LEN, "image_base_grid_align");
}
#endif

int rule_image_base_grid_align(const struct evidence_set *ev,
                               const struct estimate *est,
                               struct constraint *out, int out_max) {
  (void)ev; /* reads only the resolved estimate, never raw evidence */
#if !IMAGE_BASE_RESIDUE_FIXED
  /* _text's grid residue is not architecturally fixed on this arch; snapping a
   * bound to the assumed grid could cross the true base. Inert. */
  (void)est;
  (void)out;
  (void)out_max;
  return 0;
#else

  const struct estimate *e = &est[Q_VIRT_IMAGE_BASE];
  if (e->kind != LK_INTERVAL)
    return 0;
  int n = 0;

  /* Ceiling: floor a REAL upper bound down to the grid. hi_binding == 0 is the
   * honest top (no constraint bounds the edge); flooring the arch max is noise.
   * floored >= _text always holds, so floored >= lo for any satisfiable
   * estimate; the lo guard is defensive against an already-unsatisfiable input
   * (a window with no grid candidate). */
  if (e->hi_binding != 0 && n < out_max) {
    unsigned long floored = kasld_floor_text_base(e->hi);
    if (floored < e->hi && floored >= e->lo)
      emit_bound(&out[n++], C_UPPER_BOUND, floored, e->hi_conf, e->hi_binding);
  }

  /* Floor: raise a REAL lower bound up to the grid. Symmetric: ceiled <= _text
   * always holds, so ceiled <= hi for any satisfiable estimate; the hi guard is
   * the same defensive check against a candidate-free window. */
  if (e->lo_binding != 0 && n < out_max) {
    unsigned long ceiled = kasld_ceil_text_base(e->lo);
    if (ceiled > e->lo && ceiled <= e->hi)
      emit_bound(&out[n++], C_LOWER_BOUND, ceiled, e->lo_conf, e->lo_binding);
  }

  return n;
#endif
}
