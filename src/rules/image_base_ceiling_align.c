// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: snap the guaranteed virtual image-base CEILING to the KASLR grid.
//
// _text is congruent to IMAGE_BASE_OFFSET modulo the compile-time
// KASLR_VIRT_ALIGN by construction (the residue is an exact architectural
// constant — linker script / boot protocol). So the largest grid point <= any
// sound upper bound on _text is still >= _text: flooring the ceiling
// residue-aware is a SOUND sharpening that never drops below the truth, even on
// the sub-offset arches (riscv64 +0x2000, arm32 +0x8000, s390 +0x100000, mips
// +0x400) where a plain floor(sample, align) would.
//
// This complements range_from_interior, whose raw interior-sample ceiling is
// deliberately left un-floored (a plain floor there once rejected the real
// riscv64 kallsyms pin). That rule's header defers "sound alignment-tightening
// [to] the aligned image base, not [...] _stext" — this rule is that step: it
// floors the RESOLVED base ceiling, not the raw sample. It bites where the raw
// interior sample is the tightest ceiling (typically the hidden/hardened
// profiles, where a dense-probe sample sits near _text), shaving up to one
// slot.
//
// Compile-time KASLR_VIRT_ALIGN (via kasld_floor_text_base), NOT the resolved
// Q_VIRT_KASLR_ALIGN: the compile-time residue is valid modulo the compile-time
// granule on every arch unconditionally, whereas a runtime-raised alignment
// (only x86_64's boot_params_kaslr_align today) could invalidate the residue
// modulo the larger granule on a nonzero-residue arch. The source-specific
// ceiling rules already capture the escalation win where it is sound (x86_64,
// residue 0).
//
// Self-edge (reads est[Q_VIRT_IMAGE_BASE], writes the same quantity): reviewed
// in tests/check-self-edges; soundness test in tests/test_engine.c. Idempotent
// — floor(floor(hi)) == floor(hi) — so it reaches a fixpoint in one
// application.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"

#include <string.h>

int rule_image_base_ceiling_align(const struct evidence_set *ev,
                                  const struct estimate *est,
                                  struct constraint *out, int out_max) {
  (void)ev; /* reads only the resolved estimate, never raw evidence */

  const struct estimate *e = &est[Q_VIRT_IMAGE_BASE];

  /* Only sharpen a REAL ceiling. hi_binding == 0 is the honest top (no
   * constraint bounds the upper edge yet); flooring the arch max is noise. */
  if (e->kind != LK_INTERVAL || e->hi_binding == 0 || out_max < 1)
    return 0;

  unsigned long floored = kasld_floor_text_base(e->hi);

  /* Emit only when it strictly tightens and stays a sound, non-empty interval.
   * floored >= _text always holds (it is the largest grid point <= hi and _text
   * is a grid point <= hi), so floored >= lo for any satisfiable estimate; the
   * lo guard is purely defensive against an already-unsatisfiable input. */
  if (floored >= e->hi || floored < e->lo)
    return 0;

  struct constraint *c = &out[0];
  memset(c, 0, sizeof(*c));
  c->q = Q_VIRT_IMAGE_BASE;
  c->op = C_UPPER_BOUND;
  c->value = floored;
  c->conf = e->hi_conf; /* as trustworthy as the ceiling it sharpens, no more */
  c->derived_from[0] = e->hi_binding;
  c->lineage_count = 1;
  snprintf(c->origin, ORIGIN_LEN, "image_base_ceiling_align");
  return 1;
}
