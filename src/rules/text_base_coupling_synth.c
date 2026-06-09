// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: symmetric phys↔virt text-base coupling synthesizer.
//
// On TEXT_TRACKS_DIRECTMAP arches the kernel image is mapped at a fixed
// offset (PAGE_OFFSET) above its physical load, so:
//
//   virt_text_base ≈ virt_page_offset + (phys_text_base - PHYS_OFFSET)
//
// Reads the post-narrowing estimates and propagates each side's interval
// onto the other:
//
//   est[Q_VIRT_TEXT_BASE]  → bounds on Q_PHYS_TEXT_BASE
//   est[Q_PHYS_TEXT_BASE]  → bounds on Q_VIRT_TEXT_BASE
//
// This complements:
//   * text_pin_from_observation, which only fires when a direct text-base
//     witness exists on the target side.
//   * kernel_image_phys_bound, which projects raw phys observations onto
//     Q_VIRT_TEXT_BASE but never the other direction, and reads raw
//     observations (not the post-narrowing estimate).
//
// Net effect: any narrowing of either text base — by an iomem/kallsyms
// pin, by image-size ceilings, by module-relative bounds, by DRAM bounds,
// or by upstream coupling — is now propagated symmetrically. The
// dominant win is on a coupled arch with only a virt leak (kallsyms but
// no iomem): Q_PHYS_TEXT_BASE collapses from its honest top to a small
// window around the implied phys base.
//
// Soundness:
//   * Requires Q_PAGE_OFFSET pinned (po->lo == po->hi). On
//     DIRECTMAP_STATIC arches this is provided by phys_virt_synth (from
//     paired directmap+DRAM leaks) or page_offset_invariant_pin (on the
//     architecturally-fixed subset). Without that pin we cannot project
//     symbols across the boundary.
//   * The TEXT_OFFSET safety margin accounts for the image header /
//     EFI-stub slack between the linker-defined _text base and what
//     components actually observe (e.g. kallsyms _stext vs iomem
//     "Kernel code" — empirically a 128 KiB gap on LoongArch6.18). Same
//     convention as kernel_image_phys_bound.
//   * Emitted at CONF_DERIVED (below CONF_PARSED); any contradicting
//     witness from a direct observation wins the engine's conflict
//     resolution rather than being overridden by this synthesizer.
//   * Bounds-only emission (no C_EQUALS) — the meet of the four bounds
//     pins the target when one side is itself pinned.
//
// Inert on decoupled arches (TEXT_TRACKS_DIRECTMAP=0): arm64, riscv64,
// s390, x86_64 carry independent phys/virt KASLR slides; the coupling
// here would be unsound for them.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"

#include <limits.h>
#include <string.h>

int rule_text_base_coupling_synth(const struct evidence_set *ev,
                                  const struct estimate *est,
                                  struct constraint *out, int out_max) {
  (void)ev;
#if TEXT_TRACKS_DIRECTMAP
  const struct estimate *po = &est[Q_PAGE_OFFSET];
  if (po->lo != po->hi)
    return 0; /* virt_page_offset must be pinned for the projection to be sound
               */
  const unsigned long virt_page_offset = po->lo;

  const struct estimate *vt = &est[Q_VIRT_TEXT_BASE];
  const struct estimate *pt = &est[Q_PHYS_TEXT_BASE];
  const unsigned long phys_off = (unsigned long)PHYS_OFFSET;
  const unsigned long text_off = (unsigned long)TEXT_OFFSET;
  /* virt_to_phys delta: PAGE_OFFSET - PHYS_OFFSET. Positive on every
   * TEXT_TRACKS_DIRECTMAP arch (kernel virt > kernel phys). */
  const unsigned long v_minus_p = virt_page_offset - phys_off;

  int n = 0;

  /* Two-stage overflow guards on the (v_minus_p + text_off) sub-expression.
   * Realistic kernel constants are far below ULONG_MAX so this is purely
   * defensive — protects against a port-day arch with unusual offsets where
   * the inner addition could otherwise wrap and let the outer subtraction /
   * addition silently produce nonsense bounds. */
  int vplus_off_safe = (v_minus_p <= ULONG_MAX - text_off);

  /* virt → phys: phys ∈ [vt.lo - v_minus_p - TEXT_OFFSET,  vt.hi - v_minus_p]
   */
  if (vplus_off_safe && vt->lo > v_minus_p + text_off && n < out_max) {
    struct constraint *c = &out[n++];
    memset(c, 0, sizeof(*c));
    c->q = Q_PHYS_TEXT_BASE;
    c->op = C_LOWER_BOUND;
    c->value = vt->lo - v_minus_p - text_off;
    c->conf = CONF_DERIVED;
    c->lineage_count = 0;
    snprintf(c->origin, ORIGIN_LEN, "text_base_coupling_synth");
  }
  if (vt->hi > v_minus_p && n < out_max) {
    struct constraint *c = &out[n++];
    memset(c, 0, sizeof(*c));
    c->q = Q_PHYS_TEXT_BASE;
    c->op = C_UPPER_BOUND;
    c->value = vt->hi - v_minus_p;
    c->conf = CONF_DERIVED;
    c->lineage_count = 0;
    snprintf(c->origin, ORIGIN_LEN, "text_base_coupling_synth");
  }

  /* phys → virt: virt ∈ [pt.lo + v_minus_p,  pt.hi + v_minus_p + TEXT_OFFSET]
   */
  if (pt->lo <= ULONG_MAX - v_minus_p && n < out_max) {
    struct constraint *c = &out[n++];
    memset(c, 0, sizeof(*c));
    c->q = Q_VIRT_TEXT_BASE;
    c->op = C_LOWER_BOUND;
    c->value = pt->lo + v_minus_p;
    c->conf = CONF_DERIVED;
    c->lineage_count = 0;
    snprintf(c->origin, ORIGIN_LEN, "text_base_coupling_synth");
  }
  if (vplus_off_safe && pt->hi <= ULONG_MAX - v_minus_p - text_off &&
      n < out_max) {
    struct constraint *c = &out[n++];
    memset(c, 0, sizeof(*c));
    c->q = Q_VIRT_TEXT_BASE;
    c->op = C_UPPER_BOUND;
    c->value = pt->hi + v_minus_p + text_off;
    c->conf = CONF_DERIVED;
    c->lineage_count = 0;
    snprintf(c->origin, ORIGIN_LEN, "text_base_coupling_synth");
  }
  return n;
#else
  (void)est;
  (void)out;
  (void)out_max;
  return 0;
#endif
}
