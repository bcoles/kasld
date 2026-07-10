// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: snap the guaranteed image-base window to the RESOLVED KASLR grid.
//
// image_base_grid_align snaps the window to the COMPILE-TIME granule
// (KASLR_VIRT_ALIGN / KASLR_PHYS_ALIGN) — sound on every arch unconditionally.
// But when a parsed CONFIG_PHYSICAL_ALIGN / boot_params / EFI kimage align
// raises the resolved align quantity above that granule, the base actually
// steps by the coarser granule, so the sub-slots between two coarse grid points
// hold no valid base. Floor the upper bound and raise the lower bound to the
// resolved grid to carve them out.
//
// On a window whose only resolved-grid position is a single address this
// collapses [lo, hi] to a pin — the concrete base. That is the same
// "1 candidate / ~0 bits" state quantity_slots already reports from the coarse
// align, made nameable: the interval lattice cannot express "only one sub-slot
// in this span is a valid base", so the window stays a few compile-granule
// slots wide until this rule snaps it.
//
// Sound for the same reason as image_base_grid_align: the base is congruent to
// its default modulo the KASLR granule (the granule IS the randomization
// stride), so the largest resolved-grid point <= hi is still >= the base and
// the smallest resolved-grid point >= lo is still <= the base. Neither snap
// crosses the base. The resolved granule is only ever raised above the
// compile-time granule by a parsed alignment source — the true stride — so the
// residue modulo the coarser granule is exact. Mirrors ceiling_from_image_size,
// which already floors its image-size ceiling to these same resolved align
// quantities.
//
// Both axes: the virtual base carries KERNEL_VIRT_TEXT_DEFAULT's sub-offset
// residue (0 on x86_64/arm64, nonzero on riscv64/arm32/s390/mips); the physical
// base carries no sub-offset (residue 0). The phys axis is decoupled-only
// (#if !TEXT_TRACKS_DIRECTMAP), matching ceiling_from_image_size — on coupled
// arches phys and virt slide together and the virt snap covers both.
//
// Gated on the resolved granule being strictly coarser than the compile-time
// one: image_base_grid_align already covers the equal case, and this rule adds
// nothing there.
//
// Self-edges (reads est[Q_VIRT_IMAGE_BASE] / est[Q_PHYS_IMAGE_BASE], writes the
// same quantities): reviewed in tests/check-self-edges; soundness tests in
// tests/test_engine.c. Idempotent — snapping an already-grid bound is itself —
// so it reaches a fixpoint in one application.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"

#include <string.h>

/* Fill a snapped-bound constraint except its quantity, which each axis sets
 * literally below (so the self-edge guard's static write-detection sees it). */
static void set_bound(struct constraint *c, enum constraint_op op,
                      unsigned long value, enum kasld_confidence conf,
                      uint32_t from) {
  memset(c, 0, sizeof(*c));
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
  int n = 0;

  /* Virtual axis. Snap to the resolved grid preserving _text's sub-offset
   * residue (0 where the base is granule-aligned). The lo/hi guards drop a snap
   * that would invert the window (a candidate-free span holds no valid base).
   */
  {
    const struct estimate *e = &est[Q_VIRT_IMAGE_BASE];
    unsigned long align = est[Q_VIRT_KASLR_ALIGN].lo;
    unsigned long def = (unsigned long)KERNEL_VIRT_TEXT_DEFAULT;
    if (e->kind == LK_INTERVAL && align > (unsigned long)KASLR_VIRT_ALIGN) {
      if (e->hi_binding != 0 && n < out_max) {
        unsigned long f = kasld_floor_aligned_suboffset(e->hi, align, def);
        if (f < e->hi && f >= e->lo) {
          set_bound(&out[n], C_UPPER_BOUND, f, e->hi_conf, e->hi_binding);
          out[n++].q = Q_VIRT_IMAGE_BASE;
        }
      }
      if (e->lo_binding != 0 && n < out_max) {
        unsigned long c = kasld_ceil_aligned_suboffset(e->lo, align, def);
        if (c > e->lo && c <= e->hi) {
          set_bound(&out[n], C_LOWER_BOUND, c, e->lo_conf, e->lo_binding);
          out[n++].q = Q_VIRT_IMAGE_BASE;
        }
      }
    }
  }

#if !TEXT_TRACKS_DIRECTMAP
  /* Physical axis (decoupled arches): residue 0, no sub-offset. On coupled
   * arches the virt snap already covers the locked phys base. */
  {
    const struct estimate *e = &est[Q_PHYS_IMAGE_BASE];
    unsigned long align = est[Q_PHYS_KASLR_ALIGN].lo;
    if (e->kind == LK_INTERVAL && align > (unsigned long)KASLR_PHYS_ALIGN) {
      if (e->hi_binding != 0 && n < out_max) {
        unsigned long f = kasld_floor_aligned_suboffset(e->hi, align, 0ul);
        if (f < e->hi && f >= e->lo) {
          set_bound(&out[n], C_UPPER_BOUND, f, e->hi_conf, e->hi_binding);
          out[n++].q = Q_PHYS_IMAGE_BASE;
        }
      }
      if (e->lo_binding != 0 && n < out_max) {
        unsigned long c = kasld_ceil_aligned_suboffset(e->lo, align, 0ul);
        if (c > e->lo && c <= e->hi) {
          set_bound(&out[n], C_LOWER_BOUND, c, e->lo_conf, e->lo_binding);
          out[n++].q = Q_PHYS_IMAGE_BASE;
        }
      }
    }
  }
#endif
  return n;
}
