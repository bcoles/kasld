// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: derive Q_MODULE_BASE from the resolved text base, on arches where the
// module region is placed relative to the kernel image.
//
// module_text_bound runs this relation module -> text. This is the inverse. It
// exists because on those arches Q_MODULE_BASE otherwise falls back to the raw
// validation band, which is enormous (riscv64: ~35 million 4 KiB candidates)
// even with the text base fully pinned -- despite the region's placement being
// a function of that very base.
//
// Both directions are read off the same arch constant. module_text_bound uses
//
//   image_base <= module_lo + MODULES_END_TO_TEXT_OFFSET   (both cases, modulo
//                                                           a Case A image-size
//                                                           term)
//
// so the contrapositive bounds the module base from below:
//
//   module_base >= image_base_lo - MODULES_END_TO_TEXT_OFFSET
//
// and the module region lies BELOW the image wherever this relation holds at
// all -- riscv64 has MODULES_END = _start, and s390, on the arrangement that
// places the band against the image, has MODULES_END =
// round_down(kernel_start, _SEGMENT_SIZE) -- so the image base bounds it from
// above:
//
//   module_base <= image_base_hi
//
// Deliberately the weaker of the available forms in two places. Case A
// (riscv64) could add MTB_MIN_KERNEL_IMAGE_SIZE to the floor, and s390 could
// subtract MODULES_LEN from the ceiling, but both refinements need a quantity
// this rule does not otherwise read (the image size, the segment rounding).
// Widening is the safe direction for a bound, and the coarse form already
// removes most of the band.
//
// WHERE THE ANCHOR IS NOT A BUILD-TIME PROPERTY. An arch may answer
// MOD_ANCHOR_RUNTIME, meaning it has carried more than one arrangement and the
// build cannot tell which one booted. Both bounds above are then conditional on
// an arrangement that may not be the one in force, and emitting either on the
// wrong one does not report a loose window but one that excludes the true base
// -- on s390 the two arrangements sit at opposite ends of the address space.
// So the anchor is established from evidence first, and nothing is emitted
// until it is.
//
// Nothing is emitted rather than something demoted to the likely window. The
// sibling module_base_from_text_bracket does demote, because there the
// unestablished case makes its floor merely loose. Here the unestablished case
// makes both edges wrong, and there is no reason to prefer one arrangement:
// both are in service, on kernels a run cannot date.
//
// kasld_module_anchor_proven() is the one answer, shared with module_text_bound
// and with the layout renderer, so a band bounded here cannot be drawn in the
// other arrangement's place. It reaches its conclusion from a parsed config or
// from a known module address, whichever the vantage has -- this rule earns its
// keep where there is no module address at all, and then the config is the only
// witness left.
//
// Inert where MODULES_MAY_TRACK_TEXT == 0, and inert until the image base is
// narrowed from its honest top -- an unnarrowed text base would derive an
// unnarrowed module base and say nothing.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"
#include "include/kasld/regions.h"

#include <string.h>

int rule_module_base_from_text(const struct evidence_set *ev,
                               const struct estimate *est,
                               struct constraint *out, int out_max) {
#if MODULES_MAY_TRACK_TEXT
  if (out_max < 1)
    return 0;

  /* Establish the anchor before deriving from it (see the note above). */
#if MODULES_ANCHOR_IS_RUNTIME
  {
    unsigned long avt_lo = 0, avt_hi = 0;
    (void)quantity_window(Q_VIRT_IMAGE_BASE, &est[Q_VIRT_IMAGE_BASE], &avt_lo,
                          &avt_hi);
    if (kasld_module_anchor_proven(ev, avt_lo, avt_hi) != S390_LAYOUT_UNCOUPLED)
      return 0;
  }
#else
  (void)ev;
#endif

  const struct estimate *vt = &est[Q_VIRT_IMAGE_BASE];
  struct estimate top;
  quantities[Q_VIRT_IMAGE_BASE].init_top(&top);

  const unsigned long off = (unsigned long)MODULES_END_TO_TEXT_OFFSET;
  int n = 0;

  /* Floor: only from a raised lower edge. An untouched edge carries no
   * information, and subtracting the offset from the architectural floor would
   * emit a bound weaker than the quantity's own top. */
  if (vt->lo > top.lo && vt->lo > off && n < out_max) {
    struct constraint *c = &out[n++];
    memset(c, 0, sizeof(*c));
    c->q = Q_MODULE_BASE;
    c->op = C_LOWER_BOUND;
    c->value = vt->lo - off;
    c->conf = CONF_INFERRED;
    /* No observation lineage: this derives from another QUANTITY, not from a
     * leak. derived_from holds observation ids, so threading the estimate's
     * binding constraint id through it would be a dangling reference. */
    snprintf(c->origin, ORIGIN_LEN, "module_base_from_text");
  }

  /* Ceiling: with the anchor established the module region sits below the
   * image, so the image base caps it. Only from a lowered upper edge, for the
   * same reason. */
  if (vt->hi < top.hi && vt->hi && n < out_max) {
    struct constraint *c = &out[n++];
    memset(c, 0, sizeof(*c));
    c->q = Q_MODULE_BASE;
    c->op = C_UPPER_BOUND;
    c->value = vt->hi;
    c->conf = CONF_INFERRED;
    snprintf(c->origin, ORIGIN_LEN, "module_base_from_text");
  }

  return n;
#else
  (void)ev;
  (void)est;
  (void)out;
  (void)out_max;
  return 0;
#endif
}
