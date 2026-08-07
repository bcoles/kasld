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
// and the module region lies BELOW the image on both arches -- riscv64 has
// MODULES_END = _start, s390 has MODULES_END = round_down(kernel_start,
// _SEGMENT_SIZE) -- so the image base bounds it from above:
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
// Inert where MODULES_RELATIVE_TO_TEXT == 0, and inert until the image base is
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
#if MODULES_RELATIVE_TO_TEXT
  (void)ev;
  if (out_max < 1)
    return 0;

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

  /* Ceiling: the module region sits below the image on both arches, so the
   * image base caps it. Only from a lowered upper edge, for the same reason. */
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
