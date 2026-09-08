// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: floor Q_MODULE_BASE from the resolved image base on arches whose module
// allocator draws its window around the kernel image.
//
// Where MODULES_BRACKET_TEXT is a byte size W, every module allocation comes
// from a window of at most W bytes that also contains [_text, _end]. The window
// starts no lower than _end - W, and _end is never below _text, so the lowest
// address the allocator can hand out obeys
//
//   module_base >= _text - W
//
// and the LOWEST image base the resolved window still admits gives the sound
// floor. This is the converse of module_text_bracket, which reads module
// ADDRESSES to bound the image; this reads the resolved IMAGE to bound the
// module base, and so answers on a vantage that has no module leak at all.
//
// WHY THE FLOOR ONLY. The matching ceiling looks equally free -- the window
// starts at or below the image on every current allocator -- but it is not
// sound across the generations this arch admits: an older allocator measures
// its window from _stext rather than _text, so a base can exceed _text by the
// image's head gap and a _text-derived ceiling would sit below it. The ceiling
// worth having comes from an observed module address instead, which
// module_base_bounds already applies and which needs no generation argument.
//
// The floor is the edge that has none: the module band's compile-time union is
// drawn a full bracket below the LOWEST image base the arch admits, so it never
// moves with the evidence, and on a kernel whose image is resolved far above
// that floor the reported band keeps a lower edge hundreds of TiB below
// anything the allocator could have chosen.
//
// PRECONDITION. W bounds the allocator only on the modern VA layout; see the
// PRECONDITION note in module_text_bracket for the older generations and why a
// version string cannot separate them. The witness here is the resolved image
// base itself -- an image proven to sit above the linear map is impossible on
// the old layout, where every kernel region sat below it. Where the layout is
// not established the floor is still emitted, below the sound floor, so it
// shapes the likely window only.
//
// PURE CROSS-QUANTITY: reads the estimates and nothing else, and so carries no
// observation lineage -- no observation supports the floor, which follows from
// the resolved image base and the architecture's own allocator geometry. The
// edge-setting binding on an estimate names the CONSTRAINT that set it, which
// is a different vocabulary from the observation ids a constraint's lineage
// records; attributing one to the other would name an unrelated observation and
// survive its invalidation.
//
// Not a self-edge: reads Q_VIRT_IMAGE_BASE and Q_PAGE_OFFSET, writes
// Q_MODULE_BASE. Inert where MODULES_BRACKET_TEXT == 0, and inert until the
// image base is resolved.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"

#include <string.h>

int rule_module_base_from_text_bracket(const struct evidence_set *ev,
                                       const struct estimate *est,
                                       struct constraint *out, int out_max) {
#if MODULES_BRACKET_TEXT > 0
  (void)ev;
  if (out_max < 1)
    return 0;

  const unsigned long w = (unsigned long)MODULES_BRACKET_TEXT;
  const struct estimate *vt = &est[Q_VIRT_IMAGE_BASE];

  unsigned long vt_lo = 0, vt_hi = 0;
  if (!quantity_window(Q_VIRT_IMAGE_BASE, vt, &vt_lo, &vt_hi) || vt_lo == 0)
    return 0;
  /* An image within W of the bottom of the address space cannot be bounded
   * below; a wrapped floor would name the wrong end of it. */
  if (vt_lo < w)
    return 0;

  /* Establish the layout before claiming the width (see PRECONDITION above). */
#if defined(__aarch64__)
  enum kasld_confidence conf = CONF_HEURISTIC;
  {
    unsigned long po_lo = 0, po_hi = 0;
    if (quantity_window(Q_PAGE_OFFSET, &est[Q_PAGE_OFFSET], &po_lo, &po_hi) &&
        arm64_modern_layout_proven(vt_lo, po_hi))
      conf = CONF_INFERRED;
  }
#else
#error                                                                         \
    "MODULES_BRACKET_TEXT on a non-arm64 arch: state whether the bracket width holds across every VA layout the header admits, or supply that arch's layout witness here"
#endif

  struct constraint *c = &out[0];
  memset(c, 0, sizeof(*c));
  c->q = Q_MODULE_BASE;
  c->op = C_LOWER_BOUND;
  c->value = vt_lo - w;
  c->conf = conf;
  snprintf(c->origin, ORIGIN_LEN, "module_base_from_text_bracket");
  return 1;
#else
  (void)ev;
  (void)est;
  (void)out;
  (void)out_max;
  return 0;
#endif
}
