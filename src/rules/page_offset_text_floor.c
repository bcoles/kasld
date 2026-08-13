// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: the kernel image sits at or above the linear-map base.
//
// On a coupled architecture the image is placed inside the linear map at
// PAGE_OFFSET + TEXT_OFFSET, with TEXT_OFFSET >= IMAGE_BASE_OFFSET (the
// architecture's smallest head gap). So for any admissible base:
//
//   virt_image_base >= PAGE_OFFSET + IMAGE_BASE_OFFSET
//
// and the LOWEST base the resolved window still admits gives the sound floor.
// The lower edge rather than a pinned point: a lower bound only needs the
// smallest value the target could have, so requiring the window to collapse
// first would leave the rule inert on exactly the architectures where the split
// is a build choice and this floor is most wanted. Where one base is admissible
// the edge IS that base.
//
// PURE CROSS-QUANTITY: reads the estimate and nothing else. It carries no
// observation lineage because no observation supports it — the claim follows
// from the resolved base and the architecture's own placement rule. That is
// what separates it from dram_floor_bound, whose floor is a fact about DRAM and
// is attributed to the DRAM witness that established it.
//
// Decoupled arches are excluded: there the image is randomised independently of
// the linear map and may sit below PAGE_OFFSET entirely.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"

#include <limits.h>
#include <string.h>

int rule_page_offset_text_floor(const struct evidence_set *ev,
                                const struct estimate *est,
                                struct constraint *out, int out_max) {
  (void)ev;
#if TEXT_TRACKS_DIRECTMAP
  if (out_max < 1)
    return 0;

  unsigned long po_lo = 0;
  if (!quantity_window(Q_PAGE_OFFSET, &est[Q_PAGE_OFFSET], &po_lo, NULL))
    return 0;
  if (po_lo > ULONG_MAX - IMAGE_BASE_OFFSET)
    return 0;

  unsigned long virt_lo = po_lo + (unsigned long)IMAGE_BASE_OFFSET;
  /* Round DOWN to a slot: a lower bound only weakens by doing so. */
  if (KASLR_VIRT_ALIGN > 0)
    virt_lo &= ~(KASLR_VIRT_ALIGN - 1); /* virt-floor-ok */
  if (virt_lo <= KASLR_VIRT_TEXT_MIN)
    return 0; /* the honest top already says at least this much */

  struct constraint *c = &out[0];
  memset(c, 0, sizeof(*c));
  c->q = Q_VIRT_IMAGE_BASE;
  c->op = C_LOWER_BOUND;
  c->value = virt_lo;
  /* The confidence of the base it rests on: a floor derived from a heuristic
   * base is itself heuristic, and must not shape the guaranteed window. */
  c->conf = est[Q_PAGE_OFFSET].lo_conf;
  c->lineage_count = 0;
  snprintf(c->origin, ORIGIN_LEN, "page_offset_text_floor");
  return 1;
#else
  (void)est;
  (void)out;
  (void)out_max;
  return 0;
#endif
}
