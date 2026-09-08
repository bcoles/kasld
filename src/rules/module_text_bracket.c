// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: bracket the kernel text base from leaked module addresses on arches
// whose module allocator draws its window around the kernel image.
//
// Where MODULES_BRACKET_TEXT is a byte size W, the allocator guarantees every
// module allocation comes from a window of at most W bytes that also contains
// [_text, _end]. Both therefore lie in one W-wide window, so:
//
//   for every module allocation M:   |M - _text| < W
//
// Taken over all observed allocations that gives a two-sided bound:
//
//   image_base >  max(M) - W        (lower, from the HIGHEST allocation)
//   image_base <  min(M) + W        (upper, from the LOWEST allocation)
//
// The relation is purely relative — it never reads the band's absolute
// position — which is what makes it usable on an arch (arm64) whose static
// MODULES_START/END are a wide union of several VA layouts rather than the
// live band.
//
// PRECONDITION — W bounds the allocator only on the MODERN VA layout. On the
// older arm64 layout the module region was randomized across the whole vmalloc
// span, deliberately decoupled from the image ("this prevents modules from
// leaking any information about the address of the kernel itself"), and an
// intermediate generation drew the window at twice this width. A module
// address on such a kernel can sit far further from _text than W, so applying
// W there would place the guaranteed window where _text is not — the one
// failure the sound floor exists to prevent. Neither generation can be
// identified from a version string, so the layout is established from evidence:
// the lowest module address itself is the witness, and
// arm64_modern_layout_proven() answers whether it lies above every PAGE_OFFSET
// still admitted.
//
// Unproven does not mean silent. The bounds are still emitted, at a confidence
// BELOW the sound floor, so they shape the likely window and leave the
// guaranteed one untouched. The modern layout is the overwhelmingly common
// case, so this keeps the precision where it is a reported best guess and
// withdraws it only from the window that must hold.
//
// PROVENANCE: reads VIRT REGION_MODULE only, NOT REGION_MODULE_BAND. The
// weaker tag covers addresses classified as module merely because they fell
// inside that union, and on arm64 the union overlaps a VA_BITS=48 direct map,
// so a range-classified kmalloc pointer would bracket the text base around the
// wrong region entirely — placing the ceiling far below the true _text and
// carving truth out of the guaranteed window. See the module-region note in
// api.h. That is also why this rule cannot simply re-check the band itself:
// the band is exactly what is untrustworthy here.
//
// Distinct from module_text_bound, which handles the tighter fixed-OFFSET
// geometry (MODULES_RELATIVE_TO_TEXT); the two axes are mutually exclusive.
// Inert where MODULES_BRACKET_TEXT == 0, and inert with no module observation.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"
#include "include/kasld/regions.h"

#include <limits.h>
#include <string.h>

int rule_module_text_bracket(const struct evidence_set *ev,
                             const struct estimate *est, struct constraint *out,
                             int out_max) {
#if MODULES_BRACKET_TEXT > 0
  if (out_max < 1)
    return 0;

  unsigned long valign = est[Q_VIRT_KASLR_ALIGN].lo;
  if (valign < (unsigned long)KASLR_VIRT_ALIGN)
    valign = (unsigned long)KASLR_VIRT_ALIGN;
  if (valign == 0)
    return 0;

  const unsigned long w = (unsigned long)MODULES_BRACKET_TEXT;

  unsigned long vmod_lo = ULONG_MAX, vmod_hi = 0;
  uint32_t lo_src = 0, hi_src = 0;
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->value_kind != OBS_ADDRESS ||
        o->eff_type != KASLD_TYPE_VIRT)
      continue;
    if (o->eff_region != REGION_MODULE)
      continue;
    unsigned long a = obs_anchor(o);
    if (a == 0)
      continue;
    if (a < vmod_lo) {
      vmod_lo = a;
      lo_src = o->id;
    }
    if (a > vmod_hi) {
      vmod_hi = a;
      hi_src = o->id;
    }
  }
  if (vmod_lo == ULONG_MAX)
    return 0;

  /* Establish the layout before claiming the width (see PRECONDITION above).
   * The lowest module address is the witness: proving IT sits above the linear
   * map proves the whole region does, since nothing places a module below the
   * region's own base. */
#if defined(__aarch64__)
  enum kasld_confidence conf = CONF_HEURISTIC;
  {
    unsigned long po_lo = 0, po_hi = 0;
    if (quantity_window(Q_PAGE_OFFSET, &est[Q_PAGE_OFFSET], &po_lo, &po_hi) &&
        arm64_modern_layout_proven(vmod_lo, po_hi))
      conf = CONF_INFERRED;
  }
#else
#error                                                                         \
    "MODULES_BRACKET_TEXT on a non-arm64 arch: state whether the bracket width holds across every VA layout the header admits, or supply that arch's layout witness here"
#endif

  int n = 0;

  /* Upper bound: image_base <= vmod_lo + W - 1, floored onto the image-base
   * grid. Skip on wrap — an address within W of ULONG_MAX cannot be bounded
   * above, and a wrapped value would be a spuriously tight ceiling. */
  if (vmod_lo <= ULONG_MAX - w) {
    unsigned long new_max =
        kasld_floor_virt_text_bound(vmod_lo + w - 1, valign);
    /* Fail-safe, not the soundness guard: a genuine module allocation yields a
     * bound inside the quantity's honest top, so a ceiling below that window's
     * floor means the observation was not what it claimed — emitting it would
     * empty the estimate rather than narrow it. Dropping widens, which is the
     * safe direction. The floor is the _WIDE variant (the same window
     * top_virt_image_base uses), not KERNEL_VIRT_TEXT_MIN: on arm64 the latter
     * sits above the honest top's floor and would discard sound bounds. */
    if (new_max >= (unsigned long)KASLR_VIRT_TEXT_MIN_WIDE && n < out_max) {
      struct constraint *c = &out[n++];
      memset(c, 0, sizeof(*c));
      c->q = Q_VIRT_IMAGE_BASE;
      c->op = C_UPPER_BOUND;
      c->value = new_max;
      c->conf = conf;
      c->derived_from[0] = lo_src;
      c->lineage_count = 1;
      snprintf(c->origin, ORIGIN_LEN, "module_text_bracket");
    }
  }

  /* Lower bound: image_base >= vmod_hi - W + 1, raised onto the image-base
   * grid. Skip on underflow (module below W from 0 cannot bound from below). */
  if (vmod_hi >= w) {
    unsigned long new_min = kasld_ceil_aligned_suboffset(
        vmod_hi - w + 1, valign, (unsigned long)KERNEL_VIRT_TEXT_DEFAULT);
    if (new_min <= (unsigned long)KASLR_VIRT_TEXT_MAX_WIDE && n < out_max) {
      struct constraint *c = &out[n++];
      memset(c, 0, sizeof(*c));
      c->q = Q_VIRT_IMAGE_BASE;
      c->op = C_LOWER_BOUND;
      c->value = new_min;
      c->conf = conf;
      c->derived_from[0] = hi_src;
      c->lineage_count = 1;
      snprintf(c->origin, ORIGIN_LEN, "module_text_bracket");
    }
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
