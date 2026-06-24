// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: arm64 kernel text base, VA_BITS-aware (Phase 2 of the sub-48 work).
//
// arm64 places the kernel image at KIMAGE_VADDR = _PAGE_END(VA_BITS_MIN) +
// module_region_size, where VA_BITS_MIN = min(VA_BITS, 48). KIMAGE_VADDR is
// thus a function of the paging config, NOT a single compile-time constant — so
// the generic virt_kaslr_disabled_pin (one fixed default) is opted out for
// arm64 (KASLR_DISABLED_PINS_VIRT_TEXT 0) and this rule owns the text base,
// anchored on the resolved PAGE_OFFSET (= -(1<<VA_BITS), not randomized —
// recovered by mmap_arm64_va_bits / arm64_va_bits_from_directmap).
//
// Once PAGE_OFFSET resolves to a single candidate value:
//   * narrow Q_VIRT_IMAGE_BASE to that VA_BITS_MIN's text band
//     [KIMAGE_VADDR(VA_BITS_MIN), KIMAGE_VADDR + max-KASLR-offset], tightening
//     the (deliberately wide, union-over-all-VA_BITS) honest top — so a 48-bit
//     KASLR-on kernel regains the tight window the union top widened, and a
//     sub-48 kernel gets its own band;
//   * if KASLR is reported off, additionally pin the base to
//     KIMAGE_VADDR(VA_BITS_MIN) (the link-time default for that config).
//
// All emissions are CONF_INFERRED (the pin capped to the disabled signal), so a
// real text leak overrides them by confidence. Acts only once PAGE_OFFSET is
// pinned to a known candidate: the honest top spans every VA_BITS' PAGE_OFFSET,
// so acting earlier would constrain off the wrong layout — and when PAGE_OFFSET
// never resolves (probe blocked, no leak) nothing is pinned, leaving the sound
// wide window (the conservative choice for an unknown VA_BITS_MIN).
//
// The module_region_size that sets KIMAGE_VADDR varies by version
// (128M/256M/2G) and is not runtime-discoverable, so the band BRACKETS the
// whole spread without keying on a version number: the floor uses the smallest
// region (lowest KIMAGE_VADDR), the ceiling/no-KASLR cap use the largest.
// Pinning the floor at the 2G value would exclude a 5.4..6.1 (128M-region)
// kernel whose text sits at _PAGE_END+128M. Because the size is unknown,
// no-KASLR yields a tight RANGE across the candidate KIMAGE_VADDRs, not a
// single point.
//
// arm64 only; inert elsewhere.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"

#include <string.h>

#if defined(__aarch64__)

/* Widest plausible KASLR offset above KIMAGE_VADDR for VA_BITS_MIN, from the
 * v6.6 kaslr_early.c formula BIT(VA_BITS_MIN-3) + GENMASK(VA_BITS_MIN-3, 0)
 * (>= the v6.12 window). For VA_BITS_MIN=48 this is (1<<45)+(1<<46), so
 * KIMAGE_VADDR(48) + this == KASLR_VIRT_TEXT_MAX. */
static unsigned long arm64_kaslr_offset_max(unsigned long va_min) {
  return (1UL << (va_min - 3)) + (1UL << (va_min - 2));
}

int rule_arm64_text_base(const struct evidence_set *ev,
                         const struct estimate *est, struct constraint *out,
                         int out_max) {
  if (out_max < 1)
    return 0;

  const struct estimate *po = &est[Q_PAGE_OFFSET];
  /* Act only once PAGE_OFFSET is resolved to a single value. */
  if (po->kind != LK_INTERVAL || po->lo != po->hi)
    return 0;

  /* Map the resolved PAGE_OFFSET back to its VA_BITS (PAGE_OFFSET = -(1<<va)).
   */
  static const unsigned long cands[] = VA_BITS_CANDIDATES;
  const int ncands = (int)(sizeof(cands) / sizeof(cands[0]));
  unsigned long va = 0;
  for (int k = 0; k < ncands; k++) {
    if (arm64_page_offset_for(cands[k]) == po->lo) {
      va = cands[k];
      break;
    }
  }
  if (va == 0)
    return 0; /* resolved PAGE_OFFSET is not a known candidate */

  unsigned long va_min = va < 48ul ? va : 48ul;
  unsigned long page_end = arm64_page_end_for(va_min);
  /* KIMAGE_VADDR spans the module-region version spread; bracket it. The floor
   * uses the smallest region (lowest base), the ceiling/no-KASLR cap the
   * largest. */
  unsigned long kimg_lo = page_end + ARM64_MODULE_REGION_SIZE_MIN;
  unsigned long kimg_hi = page_end + ARM64_MODULE_REGION_SIZE;
  unsigned long ceiling = kimg_hi + arm64_kaslr_offset_max(va_min);

  int n = 0;
  /* Narrow the union honest top to this VA_BITS_MIN's text band (KASLR on or
   * off): floor at the lowest KIMAGE_VADDR (admits the no-KASLR base and every
   * module-region size), ceiling at the widest KASLR-window top. Inferred — a
   * real leak overrides. */
  if (n < out_max) {
    struct constraint *c = &out[n++];
    memset(c, 0, sizeof(*c));
    c->q = Q_VIRT_IMAGE_BASE;
    c->op = C_LOWER_BOUND;
    c->value = kimg_lo;
    c->conf = CONF_INFERRED;
    c->derived_from[0] = po->lo_binding;
    c->lineage_count = po->lo_binding ? 1 : 0;
    snprintf(c->origin, ORIGIN_LEN, "arm64_text_base");
  }
  if (n < out_max) {
    struct constraint *c = &out[n++];
    memset(c, 0, sizeof(*c));
    c->q = Q_VIRT_IMAGE_BASE;
    c->op = C_UPPER_BOUND;
    c->value = ceiling;
    c->conf = CONF_INFERRED;
    c->derived_from[0] = po->lo_binding;
    c->lineage_count = po->lo_binding ? 1 : 0;
    snprintf(c->origin, ORIGIN_LEN, "arm64_text_base");
  }

  /* No-KASLR: the base is the link-time KIMAGE_VADDR(VA_BITS_MIN) exactly (no
   * slide; IMAGE_BASE_OFFSET is 0 on arm64). The module-region size is unknown,
   * so KIMAGE_VADDR is one of {_PAGE_END+128M, +256M, +2G} — cap the base at
   * the largest (kimg_hi); the floor (kimg_lo) already bounds below, giving the
   * tight no-KASLR range [kimg_lo, kimg_hi] without the KASLR slide on top.
   * Capped to the disabled signal's confidence (and to inferred), so a real
   * text leak still wins. Window-containment: skip if the cap falls below the
   * current floor (e.g. a real leak already raised it). */
  uint32_t sig_id = 0;
  enum kasld_confidence sig_conf = CONF_UNKNOWN;
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->value_kind != OBS_SCALAR)
      continue;
    if (o->scalar_fact == SF_VIRT_KASLR_DISABLED && o->scalar_value != 0) {
      sig_id = o->id;
      sig_conf = o->conf;
      break;
    }
  }
  if (sig_id != 0 && n < out_max) {
    const struct estimate *vt = &est[Q_VIRT_IMAGE_BASE];
    if (kimg_hi >= vt->lo) {
      struct constraint *c = &out[n++];
      memset(c, 0, sizeof(*c));
      c->q = Q_VIRT_IMAGE_BASE;
      c->op = C_UPPER_BOUND;
      c->value = kimg_hi;
      c->conf = sig_conf < CONF_INFERRED ? sig_conf : CONF_INFERRED;
      c->derived_from[0] = sig_id;
      c->lineage_count = 1;
      snprintf(c->origin, ORIGIN_LEN, "arm64_text_base");
    }
  }
  return n;
}

#else

int rule_arm64_text_base(const struct evidence_set *ev,
                         const struct estimate *est, struct constraint *out,
                         int out_max) {
  (void)ev;
  (void)est;
  (void)out;
  (void)out_max;
  return 0;
}

#endif
