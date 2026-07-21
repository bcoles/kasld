// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: arm64 kernel-image-base window from a resolved PAGE_OFFSET (VA_BITS).
//
// arm64 places the kernel image at KIMAGE_VADDR = _PAGE_END(VA_BITS_MIN) +
// module_region on the modern (v5.4+ "flipped") VA layout, VA_BITS_MIN =
// min(VA_BITS, 48); the KASLR slide sits on top. Once PAGE_OFFSET resolves to a
// single candidate (PAGE_OFFSET = -(1<<VA_BITS)), this rule narrows the
// (deliberately wide, union-over-all-VA_BITS) honest-top window to that band.
//
// LAYOUT AMBIGUITY — the FLOOR is gated on ONE specific resolved value; do not
// change this to "always a floor" or "never a floor". Both are wrong, and both
// have been tried:
//
//   Before v5.4 the kernel image sat LOW, at VA_START(VA_BITS)+module =
//   -(1<<VA_BITS)+module, one canonical bit BELOW the modern _PAGE_END base
//   (e.g. v4.14 VA48 _text = 0xffff000008080000). The pre-v5.4 linear map was
//   PAGE_OFFSET = -(1<<(VA_BITS-1)), so an old-VA_X directmap reads as modern
//   VA_(X-1) under the -(1<<VA_BITS) formula. Across the candidate set
//   {39,42,47,48,52} — pre-v5.4 supported only {39,42,47,48}, no LVA/52 — the
//   ONLY value shared between an old layout and a modern candidate is
//   old-VA48 == modern-VA47, both at arm64_page_offset_for(47) =
//   0xffff800000000000. Every OTHER old layout resolves to a non-candidate
//   linear-map base and never reaches this rule (its honest top stays wide).
//
//   Consequently:
//     * PAGE_OFFSET == 0xffff800000000000 (va == 47) is ambiguous (modern VA47
//       or pre-v5.4 VA48) — emit NO floor. The honest-top floor
//       KASLR_VIRT_TEXT_MIN_WIDE (the lowest KIMAGE across all layouts) already
//       bounds below and admits the low old-VA48 image. Forcing the modern
//       _PAGE_END(47)+128M floor here would exclude that image — unsound.
//     * ANY OTHER resolved PAGE_OFFSET (va in {39,42,48,52}) proves the modern
//       layout, so the tight modern floor _PAGE_END(VA_BITS_MIN)+128M is sound.
//       Dropping the gate to "never a floor" needlessly widens every modern
//       kernel's window down to the historical honest floor.
//   (A VA47 modern kernel — 16K/3-level — also lands on the ambiguous value and
//   keeps the wide floor; recovering it would need a separate modern-layout
//   proof, e.g. an observed text address >= _PAGE_END(48) or a vmemmap sample
//   above the directmap, neither reachable on the pre-v5.4 layout.)
//
// The CEILING is an upper bound the low old layout can never violate, so it is
// always narrowed. If KASLR is off, additionally cap the base at the largest
// KIMAGE_VADDR (upper bound). The module_region size (128M/256M/2G) is not
// runtime-discoverable, so the floor uses the smallest (128M, lowest base) and
// the ceiling the largest (2G).
//
// All emissions are CONF_INFERRED, so a real text leak overrides them; when
// PAGE_OFFSET never resolves, nothing is emitted.
//
// arm64 only; inert elsewhere.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"

#include <string.h>

#if defined(__aarch64__)

/* The one resolved VA_BITS shared with a pre-v5.4 layout (old VA48's linear map
 * is arm64_page_offset_for(47)); a floor is unsafe only for this value. */
#define ARM64_TEXT_AMBIGUOUS_VA 47ul

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
  unsigned long kimg_lo = page_end + ARM64_MODULE_REGION_SIZE_MIN;
  unsigned long kimg_hi = page_end + ARM64_MODULE_REGION_SIZE;
  unsigned long ceiling = kimg_hi + arm64_kaslr_offset_max(va_min);

  int n = 0;

  /* FLOOR — only when the resolved PAGE_OFFSET proves the modern layout. The
   * ambiguous value (va == 47) is shared with the pre-v5.4 VA48 low image,
   * whose base is below this floor; leaving it at the honest top keeps that
   * sound. See the header for why this gate is neither "always" nor "never". */
  if (va != ARM64_TEXT_AMBIGUOUS_VA && n < out_max) {
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

  /* CEILING — an upper bound the low old layout cannot violate, so always safe
   * to narrow. Inferred; a real leak overrides. */
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
   * so cap the base at the largest candidate (kimg_hi) — UPPER bound only,
   * sound for the low old layout too. The floor (above, when unambiguous)
   * already bounds below. Capped to the disabled signal's confidence (and to
   * inferred), so a real text leak still wins. Skip if the cap falls below the
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
