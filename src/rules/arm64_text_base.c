// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: arm64 kernel-image-base window from a resolved PAGE_OFFSET, or from
// the resolved VA_BITS alone where the layout stays ambiguous.
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
// When PAGE_OFFSET does NOT resolve -- the leak-free case, because a width
// admits both linear-map bases and so leaves two candidates -- the band above
// cannot be chosen, but the pair of them can be emitted as a union. That path
// is keyed on the resolved WIDTH instead, which is unambiguous where a resolved
// PAGE_OFFSET is not, and is described at arm64_text_band_union below.
//
// All emissions are CONF_INFERRED, so a real text leak overrides them; when
// neither PAGE_OFFSET nor the width resolves, nothing is emitted.
//
// arm64 only; inert elsewhere.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"
#include "include/kasld/quantity.h"

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

/* The KASAN shadow that sat under the pre-flip image, at its LARGEST.
 * arch/arm64/Makefile sets KASAN_SHADOW_SCALE_SHIFT to 3 for the generic mode
 * and 4 for software tags, in the pre-flip era and today alike, so 3 is the
 * shift that yields the biggest shadow and therefore the highest image. Zero
 * without CONFIG_KASAN, which is not observable -- so it belongs in the
 * CEILING, where admitting a shadow that is not there only widens, and never in
 * the floor, where it would lift the bound past a kernel built without it. */
static unsigned long arm64_kasan_shadow_max(unsigned long va) {
  return 1UL << (va - 3);
}

/* The image-base band for each VA layout at a resolved width, as a union.
 *
 * Reached when PAGE_OFFSET has NOT resolved to one value, which leak-free is
 * the normal case: the width resolves from an mmap probe, but a width admits
 * both linear-map bases, so arm64_page_offset_from_va_bits leaves two
 * candidates and the pinned path above never runs. The image base was then left
 * at the honest top with nothing stripped.
 *
 * Keyed on the WIDTH rather than on PAGE_OFFSET, which is what makes a floor
 * safe here where the pinned path has to gate it. A resolved PAGE_OFFSET is
 * ambiguous at one value -- old-VA48 and modern-VA47 share a linear-map base --
 * but a width is not: TASK_SIZE is 1 << VA_BITS under both layouts, so a
 * pre-flip VA48 kernel reports 48 and gets the VA48 union, whose pre-flip band
 * covers its low image. Each band is anchored at the UN-SLID KIMAGE_VADDR, so
 * no minimum-offset formula is assumed and every no-KASLR base is inside by
 * construction.
 *
 *   modern:   _PAGE_END(VA_BITS_MIN) + module_region, slide up to
 *             arm64_kaslr_offset_max(VA_BITS_MIN)
 *   pre-flip: VA_START + 128 MiB (modules) at the floor; the ceiling adds the
 *             second 128 MiB region (BPF, absent on v4.x) and the KASAN shadow
 *
 * The two always MEET, so the union is one band and no hole is carved. That is
 * arithmetic, not a coincidence of the widths: measured from VA_START, the
 * modern floor sits at 2^(va-1) + 128 MiB, and the pre-flip ceiling at
 * 256 MiB + 2^(va-3) (shadow) + 2^(va-3) + 2^(va-2) (slide) = 256 MiB +
 * 2^(va-1). The difference is 128 MiB at every width, so admitting the shadow
 * -- which is not observable, and so must be admitted -- closes any gap the
 * bands would otherwise have. */
static int arm64_text_band_union(const struct estimate *est,
                                 struct constraint *out, int out_max) {
  unsigned long va = 0;
  if (!estimate_finset_value(&quantities[Q_VA_BITS], &est[Q_VA_BITS], &va))
    return 0;
  /* Arithmetic guard, not a policy one: the band arithmetic shifts by va - 3,
   * so anything that would underflow is refused. Which widths are admissible is
   * the arch header's VA_BITS_CANDIDATES to say, and estimate_finset_value only
   * ever returns one of those -- naming the narrowest here as well would go
   * stale the moment a width is added. */
  if (va < 4ul || va >= sizeof(unsigned long) * 8)
    return 0;

  const unsigned long va_min = va < 48ul ? va : 48ul;
  const unsigned long m_lo =
      arm64_page_end_for(va_min) + ARM64_MODULE_REGION_SIZE_MIN;
  const unsigned long m_hi = arm64_page_end_for(va_min) +
                             ARM64_MODULE_REGION_SIZE +
                             arm64_kaslr_offset_max(va_min);

  /* The pre-flip partner of a measured 52 is the 48-bit layout: pre-flip never
   * offered a 52-bit kernel VA, and the one configuration that showed userspace
   * 52 bits kept the kernel at 48. Same pairing as
   * arm64_page_offset_from_va_bits. */
  const unsigned long va_old = (va == 52ul) ? 48ul : va;
  const unsigned long vstart = arm64_page_offset_for(va_old);
  const unsigned long p_lo = vstart + ARM64_MODULE_REGION_SIZE_MIN;
  const unsigned long p_hi = vstart + 2ul * ARM64_MODULE_REGION_SIZE_MIN +
                             arm64_kasan_shadow_max(va_old) +
                             arm64_kaslr_offset_max(va_old);

  const unsigned long lo = p_lo < m_lo ? p_lo : m_lo;
  const unsigned long hi = p_hi > m_hi ? p_hi : m_hi;
  const uint32_t src = est[Q_VA_BITS].lo_binding;

  int n = 0;
  if (n < out_max) {
    struct constraint *c = &out[n++];
    memset(c, 0, sizeof(*c));
    c->q = Q_VIRT_IMAGE_BASE;
    c->op = C_LOWER_BOUND;
    c->value = lo;
    c->conf = CONF_INFERRED;
    c->derived_from[0] = src;
    c->lineage_count = src ? 1 : 0;
    snprintf(c->origin, ORIGIN_LEN, "arm64_text_base");
  }
  if (n < out_max) {
    struct constraint *c = &out[n++];
    memset(c, 0, sizeof(*c));
    c->q = Q_VIRT_IMAGE_BASE;
    c->op = C_UPPER_BOUND;
    c->value = hi;
    c->conf = CONF_INFERRED;
    c->derived_from[0] = src;
    c->lineage_count = src ? 1 : 0;
    snprintf(c->origin, ORIGIN_LEN, "arm64_text_base");
  }
  return n;
}

int rule_arm64_text_base(const struct evidence_set *ev,
                         const struct estimate *est, struct constraint *out,
                         int out_max) {
  if (out_max < 1)
    return 0;

  const struct estimate *po = &est[Q_PAGE_OFFSET];
  /* A resolved PAGE_OFFSET gives the tighter single band below. Without one --
   * the leak-free case, where the width resolves but the layout does not -- the
   * two layouts' bands are emitted as a union instead. */
  unsigned long po_pin;
  if (!quantity_pinned(Q_PAGE_OFFSET, po, &po_pin))
    return arm64_text_band_union(est, out, out_max);

  /* Map the resolved PAGE_OFFSET back to its VA_BITS (PAGE_OFFSET = -(1<<va)).
   */
  static const unsigned long cands[] = VA_BITS_CANDIDATES;
  const int ncands = (int)(sizeof(cands) / sizeof(cands[0]));
  unsigned long va = 0;
  for (int k = 0; k < ncands; k++) {
    if (arm64_page_offset_for(cands[k]) == po_pin) {
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
