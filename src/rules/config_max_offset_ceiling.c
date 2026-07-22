// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: CONFIG_RANDOMIZE_BASE_MAX_OFFSET ceiling on the virtual text base.
//
// On MIPS and LoongArch the KASLR placement code does:
//
//   random_offset = entropy << 16;
//   random_offset &= (CONFIG_RANDOMIZE_BASE_MAX_OFFSET - 1);
//   if (random_offset < kernel_length)
//       random_offset += ALIGN(kernel_length, 0xffff);
//
// — i.e. a slide that would land inside the original image is bumped past
// the image to avoid overlap. The naive ceiling KASLR_VIRT_TEXT_MIN +
// MAX_OFFSET is therefore UNSOUND on kernels where kernel_length ≥ MAX_OFFSET
// (every realistic kernel — typical image is 20–60 MiB, MAX_OFFSET defaults to
// 16 MiB). Confirmed against arch/loongarch/kernel/relocate.c and
// arch/mips/kernel/relocate.c on Linux 6.17 (identical formula in 6.18).
//
// Corrected ceiling:
//
//   virt_image_base ≤ KASLR_VIRT_TEXT_MIN + MAX_OFFSET + ALIGN(kernel_length,
//   0xffff)
//
// `kernel_length` is extracted from observations:
//   * Preferred: PHYS iomem extent (kernel_text.lo..kernel_bss.hi or
//     kernel_text.lo..kernel_data.hi when bss is absent).
//   * Fallback: VIRT _stext..max kernel-image/data/bss observation.
//   * If neither side is observable (no iomem, no kallsyms — fully
//     low-priv with no leaks), emit nothing rather than guess. The
//     remaining engine rules (DRAM bounds, image-size ceilings) carry
//     the constraint set in that case.
//
// `KASLR_VIRT_TEXT_MIN` is the KASLR window base — the offset is measured
// from there, not from the engine's possibly-tightened lower edge.
//
// Naturally inert where SF_VIRT_RANDOMIZE_MAX_OFFSET is absent (x86, arm64,
// riscv64, s390 emit no such scalar): absence yields no constraint.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"
#include "include/kasld/regions.h"

#include <limits.h>
#include <string.h>

#if defined(__mips__) || defined(__loongarch__)
/* Measure the kernel image's [_text, _end] extent from observations of one
 * address type. kernel_length must OVER-estimate the true _end - _text: the
 * kernel adds ALIGN(kernel_length, 0xffff) to the slide, so under-sizing it
 * puts the ceiling below the true base. The span is exact only when anchored
 * low at _text (a KERNEL_IMAGE base — the image head) AND high at _end (a
 * KERNEL_BSS extent's hi). Without the BSS extent the span stops at _edata
 * (KERNEL_DATA hi) and under-estimates by the BSS size; some arches'
 * iomem/dmesg omit the "Kernel bss" entry entirely (e.g. loongarch, which
 * exposes only "Kernel code" and "Kernel data"). Require both anchors as
 * genuine extents (HAS_LO/HAS_HI, not obs_anchor point samples) and return 0 —
 * emit nothing — otherwise, rather than a truncated, unsound length. */
static unsigned long
config_max_offset_ceiling__extent(const struct evidence_set *ev,
                                  enum kasld_addr_type type) {
  unsigned long lo = ULONG_MAX, hi = 0;
  int have_image = 0, have_bss = 0;
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->value_kind != OBS_ADDRESS || o->eff_type != type)
      continue;
    if (o->eff_region != REGION_KERNEL_TEXT &&
        o->eff_region != REGION_KERNEL_IMAGE &&
        o->eff_region != REGION_KERNEL_DATA &&
        o->eff_region != REGION_KERNEL_BSS)
      continue;
    if (HAS_LO(o) && o->lo < lo)
      lo = o->lo;
    if (HAS_HI(o) && o->hi > hi)
      hi = o->hi;
    if (o->eff_region == REGION_KERNEL_IMAGE && HAS_LO(o))
      have_image = 1; /* low anchor at _text (the image head) */
    if (o->eff_region == REGION_KERNEL_BSS && HAS_HI(o))
      have_bss = 1; /* high anchor at _end (__bss_stop) */
  }
  if (have_image && have_bss && lo != ULONG_MAX && hi > lo)
    return hi - lo + 1;
  return 0;
}

/* Prefer the PHYS extent (iomem); fall back to VIRT (dmesg layout). */
static unsigned long
config_max_offset_ceiling__kernel_length(const struct evidence_set *ev) {
  unsigned long len = config_max_offset_ceiling__extent(ev, KASLD_TYPE_PHYS);
  if (len)
    return len;
  return config_max_offset_ceiling__extent(ev, KASLD_TYPE_VIRT);
}
#endif

int rule_config_max_offset_ceiling(const struct evidence_set *ev,
                                   const struct estimate *est,
                                   struct constraint *out, int out_max) {
  (void)est;
#if !defined(__mips__) && !defined(__loongarch__)
  (void)ev;
  (void)out;
  (void)out_max;
  return 0;
#else
  if (out_max < 1)
    return 0;

  unsigned long max_offset = 0;
  uint32_t src = 0;
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (o->valid && o->value_kind == OBS_SCALAR &&
        o->scalar_fact == SF_VIRT_RANDOMIZE_MAX_OFFSET) {
      max_offset = o->scalar_value;
      src = o->id;
      break;
    }
  }
  if (max_offset == 0)
    return 0;

  unsigned long kernel_length = config_max_offset_ceiling__kernel_length(ev);
  if (kernel_length == 0)
    return 0; /* honest: no width signal to bound the +ALIGN(kl) bump */

  /* ALIGN(kernel_length, 0xffff): the kernel rounds up to a 64 KiB-1
   * grain (literal 0xffff, not SZ_64K - 1). Reproduce verbatim. */
  unsigned long aligned_kl = (kernel_length + 0xffff) & ~0xfffful;
  unsigned long ceiling =
      (unsigned long)KASLR_VIRT_TEXT_MIN + max_offset + aligned_kl;
  if (ceiling <= (unsigned long)KASLR_VIRT_TEXT_MIN) /* overflow */
    return 0;

  struct constraint *c = &out[0];
  memset(c, 0, sizeof(*c));
  c->q = Q_VIRT_IMAGE_BASE;
  c->op = C_UPPER_BOUND;
  c->value = ceiling;
  c->conf = CONF_PARSED;
  c->derived_from[0] = src;
  c->lineage_count = src ? 1 : 0;
  snprintf(c->origin, ORIGIN_LEN, "config_max_offset_ceiling");
  return 1;
#endif
}
