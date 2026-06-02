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
// the image to avoid overlap. The naive ceiling KASLR_TEXT_MIN + MAX_OFFSET
// is therefore UNSOUND on kernels where kernel_length ≥ MAX_OFFSET (every
// realistic kernel — typical image is 20–60 MiB, MAX_OFFSET defaults to
// 16 MiB). Confirmed against arch/loongarch/kernel/relocate.c and
// arch/mips/kernel/relocate.c on Linux 6.17 (identical formula in 6.18).
//
// Corrected ceiling:
//
//   virt_text_base ≤ KASLR_TEXT_MIN + MAX_OFFSET + ALIGN(kernel_length, 0xffff)
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
// `KASLR_TEXT_MIN` is the KASLR window base — the offset is measured
// from there, not from the engine's possibly-tightened lower edge.
//
// Naturally inert where SF_RANDOMIZE_MAX_OFFSET is absent (x86, arm64,
// riscv64, s390 emit no such scalar): absence yields no constraint.
// ---
// <bcoles@gmail.com>

#include "../include/kasld/engine_rules.h"
#include "../include/kasld/regions.h"

#include <limits.h>
#include <string.h>

#if defined(__mips__) || defined(__loongarch__)
/* Compute the kernel image's contiguous extent from observations.
 * Returns 0 if no usable observations are available. */
static unsigned long
config_max_offset_ceiling__kernel_length(const struct evidence_set *ev) {
  /* PHYS path: iomem text..bss/data span. */
  unsigned long pmin = ULONG_MAX, pmax = 0;
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->value_kind != OBS_ADDRESS ||
        o->eff_type != KASLD_TYPE_PHYS)
      continue;
    if (o->eff_region != REGION_KERNEL_TEXT &&
        o->eff_region != REGION_KERNEL_IMAGE &&
        o->eff_region != REGION_KERNEL_DATA &&
        o->eff_region != REGION_KERNEL_BSS)
      continue;
    if (HAS_LO(o) && o->lo < pmin)
      pmin = o->lo;
    if (HAS_HI(o) && o->hi > pmax)
      pmax = o->hi;
  }
  if (pmin != ULONG_MAX && pmax > pmin)
    return pmax - pmin + 1;

  /* VIRT path: same shape, but anchors only (no hi typically). */
  unsigned long vmin = ULONG_MAX, vmax = 0;
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->value_kind != OBS_ADDRESS ||
        o->eff_type != KASLD_TYPE_VIRT)
      continue;
    if (o->eff_region != REGION_KERNEL_TEXT &&
        o->eff_region != REGION_KERNEL_IMAGE &&
        o->eff_region != REGION_KERNEL_DATA &&
        o->eff_region != REGION_KERNEL_BSS)
      continue;
    unsigned long a = obs_anchor(o);
    if (a == 0)
      continue;
    if (a < vmin)
      vmin = a;
    if (a > vmax)
      vmax = a;
  }
  if (vmin != ULONG_MAX && vmax > vmin)
    return vmax - vmin;
  return 0;
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
        o->scalar_fact == SF_RANDOMIZE_MAX_OFFSET) {
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
      (unsigned long)KASLR_TEXT_MIN + max_offset + aligned_kl;
  if (ceiling <= (unsigned long)KASLR_TEXT_MIN) /* overflow */
    return 0;

  struct constraint *c = &out[0];
  memset(c, 0, sizeof(*c));
  c->q = Q_VIRT_TEXT_BASE;
  c->op = C_UPPER_BOUND;
  c->value = ceiling;
  c->conf = CONF_PARSED;
  c->derived_from[0] = src;
  c->lineage_count = src ? 1 : 0;
  snprintf(c->origin, ORIGIN_LEN, "config_max_offset_ceiling");
  return 1;
#endif
}
