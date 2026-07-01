// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: s390 image-base window from the parsed kernel config layout selector.
//
// s390 has two kernel-text layouts that place the image ~4 TiB apart, so with
// no address leak the honest Q_VIRT_IMAGE_BASE window must span both
// ([0, ASCE limit]) — sound but very loose. A readable kernel config
// (CONFIG_S390=y) resolves which layout is in use WITHOUT trusting version
// numbers, via SF_VIRT_KERNEL_IMAGE_BASE (CONFIG_KERNEL_IMAGE_BASE, emitted by
// proc_config / boot_config):
//
//   value > 0  — modern (v6.8+) high separate-kernel-mapping layout. The image
//     base is placed at >= CONFIG_KERNEL_IMAGE_BASE (the KASLR window minimum;
//     arch/s390/boot/startup.c). Floor Q_VIRT_IMAGE_BASE at that value. The
//     value is the image-base floor itself (not _stext); flooring at it without
//     adding IMAGE_BASE_OFFSET stays at or below the true _text under either
//     image-base/_stext modeling, so it cannot exclude truth. When
//     SF_VIRT_KASLR_DISABLED is also present the base does not slide, so the
//     floor becomes an exact PIN — this rule owns the s390 no-KASLR base (s390
//     opts out of the generic compile-time-default disabled-pin; see s390.h),
//     pinning the layout-correct PARSED value rather than an assumed default.
//
//   value == 0 — config is an s390 config that LACKS the knob: the pre-v6.8
//     identity-mapped layout (__identity_base = 0, no RANDOMIZE_IDENTITY_BASE),
//     where virt == phys and kernel text lives in low physical RAM. Cap
//     Q_VIRT_IMAGE_BASE at the top of spanned RAM (max_pfn, else MemTotal):
//     a RAM-resident address cannot exceed it.
//
// s390 only; inert elsewhere and when no config was readable.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"

#include <string.h>

int rule_s390_image_base_from_config(const struct evidence_set *ev,
                                     const struct estimate *est,
                                     struct constraint *out, int out_max) {
#if defined(__s390x__) || defined(__zarch__)
  (void)est;
  if (out_max < 1)
    return 0;

  int have_sel = 0;
  unsigned long image_base = 0, max_pfn = 0, memtotal = 0, page_size = 0;
  uint32_t sel_src = 0, kaslr_off_id = 0;
  enum kasld_confidence kaslr_off_conf = CONF_UNKNOWN;
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->value_kind != OBS_SCALAR)
      continue;
    switch (o->scalar_fact) {
    case SF_VIRT_KERNEL_IMAGE_BASE:
      have_sel = 1;
      image_base = o->scalar_value;
      sel_src = o->id;
      break;
    case SF_VIRT_KASLR_DISABLED:
      if (o->scalar_value != 0) {
        kaslr_off_id = o->id;
        kaslr_off_conf = o->conf;
      }
      break;
    case SF_PHYS_MAX_PFN:
      max_pfn = o->scalar_value;
      break;
    case SF_PHYS_MEMTOTAL:
      memtotal = o->scalar_value;
      break;
    case SF_PAGE_SIZE:
      page_size = o->scalar_value;
      break;
    default:
      break;
    }
  }
  if (!have_sel)
    return 0;

  struct constraint *c = &out[0];
  memset(c, 0, sizeof(*c));
  c->q = Q_VIRT_IMAGE_BASE;
  c->conf = CONF_PARSED;
  c->derived_from[0] = sel_src;
  c->lineage_count = 1;
  snprintf(c->origin, ORIGIN_LEN, "s390_image_base_from_config");

  if (image_base > 0) {
    /* Modern layout. Guard against an implausible value pushing past the top.
     */
    if (image_base >= (unsigned long)KERNEL_VIRT_TEXT_MAX)
      return 0;
    c->value = image_base;
    if (kaslr_off_id) {
      /* KASLR confirmed off + parsed modern base ⇒ the image base IS
       * CONFIG_KERNEL_IMAGE_BASE exactly (no slide): PIN it. This is the sound,
       * layout-correct replacement for the generic compile-time-default
       * disabled-pin (s390 opts that out — see s390.h). Confidence is the
       * weaker of the parsed config and the off-signal: a parsed off-signal
       * keeps the pin in the guaranteed window; a weaker detector lands it in
       * likely. */
      c->op = C_EQUALS;
      c->conf = kasld_conf_min(CONF_PARSED, kaslr_off_conf);
      c->derived_from[c->lineage_count++] = kaslr_off_id;
    } else {
      /* KASLR may slide the base up from this floor. */
      c->op = C_LOWER_BOUND;
    }
    return 1;
  }

  /* Identity-mapped layout: cap at the top of spanned physical RAM (virt ==
   * phys). max_pfn is the principled top; MemTotal is the fallback. */
  if (page_size == 0)
    page_size = 0x1000ul;
  unsigned long ram_top = 0;
  if (max_pfn > 0 && max_pfn < (~0ul / page_size))
    ram_top = (max_pfn + 1ul) * page_size; /* last RAM byte < this */
  else if (memtotal > 0)
    ram_top = memtotal;
  if (ram_top == 0)
    return 0;
  c->op = C_UPPER_BOUND;
  c->value = ram_top;
  return 1;
#else
  (void)ev;
  (void)est;
  (void)out;
  (void)out_max;
  return 0;
#endif
}
