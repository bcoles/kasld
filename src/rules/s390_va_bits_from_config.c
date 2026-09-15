// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: s390 paging level, computed the way the kernel computes it.
//
// s390 does not expose its ASCE limit, and it cannot be measured: an mmap
// boundary probe reads the USER address space, which is per-mm, starts at
// _REGION2_SIZE for every process and grows on demand, so it reports the
// 4-level width whatever the kernel chose. See the note beside
// VA_BITS_CANDIDATES in s390.h.
//
// The level is not measured here either. It is DERIVED, by reproducing the
// decision the boot code makes. arch/s390/boot/startup.c
// setup_kernel_memory_layout() takes the 4-level limit when
//
//     IS_ENABLED(CONFIG_KASAN)
//     || __NO_KASLR_END_KERNEL > _REGION2_SIZE
//     || (vsize > _REGION2_SIZE && kaslr_enabled())
//
// and the 3-level limit otherwise, where __NO_KASLR_END_KERNEL is
// CONFIG_KERNEL_IMAGE_BASE + KERNEL_IMAGE_SIZE (asm/page.h).
//
// The first two disjuncts are parsed facts already in evidence:
// SF_KASAN_ENABLED and SF_VIRT_KERNEL_IMAGE_BASE, both from a readable kernel
// config. Either one being true PROVES the 4-level limit.
//
// ONE DIRECTION ONLY, and the asymmetry is the point. Proving 4-level needs
// any single disjunct; proving 3-level needs ALL THREE false, including the
// vsize term, which is an estimate this rule does not compute. So a true
// disjunct pins the width and anything else leaves the quantity alone. A rule
// that cannot express the negative cannot get the negative wrong.
//
// Modern layout only. Both disjuncts describe code that arrived with
// CONFIG_KERNEL_IMAGE_BASE itself; a kernel predating it lays memory out
// differently and reports the knob absent as a zero, which gates this rule off.
//
// s390 only; inert elsewhere, and inert without a readable config.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"

#include <string.h>

int rule_s390_va_bits_from_config(const struct evidence_set *ev,
                                  const struct estimate *est,
                                  struct constraint *out, int out_max) {
#if defined(__s390x__) || defined(__zarch__)
  (void)est;
  if (out_max < 1)
    return 0;

  int have_base = 0;
  unsigned long image_base = 0, kasan = 0;
  uint32_t base_src = 0, kasan_src = 0;
  enum kasld_confidence base_conf = CONF_UNKNOWN, kasan_conf = CONF_UNKNOWN;

  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->value_kind != OBS_SCALAR)
      continue;
    switch (o->scalar_fact) {
    case SF_VIRT_KERNEL_IMAGE_BASE:
      have_base = 1;
      image_base = o->scalar_value;
      base_src = o->id;
      base_conf = o->conf;
      break;
    case SF_KASAN_ENABLED:
      kasan = o->scalar_value;
      kasan_src = o->id;
      kasan_conf = o->conf;
      break;
    default:
      break;
    }
  }

  /* A zero is the knob's absence, which is the pre-uncoupled layout: the
   * decision reproduced below is not the one that kernel makes. */
  if (!have_base || image_base == 0)
    return 0;

  uint32_t src = 0;
  enum kasld_confidence conf = CONF_UNKNOWN;

  /* Disjunct 2: the configured base puts the image's end above the 3-level
   * limit, so that limit cannot hold the image. Written as a subtraction so
   * the sum cannot overflow; S390_KERNEL_IMAGE_SIZE is far below the limit. */
  if (image_base >
      (unsigned long)S390_ASCE_LIMIT_3LEVEL - (unsigned long)S390_KERNEL_IMAGE_SIZE) {
    src = base_src;
    conf = base_conf;
  } else if (kasan != 0) {
    /* Disjunct 1. The layout gate above is what makes this the right decision
     * to reproduce, so the config carries the conclusion jointly with the
     * KASAN flag and the weaker of the two bounds it. */
    src = kasan_src;
    conf = kasld_conf_min(kasan_conf, base_conf);
  } else {
    /* Neither parsed disjunct holds. The third is an estimate this rule does
     * not compute, so the level stays unresolved rather than assumed 3-level. */
    return 0;
  }

  struct constraint *c = &out[0];
  memset(c, 0, sizeof(*c));
  c->q = Q_VA_BITS;
  c->op = C_EQUALS;
  c->value = 53ul; /* the width VA_BITS_CANDIDATES names for _REGION1_SIZE */
  c->conf = conf;
  c->derived_from[0] = src;
  c->lineage_count = 1;
  if (src != base_src && base_src != 0)
    c->derived_from[c->lineage_count++] = base_src;
  snprintf(c->origin, ORIGIN_LEN, "s390_va_bits_from_config");
  return 1;
#else
  (void)ev;
  (void)est;
  (void)out;
  (void)out_max;
  return 0;
#endif
}
