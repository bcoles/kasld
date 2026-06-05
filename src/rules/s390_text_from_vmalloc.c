// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: s390 VMALLOC observation → Q_VIRT_TEXT_BASE lower bound.
//
// arch/s390/boot/startup.c packs vmalloc / modules / kernel image
// adjacently in VAS, no gaps:
//
//   MODULES_END   = round_down(kernel_start, _SEGMENT_SIZE)
//   MODULES_VADDR = MODULES_END - MODULES_LEN     (= 2 GiB)
//   VMALLOC_END   = MODULES_VADDR
//   VMALLOC_START = VMALLOC_END - vmalloc_size
//
// So `VMALLOC_END == MODULES_END − MODULES_LEN ≤ text_base − MODULES_LEN`,
// and any VIRT/VMALLOC observation V_va < VMALLOC_END witnesses
//
//   text_base > V_va + MODULES_LEN
//
// (strict; +1 to express the strict gt as a C_LOWER_BOUND). MODULES_LEN is
// SZ_2G = 0x80000000 on s390 (arch/s390/include/asm/setup.h).
//
// Companion to module_text_bound's s390 case (modules ↔ text bounds); the
// single-vmalloc-leak case here pushes the text floor up by exactly the
// 2 GiB modules region.
//
// Inert when no s390 VIRT/VMALLOC observation is present. s390 only.
// ---
// <bcoles@gmail.com>

#include "../include/kasld/engine_rules.h"

#include <string.h>

#define S390_MODULES_LEN 0x80000000ul /* SZ_2G */

int rule_s390_text_from_vmalloc(const struct evidence_set *ev,
                                const struct estimate *est,
                                struct constraint *out, int out_max) {
  (void)est;
#if defined(__s390__) || defined(__s390x__)
  if (out_max < 1)
    return 0;

  /* Highest VMALLOC observation — the closest one to VMALLOC_END, which
   * gives the tightest lower bound on text. */
  unsigned long highest = 0;
  enum kasld_confidence conf = CONF_UNKNOWN;
  uint32_t src = 0;
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->value_kind != OBS_ADDRESS ||
        o->eff_type != KASLD_TYPE_VIRT || o->eff_region != REGION_VMALLOC)
      continue;
    unsigned long a = obs_anchor(o);
    if (a == 0)
      continue;
    if (a > highest) {
      highest = a;
      conf = o->conf;
      src = o->id;
    }
  }
  if (src == 0)
    return 0;

  /* text_base > V_va + MODULES_LEN; encode as text_base ≥ V_va + MODULES_LEN
   * + 1. */
  if (highest > ULONG_MAX - S390_MODULES_LEN - 1)
    return 0; /* overflow guard */
  unsigned long lower = highest + S390_MODULES_LEN + 1;

  struct constraint *c = &out[0];
  memset(c, 0, sizeof(*c));
  c->q = Q_VIRT_TEXT_BASE;
  c->op = C_LOWER_BOUND;
  c->value = lower;
  c->conf = conf;
  c->derived_from[0] = src;
  c->lineage_count = 1;
  snprintf(c->origin, ORIGIN_LEN, "s390_text_from_vmalloc");
  return 1;
#else
  (void)ev;
  (void)out;
  (void)out_max;
  return 0;
#endif
}
