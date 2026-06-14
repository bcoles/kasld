// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: bound the text base from interior kernel-image samples.
//
// Any address inside the kernel image satisfies sample = image_base + offset
// with offset >= 0, so image_base <= sample regardless of which symbol the
// offset belongs to. The raw sample is therefore always a SOUND upper bound on
// the text base, independent of alignment assumptions (mirrors the documented
// approach in kernel_image_phys_bound). Emits a C_UPPER_BOUND on
// Q_VIRT_IMAGE_BASE (virt samples) / Q_PHYS_IMAGE_BASE (phys samples) at the
// minimum interior sample observed.
//
// It deliberately does NOT floor the ceiling to the KASLR alignment. The text
// base is _stext (KERNEL_VIRT_TEXT_DEFAULT names _stext, not the image base),
// and on sub-offset arches (riscv64 +0x2000, arm32 +0x8000, s390 +0x100000)
// _stext is not alignment-aligned, so floor(sample, align) drops the ceiling
// BELOW the truth — an unsoundness that previously rejected the real kallsyms
// pin on riscv64. Sound alignment-tightening belongs on the aligned image base,
// not on _stext.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"
#include "include/kasld/regions.h"

#include <limits.h>
#include <string.h>

static int emit_min_sample(const struct evidence_set *ev,
                           enum kasld_addr_type type, enum kasld_quantity q,
                           struct constraint *out, int slot, int out_max) {
  unsigned long min_sample = ULONG_MAX;
  enum kasld_confidence conf = CONF_UNKNOWN;
  uint32_t src = 0;
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->eff_type != type)
      continue;
    if (!is_kernel_image_region(o->eff_region) || !HAS_SAMPLE(o))
      continue;
    if (o->sample < min_sample) {
      min_sample = o->sample;
      conf = o->conf;
      src = o->id;
    }
  }
  if (min_sample == ULONG_MAX || slot >= out_max)
    return 0;
  /* No alignment floor: the raw sample is the sound ceiling (see header). */

  struct constraint *c = &out[slot];
  memset(c, 0, sizeof(*c));
  c->q = q;
  c->op = C_UPPER_BOUND;
  c->value = min_sample;
  c->conf = conf;
  c->derived_from[0] = src;
  c->lineage_count = 1;
  snprintf(c->origin, ORIGIN_LEN, "range_from_interior");
  return 1;
}

int rule_range_from_interior(const struct evidence_set *ev,
                             const struct estimate *est, struct constraint *out,
                             int out_max) {
  int n = 0;
  (void)
      est; /* no longer reads the alignment quantities — raw sample is sound */

  n += emit_min_sample(ev, KASLD_TYPE_VIRT, Q_VIRT_IMAGE_BASE, out, n, out_max);
  n += emit_min_sample(ev, KASLD_TYPE_PHYS, Q_PHYS_IMAGE_BASE, out, n, out_max);
  return n;
}
