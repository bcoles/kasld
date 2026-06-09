// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Curation rule: x86-64 directmap/text coupling validation.
//
// Two
// classes of virtual observation are misclassified by construction on x86-64
// and are invalidated (V_INVALID):
//
//   - a DIRECTMAP observation at or above KERNEL_VIRT_TEXT_MIN: the direct map
//   never
//     reaches __START_KERNEL_map, so such an address is not directmap;
//   - a kernel-text/image observation below KERNEL_VIRT_TEXT_MIN: below the
//   kernel
//     image map's floor (__START_KERNEL_map), so not a valid text base.
//
// IMPORTANT: the text-floor check uses KERNEL_VIRT_TEXT_MIN (the *validation*
// range — the kernel image map's architectural floor), NOT KASLR_VIRT_TEXT_MIN
// (the per-build *KASLR randomization window*'s lower edge, which bakes in
// CONFIG_PHYSICAL_START at its compile-time default). On x86_64 a kernel built
// with a non-default CONFIG_PHYSICAL_START legitimately places text below
// KASLR_VIRT_TEXT_MIN — using it here would invalidate that real text leak,
// defeating the wide-floor inference (KASLR_VIRT_TEXT_MIN_WIDE) downstream.
//
// Emits verdicts rather than mutating: the engine applies them via
// evidence_resolve() so the constraint rules see the curated evidence. The
// ruling is a pure function of each observation's own region and anchor
// versus compile-time geometry — no cross-observation or estimate
// dependency.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"

#include <string.h>

int rule_coupling_validate(const struct evidence_set *ev, struct verdict *out,
                           int out_max) {
#if defined(__x86_64__)
  int n = 0;
  for (int i = 0; i < ev->n_obs && n < out_max; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->value_kind != OBS_ADDRESS ||
        o->eff_type != KASLD_TYPE_VIRT)
      continue;

    unsigned long a = obs_anchor(o);
    int bad =
        (o->eff_region == REGION_DIRECTMAP && a >= KERNEL_VIRT_TEXT_MIN) ||
        ((o->eff_region == REGION_KERNEL_TEXT ||
          o->eff_region == REGION_KERNEL_IMAGE) &&
         a < KERNEL_VIRT_TEXT_MIN);
    if (!bad)
      continue;

    struct verdict *v = &out[n++];
    memset(v, 0, sizeof(*v));
    v->observation_id = o->id;
    v->kind = V_INVALID;
    v->conf = o->conf;
    v->derived_from[0] = o->id;
    v->lineage_count = 1;
    snprintf(v->origin, ORIGIN_LEN, "coupling_validate");
  }
  return n;
#else
  (void)ev;
  (void)out;
  (void)out_max;
  return 0;
#endif
}
