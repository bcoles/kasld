// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: x86_64 virt_page_offset from a same-origin VIRT/PHYS leak pair.
//
// When one
// component leaks the same kernel object in BOTH address spaces (matching
// origin + region + name), the direct-map base is their difference:
//
//   virt_page_offset == virt_anchor - phys_anchor   (the tightest possible
//   signal)
//
// Emits C_EQUALS on Q_PAGE_OFFSET when the candidate is page-aligned and inside
// the current virt_page_offset window (the engine's meet drops it otherwise). A
// cross-origin heuristic (Path 2: min(directmap) - min(RAM base)) would be a
// looser fallback; not implemented. x86_64 only; inert when no paired
// VIRT directmap + PHYS RAM observation is present.
// ---
// <bcoles@gmail.com>

#include "../include/kasld/engine_rules.h"

#include <string.h>

int rule_randomize_memory_page_offset(const struct evidence_set *ev,
                                      const struct estimate *est,
                                      struct constraint *out, int out_max) {
#if defined(__x86_64__)
  if (out_max < 1)
    return 0;

  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *v = &ev->obs[i];
    if (!v->valid || v->value_kind != OBS_ADDRESS ||
        v->eff_type != KASLD_TYPE_VIRT || v->origin[0] == '\0')
      continue;
    for (int j = 0; j < ev->n_obs; j++) {
      const struct observation *p = &ev->obs[j];
      if (!p->valid || p->value_kind != OBS_ADDRESS ||
          p->eff_type != KASLD_TYPE_PHYS)
        continue;
      if (strcmp(p->origin, v->origin) != 0 || p->eff_region != v->eff_region ||
          strcmp(p->name, v->name) != 0)
        continue;
      unsigned long va = obs_anchor(v), pa = obs_anchor(p);
      if (va == 0 || pa == 0 || va <= pa)
        continue;
      unsigned long candidate = va - pa;
      /* virt_page_offset is at least PMD-aligned; reject obviously-bogus pairs.
       */
      if (candidate & ((2ul * 1024 * 1024) - 1))
        continue;

      struct constraint *c = &out[0];
      memset(c, 0, sizeof(*c));
      c->q = Q_PAGE_OFFSET;
      c->op = C_EQUALS;
      c->value = candidate;
      c->conf = CONF_INFERRED;
      c->derived_from[0] = v->id;
      c->derived_from[1] = p->id;
      c->lineage_count = 2;
      snprintf(c->origin, ORIGIN_LEN, "randomize_memory_page_offset");
      return 1;
    }
  }

  /* Path 2 (no same-origin pair): cross-origin reconstruction
   * virt_page_offset_base = min(DIRECTMAP virt) - min(PHYS RAM base). The
   * directmap maps physical RAM starting at PAGE_OFFSET, so the lowest
   * direct-map address minus the lowest RAM base is the directmap base.
   * Validated: PUD-aligned (1 GiB) and within the resolved virt_page_offset
   * window. Only REGION_RAM phys bases (not initrd/reserved) and
   * REGION_DIRECTMAP virt leaks qualify. */
  {
    const unsigned long pud_size = 1ul << 30;
    unsigned long vdmap_min = ULONG_MAX, pram_min = ULONG_MAX;
    uint32_t vsrc = 0, psrc = 0;
    for (int i = 0; i < ev->n_obs; i++) {
      const struct observation *o = &ev->obs[i];
      if (!o->valid || o->value_kind != OBS_ADDRESS)
        continue;
      if (o->eff_type == KASLD_TYPE_VIRT && o->eff_region == REGION_DIRECTMAP) {
        unsigned long a = obs_anchor(o);
        if (a && a < vdmap_min) {
          vdmap_min = a;
          vsrc = o->id;
        }
      } else if (o->eff_type == KASLD_TYPE_PHYS &&
                 o->eff_region == REGION_RAM && HAS_LO(o)) {
        if (o->lo < pram_min) {
          pram_min = o->lo;
          psrc = o->id;
        }
      }
    }
    if (vdmap_min == ULONG_MAX || pram_min == ULONG_MAX ||
        vdmap_min <= pram_min)
      return 0;
    unsigned long candidate = vdmap_min - pram_min;
    if (candidate & (pud_size - 1))
      return 0;
    const struct estimate *po = &est[Q_PAGE_OFFSET];
    if (candidate < po->lo || candidate > po->hi)
      return 0;

    struct constraint *c = &out[0];
    memset(c, 0, sizeof(*c));
    c->q = Q_PAGE_OFFSET;
    c->op = C_EQUALS;
    c->value = candidate;
    c->conf = CONF_DERIVED;
    c->derived_from[0] = vsrc;
    c->derived_from[1] = psrc;
    c->lineage_count = 2;
    snprintf(c->origin, ORIGIN_LEN, "randomize_memory_page_offset");
    return 1;
  }
#else
  (void)ev;
  (void)est;
  (void)out;
  (void)out_max;
  return 0;
#endif
}
