// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: virtual KASLR ceiling from MemTotal (coupled arches).
//
// The coupled-arch counterpart to phys_ceiling_from_memtotal. On a coupled arch
// (x86-32, MIPS, PPC32 BookE, LoongArch) phys_to_directmap_virt() links
// physical DRAM to the virtual text window, so the RAM-fits-the-image ceiling
// maps to a virtual upper bound. It carries the SAME dram_top-vs-MemTotal
// discipline as phys_ceiling_from_memtotal:
//
//   preferred:  virt_ceiling = PAGE_OFFSET_runtime + (dram_top - PHYS_OFFSET)
//                              - min_image + IMAGE_BASE_OFFSET
//               from the spanned DRAM extent (zoneinfo REGION_RAM POS_TOP),
//               at observation confidence — reaches the guaranteed window.
//   fallback:   PAGE_OFFSET_runtime + (phys_floor - PHYS_OFFSET) + MemTotal
//                              - min_image + IMAGE_BASE_OFFSET
//               when no DRAM extent is observed, capped at CONF_HEURISTIC.
//
// The MemTotal fallback is a convention, not a fact: MemTotal under-counts the
// spanned extent (reserved regions) AND is virtualisable inside a container /
// cgroup (lxcfs reports the cgroup limit, not host RAM), so a MemTotal-derived
// ceiling can fall below the true base. Capping it below the sound floor keeps
// a faked or under-counted value out of the guaranteed window.
//
// This is a CROSS-QUANTITY rule: it uses the engine's resolved Q_PAGE_OFFSET
// rather than the compile-time PAGE_OFFSET, because the runtime value can
// differ (e.g. x86-32 VMSPLIT). It therefore fires only once Q_PAGE_OFFSET has
// collapsed to a point (a landmark pinned it) — the engine's fixpoint loop
// re-runs this rule after page_offset_from_landmark resolves. If
// virt_page_offset is still an interval (no landmark observed), the rule emits
// nothing: we cannot soundly map the ceiling through an unknown origin. That is
// correct under the "a component may return nothing" principle — absence yields
// no constraint, never a wrong one.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"
#include "include/kasld/regions.h"

#include <limits.h>
#include <string.h>

int rule_virt_ceiling_from_memtotal(const struct evidence_set *ev,
                                    const struct estimate *est,
                                    struct constraint *out, int out_max) {
#if !TEXT_TRACKS_DIRECTMAP
  (void)ev;
  (void)est;
  (void)out;
  (void)out_max;
  return 0; /* decoupled arches use phys_ceiling_from_memtotal instead */
#else
  if (out_max < 1)
    return 0;

  /* Cross-quantity input: a pinned virt_page_offset (lo == hi). */
  const struct estimate *po = &est[Q_PAGE_OFFSET];
  if (po->lo != po->hi)
    return 0; /* virt_page_offset not yet resolved to a point */
  unsigned long virt_page_offset = po->lo;

  unsigned long memtotal = 0, phys_floor = ULONG_MAX, dram_top = 0;
  enum kasld_confidence mconf = CONF_UNKNOWN, fconf = CONF_PARSED,
                        tconf = CONF_UNKNOWN;
  uint32_t msrc = 0, fsrc = 0, tsrc = 0;
  const unsigned long min_image = evidence_image_size_min_or_floor(ev);
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid)
      continue;
    if (o->value_kind == OBS_SCALAR && o->scalar_fact == SF_PHYS_MEMTOTAL) {
      memtotal = o->scalar_value;
      mconf = o->conf;
      msrc = o->id;
    } else if (o->value_kind == OBS_ADDRESS && o->eff_type == KASLD_TYPE_PHYS &&
               is_phys_dram_region(o->eff_region)) {
      unsigned long a = obs_anchor(o);
      if (a < phys_floor) {
        phys_floor = a;
        fconf = o->conf;
        fsrc = o->id;
      }
      /* Spanned DRAM extent top (REGION_RAM POS_TOP, from zoneinfo). */
      if (o->eff_region == REGION_RAM && HAS_HI(o) && o->hi > dram_top) {
        dram_top = o->hi;
        tconf = o->conf;
        tsrc = o->id;
      }
    }
  }

  unsigned long ceiling;
  uint32_t src_a = 0, src_b = 0;
  enum kasld_confidence cconf;

  if (dram_top != 0) {
    /* Preferred: the spanned DRAM extent (host-true zoneinfo), mapped through
     * the resolved page_offset. Sound regardless of reserved regions inside
     * DRAM or a container-virtualised MemTotal. Observation confidence, so it
     * reaches the guaranteed window. */
    if (dram_top <= (unsigned long)PHYS_OFFSET)
      return 0;
    unsigned long virt_top =
        virt_page_offset + (dram_top - (unsigned long)PHYS_OFFSET);
    if (virt_top <= min_image)
      return 0;
    ceiling = virt_top - min_image + IMAGE_BASE_OFFSET;
    src_a = tsrc;
    cconf = tconf;
  } else {
    /* Fallback: MemTotal. It counts USABLE pages, so it under-counts the
     * spanned extent when holes/reserved regions sit inside DRAM, AND it is
     * virtualisable inside a container/cgroup (lxcfs reports the cgroup limit).
     * Either way the ceiling can fall BELOW the true base, so it is a
     * convention, not a fact: capped at CONF_HEURISTIC to shape the LIKELY
     * window only, never the guaranteed one. */
    if (memtotal == 0 || memtotal <= min_image)
      return 0;
    if (phys_floor == ULONG_MAX)
      phys_floor = PHYS_OFFSET;
    unsigned long phys_floor_offset =
        (phys_floor > PHYS_OFFSET) ? (phys_floor - PHYS_OFFSET) : 0;
    ceiling = virt_page_offset + phys_floor_offset + memtotal - min_image +
              IMAGE_BASE_OFFSET;
    src_a = msrc;
    src_b = fsrc;
    cconf = kasld_conf_min(CONF_HEURISTIC, (mconf < fconf) ? mconf : fconf);
  }
  /* Align to the resolved Q_VIRT_KASLR_ALIGN (>= compile-time
   * KASLR_VIRT_ALIGN). */
  unsigned long valign = est[Q_VIRT_KASLR_ALIGN].lo;
  if (valign < (unsigned long)KASLR_VIRT_ALIGN)
    valign = (unsigned long)KASLR_VIRT_ALIGN;
  ceiling = kasld_floor_virt_text_bound(ceiling, valign);
  if (ceiling <= KASLR_VIRT_TEXT_MIN)
    return 0;

  struct constraint *c = &out[0];
  memset(c, 0, sizeof(*c));
  c->q = Q_VIRT_IMAGE_BASE;
  c->op = C_UPPER_BOUND;
  c->value = ceiling;
  c->conf = cconf;
  c->derived_from[0] = src_a;
  c->lineage_count = 1;
  if (src_b) {
    c->derived_from[1] = src_b;
    c->lineage_count = 2;
  }
  snprintf(c->origin, ORIGIN_LEN, "virt_ceiling_from_memtotal");
  return 1;
#endif
}
