// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: virt_page_offset upper bound from the lowest leaked directmap address.
//
// The direct map starts at PAGE_OFFSET, so the lowest leaked DIRECTMAP virtual
// address is an upper bound on PAGE_OFFSET itself:
//
//   virt_page_offset <= min(leaked DIRECTMAP virtual addresses)
//
// Reads VIRT REGION_DIRECTMAP leaks; emits a C_UPPER_BOUND on Q_PAGE_OFFSET
// (the engine's monotone meet drops it if it falls outside the current window).
//
// Lower bound: the leaked directmap pointer maps SOME physical page P, with
//   virt_page_offset = V - (P - PHYS_OFFSET).
// P lies within the direct-mapped physical range [PHYS_OFFSET, max_pfn*PAGE),
// so P is maximised at the top of the direct map and the base is minimised:
//   virt_page_offset >= V - (max_pfn*PAGE_SIZE - PHYS_OFFSET).
// max_pfn (SF_PHYS_MAX_PFN, /proc/zoneinfo) is the kernel's own direct-map
// extent — the SOUND, tight span (not MemTotal, which undercounts physical
// address space by the reserved/firmware regions and would make the bound too
// high). With it, a directmap leak pins the randomized direct-map base to
// within max_pfn pages
// (~RAM/1GiB PUD-aligned candidates). Emits nothing without SF_PHYS_MAX_PFN —
// absence yields no lower bound, never a wrong one.
//
// Speculative likely edge (POS_BASE): a base-position directmap observation
// (prefetch_directmap's located left edge) asserts the base itself, not a
// generic interior address. The sound upper bound above already gives
// virt_page_offset <= base; this adds the matching lower edge base - align so
// the LIKELY window brackets the base to a single PUD slot instead of the
// max_pfn-wide guaranteed span (a timing scan can round the edge one slot high,
// never below — nothing is mapped under page_offset_base; the same
// text_pin_from_observation [base - align, base] treatment). Its confidence is
// capped BELOW the sound floor (kasld_conf_min(., CONF_HEURISTIC)) so it shapes
// the likely window only and can never move the guaranteed one. That cap is
// load-bearing: the directmap base observation merges with an interior
// directmap sample (dmesg backtrace) whose parsed confidence would otherwise
// launder the timing base up to the sound floor and pin the guaranteed window
// from a guess.
//
// Both bounds are aligned to RANDOMIZE_MEMORY_ALIGN (PUD_SIZE = 1 GiB on
// x86_64) when defined — the kernel's KASLR layout code places
// virt_page_offset_base on PUD-aligned boundaries (arch/x86/mm/kaslr.c:166
// `vaddr = round_up(vaddr + 1, PUD_SIZE)`), so unaligned bound values
// are provably non-bases. Upper is aligned DOWN (the highest aligned
// address ≤ raw upper), lower aligned UP (lowest aligned address ≥ raw
// lower). Saves up to ~2 PUD slots on the displayed window. Inert on
// arches without RANDOMIZE_MEMORY_ALIGN (RANDOMIZE_MEMORY_ALIGN = 0 →
// no-op masks).
//
// Inert when no VIRT directmap observation is present.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"

#include <limits.h>
#include <string.h>

int rule_directmap_page_offset_bounds(const struct evidence_set *ev,
                                      const struct estimate *est,
                                      struct constraint *out, int out_max) {
  (void)est;
  if (out_max < 1)
    return 0;

  unsigned long vdmap_min = ULONG_MAX, max_pfn = 0;
  unsigned long base_lo = ULONG_MAX;
  enum kasld_confidence base_conf = CONF_UNKNOWN;
  uint32_t src = 0, pfn_src = 0, base_src = 0;
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid)
      continue;
    if (o->value_kind == OBS_SCALAR && o->scalar_fact == SF_PHYS_MAX_PFN) {
      max_pfn = o->scalar_value;
      pfn_src = o->id;
      continue;
    }
    if (o->value_kind != OBS_ADDRESS)
      continue;
    if (o->eff_type == KASLD_TYPE_VIRT && o->eff_region == REGION_DIRECTMAP) {
      unsigned long a = obs_anchor(o);
      if (a < vdmap_min) {
        vdmap_min = a;
        src = o->id;
      }
      /* A POS_BASE directmap observation asserts the base itself (the located
       * left edge), feeding the speculative likely edge below. Lowest wins —
       * the base is the region floor, so the lowest base claim is the soundest.
       */
      if (o->pos == POS_BASE && HAS_LO(o) && o->lo < base_lo) {
        base_lo = o->lo;
        base_conf = o->conf;
        base_src = o->id;
      }
    }
  }
  if (vdmap_min == ULONG_MAX)
    return 0;

  /* RANDOMIZE_MEMORY_ALIGN = PUD_SIZE on x86_64 (1 GiB) — the alignment
   * the kernel's KASLR code places virt_page_offset_base on. Zero on arches
   * without RANDOMIZE_MEMORY (the mask collapses to 0, alignment is a
   * no-op). Use an alignment mask that defaults to 0 for those. */
  const unsigned long align = (unsigned long)RANDOMIZE_MEMORY_ALIGN;
  const unsigned long mask = align ? (align - 1) : 0ul;

  int n = 0;
  /* Upper bound: virt_page_offset <= lowest directmap leak, aligned DOWN to
   * PUD. */
  unsigned long upper = vdmap_min & ~mask;
  struct constraint *c = &out[n++];
  memset(c, 0, sizeof(*c));
  c->q = Q_PAGE_OFFSET;
  c->op = C_UPPER_BOUND;
  c->value = upper;
  c->conf = CONF_INFERRED;
  c->derived_from[0] = src;
  c->lineage_count = 1;
  snprintf(c->origin, ORIGIN_LEN, "directmap_page_offset_bounds");

  /* Lower bound: virt_page_offset >= V - (max_pfn*PAGE_SIZE - PHYS_OFFSET),
   * aligned UP to PUD. */
  if (max_pfn && n < out_max) {
    unsigned long span = max_pfn * PAGE_SIZE; /* direct-mapped phys extent */
    if (span / PAGE_SIZE == max_pfn           /* no multiply overflow */
#if PHYS_OFFSET
        && span >= (unsigned long)PHYS_OFFSET
#endif
    ) {
      unsigned long reach = span - (unsigned long)PHYS_OFFSET;
      if (vdmap_min > reach) { /* keep the bound below the leak */
        unsigned long raw_lower = vdmap_min - reach;
        /* Align UP: smallest aligned value >= raw_lower. Guard against
         * overflow when raw_lower is near ULONG_MAX. */
        unsigned long lower = mask ? ((raw_lower + mask) & ~mask) : raw_lower;
        if (lower < raw_lower)
          lower = raw_lower; /* overflow → keep raw, don't relax bound */
        if (lower <= upper) {
          struct constraint *lc = &out[n++];
          memset(lc, 0, sizeof(*lc));
          lc->q = Q_PAGE_OFFSET;
          lc->op = C_LOWER_BOUND;
          lc->value = lower;
          lc->conf = CONF_INFERRED;
          lc->derived_from[0] = src;
          lc->derived_from[1] = pfn_src;
          lc->lineage_count = 2;
          snprintf(lc->origin, ORIGIN_LEN, "directmap_page_offset_bounds");
        }
      }
    }
  }

  /* Speculative likely edge from a POS_BASE observation: base - align, capped
   * below the sound floor (see header). Shapes the likely window only; the
   * guaranteed window keeps the max_pfn-wide lower bound above. Gated to
   * align >= 2 MiB (RANDOMIZE_MEMORY_ALIGN = 1 GiB where defined; 0 elsewhere,
   * making the gate inert). */
  if (base_lo != ULONG_MAX && align >= 2 * MB && n < out_max) {
    /* The base sits on the PUD grid; align the witness DOWN (an unaligned base
     * claim is provably a non-base) so the edge lands on grid too. */
    unsigned long abase = base_lo & ~mask;
    if (abase > align) {
      struct constraint *bc = &out[n++];
      memset(bc, 0, sizeof(*bc));
      bc->q = Q_PAGE_OFFSET;
      bc->op = C_LOWER_BOUND;
      bc->value = abase - align;
      bc->conf = kasld_conf_min(base_conf, CONF_HEURISTIC);
      bc->derived_from[0] = base_src;
      bc->lineage_count = 1;
      snprintf(bc->origin, ORIGIN_LEN, "directmap_page_offset_bounds");
    }
  }
  return n;
}
