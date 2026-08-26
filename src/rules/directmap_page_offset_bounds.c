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
// REGION_DIRECTMAP_BAND is read too, as a SEPARATE class capped below the sound
// floor. A band-tagged address is exact but its region rests on a window test —
// kasld_addr_is_directmap() means "below the text window", so it also spans
// vmalloc and vmemmap wherever those are not separately bounded — and what such
// a value implies about the linear-map base is therefore a guess. Separate
// rather than merged because this rule bounds from the LOWEST witness: a lower
// band sample folded into one minimum would displace a bound the guaranteed
// window had earned. The POS_BASE edge below stays established-only; a base
// claim states where the region begins, which a range verdict cannot do.
//
// Lower bound: the leaked directmap pointer maps SOME physical page P, with
//   virt_page_offset = V - (P - PHYS_OFFSET).
// P lies within the direct-mapped physical range [PHYS_OFFSET, max_pfn*PAGE),
// so P is maximised at the top of the direct map and the base is minimised:
//   virt_page_offset >= V - (max_pfn pages - PHYS_OFFSET).
// A page here is the TARGET kernel's page, never this build's: four of the
// eight architecture families admit several sizes, and converting max_pfn at
// 4 KiB on a 64 KiB-page kernel understates the span 16x, which lifts the bound
// above the true base. The multiplier is pfn_to_phys() where the arch admits
// one size and the observed SF_PAGE_SIZE where it does not; absent both, no
// lower bound is emitted.
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

/* RANDOMIZE_MEMORY_ALIGN = PUD_SIZE on x86_64 (1 GiB) — the alignment the
 * kernel's KASLR code places virt_page_offset_base on. Zero on arches without
 * RANDOMIZE_MEMORY (the mask collapses to 0, alignment is a no-op). */
#define DPO_ALIGN ((unsigned long)RANDOMIZE_MEMORY_ALIGN)
#define DPO_MASK (DPO_ALIGN ? (DPO_ALIGN - 1) : 0ul)

/* Derive the two bounds from the lowest directmap witness of ONE provenance
 * class, emitting at `conf`.
 *
 * Established (`REGION_DIRECTMAP`) and range-classified
 * (`REGION_DIRECTMAP_BAND`) witnesses are collected SEPARATELY rather than
 * mixed into one minimum. This rule bounds from the lowest witness, so folding
 * a lower band sample into the same minimum would replace a bound the
 * guaranteed window had earned with a capped one, and that window would
 * silently lose it. Two passes, one per provenance, let the engine's meet take
 * the tighter of each inside its own window — the same split
 * range_from_interior uses for the text family. */
static int dpo_emit_bounds(const struct evidence_set *ev,
                           enum kasld_region region, enum kasld_confidence conf,
                           unsigned long max_pfn, uint32_t pfn_src,
                           struct constraint *out, int slot, int out_max) {
  unsigned long vdmap_min = ULONG_MAX;
  uint32_t src = 0;
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->value_kind != OBS_ADDRESS)
      continue;
    if (o->eff_type != KASLD_TYPE_VIRT || o->eff_region != region)
      continue;
    unsigned long a = obs_anchor(o);
    if (a < vdmap_min) {
      vdmap_min = a;
      src = o->id;
    }
  }
  if (vdmap_min == ULONG_MAX || slot >= out_max)
    return 0;

  const unsigned long align = DPO_ALIGN;
  const unsigned long mask = DPO_MASK;
  int n = 0;
  (void)align;

  /* Upper bound: virt_page_offset <= lowest directmap leak, aligned DOWN to
   * PUD. */
  unsigned long upper = vdmap_min & ~mask;
  struct constraint *c = &out[slot + n++];
  memset(c, 0, sizeof(*c));
  c->q = Q_PAGE_OFFSET;
  c->op = C_UPPER_BOUND;
  c->value = upper;
  c->conf = conf;
  c->derived_from[0] = src;
  c->lineage_count = 1;
  snprintf(c->origin, ORIGIN_LEN, "directmap_page_offset_bounds");

  /* Lower bound: virt_page_offset >= V - (max_pfn pages - PHYS_OFFSET),
   * aligned UP to PUD.
   *
   * The span is sound only while it is at least the true top of physical
   * memory: understate it and `reach` shrinks with it, so the bound lands
   * ABOVE the true base and the guaranteed window excludes it. max_pfn counts
   * the TARGET kernel's pages, so the multiplier is that kernel's page size --
   * pfn_to_phys() where the architecture admits exactly one, and the observed
   * SF_PAGE_SIZE where it admits several. Without either there is no sound
   * span and so no lower bound: declining costs a bound, guessing costs the
   * guarantee. pfn_to_phys() returns 0 on overflow, and the explicit check
   * covers the runtime path. */
  unsigned long span = 0;
  enum kasld_confidence span_conf = conf;
  uint32_t span_src = 0;
#ifdef pfn_to_phys
  span = pfn_to_phys(max_pfn);
#else
  {
    enum kasld_confidence ps_conf = CONF_UNKNOWN;
    uint32_t ps_src = 0;
    unsigned long ps =
        kasld_scalar_fact_value(ev, SF_PAGE_SIZE, &ps_conf, &ps_src);
    /* This value crossed the tagged-line protocol, so it is a parse and is
     * checked like one: a page size outside what the architecture admits, or
     * one that is not a power of two, is an artefact rather than a
     * measurement. The bracket is the arch's own declared axis rather than a
     * round number, so it tightens automatically wherever an arch states a
     * narrower range. (proc_zoneinfo asks sysconf instead and deliberately
     * does not check: there the syscall is more authoritative about the
     * running kernel than this build's axis is.) */
    if (ps && (ps & (ps - 1)) == 0 && ps >= (unsigned long)PAGE_SIZE_MIN &&
        ps <= (unsigned long)PAGE_SIZE_MAX &&
        max_pfn <= (unsigned long)-1 / ps) {
      span = max_pfn * ps;
      /* Three facts now, so the bound is only as good as the weakest of them:
       * a page size observed below the sound floor must not lift a bound above
       * it. */
      span_conf = kasld_conf_min(conf, ps_conf);
      span_src = ps_src;
    }
  }
#endif

  if (max_pfn && span && slot + n < out_max) {
    if (1
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
          struct constraint *lc = &out[slot + n++];
          memset(lc, 0, sizeof(*lc));
          lc->q = Q_PAGE_OFFSET;
          lc->op = C_LOWER_BOUND;
          lc->value = lower;
          lc->conf = span_conf;
          lc->derived_from[0] = src;
          lc->derived_from[1] = pfn_src;
          lc->lineage_count = 2;
          /* The observed page size is the third input wherever the span was
           * computed from one, so the bound names it too. */
          if (span_src) {
            lc->derived_from[2] = span_src;
            lc->lineage_count = 3;
          }
          snprintf(lc->origin, ORIGIN_LEN, "directmap_page_offset_bounds");
        }
      }
    }
  }
  return n;
}

int rule_directmap_page_offset_bounds(const struct evidence_set *ev,
                                      const struct estimate *est,
                                      struct constraint *out, int out_max) {
  (void)est;
  if (out_max < 1)
    return 0;

  /* max_pfn is a scalar fact, not tied to either provenance class, so it is
   * collected once and handed to both passes. */
  unsigned long max_pfn = 0, base_lo = ULONG_MAX;
  enum kasld_confidence base_conf = CONF_UNKNOWN;
  uint32_t pfn_src = 0, base_src = 0;
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid)
      continue;
    if (o->value_kind == OBS_SCALAR && o->scalar_fact == SF_PHYS_MAX_PFN) {
      max_pfn = o->scalar_value;
      pfn_src = o->id;
      continue;
    }
    /* A POS_BASE directmap observation asserts the base itself (the located
     * left edge), feeding the speculative likely edge below. Lowest wins — the
     * base is the region floor, so the lowest base claim is the soundest. Read
     * from the ESTABLISHED region only: a base claim is a statement about where
     * the region begins, which a range verdict cannot make. */
    if (o->value_kind == OBS_ADDRESS && o->eff_type == KASLD_TYPE_VIRT &&
        o->eff_region == REGION_DIRECTMAP && o->pos == POS_BASE && HAS_LO(o) &&
        o->lo < base_lo) {
      base_lo = o->lo;
      base_conf = o->conf;
      base_src = o->id;
    }
  }

  const unsigned long align = DPO_ALIGN;
  const unsigned long mask = DPO_MASK;
  int n = 0;

  n += dpo_emit_bounds(ev, REGION_DIRECTMAP, CONF_INFERRED, max_pfn, pfn_src,
                       out, n, out_max);
  /* Range-classified witnesses, capped below the sound floor: the value is
   * exact but its REGION rests on a window test, so what it implies about the
   * linear-map base is a guess. Shapes the likely window and never the
   * guaranteed one. Without this the family had no consumer at all, and an
   * address that used to bound Q_PAGE_OFFSET bounded nothing in either window.
   */
  n += dpo_emit_bounds(ev, REGION_DIRECTMAP_BAND, CONF_HEURISTIC, max_pfn,
                       pfn_src, out, n, out_max);

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
