// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Verdict: x86_64 VMALLOC/VMEMMAP pairwise invariant — invalidate the
// non-conforming side when a pair contradicts kernel_randomize_memory()'s
// fixed ordering.
//
// When both a VIRT/VMALLOC observation V_va and a VIRT/VMEMMAP observation
// V_mm are present, the kernel invariant
//
//   virt_vmemmap_base ≥ virt_vmalloc_base + VMALLOC_SIZE_TB·1TB + PUD_SIZE
//
// (≥ 33 TiB on L4, ≥ 12801 TiB on L5) implies, for any actual witness pair:
//
//   V_mm − V_va ≥ VMALLOC_SIZE_TB·1TB + PUD_SIZE
//
// If this fails, one of the two observations is misclassified — most likely a
// directmap pointer mistagged as vmemmap, or a vmemmap pointer mistagged as
// vmalloc. The ordering also requires V_mm > V_va; an inverted pair is the
// same class of error.
//
// Disposition: emit V_INVALID for BOTH observations involved in the failing
// pair. We cannot tell which side is wrong from the pair alone; further
// curation (consensus among multiple same-region observations) is left to
// the regular cluster filters. Invalidating both is the conservative move
// that prevents an unsound back-bound on Q_PAGE_OFFSET via
// x86_64_page_offset_from_vmalloc_vmemmap.
//
// Inert when no VIRT VMALLOC + VIRT VMEMMAP pair is present. x86_64 only.
// ---
// <bcoles@gmail.com>

#include "../include/kasld/engine_rules.h"

#include <limits.h>
#include <string.h>

#define TB_SHIFT 40
#define PUD_SHIFT 30
#define VMALLOC_SIZE_TB_L4 32ul

int rule_x86_64_vmalloc_vmemmap_invariant(const struct evidence_set *ev,
                                          struct verdict *out, int out_max) {
#if defined(__x86_64__)
  /* Gather candidate observations. The verdict applies to ALL such pairs;
   * we don't try to pick one — if any vmalloc is too close to any vmemmap,
   * both lineages are tainted. */
  int n = 0;
  for (int i = 0; i < ev->n_obs && n < out_max; i++) {
    const struct observation *vi = &ev->obs[i];
    if (!vi->valid || vi->value_kind != OBS_ADDRESS ||
        vi->eff_type != KASLD_TYPE_VIRT || vi->eff_region != REGION_VMALLOC)
      continue;
    unsigned long va = obs_anchor(vi);
    if (va == 0)
      continue;

    for (int j = 0; j < ev->n_obs && n < out_max; j++) {
      const struct observation *vj = &ev->obs[j];
      if (!vj->valid || vj->value_kind != OBS_ADDRESS ||
          vj->eff_type != KASLD_TYPE_VIRT || vj->eff_region != REGION_VMEMMAP)
        continue;
      unsigned long mm = obs_anchor(vj);
      if (mm == 0)
        continue;

      /* L4 vs L5 — invalidate ONLY when the gap is too small even under
       * the L4 assumption (32 TiB + PUD). On L5 the required gap is far
       * larger (12800 TiB + PUD), but presuming L5 here would let us
       * invalidate observations that are actually valid under L4 — unsound
       * curation. The verdict is conservative-by-construction: a pair is
       * incompatible only when no plausible mode admits it. */
      unsigned long required_gap =
          VMALLOC_SIZE_TB_L4 * (1ul << TB_SHIFT) + (1ul << PUD_SHIFT);

      int bad = (mm <= va) || (mm - va < required_gap);
      if (!bad)
        continue;

      /* Emit V_INVALID for both — conservative: we don't know which is
       * misclassified. Deduped by the engine via (observation_id, kind). */
      if (n < out_max) {
        struct verdict *v = &out[n++];
        memset(v, 0, sizeof(*v));
        v->observation_id = vi->id;
        v->kind = V_INVALID;
        v->conf = vi->conf;
        v->derived_from[0] = vi->id;
        v->derived_from[1] = vj->id;
        v->lineage_count = 2;
        snprintf(v->origin, ORIGIN_LEN, "x86_64_vmalloc_vmemmap_invariant");
      }
      if (n < out_max) {
        struct verdict *v = &out[n++];
        memset(v, 0, sizeof(*v));
        v->observation_id = vj->id;
        v->kind = V_INVALID;
        v->conf = vj->conf;
        v->derived_from[0] = vi->id;
        v->derived_from[1] = vj->id;
        v->lineage_count = 2;
        snprintf(v->origin, ORIGIN_LEN, "x86_64_vmalloc_vmemmap_invariant");
      }
    }
  }
  return n;
#else
  (void)ev;
  (void)out;
  (void)out_max;
  return 0;
#endif
}
