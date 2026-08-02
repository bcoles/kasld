// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: x86_64 RANDOMIZE_MEMORY shared-entropy-budget bounds on the three
// region bases.
//
// kernel_randomize_memory() places page_offset_base, vmalloc_base and
// vmemmap_base (in that fixed order) by walking a SHARED entropy budget:
//
//   remain = (vaddr_end - vaddr_start) - (dm_size + vmalloc_size +
//   vmemmap_size) region i gap  e_i <= remain/(3 - i)   (PUD-granular), then
//   remain -= e_i base_i = vaddr_start + Sum_{j<i}(size_j + pad_j) + Sum_{j<=i}
//   e_j
//
// vaddr_start = __PAGE_OFFSET_BASE (L4 or L5); vaddr_end = CPU_ENTRY_AREA_BASE
// (identical L4/L5). The fair-share `/(3-i)` cap bounds how far each base can
// climb, INDEPENDENT of any leak — so the whole region group is confined to a
// budget-wide band above vaddr_start. The existing forward/backward chain rules
// model only the minimum inter-region GAPS and leave vmalloc/vmemmap unbounded
// above (honest top = the full kernel VAS) until a leak lands inside them; this
// rule adds the leak-free budget confinement.
//
// Sound bounds (each term independently worst-cased; the true base is never
// excluded):
//
//   e_0 <= floor(remain/3)              ; e_0 + e_1 <= 2*remain/3
//   remain is largest when the region sizes are smallest, so a ceiling that
//   uses remain must use the MINIMUM directmap size (dm_min, from max_pfn with
//   zero padding and no ZONE_DEVICE inflation); a floor that adds a preceding
//   region size must use that same minimum. A ceiling that ALSO adds the
//   region's own preceding directmap offset (vmalloc) is increasing in the
//   directmap size, so it uses the MAXIMUM (architectural) directmap size.
//   vmemmap size is dropped (>= 0) wherever dropping it only loosens a bound.
//
//   page_offset : [vaddr_start,                       vaddr_start +
//   remain_lo/3] vmalloc     : [vaddr_start + dm_min,              vaddr_start
//   + PUD +
//                  (dm_max + 2*(span - vmalloc_size)) / 3]
//   vmemmap     : [vaddr_start + dm_min + vmalloc_size, -- ceiling left to the
//                  existing CPU_ENTRY_AREA - vmemmap_size bound, which is
//                  tighter than the budget gives here]
//
//   where span = vaddr_end - vaddr_start, remain_lo = span - dm_min -
//   vmalloc_size (an over-estimate of the true remain, hence a sound ceiling).
//
// The page_offset lower bound (vaddr_start) needs only the paging level; it
// holds whether or not RANDOMIZE_MEMORY is active (the un-randomized default
// base equals vaddr_start). Every size-dependent bound needs SF_PHYS_MAX_PFN.
//
// The active paging level is taken from a resolved Q_VA_BITS (pinned from a
// runtime directmap address by x86_64_la57_from_directmap) when present, else
// from the leak-free cpuinfo width SF_VIRT_ADDR_BITS — but that scalar is
// trusted to mean L4 only when it is exactly 48: a 48-bit-virtual CPU cannot
// run 5-level paging, so L4 is certain, whereas a width of 57 is the CPU
// capability and does not prove the kernel enabled 5-level, so L5 is committed
// only from the runtime finset. Absent a sound level the rule emits nothing
// rather than guess a floor an L5 system would violate.
//
// C_LOWER_BOUND / C_UPPER_BOUND on Q_PAGE_OFFSET / Q_VMALLOC_BASE /
// Q_VMEMMAP_BASE, capped at CONF_INFERRED (a minimum-padding structural model).
// x86-64 only; inert elsewhere and when the paging level is unresolved.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"
#include "include/kasld/quantity.h"
#include "include/kasld/randomize_memory.h"

#include <string.h>

#define TB_SHIFT KASLD_RM_TB_SHIFT
#define PUD_SHIFT KASLD_RM_PUD_SHIFT
#define PAGE_SHIFT KASLD_RM_PAGE_SHIFT

int rule_x86_64_randomize_memory_budget(const struct evidence_set *ev,
                                        const struct estimate *est,
                                        struct constraint *out, int out_max) {
#if defined(__x86_64__)
  if (out_max < 1)
    return 0;

  /* One shared evaluation of kernel_randomize_memory()'s budget (paging level,
   * max_pfn and the page_offset window), so the rule and the summary's entropy
   * denominator cannot model it two ways. Returns 0 when the level is
   * unresolved, no SF_PHYS_MAX_PFN exists, or the fixed region sizes already
   * fill the span — the rule has nothing sound to say in any of those. */
  struct kasld_rm_budget b;
  if (!kasld_rm_budget_from_evidence(ev, est, &b))
    return 0;

  const unsigned long one_tb = 1ul << TB_SHIFT;
  const unsigned long pud = 1ul << PUD_SHIFT;
  const unsigned long span = b.lv.vaddr_end - b.lv.vaddr_start;

  int n = 0;

  /* No page_offset LOWER bound is emitted here. vaddr_start
   * (__PAGE_OFFSET_BASE) — b.lo — would be a sound lower edge on the direct-map
   * base, but the x86_64 directmap floor is deliberately kept at the canonical
   * half boundary (0xffff800000000000) so that low static-layout addresses (LDT
   * remap, etc.) are not rejected; this rule does not override that choice. It
   * contributes the UPPER bounds the budget newly provides, plus the region
   * floors on the separate vmalloc/vmemmap quantities. */

  /* dm_min: the smallest possible directmap size — DIV_ROUND_UP(RAM, 1TiB) with
   * zero padding, capped at the architectural maximum. The real directmap is
   * never smaller (padding >= 0; ZONE_DEVICE only enlarges it), so using dm_min
   * where a larger size would tighten a bound keeps it sound. Recomputed from
   * the same max_pfn the window was built from. */
  unsigned long ram_bytes = b.max_pfn << PAGE_SHIFT;
  unsigned long dm_min_tb = (ram_bytes + one_tb - 1) / one_tb;
  if (dm_min_tb > b.lv.dm_max_tb)
    dm_min_tb = b.lv.dm_max_tb;

  unsigned long dm_min = dm_min_tb * one_tb;
  unsigned long vmalloc_sz = b.lv.vmalloc_tb * one_tb;
  unsigned long dm_max = b.lv.dm_max_tb * one_tb;

  const enum kasld_confidence cap = kasld_conf_min(CONF_INFERRED, b.pfn_conf);

  /* page_offset upper bound: base_0 = vaddr_start + e_0, e_0 <= remain/3,
   * floored to the PUD boundary — b.hi, the top of the shared window. */
  if (n < out_max) {
    struct constraint *c = &out[n++];
    memset(c, 0, sizeof(*c));
    c->q = Q_PAGE_OFFSET;
    c->op = C_UPPER_BOUND;
    c->value = b.hi;
    c->conf = cap;
    c->derived_from[0] = b.pfn_src;
    c->lineage_count = 1;
    snprintf(c->origin, ORIGIN_LEN, "x86_64_randomize_memory_budget");
  }

  /* vmalloc lower bound: base_1 >= vaddr_start + dm_min (e_0, e_1, pad >= 0,
   * smallest preceding directmap). */
  if (n < out_max) {
    struct constraint *c = &out[n++];
    memset(c, 0, sizeof(*c));
    c->q = Q_VMALLOC_BASE;
    c->op = C_LOWER_BOUND;
    c->value = b.lv.vaddr_start + dm_min;
    c->conf = cap;
    c->derived_from[0] = b.pfn_src;
    c->lineage_count = 1;
    snprintf(c->origin, ORIGIN_LEN, "x86_64_randomize_memory_budget");
  }

  /* vmalloc upper bound: base_1 <= vaddr_start + pad + dm*TB + 2*remain/3,
   * combined over the actual directmap size = vaddr_start + PUD +
   * (dm_max + 2*(span - vmalloc_size)) / 3 (increasing in dm => dm_max). */
  if (n < out_max) {
    unsigned long num = dm_max + 2ul * (span - vmalloc_sz);
    unsigned long upper = (b.lv.vaddr_start + pud + num / 3) & ~(pud - 1);
    /* vmalloc_base is PUD-granular too; floor to align + tighten (see above).
     */
    /* Only emit when it actually sits below the region-group ceiling. */
    if (upper < b.lv.vaddr_end && upper > b.lv.vaddr_start + dm_min) {
      struct constraint *c = &out[n++];
      memset(c, 0, sizeof(*c));
      c->q = Q_VMALLOC_BASE;
      c->op = C_UPPER_BOUND;
      c->value = upper;
      c->conf = cap;
      c->derived_from[0] = b.pfn_src;
      c->lineage_count = 1;
      snprintf(c->origin, ORIGIN_LEN, "x86_64_randomize_memory_budget");
    }
  }

  /* vmemmap lower bound: base_2 >= vaddr_start + dm_min + vmalloc_size. */
  if (n < out_max) {
    struct constraint *c = &out[n++];
    memset(c, 0, sizeof(*c));
    c->q = Q_VMEMMAP_BASE;
    c->op = C_LOWER_BOUND;
    c->value = b.lv.vaddr_start + dm_min + vmalloc_sz;
    c->conf = cap;
    c->derived_from[0] = b.pfn_src;
    c->lineage_count = 1;
    snprintf(c->origin, ORIGIN_LEN, "x86_64_randomize_memory_budget");
  }

  return n;
#else
  (void)ev;
  (void)est;
  (void)out;
  (void)out_max;
  return 0;
#endif
}
