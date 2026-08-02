// This file is part of KASLD - https://github.com/bcoles/kasld
//
// x86_64 kernel_randomize_memory() entropy-budget model.
//
// kernel_randomize_memory() places page_offset_base, vmalloc_base and
// vmemmap_base (in that fixed order) out of one SHARED entropy budget:
//
//   remain = (vaddr_end - vaddr_start) - (dm_size + vmalloc_size +
//                                         vmemmap_size)
//   region i gap  e_i <= remain/(3 - i)   (PUD-granular), then remain -= e_i
//
// so the FIRST region drawn -- the direct map -- can climb at most remain/3
// above vaddr_start, whatever the other two do. That is what the budget
// contributes: page_offset_base lies in
//
//   [vaddr_start, vaddr_start + remain_lo/3]   (PUD-granular)
//
// where remain_lo = span - dm_min - vmalloc_size over-estimates the kernel's
// own `remain` (it drops the vmemmap size, >= 0, and uses the SMALLEST
// possible direct-map size), so the upper edge is never too low.
//
// Two consumers need the same window and must not model it separately:
//
//   - the engine rule (x86_64_randomize_memory_budget), which turns the upper
//     edge into a C_UPPER_BOUND on Q_PAGE_OFFSET; and
//   - the summary, which needs the window's SIZE as the denominator for the
//     direct-map base's residual entropy ("~4 of N bits"). It cannot read that
//     back off the resolved estimate: the rule deliberately emits no lower
//     bound on Q_PAGE_OFFSET (the x86_64 direct-map floor is held at the
//     canonical half boundary so low static-layout addresses are not
//     rejected), so the resolved window's low edge is not vaddr_start.
//
// The whole model rests on the direct-map size, i.e. on the SF_PHYS_MAX_PFN
// observation: `pfn_conf` is carried out with the window so a caller can hold
// the result to a confidence floor (presenting a sub-floor denominator under a
// guaranteed-window numerator would mix trust levels).
//
// The active paging level is taken from a resolved Q_VA_BITS (pinned from a
// runtime directmap address by x86_64_la57_from_directmap) when present, else
// from the leak-free cpuinfo width SF_VIRT_ADDR_BITS -- but that scalar is
// trusted to mean L4 only when it is exactly 48: a 48-bit-virtual CPU cannot
// run 5-level paging, so L4 is certain, whereas a width of 57 is the CPU
// capability and does not prove the kernel enabled 5-level, so L5 is committed
// only from the runtime finset. Absent a sound level nothing is returned
// rather than a guess an L5 system would violate.
//
// vaddr_start = __PAGE_OFFSET_BASE (L4 or L5); vaddr_end = CPU_ENTRY_AREA_BASE
// (identical L4/L5). Constants verified against kernel_randomize_memory() and
// the x86_64 page-table type headers.
//
// References:
//   arch/x86/mm/kaslr.c: kernel_randomize_memory()
//   arch/x86/include/asm/pgtable_64_types.h
// ---
// <bcoles@gmail.com>

#ifndef KASLD_RANDOMIZE_MEMORY_H
#define KASLD_RANDOMIZE_MEMORY_H

#include "engine_rules.h"
#include "quantity.h"

#include <stdint.h>

#define KASLD_RM_TB_SHIFT 40
#define KASLD_RM_PUD_SHIFT 30
#define KASLD_RM_PAGE_SHIFT 12

/* Per-paging-level layout constants. */
struct kasld_rm_level {
  unsigned long vaddr_start; /* __PAGE_OFFSET_BASE */
  unsigned long vaddr_end;   /* CPU_ENTRY_AREA_BASE */
  unsigned long vmalloc_tb;  /* VMALLOC_SIZE_TB */
  unsigned long dm_max_tb;   /* 1 << (MAX_PHYSMEM_BITS - TB_SHIFT) */
};

/* Everything the budget model produces from one evidence set: the inputs it
 * committed to (so a caller can build the size-dependent bounds the model
 * shares with it) and the resulting page_offset window [lo, hi]. */
struct kasld_rm_budget {
  struct kasld_rm_level lv;
  unsigned long va_bits;
  unsigned long max_pfn;
  uint32_t pfn_src;               /* observation id, for lineage */
  enum kasld_confidence pfn_conf; /* confidence of that observation */
  unsigned long lo, hi;           /* page_offset budget window */
};

#if defined(__x86_64__)

/* Fill `lv` for the active paging level, given its VA width (48 = 4-level,
 * 57 = 5-level). Returns 0 for any other width. */
__attribute__((unused)) static int
kasld_rm_level_for(unsigned long va_bits, struct kasld_rm_level *lv) {
  if (va_bits == 48) {
    lv->vaddr_start = 0xffff888000000000ul;
    lv->vaddr_end = 0xfffffe0000000000ul;
    lv->vmalloc_tb = 32ul;
    lv->dm_max_tb = 1ul << (46 - KASLD_RM_TB_SHIFT); /* 64 TiB */
    return 1;
  }
  if (va_bits == 57) {
    lv->vaddr_start = 0xff11000000000000ul;
    lv->vaddr_end = 0xfffffe0000000000ul;
    lv->vmalloc_tb = 12800ul;
    lv->dm_max_tb = 1ul << (52 - KASLD_RM_TB_SHIFT); /* 4096 TiB */
    return 1;
  }
  return 0;
}

/* Evaluate the budget over an evidence set + resolved estimates. Returns 0 --
 * writing nothing -- when the paging level is unresolved, no SF_PHYS_MAX_PFN
 * observation exists, or the fixed region sizes already fill the span (the
 * degenerate huge-RAM case, where the model says nothing).
 *
 * The ceiling is floored to the PUD boundary: page_offset_base is PUD-granular,
 * so the true base is a PUD multiple <= the ragged remain/3 edge and flooring
 * tightens the bound while staying sound. */
__attribute__((unused)) static int
kasld_rm_budget_from_evidence(const struct evidence_set *ev,
                              const struct estimate *est,
                              struct kasld_rm_budget *out) {
  struct kasld_rm_budget b;
  memset(&b, 0, sizeof(b));
  b.pfn_conf = CONF_UNKNOWN;

  if (!estimate_finset_value(&quantities[Q_VA_BITS], &est[Q_VA_BITS],
                             &b.va_bits)) {
    for (int i = 0; i < ev->n_obs; i++) {
      const struct observation *o = &ev->obs[i];
      if (o->valid && o->value_kind == OBS_SCALAR &&
          o->scalar_fact == SF_VIRT_ADDR_BITS && o->scalar_value == 48) {
        b.va_bits = 48;
        break;
      }
    }
  }
  if (!kasld_rm_level_for(b.va_bits, &b.lv))
    return 0;

  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (o->valid && o->value_kind == OBS_SCALAR &&
        o->scalar_fact == SF_PHYS_MAX_PFN) {
      b.max_pfn = o->scalar_value;
      b.pfn_src = o->id;
      b.pfn_conf = o->conf;
      break;
    }
  }
  if (!b.max_pfn)
    return 0;

  const unsigned long one_tb = 1ul << KASLD_RM_TB_SHIFT;
  const unsigned long pud = 1ul << KASLD_RM_PUD_SHIFT;
  const unsigned long span = b.lv.vaddr_end - b.lv.vaddr_start;

  /* dm_min: the smallest possible direct-map size — DIV_ROUND_UP(RAM, 1 TiB)
   * with zero padding, capped at the architectural maximum. The real direct
   * map is never smaller (padding >= 0; ZONE_DEVICE only enlarges it), so the
   * remainder it leaves is never under-stated. */
  unsigned long ram_bytes = b.max_pfn << KASLD_RM_PAGE_SHIFT;
  unsigned long dm_min_tb = (ram_bytes + one_tb - 1) / one_tb;
  if (dm_min_tb > b.lv.dm_max_tb)
    dm_min_tb = b.lv.dm_max_tb;

  unsigned long dm_min = dm_min_tb * one_tb;
  unsigned long vmalloc_sz = b.lv.vmalloc_tb * one_tb;
  if (dm_min + vmalloc_sz >= span)
    return 0;

  b.lo = b.lv.vaddr_start;
  b.hi = (b.lv.vaddr_start + (span - dm_min - vmalloc_sz) / 3) & ~(pud - 1);
  *out = b;
  return 1;
}

#else /* !x86_64: RANDOMIZE_MEMORY is x86_64-only, and the level constants do  \
       * not fit a 32-bit unsigned long. */

__attribute__((unused)) static int
kasld_rm_budget_from_evidence(const struct evidence_set *ev,
                              const struct estimate *est,
                              struct kasld_rm_budget *out) {
  (void)ev;
  (void)est;
  (void)out;
  return 0;
}

#endif /* x86_64 */

#endif /* KASLD_RANDOMIZE_MEMORY_H */
