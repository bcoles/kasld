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

#include <string.h>

#define TB_SHIFT 40
#define PUD_SHIFT 30
#define PAGE_SHIFT 12

/* Per-paging-level layout constants (verified against kernel_randomize_memory
 * and the x86_64 page-table type headers). */
struct rm_level {
  unsigned long vaddr_start; /* __PAGE_OFFSET_BASE */
  unsigned long vaddr_end;   /* CPU_ENTRY_AREA_BASE */
  unsigned long vmalloc_tb;  /* VMALLOC_SIZE_TB */
  unsigned long dm_max_tb;   /* 1 << (MAX_PHYSMEM_BITS - TB_SHIFT) */
};

int rule_x86_64_randomize_memory_budget(const struct evidence_set *ev,
                                        const struct estimate *est,
                                        struct constraint *out, int out_max) {
#if defined(__x86_64__)
  if (out_max < 1)
    return 0;

  /* Active paging level: the runtime-observed Q_VA_BITS finset is
   * authoritative; else the cpuinfo width, trusted only when it is 48 (a 48-bit
   * CPU cannot run 5-level, so L4 is certain; 57 is a capability, not proof of
   * 5-level). */
  unsigned long va_bits = 0;
  if (!estimate_finset_value(&quantities[Q_VA_BITS], &est[Q_VA_BITS],
                             &va_bits)) {
    for (int i = 0; i < ev->n_obs; i++) {
      const struct observation *o = &ev->obs[i];
      if (o->valid && o->value_kind == OBS_SCALAR &&
          o->scalar_fact == SF_VIRT_ADDR_BITS && o->scalar_value == 48) {
        va_bits = 48;
        break;
      }
    }
  }

  struct rm_level lv;
  if (va_bits == 48) {
    lv.vaddr_start = 0xffff888000000000ul;
    lv.vaddr_end = 0xfffffe0000000000ul;
    lv.vmalloc_tb = 32ul;
    lv.dm_max_tb = 1ul << (46 - TB_SHIFT); /* 64 TiB */
  } else if (va_bits == 57) {
    lv.vaddr_start = 0xff11000000000000ul;
    lv.vaddr_end = 0xfffffe0000000000ul;
    lv.vmalloc_tb = 12800ul;
    lv.dm_max_tb = 1ul << (52 - TB_SHIFT); /* 4096 TiB */
  } else {
    return 0;
  }

  const unsigned long one_tb = 1ul << TB_SHIFT;
  const unsigned long pud = 1ul << PUD_SHIFT;
  const unsigned long span = lv.vaddr_end - lv.vaddr_start;

  int n = 0;

  /* No page_offset LOWER bound is emitted here. vaddr_start
   * (__PAGE_OFFSET_BASE) would be a sound lower edge on the direct-map base,
   * but the x86_64 directmap floor is deliberately kept at the canonical half
   * boundary (0xffff800000000000) so that low static-layout addresses (LDT
   * remap, etc.) are not rejected; this rule does not override that choice. It
   * contributes the UPPER bounds the budget newly provides, plus the region
   * floors on the separate vmalloc/vmemmap quantities. */

  /* Everything needs the directmap size, i.e. SF_PHYS_MAX_PFN. */
  unsigned long max_pfn = 0;
  uint32_t pfn_src = 0;
  enum kasld_confidence pfn_conf = CONF_PARSED;
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (o->valid && o->value_kind == OBS_SCALAR &&
        o->scalar_fact == SF_PHYS_MAX_PFN) {
      max_pfn = o->scalar_value;
      pfn_src = o->id;
      pfn_conf = o->conf;
      break;
    }
  }
  if (!max_pfn)
    return n;

  /* dm_min: the smallest possible directmap size — DIV_ROUND_UP(RAM, 1TiB) with
   * zero padding, capped at the architectural maximum. The real directmap is
   * never smaller (padding >= 0; ZONE_DEVICE only enlarges it), so using dm_min
   * where a larger size would tighten a bound keeps it sound. */
  unsigned long ram_bytes = max_pfn << PAGE_SHIFT;
  unsigned long dm_min_tb = (ram_bytes + one_tb - 1) / one_tb;
  if (dm_min_tb > lv.dm_max_tb)
    dm_min_tb = lv.dm_max_tb;

  unsigned long dm_min = dm_min_tb * one_tb;
  unsigned long vmalloc_sz = lv.vmalloc_tb * one_tb;
  unsigned long dm_max = lv.dm_max_tb * one_tb;

  /* remain_lo: an over-estimate of the kernel's `remain` (drops vmemmap size
   * >= 0 and uses dm_min), so ceilings computed from it are sound. Guard the
   * degenerate huge-RAM case where the fixed sizes already fill the span. */
  if (dm_min + vmalloc_sz >= span)
    return n;
  unsigned long remain_lo = span - dm_min - vmalloc_sz;
  const enum kasld_confidence cap = kasld_conf_min(CONF_INFERRED, pfn_conf);

  /* page_offset upper bound: base_0 = vaddr_start + e_0, e_0 <= remain/3. */
  if (n < out_max) {
    unsigned long upper = lv.vaddr_start + remain_lo / 3;
    struct constraint *c = &out[n++];
    memset(c, 0, sizeof(*c));
    c->q = Q_PAGE_OFFSET;
    c->op = C_UPPER_BOUND;
    c->value = upper;
    c->conf = cap;
    c->derived_from[0] = pfn_src;
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
    c->value = lv.vaddr_start + dm_min;
    c->conf = cap;
    c->derived_from[0] = pfn_src;
    c->lineage_count = 1;
    snprintf(c->origin, ORIGIN_LEN, "x86_64_randomize_memory_budget");
  }

  /* vmalloc upper bound: base_1 <= vaddr_start + pad + dm*TB + 2*remain/3,
   * combined over the actual directmap size = vaddr_start + PUD +
   * (dm_max + 2*(span - vmalloc_size)) / 3 (increasing in dm => dm_max). */
  if (n < out_max) {
    unsigned long num = dm_max + 2ul * (span - vmalloc_sz);
    unsigned long upper = lv.vaddr_start + pud + num / 3;
    /* Only emit when it actually sits below the region-group ceiling. */
    if (upper < lv.vaddr_end && upper > lv.vaddr_start + dm_min) {
      struct constraint *c = &out[n++];
      memset(c, 0, sizeof(*c));
      c->q = Q_VMALLOC_BASE;
      c->op = C_UPPER_BOUND;
      c->value = upper;
      c->conf = cap;
      c->derived_from[0] = pfn_src;
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
    c->value = lv.vaddr_start + dm_min + vmalloc_sz;
    c->conf = cap;
    c->derived_from[0] = pfn_src;
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
