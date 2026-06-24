// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: x86_64 RANDOMIZE_MEMORY vmalloc-base lower and upper bounds.
//
// On x86_64 with
// CONFIG_RANDOMIZE_MEMORY, kernel_randomize_memory() lays the three KASLR
// regions out consecutively, each separated by a random gap of at least
// PUD_SIZE (1 GiB):
//
//   directmap base = virt_page_offset_base, size = directmap_size_tb * 1 TiB
//   vmalloc  base = virt_page_offset_base + directmap_size_tb * 1 TiB + (>=
//   PUD_SIZE) vmemmap  base = virt_vmalloc_base    + VMALLOC_SIZE_TB * 1 TiB +
//   (>= PUD_SIZE)
//
// so the vmalloc base is bounded on BOTH sides — from the direct map below and
// vmemmap above:
//
//   virt_vmalloc_base >= virt_page_offset_min + directmap_size_tb * 1 TiB +
//   PUD_SIZE virt_vmalloc_base <= virt_vmemmap_base_max - VMALLOC_SIZE_TB * 1
//   TiB - PUD_SIZE
//
// where directmap_size_tb = DIV_ROUND_UP(max_pfn * PAGE_SIZE, 1 TiB) +
// CONFIG_RANDOMIZE_MEMORY_PHYSICAL_PADDING, capped at the 4096 TiB
// architectural ceiling. max_pfn arrives as SF_PHYS_MAX_PFN (/proc/zoneinfo).
// The padding is assumed to be its MINIMUM (0): the kernel default is 0xa only
// with CONFIG_MEMORY_HOTPLUG, else 0 (range 0..0x40). A larger real padding
// only ENLARGES the real directmap, which raises the real vmalloc base — so a
// 0 assumption keeps this lower bound sound (looser) for every config.
// (Assuming 10 was unsound on no-hotplug / sub-10-padding kernels.)
// VMALLOC_SIZE_TB is 32 (L4) or 12800 (L5), by paging mode.
//
// CROSS-QUANTITY: the lower bound reads the engine's resolved Q_PAGE_OFFSET
// lower edge (the honest VAS floor when no landmark pinned virt_page_offset, a
// point when one did). The upper bound reads the resolved Q_VMEMMAP_BASE upper
// edge and fires only once it has actually been bound (hi_binding != 0) —
// symmetric to x86_64_vmemmap_base_bound, which derives vmemmap's lower edge
// from vmalloc's; the engine fixpoint orders the two. The lower bound emits
// nothing without SF_PHYS_MAX_PFN — absence yields no constraint, never a wrong
// one.
//
// C_LOWER_BOUND + optional C_UPPER_BOUND on Q_VMALLOC_BASE. x86-64 only; inert
// elsewhere (the quantity is never constrained on other arches).
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"

#include <string.h>

#define TB_SHIFT 40
#define PUD_SHIFT 30
#define PAGE_SHIFT 12
/* Minimum CONFIG_RANDOMIZE_MEMORY_PHYSICAL_PADDING (0); see the header — the
 * real padding only enlarges the real directmap, so 0 keeps the bound sound. */
#define RANDOMIZE_MEMORY_PHYSICAL_PADDING 0ul
#define VMALLOC_SIZE_TB_L4 32ul
#define VMALLOC_SIZE_TB_L5 12800ul
#define X86_64_L4_VAS_START 0xffff800000000000ul

int rule_x86_64_vmalloc_base_bound(const struct evidence_set *ev,
                                   const struct estimate *est,
                                   struct constraint *out, int out_max) {
#if defined(__x86_64__)
  if (out_max < 1)
    return 0;

  /* max_pfn (SF_PHYS_MAX_PFN) — required; without it directmap size is unknown.
   */
  unsigned long max_pfn = 0;
  uint32_t pfn_src = 0;
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (o->valid && o->value_kind == OBS_SCALAR &&
        o->scalar_fact == SF_PHYS_MAX_PFN) {
      max_pfn = o->scalar_value;
      pfn_src = o->id;
      break;
    }
  }
  if (!max_pfn)
    return 0;

  const struct estimate *po = &est[Q_PAGE_OFFSET];
  unsigned long virt_page_offset_min = po->lo;

  unsigned long one_tb = 1ul << TB_SHIFT;
  unsigned long page_bytes = max_pfn << PAGE_SHIFT;
  unsigned long memory_tb =
      (page_bytes + one_tb - 1) / one_tb + RANDOMIZE_MEMORY_PHYSICAL_PADDING;
  unsigned long directmap_size_tb = memory_tb < 4096ul ? memory_tb : 4096ul;
  unsigned long pud_size = 1ul << PUD_SHIFT;

  unsigned long candidate =
      virt_page_offset_min + directmap_size_tb * one_tb + pud_size;
  if (candidate <= virt_page_offset_min) /* overflow / sanity */
    return 0;

  int n = 0;
  if (n < out_max) {
    struct constraint *c = &out[n++];
    memset(c, 0, sizeof(*c));
    c->q = Q_VMALLOC_BASE;
    c->op = C_LOWER_BOUND;
    c->value = candidate;
    c->conf = CONF_INFERRED; /* minimum-padding model; sound for any config */
    c->lineage_count = 0;
    c->derived_from[c->lineage_count++] = pfn_src;
    if (po->lo_binding)
      c->derived_from[c->lineage_count++] = po->lo_binding;
    snprintf(c->origin, ORIGIN_LEN, "x86_64_vmalloc_base_bound");
  }

  /* Upper bound: vmemmap sits VMALLOC_SIZE_TB + (>= PUD_SIZE) above vmalloc, so
   * virt_vmalloc_base <= virt_vmemmap_base_max - VMALLOC_SIZE_TB*1TiB -
   * PUD_SIZE. Fires only once vmemmap's upper edge is itself bound (the
   * fixpoint sets it via x86_64_vmemmap_base_bound). */
  const struct estimate *vmemmap = &est[Q_VMEMMAP_BASE];
  if (vmemmap->hi_binding && n < out_max) {
    /* Default to the L4 (smaller) vmalloc size: for an UPPER bound the smaller
     * size yields the larger, looser, always-sound ceiling (on an L5 system it
     * over-estimates the ceiling — sound; on L4 it is exact). Use the L5 size
     * ONLY when page_offset is RESOLVED to a point in the L5 region. Testing
     * the floor alone is wrong: the unresolved Q_PAGE_OFFSET floor
     * (KERNEL_VIRT_VAS_START = 0xff00…, spanning L5) is itself <
     * X86_64_L4_VAS_START, so on an ordinary L4 box it would mis-select L5 and
     * push the ceiling ~12768 TiB below the true vmalloc base, excluding it. A
     * resolved page_offset < L4_VAS_START is genuinely L5 (L4 bases randomize
     * up from __PAGE_OFFSET_BASE_L4 > L4_VAS_START). */
    unsigned long vmalloc_size_tb = VMALLOC_SIZE_TB_L4;
    if (po->lo == po->hi && po->lo != 0 && po->lo < X86_64_L4_VAS_START)
      vmalloc_size_tb = VMALLOC_SIZE_TB_L5;
    unsigned long below = vmalloc_size_tb * one_tb + pud_size;
    if (vmemmap->hi > below) {
      unsigned long upper = vmemmap->hi - below;
      if (upper > candidate) { /* keep a valid, non-inverted window */
        struct constraint *c = &out[n++];
        memset(c, 0, sizeof(*c));
        c->q = Q_VMALLOC_BASE;
        c->op = C_UPPER_BOUND;
        c->value = upper;
        c->conf = CONF_INFERRED;
        c->derived_from[0] = vmemmap->hi_binding;
        c->lineage_count = 1;
        snprintf(c->origin, ORIGIN_LEN, "x86_64_vmalloc_base_bound");
      }
    }
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
