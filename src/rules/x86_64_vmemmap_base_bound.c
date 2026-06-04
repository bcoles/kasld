// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: x86_64 RANDOMIZE_MEMORY vmemmap-base lower and upper bounds.
//
// Continues x86_64_vmalloc_base_bound: kernel_randomize_memory() places vmemmap
// directly after vmalloc, separated by a >= PUD_SIZE gap, and the whole region
// group sits below CPU_ENTRY_AREA_BASE. Hence:
//
//   virt_vmemmap_base >= virt_vmalloc_base + VMALLOC_SIZE_TB * 1 TiB + PUD_SIZE
//   virt_vmemmap_base <= CPU_ENTRY_AREA_BASE - vmemmap_size
//
// VMALLOC_SIZE_TB is 32 (L4 paging) or 12800 (L5), selected by whether
// virt_page_offset sits below the L4 VAS floor. vmemmap_size =
// directmap_size_tb * 16 GiB rounded up to whole TiB (one 64-byte struct page
// per 4 KiB page).
//
// CROSS-QUANTITY: the lower bound reads the engine's resolved Q_VMALLOC_BASE
// lower edge, and fires ONLY once that edge has actually been raised by a
// constraint (lo_binding != 0). Using the honest-top VAS floor here would
// manufacture a bogus
// bound. The paging mode reads Q_PAGE_OFFSET's lower edge; the upper bound
// needs SF_PHYS_MAX_PFN and is emitted only when present.
//
// C_LOWER_BOUND + optional C_UPPER_BOUND on Q_VMEMMAP_BASE. x86-64 only.
// ---
// <bcoles@gmail.com>

#include "../include/kasld/engine_rules.h"

#include <string.h>

#define TB_SHIFT 40
#define PUD_SHIFT 30
#define PAGE_SHIFT 12
#define RANDOMIZE_MEMORY_PHYSICAL_PADDING 10ul

/* CPU_ENTRY_AREA_BASE = -4 << P4D_SHIFT = 0xfffffe0000000000 (L4 and L5). */
#define CPU_ENTRY_AREA_BASE 0xfffffe0000000000ul
#define VMALLOC_SIZE_TB_L4 32ul
#define VMALLOC_SIZE_TB_L5 12800ul
#define X86_64_L4_VAS_START 0xffff800000000000ul

int rule_x86_64_vmemmap_base_bound(const struct evidence_set *ev,
                                   const struct estimate *est,
                                   struct constraint *out, int out_max) {
#if defined(__x86_64__)
  if (out_max < 1)
    return 0;

  /* Requires a vmalloc base lower bound already raised by a constraint. */
  const struct estimate *vmalloc = &est[Q_VMALLOC_BASE];
  if (vmalloc->lo_binding == 0)
    return 0;
  unsigned long virt_vmalloc_base_min = vmalloc->lo;

  unsigned long one_tb = 1ul << TB_SHIFT;
  unsigned long pud_size = 1ul << PUD_SHIFT;

  /* Paging mode from virt_page_offset: L5 if its floor sits below the L4 VAS.
   */
  unsigned long po_lo = est[Q_PAGE_OFFSET].lo;
  unsigned long vmalloc_size_tb = (po_lo != 0 && po_lo < X86_64_L4_VAS_START)
                                      ? VMALLOC_SIZE_TB_L5
                                      : VMALLOC_SIZE_TB_L4;

  int n = 0;

  /* ---- Lower bound ---- */
  unsigned long lower =
      virt_vmalloc_base_min + vmalloc_size_tb * one_tb + pud_size;
  if (lower > virt_vmalloc_base_min && lower < CPU_ENTRY_AREA_BASE &&
      n < out_max) {
    struct constraint *c = &out[n++];
    memset(c, 0, sizeof(*c));
    c->q = Q_VMEMMAP_BASE;
    c->op = C_LOWER_BOUND;
    c->value = lower;
    c->conf = CONF_INFERRED;
    c->derived_from[0] = vmalloc->lo_binding;
    c->lineage_count = 1;
    snprintf(c->origin, ORIGIN_LEN, "x86_64_vmemmap_base_bound");
  }

  /* ---- Upper bound: CPU_ENTRY_AREA_BASE - vmemmap_size (needs max_pfn) ----
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
  if (max_pfn && n < out_max) {
    unsigned long page_bytes = max_pfn << PAGE_SHIFT;
    unsigned long memory_tb =
        (page_bytes + one_tb - 1) / one_tb + RANDOMIZE_MEMORY_PHYSICAL_PADDING;
    unsigned long directmap_size_tb = memory_tb < 4096ul ? memory_tb : 4096ul;
    /* vmemmap_size = directmap_size_tb * 16 GiB = directmap_size_tb << 34. */
    unsigned long vmemmap_size_bytes = directmap_size_tb * (1ul << 34);
    unsigned long vmemmap_size_tb = (vmemmap_size_bytes + one_tb - 1) / one_tb;
    if (vmemmap_size_tb == 0)
      vmemmap_size_tb = 1;

    unsigned long upper = CPU_ENTRY_AREA_BASE - vmemmap_size_tb * one_tb;
    if (upper > lower) {
      struct constraint *c = &out[n++];
      memset(c, 0, sizeof(*c));
      c->q = Q_VMEMMAP_BASE;
      c->op = C_UPPER_BOUND;
      c->value = upper;
      c->conf = CONF_INFERRED;
      c->derived_from[0] = pfn_src;
      c->lineage_count = 1;
      snprintf(c->origin, ORIGIN_LEN, "x86_64_vmemmap_base_bound");
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
