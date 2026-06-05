// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: x86_64 RANDOMIZE_MEMORY backward chain — VMALLOC/VMEMMAP observation
// bounds Q_PAGE_OFFSET from above.
//
// kernel_randomize_memory() lays the three regions out consecutively with
// gaps ≥ PUD_SIZE (1 GiB):
//
//   virt_vmalloc_base ≥ virt_page_offset_base + directmap_size + PUD_SIZE
//   virt_vmemmap_base ≥ virt_vmalloc_base    + VMALLOC_SIZE_TB·1TB + PUD_SIZE
//
// A *witnessed* virtual address inside the vmalloc region (or vmemmap) sits
// at or above its base, so it is an upper-bound witness on the smallest
// possible base:
//
//   virt_vmalloc_base ≤ V_va
//   virt_vmemmap_base ≤ V_mm
//
// Substituting into the layout invariants and re-arranging:
//
//   virt_page_offset_max ≤ V_va − directmap_size − PUD_SIZE
//   virt_page_offset_max ≤ V_mm − VMALLOC_SIZE_TB·1TB − directmap_size −
//   2·PUD_SIZE
//
// `directmap_size` is derived from SF_PHYS_MAX_PFN with the kernel's
// RANDOMIZE_MEMORY_PHYSICAL_PADDING (default 10 TiB). `VMALLOC_SIZE_TB` is
// 32 (L4) or 12800 (L5), discriminated from the current Q_PAGE_OFFSET lower
// edge in the same way x86_64_vmalloc_base_bound does (the L4 floor is
// 0xffff800000000000; below that is L5 territory).
//
// The forward chain rules (x86_64_vmalloc_base_bound /
// x86_64_vmemmap_base_bound) already propagate Q_PAGE_OFFSET → Q_VMALLOC_BASE
// → Q_VMEMMAP_BASE; this rule closes the loop by feeding observations back
// into Q_PAGE_OFFSET, tightening it whenever a real leak from the higher
// regions arrives.
//
// Inert when no VIRT observation tagged REGION_VMALLOC or REGION_VMEMMAP
// is present. Candidate sources include /proc/vmallocinfo (with read
// access), dmesg layout dumps on arches that still print them, or any leak
// component yielding VIRT addresses tagged with these regions.
//
// x86_64 only (the chain is RANDOMIZE_MEMORY-specific).
// ---
// <bcoles@gmail.com>

#include "../include/kasld/engine_rules.h"

#include <limits.h>
#include <string.h>

#define TB_SHIFT 40
#define PUD_SHIFT 30
#define PAGE_SHIFT 12
#define RANDOMIZE_MEMORY_PHYSICAL_PADDING 10ul
#define VMALLOC_SIZE_TB_L4 32ul
#define VMALLOC_SIZE_TB_L5 12800ul
#define X86_64_L4_VAS_START 0xffff800000000000ul

int rule_x86_64_page_offset_from_vmalloc_vmemmap(const struct evidence_set *ev,
                                                 const struct estimate *est,
                                                 struct constraint *out,
                                                 int out_max) {
#if defined(__x86_64__)
  if (out_max < 1)
    return 0;

  /* SF_PHYS_MAX_PFN is required to compute directmap_size. */
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

  /* Lowest VIRT VMALLOC / VMEMMAP observation — each is an upper-bound
   * witness on its region's base. */
  unsigned long va = ULONG_MAX, mm = ULONG_MAX;
  uint32_t va_src = 0, mm_src = 0;
  enum kasld_confidence va_conf = CONF_UNKNOWN, mm_conf = CONF_UNKNOWN;
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->value_kind != OBS_ADDRESS ||
        o->eff_type != KASLD_TYPE_VIRT)
      continue;
    unsigned long a = obs_anchor(o);
    if (a == 0)
      continue;
    if (o->eff_region == REGION_VMALLOC && a < va) {
      va = a;
      va_src = o->id;
      va_conf = o->conf;
    } else if (o->eff_region == REGION_VMEMMAP && a < mm) {
      mm = a;
      mm_src = o->id;
      mm_conf = o->conf;
    }
  }
  if (va == ULONG_MAX && mm == ULONG_MAX)
    return 0;

  /* directmap_size from max_pfn (matches x86_64_vmalloc_base_bound). */
  unsigned long one_tb = 1ul << TB_SHIFT;
  unsigned long pud_size = 1ul << PUD_SHIFT;
  unsigned long page_bytes = max_pfn << PAGE_SHIFT;
  unsigned long memory_tb =
      (page_bytes + one_tb - 1) / one_tb + RANDOMIZE_MEMORY_PHYSICAL_PADDING;
  unsigned long directmap_size = (memory_tb < 4096ul ? memory_tb : 4096ul);
  directmap_size *= one_tb;

  /* L4/L5 discrimination. The VMEMMAP-derived bound subtracts
   * VMALLOC_SIZE_TB·1TB from the witness — a bigger subtraction means a
   * smaller (tighter) upper bound, which is *unsound* if we guess L5 on an L4
   * system (excludes valid PAGE_OFFSET values). So commit to L5 only when
   * Q_PAGE_OFFSET is fully pinned in L5 territory (lo == hi AND below the L4
   * VAS floor). Otherwise default to L4 — a smaller subtraction, a looser
   * bound, which is always sound under uncertainty. */
  unsigned long vmalloc_size_tb = VMALLOC_SIZE_TB_L4;
  if (est[Q_PAGE_OFFSET].lo == est[Q_PAGE_OFFSET].hi &&
      est[Q_PAGE_OFFSET].lo < X86_64_L4_VAS_START)
    vmalloc_size_tb = VMALLOC_SIZE_TB_L5;

  int n = 0;

  /* VMALLOC observation: virt_page_offset ≤ V_va - directmap_size - PUD_SIZE.
   */
  if (va != ULONG_MAX && n < out_max) {
    unsigned long below = directmap_size + pud_size;
    if (va > below) {
      unsigned long upper = va - below;
      struct constraint *c = &out[n++];
      memset(c, 0, sizeof(*c));
      c->q = Q_PAGE_OFFSET;
      c->op = C_UPPER_BOUND;
      c->value = upper;
      c->conf = va_conf;
      c->derived_from[0] = va_src;
      c->derived_from[1] = pfn_src;
      c->lineage_count = 2;
      snprintf(c->origin, ORIGIN_LEN,
               "x86_64_page_offset_from_vmalloc_vmemmap");
    }
  }

  /* VMEMMAP observation:
   * virt_page_offset ≤ V_mm - VMALLOC_SIZE_TB·1TB - directmap_size -
   * 2·PUD_SIZE. */
  if (mm != ULONG_MAX && n < out_max) {
    unsigned long below =
        vmalloc_size_tb * one_tb + directmap_size + 2ul * pud_size;
    if (mm > below) {
      unsigned long upper = mm - below;
      struct constraint *c = &out[n++];
      memset(c, 0, sizeof(*c));
      c->q = Q_PAGE_OFFSET;
      c->op = C_UPPER_BOUND;
      c->value = upper;
      c->conf = mm_conf;
      c->derived_from[0] = mm_src;
      c->derived_from[1] = pfn_src;
      c->lineage_count = 2;
      snprintf(c->origin, ORIGIN_LEN,
               "x86_64_page_offset_from_vmalloc_vmemmap");
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
