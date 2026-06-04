// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: s390 VMEMMAP observation → Q_VIRT_TEXT_BASE lower bound.
//
// arch/s390/boot/startup.c packs the VAS as a column below text_virt:
//
//   identity_base                                                      (low)
//   ...
//   vmemmap_start = round_down(__abs_lowcore - vmemmap_size, rte_size)
//   ...
//   __abs_lowcore = __memcpy_real_area - ABS_LOWCORE_MAP_SIZE
//   __memcpy_real_area = round_down(VMALLOC_START - MEMCPY_REAL_SIZE,
//   PAGE_SIZE) VMALLOC_START = VMALLOC_END - vmalloc_size VMALLOC_END =
//   MODULES_VADDR MODULES_VADDR = MODULES_END - MODULES_LEN  (= 2 GiB)
//   MODULES_END = round_down(text_virt, _SEGMENT_SIZE)
//   text_virt                                                          (high)
//
// Chain: a VIRT/VMEMMAP observation V_mm sits below vmemmap_end which is
// below all of {abs_lowcore, memcpy_real, vmalloc, modules}. The cumulative
// offset from V_mm up to text_virt is therefore at minimum
//
//   text_virt ≥ V_mm + vmemmap_size + ABS_LOWCORE_MAP_SIZE
//                    + MEMCPY_REAL_SIZE + vmalloc_size + MODULES_LEN + 1
//
// Per the proposal's soundness note, undersizing any intermediate term
// only loosens the floor (always sound). The intermediate constants
// (ABS_LOWCORE_MAP_SIZE, MEMCPY_REAL_SIZE, vmalloc_size) depend on
// runtime config; conservatively we undersize them to 0. The dominant
// terms are:
//
//   vmemmap_size — derived from SF_PHYS_MAX_PFN × sizeof(struct page).
//                  64 bytes is the upstream default on s390; treat as
//                  undersized when actual struct grows in non-default
//                  configs. Absent SF_PHYS_MAX_PFN, use 0 (still sound).
//   MODULES_LEN  — fixed 2 GiB constant.
//
// Companion to module_text_bound (s390 case B; MODULE → text) and
// s390_text_from_vmalloc (VMALLOC → text); this rule extends the same
// pattern to the deeper VMEMMAP rung.
//
// Currently DORMANT — no production s390 component emits VIRT/VMEMMAP
// observations today (paired activation with arm64_va_bits_from_vmemmap
// and x86_64_page_offset_from_vmalloc_vmemmap). s390 only.
//
// References:
// arch/s390/boot/startup.c (the VAS layout code)
// arch/s390/include/asm/setup.h, arch/s390/include/asm/page.h
// ---
// <bcoles@gmail.com>

#include "../include/kasld/engine_rules.h"

#include <limits.h>
#include <string.h>

#define S390_MODULES_LEN 0x80000000ul       /* SZ_2G */
#define S390_VMEMMAP_STRUCT_PAGE_BYTES 64ul /* upstream default */

int rule_s390_text_from_vmemmap(const struct evidence_set *ev,
                                const struct estimate *est,
                                struct constraint *out, int out_max) {
  (void)est;
#if defined(__s390__) || defined(__s390x__)
  if (out_max < 1)
    return 0;

  /* Highest VMEMMAP observation: closest to text, tightest bound. */
  unsigned long highest = 0;
  uint32_t obs_src = 0;
  enum kasld_confidence obs_conf = CONF_UNKNOWN;
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->value_kind != OBS_ADDRESS ||
        o->eff_type != KASLD_TYPE_VIRT || o->eff_region != REGION_VMEMMAP)
      continue;
    unsigned long a = obs_anchor(o);
    if (a == 0)
      continue;
    if (a > highest) {
      highest = a;
      obs_src = o->id;
      obs_conf = o->conf;
    }
  }
  if (obs_src == 0)
    return 0;

  /* SF_PHYS_MAX_PFN → vmemmap_size = max_pfn × sizeof(struct page) (lower
   * bound; upstream default 64 bytes — under-estimating on configs with a
   * larger struct keeps the derived floor sound). Absent SF_PHYS_MAX_PFN, treat
   * vmemmap_size as 0 (still sound, just looser). */
  unsigned long vmemmap_size = 0;
  uint32_t pfn_src = 0;
  enum kasld_confidence pfn_conf = CONF_UNKNOWN;
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->value_kind != OBS_SCALAR ||
        o->scalar_fact != SF_PHYS_MAX_PFN)
      continue;
    /* Overflow-guarded multiplication. */
    if (o->scalar_value > ULONG_MAX / S390_VMEMMAP_STRUCT_PAGE_BYTES)
      vmemmap_size = ULONG_MAX;
    else
      vmemmap_size = o->scalar_value * S390_VMEMMAP_STRUCT_PAGE_BYTES;
    pfn_src = o->id;
    pfn_conf = o->conf;
    break;
  }

  /* text_virt ≥ V_mm + vmemmap_size + MODULES_LEN + 1 (intermediate rungs
   * conservatively undersized to 0). Overflow-guarded against pathological
   * inputs. */
  if (vmemmap_size > ULONG_MAX - S390_MODULES_LEN - 1ul)
    return 0;
  unsigned long offset = vmemmap_size + S390_MODULES_LEN + 1ul;
  if (highest > ULONG_MAX - offset)
    return 0;
  unsigned long lower = highest + offset;

  struct constraint *c = &out[0];
  memset(c, 0, sizeof(*c));
  c->q = Q_VIRT_TEXT_BASE;
  c->op = C_LOWER_BOUND;
  c->value = lower;
  c->conf = (obs_conf < pfn_conf || pfn_src == 0) ? obs_conf : pfn_conf;
  c->derived_from[0] = obs_src;
  c->lineage_count = 1;
  if (pfn_src) {
    c->derived_from[1] = pfn_src;
    c->lineage_count = 2;
  }
  snprintf(c->origin, ORIGIN_LEN, "s390_text_from_vmemmap");
  return 1;
#else
  (void)ev;
  (void)out;
  (void)out_max;
  return 0;
#endif
}
