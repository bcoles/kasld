// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: s390 below-text cascade — any VIRT observation in a region packed
// below text_virt floors Q_VIRT_IMAGE_BASE. Consolidates the per-region rungs
// (formerly s390_text_from_vmalloc + s390_text_from_vmemmap) into one
// table-driven cascade, and is structured so a deeper rung is one table row
// once its KASLD_REGION_* tag and a collector component exist.
//
// arch/s390/boot/startup.c packs the VAS as a column directly below text_virt,
// no gaps:
//
//   identity_base                                                      (low)
//   ...
//   vmemmap_start      = round_down(__abs_lowcore - vmemmap_size, rte_size)
//   ...
//   __abs_lowcore      = __memcpy_real_area - ABS_LOWCORE_MAP_SIZE
//   __memcpy_real_area = round_down(VMALLOC_START - MEMCPY_REAL_SIZE, PAGE)
//   VMALLOC_START      = VMALLOC_END - vmalloc_size
//   VMALLOC_END        = MODULES_VADDR
//   MODULES_VADDR      = MODULES_END - MODULES_LEN   (= 2 GiB)
//   MODULES_END        = round_down(text_virt, _SEGMENT_SIZE)
//   text_virt                                                          (high)
//
// A VIRT observation in region R sits below every region above it, so
//
//   text_virt >= V_R + cumulative_offset(R) + 1
//
// where cumulative_offset(R) sums the region sizes between R's top and
// text_virt. Undersizing any intermediate term only loosens the floor, so the
// bound stays sound; we conservatively undersize the runtime-variable
// intermediate sizes (ABS_LOWCORE_MAP_SIZE, MEMCPY_REAL_SIZE, vmalloc_size) to
// 0 and keep the dominant constants.
//
// Rungs (cumulative MIN offset below text_virt):
//
//   MODULE   : 0                          (owned by module_text_bound, which
//                                           also derives the upper bound)
//   VMALLOC  : MODULES_LEN
//   VMEMMAP  : MODULES_LEN + vmemmap_size
//
//   -- deeper rungs, pending new KASLD_REGION_* tags + collector components:
//   -- memcpy_real : MODULES_LEN + vmalloc_size + MEMCPY_REAL_SIZE
//   -- abs_lowcore : + ABS_LOWCORE_MAP_SIZE
//   -- identity    : + vmemmap_size (and below)
//
// For each below-text region we take the HIGHEST observation (closest to text
// => tightest floor) and emit the single MAX floor across all rungs (the engine
// meet over per-region C_LOWER_BOUNDs collapses to exactly this max).
//
// Reads evidence only (no estimates); fully determined by the observation set.
// Inert when no s390 below-text VIRT observation is present. s390 only.
//
// References:
// arch/s390/boot/startup.c (the VAS layout code)
// arch/s390/include/asm/setup.h, arch/s390/include/asm/page.h
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"

#include <limits.h>
#include <string.h>

#define S390_MODULES_LEN 0x80000000ul       /* SZ_2G */
#define S390_STRUCT_PAGE_BYTES_DEFAULT 64ul /* common sizeof(struct page) */

/* One below-text rung: the region, its constant cumulative offset to text, and
 * whether the runtime vmemmap_size term applies (only the VMEMMAP rung). */
struct s390_below_rung {
  enum kasld_region region;
  unsigned long const_off;
  int add_vmemmap_size;
};

int rule_s390_text_from_belows(const struct evidence_set *ev,
                               const struct estimate *est,
                               struct constraint *out, int out_max) {
  (void)est;
#if defined(__s390__) || defined(__s390x__)
  if (out_max < 1)
    return 0;

  /* sizeof(struct page): exact from BTF (SF_STRUCT_PAGE_BYTES) when present,
   * else the common 64-byte default. The exact value is the real vmemmap-per-
   * frame size; the default under-estimates on a larger struct page, which only
   * loosens the floor (still sound). */
  unsigned long struct_page_bytes = S390_STRUCT_PAGE_BYTES_DEFAULT;
  uint32_t sp_src = 0;
  enum kasld_confidence sp_conf = CONF_UNKNOWN;
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (o->valid && o->value_kind == OBS_SCALAR &&
        o->scalar_fact == SF_STRUCT_PAGE_BYTES && o->scalar_value >= 1 &&
        o->scalar_value <= (1ul << 20)) {
      struct_page_bytes = o->scalar_value;
      sp_src = o->id;
      sp_conf = o->conf;
      break;
    }
  }

  /* vmemmap_size = SF_PHYS_MAX_PFN × struct_page_bytes. Absent SF_PHYS_MAX_PFN,
   * treat as 0 (still sound). */
  unsigned long vmemmap_size = 0;
  uint32_t pfn_src = 0;
  enum kasld_confidence pfn_conf = CONF_UNKNOWN;
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->value_kind != OBS_SCALAR ||
        o->scalar_fact != SF_PHYS_MAX_PFN)
      continue;
    if (o->scalar_value > ULONG_MAX / struct_page_bytes)
      vmemmap_size = ULONG_MAX;
    else
      vmemmap_size = o->scalar_value * struct_page_bytes;
    pfn_src = o->id;
    pfn_conf = o->conf;
    break;
  }

  static const struct s390_below_rung rungs[] = {
      {REGION_VMALLOC, S390_MODULES_LEN, 0},
      {REGION_VMEMMAP, S390_MODULES_LEN, 1},
      /* Deeper rungs land here once their REGION_* tag + collector exist. */
  };

  unsigned long best_lower = 0;
  uint32_t best_src = 0;
  enum kasld_confidence best_conf = CONF_UNKNOWN;
  int best_uses_pfn = 0;

  for (size_t r = 0; r < sizeof(rungs) / sizeof(rungs[0]); r++) {
    /* Highest observation in this region — closest to text, tightest floor. */
    unsigned long highest = 0;
    uint32_t src = 0;
    enum kasld_confidence conf = CONF_UNKNOWN;
    for (int i = 0; i < ev->n_obs; i++) {
      const struct observation *o = &ev->obs[i];
      if (!o->valid || o->value_kind != OBS_ADDRESS ||
          o->eff_type != KASLD_TYPE_VIRT || o->eff_region != rungs[r].region)
        continue;
      unsigned long a = obs_anchor(o);
      if (a == 0)
        continue;
      if (a > highest) {
        highest = a;
        src = o->id;
        conf = o->conf;
      }
    }
    if (src == 0)
      continue;

    unsigned long off = rungs[r].const_off;
    if (rungs[r].add_vmemmap_size) {
      if (vmemmap_size > ULONG_MAX - off)
        continue; /* overflow guard */
      off += vmemmap_size;
    }
    if (off > ULONG_MAX - 1ul)
      continue;
    off += 1ul; /* strict gt → ≥ +1 */
    if (highest > ULONG_MAX - off)
      continue; /* overflow guard */
    unsigned long lower = highest + off;
    if (lower > best_lower) {
      best_lower = lower;
      best_src = src;
      best_conf = conf;
      best_uses_pfn = rungs[r].add_vmemmap_size && pfn_src != 0;
    }
  }

  if (best_src == 0)
    return 0;

  struct constraint *c = &out[0];
  memset(c, 0, sizeof(*c));
  c->q = Q_VIRT_IMAGE_BASE;
  c->op = C_LOWER_BOUND;
  c->value = best_lower;
  c->conf = (best_uses_pfn && pfn_conf < best_conf) ? pfn_conf : best_conf;
  c->derived_from[0] = best_src;
  c->lineage_count = 1;
  if (best_uses_pfn) {
    c->derived_from[c->lineage_count++] = pfn_src;
    /* The VMEMMAP rung's floor scales with sizeof(struct page); when that came
     * from BTF, record it as a contributor and bound conf by it. */
    if (sp_src != 0) {
      c->derived_from[c->lineage_count++] = sp_src;
      if (sp_conf < c->conf)
        c->conf = sp_conf;
    }
  }
  snprintf(c->origin, ORIGIN_LEN, "s390_text_from_belows");
  return 1;
#else
  (void)ev;
  (void)out;
  (void)out_max;
  return 0;
#endif
}
