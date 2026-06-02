// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: riscv64 VMALLOC / VMEMMAP observation → Q_PAGE_OFFSET lower bound.
//
// riscv64's vmalloc area abuts PAGE_OFFSET from below with **zero gap**
// (arch/riscv/include/asm/pgtable.h):
//
//   VMALLOC_END   = PAGE_OFFSET
//   VMALLOC_START = PAGE_OFFSET - VMALLOC_SIZE
//   VMEMMAP_END   = VMALLOC_START
//   VMEMMAP_START = VMALLOC_START - VMEMMAP_SIZE
//
// Two soundness-grade lower bounds on PAGE_OFFSET fall out:
//
//   - V_va < VMALLOC_END = PAGE_OFFSET → PAGE_OFFSET ≥ V_va + 1
//     (no paging-mode dependency; always sound from a single VMALLOC leak).
//
//   - V_mm < VMEMMAP_END = PAGE_OFFSET − VMALLOC_SIZE
//                       → PAGE_OFFSET ≥ V_mm + VMALLOC_SIZE + 1
//     VMALLOC_SIZE = KERN_VIRT_SIZE >> 1 and KERN_VIRT_SIZE = −PAGE_OFFSET, so
//     each paging mode has a fixed VMALLOC_SIZE: ~80 GiB (SV39), ~44 TiB
//     (SV48), ~22 PiB (SV57). riscv64 carries the paging mode in
//     Q_PAGE_OFFSET (one discrete value per mode; the arch header does not
//     define VA_BITS_CANDIDATES, so Q_VA_BITS is single-candidate and not the
//     discriminator). The VMEMMAP branch reads Q_PAGE_OFFSET's current window
//     and picks the SMALLEST plausible VMALLOC_SIZE — sound under any
//     remaining mode ambiguity, since undersizing only loosens the derived
//     lower bound (oversizing would push it past the true PAGE_OFFSET).
//
// Tightens Q_PAGE_OFFSET from a different direction than
// directmap_page_offset_bounds (which gives PAGE_OFFSET ≤ V_directmap); the
// two together can pin PAGE_OFFSET exactly inside the SV39 512 MiB window
// when mixed-region leaks land.
//
// Currently DORMANT — no production riscv64 component emits VIRT/VMALLOC or
// VIRT/VMEMMAP observations today. Tracked in the LIVE-SYSTEM TEST LIST.
// riscv64 only.
// ---
// <bcoles@gmail.com>

#include "../include/kasld/engine_rules.h"

#include <limits.h>
#include <string.h>

#if (defined(__riscv) || defined(__riscv__)) && __riscv_xlen == 64

/* VMALLOC_SIZE per paging mode, derived from PAGE_OFFSET as
 * (-PAGE_OFFSET) >> 1. Values match riscv64.h's PAGE_OFFSET_L3/4/5 set. */
#define RISCV64_VMALLOC_SIZE_SV39                                              \
  0x1400000000ul /* (0x2800000000) >> 1 = 80 GiB  */
#define RISCV64_VMALLOC_SIZE_SV48                                              \
  0x2840000000000ul /* (0x5080000000000) >> 1 = ~44 TiB */
#define RISCV64_VMALLOC_SIZE_SV57                                              \
  0x50000000000000ul /* (0xa0000000000000) >> 1 = ~22 PiB */

/* riscv64 PAGE_OFFSET sentinels per paging mode (arch/riscv/include/asm/page.h
 * PAGE_OFFSET_L3/L4/L5). SV39 has TWO possible values (the v6.12 layout shift
 * narrowed the window from 168 GiB to 160 GiB); the window between LO and HI
 * defines the "SV39 region". */
#define RISCV64_PAGE_OFFSET_SV39_LO 0xffffffd600000000ul /* v6.12+ */
#define RISCV64_PAGE_OFFSET_SV39_HI 0xffffffd800000000ul /* v5.10..v6.10 */
#define RISCV64_PAGE_OFFSET_SV48 0xffffaf8000000000ul
#define RISCV64_PAGE_OFFSET_SV57 0xff60000000000000ul

/* Pick the smallest VMALLOC_SIZE consistent with Q_PAGE_OFFSET's window
 * [po_lo, po_hi]. Soundness rule: undersizing VMALLOC_SIZE only loosens the
 * derived lower bound on PAGE_OFFSET (sound under any mode ambiguity);
 * oversizing it would push the bound above the true PAGE_OFFSET (unsound).
 * We therefore use the SMALLEST VMALLOC_SIZE among modes whose
 * PAGE_OFFSET window still overlaps Q_PAGE_OFFSET — SV39 (80 GiB) when
 * possible, else SV48, else SV57. Returns 0 when no known mode is plausible. */
static unsigned long riscv64_vmalloc_size_from_po(unsigned long po_lo,
                                                  unsigned long po_hi) {
  if (po_lo <= RISCV64_PAGE_OFFSET_SV39_HI &&
      po_hi >= RISCV64_PAGE_OFFSET_SV39_LO)
    return RISCV64_VMALLOC_SIZE_SV39;
  if (po_lo <= RISCV64_PAGE_OFFSET_SV48 && po_hi >= RISCV64_PAGE_OFFSET_SV48)
    return RISCV64_VMALLOC_SIZE_SV48;
  if (po_lo <= RISCV64_PAGE_OFFSET_SV57 && po_hi >= RISCV64_PAGE_OFFSET_SV57)
    return RISCV64_VMALLOC_SIZE_SV57;
  return 0;
}

#endif

int rule_riscv64_page_offset_from_vmalloc_vmemmap(const struct evidence_set *ev,
                                                  const struct estimate *est,
                                                  struct constraint *out,
                                                  int out_max) {
#if (defined(__riscv) || defined(__riscv__)) && __riscv_xlen == 64
  if (out_max < 1)
    return 0;

  /* Lowest VMALLOC / VMEMMAP observation. */
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

  int n = 0;

  /* VMALLOC branch — no paging-mode dependency. */
  if (va != ULONG_MAX && va < ULONG_MAX && n < out_max) {
    struct constraint *c = &out[n++];
    memset(c, 0, sizeof(*c));
    c->q = Q_PAGE_OFFSET;
    c->op = C_LOWER_BOUND;
    c->value = va + 1ul;
    c->conf = va_conf;
    c->derived_from[0] = va_src;
    c->lineage_count = 1;
    snprintf(c->origin, ORIGIN_LEN, "riscv64_page_offset_from_vmalloc_vmemmap");
  }

  /* VMEMMAP branch — needs VMALLOC_SIZE, which depends on the paging mode.
   *
   * On riscv64 the paging mode lives in Q_PAGE_OFFSET (one discrete value per
   * mode; arch headers do not define VA_BITS_CANDIDATES, so Q_VA_BITS is a
   * single-candidate FINSET and not the discriminator here). We read the
   * current Q_PAGE_OFFSET window and pick the SMALLEST VMALLOC_SIZE among
   * still-plausible modes — sound under any remaining ambiguity (see
   * riscv64_vmalloc_size_from_po). */
  if (mm != ULONG_MAX && n < out_max) {
    const struct estimate *po = &est[Q_PAGE_OFFSET];
    unsigned long vmalloc_size = riscv64_vmalloc_size_from_po(po->lo, po->hi);
    if (vmalloc_size != 0 && mm <= ULONG_MAX - vmalloc_size - 1ul) {
      struct constraint *c = &out[n++];
      memset(c, 0, sizeof(*c));
      c->q = Q_PAGE_OFFSET;
      c->op = C_LOWER_BOUND;
      c->value = mm + vmalloc_size + 1ul;
      c->conf = mm_conf;
      c->derived_from[0] = mm_src;
      c->lineage_count = 1;
      snprintf(c->origin, ORIGIN_LEN,
               "riscv64_page_offset_from_vmalloc_vmemmap");
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
