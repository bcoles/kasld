// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: physical KASLR ceiling from DRAM extent (decoupled arches).
//
// The kernel image must fit entirely within physical RAM. The cleanest
// statement of that on a decoupled arch is:
//
//   phys_image_base <= dram_top - kernel_size
//
// where dram_top is the highest spanned-RAM physical address observed
// from the system's memory map (REGION_RAM POS_TOP — emitted by
// proc_zoneinfo from zone start_pfn + spanned, etc.).
//
// Fallback to MemTotal when no REGION_RAM extent is observed:
//
//   phys_image_base <= phys_floor + MemTotal - min_image
//
// The MemTotal fallback is sound ONLY when DRAM is contiguous from
// phys_floor (no large reserved regions between phys_floor and the
// kernel). Hosts with large reservations inside the DRAM span (e.g.
// arm64 EFI systems where firmware reserves >1 GiB for crashkernel,
// EFI runtime services, DMA pools, etc.) have MemTotal substantially
// below the spanned DRAM extent, and the MemTotal-based ceiling can
// exclude the kernel's true position. dram_top sidesteps this by
// using the spanned extent, which is what bounds kernel placement.
// So the two emissions carry different confidence: the dram_top ceiling
// is a fact (observation confidence, reaches the guaranteed window); the
// MemTotal fallback is a contiguity convention (CONF_HEURISTIC, likely
// window only).
//
// The coupled-arch virtual ceiling from MemTotal is handled separately
// by virt_ceiling_from_memtotal, which maps through the resolved
// Q_PAGE_OFFSET.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"
#include "include/kasld/regions.h"

#include <limits.h>
#include <string.h>

int rule_phys_ceiling_from_memtotal(const struct evidence_set *ev,
                                    const struct estimate *est,
                                    struct constraint *out, int out_max) {
#if TEXT_TRACKS_DIRECTMAP
  (void)est;
  (void)ev;
  (void)out;
  (void)out_max;
  return 0; /* coupled arches: deferred (see file header) */
#else
  unsigned long memtotal = 0, phys_floor = ULONG_MAX, dram_top = 0;
  enum kasld_confidence mconf = CONF_UNKNOWN, fconf = CONF_PARSED;
  enum kasld_confidence tconf = CONF_UNKNOWN;
  uint32_t msrc = 0, fsrc = 0, tsrc = 0;
  const unsigned long min_image = evidence_image_size_min_or_floor(ev);

  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid)
      continue;
    if (o->value_kind == OBS_SCALAR && o->scalar_fact == SF_PHYS_MEMTOTAL) {
      memtotal = o->scalar_value;
      mconf = o->conf;
      msrc = o->id;
    } else if (o->value_kind == OBS_ADDRESS && o->eff_type == KASLD_TYPE_PHYS &&
               is_phys_dram_region(o->eff_region)) {
      unsigned long a = obs_anchor(o);
      if (a < phys_floor) {
        phys_floor = a;
        fconf = o->conf;
        fsrc = o->id;
      }
      /* dram_top: highest hi we see from any REGION_RAM observation that
       * carries an extent. POS_BASE observations on REGION_RAM (from
       * proc_zoneinfo's start_pfn) provide phys_floor only; POS_TOP
       * observations provide hi only — both are needed for the span. */
      if (o->eff_region == REGION_RAM && HAS_HI(o) && o->hi > dram_top) {
        dram_top = o->hi;
        tconf = o->conf;
        tsrc = o->id;
      }
    }
  }

  unsigned long ceiling;
  uint32_t src_a = 0, src_b = 0;
  enum kasld_confidence cconf;

  if (dram_top != 0) {
    /* Preferred path: spanned DRAM extent. Sound regardless of reserved
     * regions inside DRAM (kernel can be placed anywhere up to dram_top
     * minus its own size). */
    if (dram_top <= min_image)
      return 0;
    ceiling = dram_top - min_image + 1; /* hi is inclusive */
    src_a = tsrc;
    cconf = tconf;
  } else {
    /* Fallback: MemTotal-based. Better than nothing on low-priv runs that
     * cannot read zoneinfo / iomem. MemTotal counts USABLE pages, so
     * phys_floor + MemTotal under-counts the spanned extent whenever holes or
     * reserved regions sit inside the DRAM span (arm64 EFI crashkernel /
     * runtime services / DMA pools) — the ceiling can then fall BELOW the true
     * base. So it is a convention, not a fact: capped at CONF_HEURISTIC so it
     * shapes the LIKELY window only, never the guaranteed one (the sound
     * dram_top path above keeps observation confidence). */
    if (memtotal == 0 || memtotal <= min_image)
      return 0;
    if (phys_floor == ULONG_MAX)
      phys_floor = PHYS_OFFSET; /* no observed DRAM: compile-time fallback */
    /* Wrap guard, mirroring virt_ceiling_from_memtotal: a phys floor plus a
     * spanned total that runs past the top of the address space (32-bit PAE)
     * yields no sound ceiling. */
    if (memtotal > ULONG_MAX - phys_floor)
      return 0;
    ceiling = phys_floor + memtotal - min_image;
    src_a = msrc;
    src_b = fsrc;
    cconf = kasld_conf_min(CONF_HEURISTIC, (mconf < fconf) ? mconf : fconf);
  }
  /* Align to the RESOLVED Q_PHYS_KASLR_ALIGN (>= compile-time
   * KASLR_PHYS_ALIGN), which boot_params_kaslr_align raises to the actual
   * CONFIG_PHYSICAL_ALIGN. */
  unsigned long palign = est[Q_PHYS_KASLR_ALIGN].lo;
  if (palign < (unsigned long)KASLR_PHYS_ALIGN)
    palign = (unsigned long)KASLR_PHYS_ALIGN;
  if (palign > 0)
    ceiling &= ~(palign - 1);
  if (ceiling <= KASLR_PHYS_MIN || out_max < 1)
    return 0;

  struct constraint *c = &out[0];
  memset(c, 0, sizeof(*c));
  c->q = Q_PHYS_IMAGE_BASE;
  c->op = C_UPPER_BOUND;
  c->value = ceiling;
  c->conf = cconf;
  c->derived_from[0] = src_a;
  c->lineage_count = 1;
  if (src_b) {
    c->derived_from[1] = src_b;
    c->lineage_count = 2;
  }
  snprintf(c->origin, ORIGIN_LEN, "phys_ceiling_from_memtotal");
  return 1;
#endif
}
