// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: 32-bit highmem lowmem ceiling (coupled arches).
//
// On a 32-bit CONFIG_HIGHMEM
// kernel the image must reside in lowmem (the linearly mapped ZONE_NORMAL), so
// the physical base is bounded by LowTotal, not MemTotal. Mapped to a virtual
// ceiling on a coupled arch:
//
//   virt_ceiling = PAGE_OFFSET_runtime + LowTotal - min_image +
//   IMAGE_BASE_OFFSET
//
// Cross-quantity (uses the engine's resolved Q_PAGE_OFFSET), so it fires only
// once virt_page_offset is pinned. Reads SF_PHYS_LOWMEM, which the bridge emits
// only when highmem is actually present (HighTotal > 0); without highmem
// LowTotal == MemTotal and the MemTotal ceiling already suffices, so the bridge
// emits nothing and this is a no-op. 64-bit / decoupled: inert.
//
// SF_PHYS_LOWMEM comes from /proc/meminfo LowTotal, which is virtualisable
// inside a container / cgroup (lxcfs reports the cgroup limit, not host RAM) —
// a faked-small LowTotal would drop this ceiling below the true base. Unlike
// the MemTotal ceilings there is no non-fakeable substitute wired up today
// (zoneinfo's REGION_RAM extent spans ALL RAM, highmem included, so it does not
// bound lowmem), so the bound is capped at CONF_HEURISTIC: it shapes the LIKELY
// window only, never the guaranteed one. The non-fakeable signal that could
// restore a sound guaranteed ceiling is the lowmem/highmem boundary
// (max_low_pfn) from zoneinfo — the ZONE_HIGHMEM start, i.e. the top of the
// highest non-highmem zone — NOT a "ZONE_NORMAL top": ZONE_NORMAL is commonly
// empty on ARM (lowmem sits in ZONE_DMA), so keying on it finds nothing.
// Extracting that boundary needs per-zone-name parsing in proc_zoneinfo (future
// work); until then soundness beats the lost precision on a genuine 32-bit
// highmem host. On typical VMSPLIT configs high_memory already sits at ~the
// arch KERNEL_VIRT_TEXT_MAX, so the gain is real only on small-lowmem boards.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"

#include <string.h>

int rule_highmem_32bit_bound(const struct evidence_set *ev,
                             const struct estimate *est, struct constraint *out,
                             int out_max) {
#if !TEXT_TRACKS_DIRECTMAP
  (void)ev;
  (void)est;
  (void)out;
  (void)out_max;
  return 0;
#else
  if (out_max < 1 || sizeof(unsigned long) != 4)
    return 0; /* meaningful only on 32-bit coupled arches */

  const struct estimate *po = &est[Q_PAGE_OFFSET];
  if (po->lo != po->hi)
    return 0; /* virt_page_offset not yet pinned */
  unsigned long virt_page_offset = po->lo;

  unsigned long lowmem = 0;
  enum kasld_confidence conf = CONF_UNKNOWN;
  uint32_t src = 0;
  const unsigned long min_image = evidence_image_size_min_or_floor(ev);
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (o->valid && o->value_kind == OBS_SCALAR &&
        o->scalar_fact == SF_PHYS_LOWMEM) {
      lowmem = o->scalar_value;
      conf = o->conf;
      src = o->id;
      break;
    }
  }
  if (lowmem <= min_image || lowmem > ULONG_MAX - virt_page_offset)
    return 0;

  unsigned long ceiling =
      virt_page_offset + lowmem - min_image + IMAGE_BASE_OFFSET;
  ceiling =
      kasld_floor_virt_text_bound(ceiling, (unsigned long)KASLR_VIRT_ALIGN);
  if (ceiling <= KASLR_VIRT_TEXT_MIN)
    return 0;

  struct constraint *c = &out[0];
  memset(c, 0, sizeof(*c));
  c->q = Q_VIRT_IMAGE_BASE;
  c->op = C_UPPER_BOUND;
  c->value = ceiling;
  /* LowTotal is /proc/meminfo-sourced (container-fakeable); keep it below the
   * sound floor so it never reaches the guaranteed window. */
  c->conf = kasld_conf_min(CONF_HEURISTIC, conf);
  c->derived_from[0] = src;
  c->lineage_count = 1;
  snprintf(c->origin, ORIGIN_LEN, "highmem_32bit_bound");
  return 1;
#endif
}
