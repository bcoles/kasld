// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: 32-bit highmem lowmem ceiling (coupled arches).
//
// On a 32-bit CONFIG_HIGHMEM
// kernel the image must reside in lowmem (the linearly mapped ZONE_NORMAL), so
// the physical base is bounded by LowTotal, not MemTotal. Mapped to a virtual
// ceiling on a coupled arch:
//
//   virt_ceiling = PAGE_OFFSET_runtime + LowTotal - MIN_IMAGE_SIZE +
//   TEXT_OFFSET
//
// Cross-quantity (uses the engine's resolved Q_PAGE_OFFSET), so it fires only
// once virt_page_offset is pinned. Reads SF_PHYS_LOWMEM, which the bridge emits
// only when highmem is actually present (HighTotal > 0); without highmem
// LowTotal == MemTotal and the MemTotal ceiling already suffices, so the bridge
// emits nothing and this is a no-op. 64-bit / decoupled: inert.
// ---
// <bcoles@gmail.com>

#include "../include/kasld/engine_rules.h"

#include <string.h>

#define MIN_IMAGE_SIZE (4UL * 1024 * 1024)

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
  if (lowmem <= MIN_IMAGE_SIZE || lowmem > ULONG_MAX - virt_page_offset)
    return 0;

  unsigned long ceiling =
      virt_page_offset + lowmem - MIN_IMAGE_SIZE + TEXT_OFFSET;
  if (KASLR_VIRT_ALIGN > 0)
    ceiling &= ~(KASLR_VIRT_ALIGN - 1);
  if (ceiling <= KASLR_VIRT_TEXT_MIN)
    return 0;

  struct constraint *c = &out[0];
  memset(c, 0, sizeof(*c));
  c->q = Q_VIRT_TEXT_BASE;
  c->op = C_UPPER_BOUND;
  c->value = ceiling;
  c->conf = conf;
  c->derived_from[0] = src;
  c->lineage_count = 1;
  snprintf(c->origin, ORIGIN_LEN, "highmem_32bit_bound");
  return 1;
#endif
}
