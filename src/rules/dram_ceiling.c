// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: top-of-RAM ceiling (coupled arches).
//
// The kernel image must fit below the
// top of physical RAM, so on a coupled arch the highest observed RAM address
// caps the virtual text base:
//
//   phys_ceiling = dram_top - kernel_size
//   virt_ceiling = (phys_ceiling - PHYS_OFFSET) + PAGE_OFFSET_runtime
//                  + TEXT_OFFSET                (aligned down)
//
// Cross-quantity (reads the engine's resolved Q_PAGE_OFFSET) like
// virt_ceiling_from_memtotal, so it fires only once virt_page_offset is pinned.
// As a pure rule it takes kernel_size from the SF_IMAGE_SIZE observation
// (emitted by the bridge / a component), never by reading /boot itself.
// dram_top is the max `hi` of any RAM-region address observation.
//
// Decoupled arches: inert (the physical ceilings cover that case directly).
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"
#include "include/kasld/regions.h"

#include <string.h>

#define MIN_IMAGE_SIZE (4UL * 1024 * 1024)

int rule_dram_ceiling(const struct evidence_set *ev, const struct estimate *est,
                      struct constraint *out, int out_max) {
#if !TEXT_TRACKS_DIRECTMAP
  (void)ev;
  (void)est;
  (void)out;
  (void)out_max;
  return 0;
#else
  if (out_max < 1)
    return 0;

  const struct estimate *po = &est[Q_PAGE_OFFSET];
  if (po->lo != po->hi)
    return 0; /* virt_page_offset not yet pinned */
  unsigned long virt_page_offset = po->lo;

  unsigned long kernel_size = 0, dram_top = 0;
  enum kasld_confidence kconf = CONF_UNKNOWN, tconf = CONF_PARSED;
  uint32_t ksrc = 0, tsrc = 0;
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid)
      continue;
    if (o->value_kind == OBS_SCALAR && o->scalar_fact == SF_IMAGE_SIZE) {
      kernel_size = o->scalar_value;
      kconf = o->conf;
      ksrc = o->id;
    } else if (o->value_kind == OBS_ADDRESS && o->eff_type == KASLD_TYPE_PHYS &&
               o->eff_region == REGION_RAM && HAS_HI(o)) {
      if (o->hi > dram_top) {
        dram_top = o->hi;
        tconf = o->conf;
        tsrc = o->id;
      }
    }
  }

  if (kernel_size == 0 || kernel_size < MIN_IMAGE_SIZE || dram_top == 0)
    return 0;
  if (dram_top <= PHYS_OFFSET || dram_top - PHYS_OFFSET <= kernel_size)
    return 0;

  unsigned long phys_ceiling = dram_top - kernel_size;
  unsigned long ceiling =
      (phys_ceiling - PHYS_OFFSET) + virt_page_offset + TEXT_OFFSET;
  if (KASLR_VIRT_ALIGN > 0)
    ceiling &= ~(KASLR_VIRT_ALIGN - 1);
  if (ceiling <= KASLR_VIRT_TEXT_MIN)
    return 0;

  struct constraint *c = &out[0];
  memset(c, 0, sizeof(*c));
  c->q = Q_VIRT_TEXT_BASE;
  c->op = C_UPPER_BOUND;
  c->value = ceiling;
  c->conf = (kconf < tconf) ? kconf : tconf;
  c->derived_from[0] = ksrc;
  c->lineage_count = 1;
  if (tsrc) {
    c->derived_from[1] = tsrc;
    c->lineage_count = 2;
  }
  snprintf(c->origin, ORIGIN_LEN, "dram_ceiling");
  return 1;
#endif
}
