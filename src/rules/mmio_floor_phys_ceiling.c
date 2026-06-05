// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: physical text ceiling from the lowest MMIO window above DRAM.
//
// On a decoupled arch the
// kernel image must fit entirely in DRAM, so the physical base cannot reach the
// lowest MMIO window that sits above DRAM:
//
//   phys_text_base <= (lowest MMIO lo strictly above the highest DRAM lo) - 1
//
// Reads leaked PHYS observations (DRAM landmarks + MMIO windows). Emits a
// C_UPPER_BOUND on Q_PHYS_TEXT_BASE. Inert on coupled arches and when no
// DRAM/MMIO pair is observed.
// ---
// <bcoles@gmail.com>

#include "../include/kasld/engine_rules.h"
#include "../include/kasld/regions.h"

#include <limits.h>
#include <string.h>

int rule_mmio_floor_phys_ceiling(const struct evidence_set *ev,
                                 const struct estimate *est,
                                 struct constraint *out, int out_max) {
  (void)est;
#if !TEXT_TRACKS_DIRECTMAP
  if (out_max < 1)
    return 0;

  /* Highest DRAM lo: the lowest address that is definitely DRAM must be at
   * least this high for an MMIO window to count as "above DRAM". */
  unsigned long dram_floor = 0;
  int have_dram = 0;
  uint32_t dram_src = 0;
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->value_kind != OBS_ADDRESS)
      continue;
    if (o->eff_type != KASLD_TYPE_PHYS || !is_phys_dram_region(o->eff_region))
      continue;
    if (!HAS_LO(o))
      continue;
    if (!have_dram || o->lo > dram_floor) {
      dram_floor = o->lo;
      have_dram = 1;
      dram_src = o->id;
    }
  }
  if (!have_dram)
    return 0;

  /* Lowest MMIO lo strictly above dram_floor. */
  unsigned long mmio_floor = ULONG_MAX;
  int have_mmio = 0;
  uint32_t mmio_src = 0;
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->value_kind != OBS_ADDRESS)
      continue;
    if (o->eff_type != KASLD_TYPE_PHYS || !is_mmio_region(o->eff_region))
      continue;
    if (!HAS_LO(o) || o->lo <= dram_floor)
      continue;
    if (!have_mmio || o->lo < mmio_floor) {
      mmio_floor = o->lo;
      have_mmio = 1;
      mmio_src = o->id;
    }
  }
  if (!have_mmio)
    return 0;

  /* Underflow impossible: mmio_floor > dram_floor >= 0 => mmio_floor >= 1. */
  unsigned long ceiling = mmio_floor - 1;
  if (ceiling <= KASLR_PHYS_MIN)
    return 0;

  struct constraint *c = &out[0];
  memset(c, 0, sizeof(*c));
  c->q = Q_PHYS_TEXT_BASE;
  c->op = C_UPPER_BOUND;
  c->value = ceiling;
  c->conf = CONF_INFERRED;
  c->derived_from[0] = mmio_src;
  c->derived_from[1] = dram_src;
  c->lineage_count = 2;
  snprintf(c->origin, ORIGIN_LEN, "mmio_floor_phys_ceiling");
  return 1;
#else
  (void)ev;
  (void)out;
  (void)out_max;
  return 0;
#endif
}
