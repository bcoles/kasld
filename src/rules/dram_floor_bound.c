// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: DRAM floor propagation.
//
// The kernel is loaded into physical RAM, so the lowest physical address
// at which any RAM exists is a lower bound on where the kernel text can
// sit. Both coupling models are handled:
//
//   Decoupled (x86-64, arm64, riscv64, s390): the RAM floor, rounded UP
//   to a slot, is a direct floor on the physical base — C_LOWER_BOUND on
//   Q_PHYS_TEXT_BASE.
//
//   Coupled (x86-32, MIPS, PPC32 BookE, LoongArch): phys_to_directmap_virt()
//   links DRAM to virtual text, so the floor maps (via the compile-time
//   PAGE_OFFSET / PHYS_OFFSET / TEXT_OFFSET — not a runtime-detected value,
//   so no Q_PAGE_OFFSET dependency) to a virtual floor, rounded DOWN to
//   stay conservative — C_LOWER_BOUND on Q_VIRT_TEXT_BASE.
//
// IMPORTANT: only POS_BASE observations on REGION_RAM count as the floor.
// An earlier version of this rule walked every region in the "dram" section
// and took the min — but observations like REGION_INITRD / REGION_CRASHKERNEL
// / REGION_VMCOREINFO / REGION_RESERVED_MEM merely indicate that DRAM *exists
// at that address*; they say nothing about how far below them DRAM extends.
// Treating them as a floor wrongly excluded layouts where the kernel sits
// below the initrd (ppc64le routinely loads text at phys 0 with the initrd
// at e.g. 0x2c90000). REGION_RAM with POS_BASE is the canonical "physical
// RAM starts here" marker that components like proc_zoneinfo /
// sysfs_devicetree_memory emit; that is what we consume.
//
// Only the floor is touched: an incomplete DRAM sample cannot rule out
// upper slots.
// ---
// <bcoles@gmail.com>

#include "../include/kasld/engine_rules.h"
#include "../include/kasld/regions.h"

#include <limits.h>
#include <string.h>

int rule_dram_floor_bound(const struct evidence_set *ev,
                          const struct estimate *est, struct constraint *out,
                          int out_max) {
  (void)est;
  if (out_max < 1)
    return 0;

  unsigned long pdram_lo = ULONG_MAX;
  enum kasld_confidence conf = CONF_PARSED;
  uint32_t src = 0;
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->value_kind != OBS_ADDRESS)
      continue;
    if (o->eff_type != KASLD_TYPE_PHYS)
      continue;
    /* Only REGION_RAM with POS_BASE represents the true low edge of DRAM;
     * see the header comment for why other dram-section regions are not
     * sound floors. */
    if (o->eff_region != REGION_RAM || o->pos != POS_BASE)
      continue;
    unsigned long a = obs_anchor(o);
    if (a < pdram_lo) {
      pdram_lo = a;
      conf = o->conf;
      src = o->id;
    }
  }
  if (pdram_lo == ULONG_MAX)
    return 0;

  struct constraint *c = &out[0];
  memset(c, 0, sizeof(*c));
  c->op = C_LOWER_BOUND;
  c->conf = conf;
  c->derived_from[0] = src;
  c->lineage_count = 1;
  snprintf(c->origin, ORIGIN_LEN, "dram_floor_bound");

#if !TEXT_TRACKS_DIRECTMAP
  /* Floor on the physical base: round UP to a slot (base must be slot-aligned
   * and >= pdram_lo). */
  unsigned long floor = pdram_lo;
  if (KASLR_PHYS_ALIGN > 0)
    floor = (floor + KASLR_PHYS_ALIGN - 1) & ~(KASLR_PHYS_ALIGN - 1);
  if (floor <= KASLR_PHYS_MIN)
    return 0;
  c->q = Q_PHYS_TEXT_BASE;
  c->value = floor;
  return 1;
#else
  /* Coupled: map to a virtual floor via the compile-time conversion, round
   * DOWN to a slot to stay a guaranteed lower bound. */
  if (pdram_lo < PHYS_OFFSET)
    return 0;
  unsigned long virt_lo = pdram_lo - PHYS_OFFSET + PAGE_OFFSET + TEXT_OFFSET;
  if (KASLR_VIRT_ALIGN > 0)
    virt_lo &= ~(KASLR_VIRT_ALIGN - 1);
  if (virt_lo <= KASLR_VIRT_TEXT_MIN)
    return 0;
  c->q = Q_VIRT_TEXT_BASE;
  c->value = virt_lo;
  return 1;
#endif
}
