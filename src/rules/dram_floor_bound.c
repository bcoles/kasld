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
//   Q_PHYS_IMAGE_BASE.
//
//   Coupled (x86-32, MIPS, PPC32 BookE, LoongArch): nothing. The floor those
//   arches place on their text base is a consequence of the linear-map base and
//   the architecture's placement rule, not of where DRAM begins, so it belongs
//   to page_offset_text_floor — where it carries no observation lineage,
//   because no observation supports it.
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

#include "include/kasld/engine_rules.h"
#include "include/kasld/regions.h"

#include <limits.h>
#include <string.h>

int rule_dram_floor_bound(const struct evidence_set *ev,
                          const struct estimate *est, struct constraint *out,
                          int out_max) {
  (void)est;
  if (out_max < 1)
    return 0;

  /* Only REGION_RAM with POS_BASE represents the true low edge of DRAM; see the
   * header comment for why other dram-section regions are not sound floors.
   * That filter lives in evidence_lowest_dram_base(), which is also what the
   * two linear-map anchoring rules read, so all three cannot disagree about
   * where DRAM starts. */
  unsigned long pdram_lo = 0;
  enum kasld_confidence conf = CONF_PARSED;
  uint32_t src = 0;
  if (!evidence_lowest_dram_base(ev, &pdram_lo, &conf, &src))
    return 0;

#if !TEXT_TRACKS_DIRECTMAP
  /* Floor on the physical base: round UP to a slot (base must be slot-aligned
   * and >= pdram_lo). */
  unsigned long floor = pdram_lo;
  if (KASLR_PHYS_ALIGN > 0)
    floor = (floor + KASLR_PHYS_ALIGN - 1) & ~(KASLR_PHYS_ALIGN - 1);
  if (floor <= KASLR_PHYS_MIN)
    return 0;
  struct constraint *c = &out[0];
  memset(c, 0, sizeof(*c));
  c->op = C_LOWER_BOUND;
  c->conf = conf;
  c->derived_from[0] = src;
  c->lineage_count = 1;
  snprintf(c->origin, ORIGIN_LEN, "dram_floor_bound");
  c->q = Q_PHYS_IMAGE_BASE;
  c->value = floor;
  return 1;
#else
  /* Coupled arches emit nothing here. The floor their text base actually gets —
   * PAGE_OFFSET + IMAGE_BASE_OFFSET — follows from the resolved linear-map base
   * and the architecture's placement rule, not from where DRAM begins, so it
   * lives in page_offset_text_floor with no observation lineage. Deriving it
   * here would attribute it to the DRAM witness that did not establish it.
   *
   * The DRAM floor is still a fact about the PHYSICAL base on these arches; it
   * is not emitted only because nothing consumes a phys floor here today. */
  (void)conf;
  (void)src;
  (void)out;
  return 0;
#endif
}
