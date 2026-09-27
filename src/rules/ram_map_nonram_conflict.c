// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Verdict: invalidate a "never System RAM" observation that a System RAM map
// places inside System RAM.
//
// A PHYS observation tagged MMIO, PCI, persistent memory or an ACPI region
// asserts more than an address: it asserts the address is not System RAM
// (FORBIDDEN_NEVER_RAM). phys_reservation_exclude turns that assertion into a
// C_EXCLUDE on Q_PHYS_IMAGE_BASE, forbidding the base from the band whose
// image would overlap the extent. Where the assertion is false the band is
// carved out of real RAM, and a true base inside it is dropped from the
// guaranteed window — truth outside a window that claims to contain it.
//
// A RAM map contradicts the assertion directly:
//
//   for each FORBIDDEN_NEVER_RAM PHYS observation O:
//     drop O if some System RAM extent contains O's address
//
// The mirror of firmware_memmap_holes, which drops a kernel-base candidate
// NOT contained by System RAM. Both read the same coverings; they differ in
// which way containment condemns the observation.
//
// Regions the image cannot occupy for the OTHER reason —
// FORBIDDEN_RESERVED_FROM_RAM: crashkernel, SWIOTLB, reserved-memory pools —
// are deliberately not tested. Those are carved out of RAM by construction, so
// every correct one is inside a RAM extent and this test would invalidate the
// lot. The reason axis is what keeps the two apart.
//
// Soundness:
//   * Containment is tested against the EXTENTS of a single map, never a hull
//     across maps. RAM is not contiguous — the PCI hole below 4 GiB is on every
//     x86 machine — so a hull test would report every device window as "inside
//     RAM" and invalidate all of them.
//   * Only coverings are read, never observations. A covering is a complete
//     single-source map (the pos=extent contract); a RAM observation may be a
//     hull bound or an interior sample, and neither establishes membership.
//   * Both error directions widen. The only consumers of these observations —
//     phys_reservation_exclude and mmio_floor_phys_ceiling — narrow, so a
//     wrongly dropped observation loses a constraint and can never move truth
//     out of a window. That is why a block-coarse map (hotplug memory blocks
//     round a partly populated block up to the whole block) is read alongside
//     the byte-exact ones: at worst it costs a constraint.
//   * Nothing user-visible is lost. Verdicts are engine-internal; the leak is
//     still reported from the captured results, so a component that found a
//     real address still gets credit for it.
//
// Consumes ev->coverings[]; V_INVALID. Arch-general: coverings come from the
// x86 E820 views, device-tree /memory nodes and hotplug blocks alike. Inert
// without a map, and inert on coupled arches in effect, since both consumers
// of what it drops are themselves inert there.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"
#include "include/kasld/regions.h"

#include <string.h>

int rule_ram_map_nonram_conflict(const struct evidence_set *ev,
                                 struct verdict *out, int out_max) {
  int n = 0;
  for (int i = 0; i < ev->n_obs && n < out_max; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->value_kind != OBS_ADDRESS ||
        o->eff_type != KASLD_TYPE_PHYS)
      continue;
    if (phys_kernel_forbidden_reason(o->eff_region) != FORBIDDEN_NEVER_RAM)
      continue;
    unsigned long a = obs_anchor(o);
    if (a == 0)
      continue;

    /* Does some System RAM extent contain the address? One extent is enough:
     * the claim being falsified is about this address alone, so no map needs
     * to be complete for the contradiction to hold. */
    int in_ram = 0;
    for (int j = 0; j < ev->n_coverings && !in_ram; j++) {
      const struct covering *m = &ev->coverings[j];
      if (!covering_active(m) || m->type != KASLD_TYPE_PHYS ||
          m->region != REGION_RAM)
        continue;
      if (a >= m->lo && a <= m->hi)
        in_ram = 1;
    }
    if (!in_ram)
      continue;

    struct verdict *v = &out[n++];
    memset(v, 0, sizeof(*v));
    v->observation_id = o->id;
    v->kind = V_INVALID;
    snprintf(v->origin, ORIGIN_LEN, "ram_map_nonram_conflict");
  }
  return n;
}
