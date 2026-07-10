// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: ppc32 physical KASLR ceiling / KASLR-disabled pin.
//
// Models the BookE KASLR scheme (arch/powerpc/kernel/kaslr_booke.c): the base
// is drawn from [0, min(MemTotal, 512 MiB)) in 64 MiB steps, and with < 64 MiB
// RAM the slot count is 0 so the kernel loads at the compile-time default.
//
//   MemTotal < 64 MiB : virt_image_base == KERNEL_VIRT_TEXT_DEFAULT  (KASLR
//   off) else              : virt_image_base <= KASLR_VIRT_TEXT_MIN +
//   min(MemTotal,512M)
//                                          - min_image  (aligned)
//
// SCOPE: the guard matches every 32-bit PowerPC (BookE *and* BookS) because
// BookE-vs-BookS is a runtime property, not a compile-time one — a pure rule
// cannot distinguish them without a cpuinfo-derived fact. On BookS (no BookE
// KASLR scheme) the ceiling is loose-but-sound: an unrandomized kernel sits at
// KERNEL_VIRT_TEXT_DEFAULT, which is <= this ceiling. (The < 64 MiB pin assumes
// the BookE no-randomization case; a BookS server with < 64 MiB RAM is
// implausible.)
//
// RAM size prefers SF_PHYS_MAX_PFN (host-true zoneinfo, at CONF_INFERRED) over
// SF_PHYS_MEMTOTAL (/proc/meminfo — container-fakeable, so used only as a
// CONF_HEURISTIC fallback): a container reporting a faked-small MemTotal must
// not drive the sub-64 MiB "KASLR off" pin or the ceiling in the guaranteed
// window. PAGE_OFFSET is fixed on PPC32 (no VMSPLIT), so the coupled mapping
// uses KASLR_VIRT_TEXT_MIN directly. ppc32 only.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"

#include <string.h>

#define BOOKE_KASLR_MIN_RAM (64ul * 1024 * 1024)
#define BOOKE_PHYS_KASLR_MAX (512ul * 1024 * 1024)

int rule_ppc32_phys_ceiling(const struct evidence_set *ev,
                            const struct estimate *est, struct constraint *out,
                            int out_max) {
  (void)est;
#if defined(__powerpc__) && !defined(__powerpc64__)
  if (out_max < 1)
    return 0;

  unsigned long mem = 0, max_pfn = 0, page_size = 0;
  uint32_t mem_src = 0, pfn_src = 0;
  const unsigned long min_image = evidence_image_size_min_or_floor(ev);
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->value_kind != OBS_SCALAR)
      continue;
    switch (o->scalar_fact) {
    case SF_PHYS_MEMTOTAL:
      mem = o->scalar_value;
      mem_src = o->id;
      break;
    case SF_PHYS_MAX_PFN:
      max_pfn = o->scalar_value;
      pfn_src = o->id;
      break;
    case SF_PAGE_SIZE:
      page_size = o->scalar_value;
      break;
    default:
      break;
    }
  }
  if (page_size == 0)
    page_size = 0x1000ul;

  /* RAM size for the BookE decision. Prefer max_pfn (host-true zoneinfo, and
   * the spanned extent the kernel's own KASLR actually measures) at the sound
   * floor; fall back to MemTotal (/proc/meminfo — container-fakeable: lxcfs
   * reports the cgroup limit, not host RAM) BELOW the floor, so a faked value
   * shapes the likely window only, never the guaranteed KASLR-off pin or the
   * ceiling. */
  unsigned long ram = 0;
  uint32_t src = 0;
  int from_max_pfn = 0;
  if (max_pfn > 0 && max_pfn < (~0ul / page_size)) {
    ram = (max_pfn + 1ul) * page_size;
    src = pfn_src;
    from_max_pfn = 1;
  } else if (mem > 0) {
    ram = mem;
    src = mem_src;
  }
  if (ram == 0)
    return 0;

  struct constraint *c = &out[0];
  memset(c, 0, sizeof(*c));
  if (from_max_pfn)
    c->conf = CONF_INFERRED;
  else
    c->conf =
        CONF_HEURISTIC; /* MemTotal-only: container-fakeable, likely-only */
  c->derived_from[0] = src;
  c->lineage_count = src ? 1 : 0;
  snprintf(c->origin, ORIGIN_LEN, "ppc32_phys_ceiling");

  if (ram < BOOKE_KASLR_MIN_RAM) {
    /* Too little RAM for the BookE KASLR scheme: the kernel loads at the
     * compile-time default. */
    c->q = Q_VIRT_IMAGE_BASE;
    c->op = C_EQUALS;
    c->value = (unsigned long)KERNEL_VIRT_TEXT_DEFAULT;
    return 1;
  }

  unsigned long cap = ram < BOOKE_PHYS_KASLR_MAX ? ram : BOOKE_PHYS_KASLR_MAX;
  if (cap <= min_image)
    return 0;
  unsigned long ceiling = (unsigned long)KASLR_VIRT_TEXT_MIN + cap - min_image;
  ceiling =
      kasld_floor_virt_text_bound(ceiling, (unsigned long)KASLR_VIRT_ALIGN);
  if (ceiling <= (unsigned long)KASLR_VIRT_TEXT_MIN)
    return 0;
  c->q = Q_VIRT_IMAGE_BASE;
  c->op = C_UPPER_BOUND;
  c->value = ceiling;
  return 1;
#else
  (void)ev;
  (void)out;
  (void)out_max;
  return 0;
#endif
}
