// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: ppc32 physical KASLR ceiling / KASLR-disabled pin.
//
// Models the BookE KASLR scheme (arch/powerpc/kernel/kaslr_booke.c): the base
// is drawn from [0, min(MemTotal, 512 MiB)) in 64 MiB steps, and with < 64 MiB
// RAM the slot count is 0 so the kernel loads at the compile-time default.
//
//   RAM < 64 MiB : virt_image_base in [PAGE_OFFSET + IMAGE_BASE_OFFSET] over
//                  the resolved PAGE_OFFSET window            (KASLR off)
//   else         : virt_image_base <= PAGE_OFFSET_hi + min(RAM, 512M)
//                                     - min_image             (aligned)
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
// not drive the sub-64 MiB "KASLR off" bounds or the ceiling in the guaranteed
// window. ppc32 only.
//
// CROSS-QUANTITY: both outputs are physical facts carried into virtual space by
// adding the linear-map base, so both read the resolved Q_PAGE_OFFSET rather
// than a compile-time address. An UPPER bound takes the window's UPPER edge —
// the highest base the target could have — which starts at PAGE_OFFSET_MAX and
// tightens as evidence narrows it. Taking the architecture's text floor instead
// is correct only while the architecture admits a single base, and silently
// under-shoots the ceiling by the width of the bracket once it admits more.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"

#include <limits.h>
#include <string.h>

#define BOOKE_KASLR_MIN_RAM (64ul * 1024 * 1024)
#define BOOKE_PHYS_KASLR_MAX (512ul * 1024 * 1024)

int rule_ppc32_phys_ceiling(const struct evidence_set *ev,
                            const struct estimate *est, struct constraint *out,
                            int out_max) {
#if defined(__powerpc__) && !defined(__powerpc64__)
  if (out_max < 2)
    return 0;

  /* The linear-map base, as a window. Both branches below project a physical
   * placement into virtual space through it. */
  unsigned long po_lo = 0, po_hi = 0;
  if (!quantity_window(Q_PAGE_OFFSET, &est[Q_PAGE_OFFSET], &po_lo, &po_hi))
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
    /* Too little RAM for the BookE KASLR scheme: the kernel loads where an
     * unrandomised one does, at the linear-map base plus the image offset.
     *
     * BOUNDS over the resolved base, not a pin at the compile-time one. The
     * placement is a fact about the target and the base is the target's; where
     * the architecture admits a single base the two bounds coincide and the
     * estimate still resolves to a point, so nothing is lost where the old pin
     * was right. */
    if (po_lo > ULONG_MAX - (unsigned long)IMAGE_BASE_OFFSET ||
        po_hi > ULONG_MAX - (unsigned long)IMAGE_BASE_OFFSET)
      return 0;
    struct constraint *hi_c = &out[1];
    memcpy(hi_c, c, sizeof(*hi_c));
    c->q = Q_VIRT_IMAGE_BASE;
    c->op = C_LOWER_BOUND;
    c->value = po_lo + (unsigned long)IMAGE_BASE_OFFSET;
    hi_c->q = Q_VIRT_IMAGE_BASE;
    hi_c->op = C_UPPER_BOUND;
    hi_c->value = po_hi + (unsigned long)IMAGE_BASE_OFFSET;
    return 2;
  }

  unsigned long cap = ram < BOOKE_PHYS_KASLR_MAX ? ram : BOOKE_PHYS_KASLR_MAX;
  if (cap <= min_image)
    return 0;
  /* Wrap guard: a 32-bit linear-map base plus a half-gigabyte span can carry
   * the sum past the top of the address space, and a wrapped ceiling is a low
   * address that would reject every real text base. */
  if (cap - min_image > ULONG_MAX - po_hi)
    return 0;
  unsigned long ceiling = po_hi + cap - min_image;
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
  (void)est;
  (void)out;
  (void)out_max;
  return 0;
#endif
}
