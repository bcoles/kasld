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
// Reads SF_PHYS_MEMTOTAL. PAGE_OFFSET is fixed on PPC32 (no VMSPLIT), so the
// coupled mapping uses KASLR_VIRT_TEXT_MIN directly. ppc32 only; the active
// path fires on a BookE host that reports a sub-64 MiB SF_PHYS_MEMTOTAL.
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

  unsigned long mem = 0;
  uint32_t src = 0;
  const unsigned long min_image = evidence_image_size_min_or_floor(ev);
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (o->valid && o->value_kind == OBS_SCALAR &&
        o->scalar_fact == SF_PHYS_MEMTOTAL) {
      mem = o->scalar_value;
      src = o->id;
      break;
    }
  }
  if (mem == 0)
    return 0;

  struct constraint *c = &out[0];
  memset(c, 0, sizeof(*c));
  c->conf = CONF_INFERRED;
  c->derived_from[0] = src;
  c->lineage_count = src ? 1 : 0;
  snprintf(c->origin, ORIGIN_LEN, "ppc32_phys_ceiling");

  if (mem < BOOKE_KASLR_MIN_RAM) {
    /* KASLR disabled: pin to the compile-time default. */
    c->q = Q_VIRT_IMAGE_BASE;
    c->op = C_EQUALS;
    c->value = (unsigned long)KERNEL_VIRT_TEXT_DEFAULT;
    return 1;
  }

  unsigned long cap = mem < BOOKE_PHYS_KASLR_MAX ? mem : BOOKE_PHYS_KASLR_MAX;
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
