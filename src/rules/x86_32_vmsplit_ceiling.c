// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: x86-32 vmsplit ceiling.
//
// On x86-32 KASLR places the
// kernel within [LOAD_PHYSICAL_ADDR, KERNEL_IMAGE_SIZE=512 MiB) of physical
// memory; coupled to virtual via va = pa + PAGE_OFFSET, the virtual text base
// is bounded by PAGE_OFFSET + 512 MiB. The VMSPLIT (3G/2G/1G) determines
// PAGE_OFFSET, which the engine resolves as Q_PAGE_OFFSET (pinned from the
// CONFIG_PAGE_OFFSET landmark) — so this is a cross-quantity rule reading the
// resolved virt_page_offset, deterministic and file-derived.
//
// C_UPPER_BOUND on Q_VIRT_TEXT_BASE; fires once virt_page_offset is pinned.
// i386 only; inert elsewhere.
// ---
// <bcoles@gmail.com>

#include "../include/kasld/engine_rules.h"

#include <string.h>

#define X86_32_KERNEL_IMAGE_SIZE (512UL * 1024 * 1024)

int rule_x86_32_vmsplit_ceiling(const struct evidence_set *ev,
                                const struct estimate *est,
                                struct constraint *out, int out_max) {
  (void)ev;
#if defined(__i386__)
  if (out_max < 1)
    return 0;
  const struct estimate *po = &est[Q_PAGE_OFFSET];
  if (po->lo != po->hi)
    return 0; /* virt_page_offset not yet pinned */

  unsigned long ceiling = po->lo + X86_32_KERNEL_IMAGE_SIZE;
  if (ceiling <= KASLR_VIRT_TEXT_MIN)
    return 0;

  struct constraint *c = &out[0];
  memset(c, 0, sizeof(*c));
  c->q = Q_VIRT_TEXT_BASE;
  c->op = C_UPPER_BOUND;
  c->value = ceiling;
  c->conf = CONF_PARSED;
  c->derived_from[0] = po->lo_binding; /* the virt_page_offset landmark */
  c->lineage_count = po->lo_binding ? 1 : 0;
  snprintf(c->origin, ORIGIN_LEN, "x86_32_vmsplit_ceiling");
  return 1;
#else
  (void)est;
  (void)out;
  (void)out_max;
  return 0;
#endif
}
