// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: x86-32 vmsplit ceiling.
//
// On x86-32 KASLR places the
// kernel within [LOAD_PHYSICAL_ADDR, KERNEL_IMAGE_SIZE=512 MiB) of physical
// memory, and the whole image has to fit inside it: the placement code in
// arch/x86/boot/compressed/kaslr.c sets mem_limit to KERNEL_IMAGE_SIZE on
// 32-bit and rejects phys_addr + image_size > mem_limit. Coupled to virtual
// via va = pa + PAGE_OFFSET, the virtual text base is bounded by
// PAGE_OFFSET + 512 MiB less the image; the limit itself is never a base. The
// VMSPLIT (3G/2G/1G) determines PAGE_OFFSET, which the engine resolves as
// Q_PAGE_OFFSET (pinned from the CONFIG_PAGE_OFFSET landmark) — so this is a
// cross-quantity rule reading the resolved virt_page_offset, deterministic and
// file-derived.
//
// C_UPPER_BOUND on Q_VIRT_IMAGE_BASE; fires once virt_page_offset is pinned.
// i386 only; inert elsewhere.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"

#include <string.h>

#define X86_32_KERNEL_IMAGE_SIZE (512UL * 1024 * 1024)

int rule_x86_32_vmsplit_ceiling(const struct evidence_set *ev,
                                const struct estimate *est,
                                struct constraint *out, int out_max) {
#if defined(__i386__)
  if (out_max < 1)
    return 0;
  const struct estimate *po = &est[Q_PAGE_OFFSET];
  unsigned long virt_page_offset;
  if (!quantity_pinned(Q_PAGE_OFFSET, po, &virt_page_offset))
    return 0; /* virt_page_offset not yet pinned */

  /* This is the tightest window the floor is subtracted from anywhere: it is
   * exactly KERNEL_IMAGE_SIZE and the placement runs to the end of it, so
   * unlike the RAM-derived ceilings there is no slack between the topmost base
   * and the limit. A floor above the true image would cut below a reachable
   * base here before it did so anywhere else, which is why
   * KASLD_MIN_IMAGE_SIZE is set an order of magnitude under the smallest
   * image anyone ships rather than close to it. */
  unsigned long min_image = evidence_image_size_min_or_floor(ev);
  if (min_image >= X86_32_KERNEL_IMAGE_SIZE)
    return 0;
  unsigned long ceiling =
      virt_page_offset + (X86_32_KERNEL_IMAGE_SIZE - min_image);
  if (ceiling <= VIRT_TEXT_MIN_DEFAULT_CONFIG)
    return 0;

  struct constraint *c = &out[0];
  memset(c, 0, sizeof(*c));
  c->q = Q_VIRT_IMAGE_BASE;
  c->op = C_UPPER_BOUND;
  c->value = ceiling;
  c->conf = CONF_PARSED;
  c->derived_from[0] = po->lo_binding; /* the virt_page_offset landmark */
  c->lineage_count = po->lo_binding ? 1 : 0;
  snprintf(c->origin, ORIGIN_LEN, "x86_32_vmsplit_ceiling");
  return 1;
#else
  (void)ev;
  (void)est;
  (void)out;
  (void)out_max;
  return 0;
#endif
}
