// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: riscv64 kernel-image floor from the resolved address-space width.
//
// riscv64 has two kernel-text layouts, split at "riscv: Move kernel mapping
// outside of linear mapping" (2bfc6cd81bd1, v5.13-rc1). Before it the image sat
// in the linear map at CONFIG_PAGE_OFFSET + a build-specific load offset, which
// can be far below the top 2 GiB; after it the image has its own mapping based
// at KERNEL_LINK_ADDR, and the KASLR slide only ever moves it UP from there
// (arch/riscv/mm/init.c: virt_offset is non-negative). So on the modern layout
// KERNEL_LINK_ADDR is a floor, and on the legacy one it is 126 GiB above the
// truth.
//
// The active address-space width settles which is running. Sv48 arrived at
// e8a62cc26ddf (v5.17-rc1) and Sv57 at 011f09d12052 (v5.18-rc1), both AFTER the
// layout move, so no riscv64 kernel has ever run Sv48 or Sv57 with its text
// inside the linear map. A resolved width of 48 or 57 is therefore proof of the
// modern layout, in a way no address is.
//
// Sv39 proves nothing -- it spans both eras -- so the rule stays inert there.
// That is the whole difference from the earlier attempt this replaces, which
// keyed on a resolved Q_PAGE_OFFSET and died on a live 5.10 Sv39 board: the
// engine's resolved direct-map estimate is not the kernel's CONFIG_PAGE_OFFSET,
// and on that board it landed in the modern Sv39 band while the text sat in the
// linear map. Keying on the WIDTH avoids the question entirely, because the
// width is measured rather than inferred from a layout-dependent address.
//
// The width can only be UNDER-reported, never over-. It comes from an mmap
// boundary probe, and riscv64 derives the user ceiling from the kernel's own
// width (TASK_SIZE_64 = PGDIR_SIZE * PTRS_PER_PGD / 2, and arch_get_mmap_end
// returns TASK_SIZE_64), so a probe that fails to reach the higher boundary
// reports the smaller width and leaves this rule inert. There is no direction
// in which a probe error turns into an unsound floor.
//
// ASSUMPTION, stated because it is the one way this can be wrong: that a kernel
// running Sv48 or Sv57 necessarily carries the layout move. True of every
// mainline kernel, since both postdate it. A vendor backporting Sv48 onto a
// pre-v5.13 tree WITHOUT the mapping change would defeat it -- the floor would
// then sit above a linear-mapped image. No such tree is known; the falsifier is
// a kernel reporting Sv48/Sv57 with _text below KERNEL_LINK_ADDR.
//
// Emits a floor only. The ceiling is already the honest top's and needs no
// KASLR-formula assumption to stay sound.
//
// riscv64 only; inert elsewhere and at Sv39.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"
#include "include/kasld/quantity.h"

#include <string.h>

int rule_riscv64_text_floor_from_va_bits(const struct evidence_set *ev,
                                         const struct estimate *est,
                                         struct constraint *out, int out_max) {
  (void)ev;
#if defined(__riscv) && __riscv_xlen == 64
  if (out_max < 1)
    return 0;

  unsigned long va_bits = 0;
  if (!estimate_finset_value(&quantities[Q_VA_BITS], &est[Q_VA_BITS], &va_bits))
    return 0;
  /* Only the widths that postdate the layout move. Sv39 spans both eras and is
   * the case the earlier attempt got wrong, so it is named as an exclusion
   * rather than left to a comparison that a new mode would silently join. */
  if (va_bits != 48ul && va_bits != 57ul)
    return 0;

  struct constraint *c = &out[0];
  memset(c, 0, sizeof(*c));
  c->q = Q_VIRT_IMAGE_BASE;
  c->op = C_LOWER_BOUND;
  c->value = (unsigned long)KERNEL_LINK_ADDR;
  /* No more trustworthy than the width that proved the layout, and that is
   * reached by a probe at the sound band; cap here so a weaker future resolver
   * cannot promote its answer through this rule. */
  c->conf = CONF_INFERRED;
  c->derived_from[0] = est[Q_VA_BITS].lo_binding;
  c->lineage_count = est[Q_VA_BITS].lo_binding ? 1 : 0;
  snprintf(c->origin, ORIGIN_LEN, "riscv64_text_floor_from_va_bits");
  return 1;
#else
  (void)est;
  (void)out;
  (void)out_max;
  return 0;
#endif
}
