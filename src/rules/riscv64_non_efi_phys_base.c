// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: riscv64 non-EFI physical text base (speculative OpenSBI-default guess).
//
// The stock OpenSBI non-EFI boot places the kernel image at
//   image_phys_base == DRAM_BASE + RISCV_PHYS_LOAD_OFFSET   (OpenSBI occupies
// the first 2 MiB of DRAM and the image follows), with the text section a
// head-text offset above the image base, so phys `_stext` (== iomem "Kernel
// code" start) is:
//
//   phys_image_base == DRAM_BASE + RISCV_PHYS_LOAD_OFFSET + IMAGE_BASE_OFFSET
//
// The +IMAGE_BASE_OFFSET term (.head.text length, 0x2000 on v5.10+) makes
// Q_PHYS_IMAGE_BASE refer to `_stext` rather than `_start`; omitting it lands
// the value 0x2000 below the iomem "Kernel code" entry.
//
// This is a firmware CONVENTION, NOT a fact, so it is emitted at CONF_HEURISTIC
// and shapes the LIKELY window only. RISC-V has NO physical KASLR — the
// physical base is pure firmware/bootloader placement, which "is not fixed
// across hardware" (riscv64.h) — so unlike the VIRTUAL sibling
// riscv64_text_base, no KASLR-off signal recovers soundness here:
// SF_VIRT_KASLR_DISABLED concerns the randomized VIRTUAL mapping and says
// nothing about physical placement, and the SBI implementation id is not
// reachable from unprivileged userspace. A non- default OpenSBI next-stage
// address, or a U-Boot stage between firmware and kernel, places the image
// elsewhere; pinning it would exclude the true base. The sound floor (phys_base
// >= DRAM_BASE) is already covered by dram_floor_bound.
//
// DRAM_BASE is taken from the canonical RAM_BASE marker (REGION_RAM with
// POS_BASE) only — observations on other dram-section regions (initrd,
// vmcoreinfo, reserved_mem, …) merely indicate "DRAM exists at this
// address" and do not yield the correct floor. Same restriction as
// dram_floor_bound.
//
// Reads SF_EFI_PRESENT (bridged in-process access check) — only fires on
// non-EFI — and a RAM_BASE phys leak. Emits C_EQUALS on Q_PHYS_IMAGE_BASE.
// riscv64 only; inert when no PHYS RAM_BASE observation is present.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"
#include "include/kasld/regions.h"

#include <limits.h>
#include <string.h>

int rule_riscv64_non_efi_phys_base(const struct evidence_set *ev,
                                   const struct estimate *est,
                                   struct constraint *out, int out_max) {
  (void)est;
#if (defined(__riscv) || defined(__riscv__)) && __riscv_xlen == 64
  if (out_max < 1)
    return 0;

  int efi_present = 0, have_efi_fact = 0;
  unsigned long pdram_lo = ULONG_MAX;
  uint32_t src = 0;
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid)
      continue;
    if (o->value_kind == OBS_SCALAR && o->scalar_fact == SF_EFI_PRESENT) {
      efi_present = (o->scalar_value != 0);
      have_efi_fact = 1;
      continue;
    }
    /* RAM_BASE markers only — see header comment for why other dram-section
     * regions are not sound floors. */
    if (o->value_kind == OBS_ADDRESS && o->eff_type == KASLD_TYPE_PHYS &&
        o->eff_region == REGION_RAM && o->pos == POS_BASE) {
      unsigned long a = obs_anchor(o);
      if (a < pdram_lo) {
        pdram_lo = a;
        src = o->id;
      }
    }
  }
  /* Only pin on confirmed non-EFI boot. */
  if (!have_efi_fact || efi_present)
    return 0;
  if (pdram_lo == ULONG_MAX)
    return 0;

  /* phys _stext = DRAM base + firmware placement + image head. */
  unsigned long phys_exact =
      pdram_lo + RISCV_PHYS_LOAD_OFFSET + IMAGE_BASE_OFFSET;
  if (phys_exact < (unsigned long)KASLR_PHYS_MIN)
    return 0;

  struct constraint *c = &out[0];
  memset(c, 0, sizeof(*c));
  c->q = Q_PHYS_IMAGE_BASE;
  c->op = C_EQUALS;
  c->value = phys_exact;
  /* CONF_HEURISTIC: the OpenSBI-default offset is a firmware convention, not a
   * fact (physical placement is not KASLR-randomized and no signal establishes
   * it), so the pin shapes the likely window only, never the guaranteed one. */
  c->conf = CONF_HEURISTIC;
  c->derived_from[0] = src;
  c->lineage_count = src ? 1 : 0;
  snprintf(c->origin, ORIGIN_LEN, "riscv64_non_efi_phys_base");
  return 1;
#else
  (void)ev;
  (void)out;
  (void)out_max;
  return 0;
#endif
}
