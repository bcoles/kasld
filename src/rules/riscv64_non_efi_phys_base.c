// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: riscv64 non-EFI physical text base.
//
// On a non-EFI (OpenSBI) riscv64 boot the kernel image is placed at
//   image_phys_base == DRAM_BASE + TEXT_OFFSET   (OpenSBI default)
// and the text section starts at the head-text offset above the image base,
// so the SF_PHYS_TEXT_BASE-equivalent (== iomem "Kernel code" start) is:
//
//   phys_text_base == DRAM_BASE + TEXT_OFFSET + RISCV64_HEAD_TEXT_OFFSET
//
// The +RISCV64_HEAD_TEXT_OFFSET term (.head.text length, 0x2000 on v5.10+)
// is what makes Q_PHYS_TEXT_BASE refer to `_stext` rather than `_start`
// (the image base / first byte of `_text`). Omitting it lands the pin
// 0x2000 below the actual phys `_stext` and the resolved window excludes
// the true text base. On a default-config riscv64 build, kallsyms reports
// `_stext = _start + 0x2000` and the iomem "Kernel code" entry begins at
// DRAM_BASE + TEXT_OFFSET + 0x2000 (the bytes of `.head.text` precede it).
//
// DRAM_BASE is taken from the canonical RAM_BASE marker (REGION_RAM with
// POS_BASE) only — observations on other dram-section regions (initrd,
// vmcoreinfo, reserved_mem, …) merely indicate "DRAM exists at this
// address" and do not yield the correct floor. Same restriction as
// dram_floor_bound.
//
// Reads SF_EFI_PRESENT (bridged in-process access check) — only fires on
// non-EFI — and a RAM_BASE phys leak. Emits C_EQUALS on Q_PHYS_TEXT_BASE.
// riscv64 only; dormant offline (needs a PHYS RAM_BASE leak) — LIVE-TEST
// list.
// ---
// <bcoles@gmail.com>

#include "../include/kasld/engine_rules.h"
#include "../include/kasld/regions.h"

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

  unsigned long phys_exact = pdram_lo + TEXT_OFFSET + RISCV64_HEAD_TEXT_OFFSET;
  if (phys_exact < (unsigned long)KASLR_PHYS_MIN)
    return 0;

  struct constraint *c = &out[0];
  memset(c, 0, sizeof(*c));
  c->q = Q_PHYS_TEXT_BASE;
  c->op = C_EQUALS;
  c->value = phys_exact;
  c->conf = CONF_INFERRED;
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
