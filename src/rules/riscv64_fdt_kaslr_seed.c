// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: riscv64 text base from the FDT kaslr-seed (seed-VALUE path).
//
// On a non-EFI riscv64 boot the
// KASLR offset is derived deterministically from the FDT /chosen/kaslr-seed:
// the kernel picks slot (seed % nr_pos) of PMD_SIZE within a PUD, where
// nr_pos = (PUD_SIZE - image_size) / PMD_SIZE.
//
//   Path 1 (image_size known): image_base == KERNEL_LINK_ADDR
//                                          + (seed % nr_pos) * PMD_SIZE  (pin)
//   Path 2 (image_size unknown): image_base <= max over i in [1,nr_pos_max] of
//                                  KERNEL_LINK_ADDR + (seed % i) * PMD_SIZE
//                                  with nr_pos_max = (PUD_SIZE - gap) /
//                                  PMD_SIZE
//
// Reads SF_FDT_KASLR_SEED (bridged binary read; 0/absent => inert — covers the
// seed-disabled/wiped case handled by virt_kaslr_disabled_pin /
// phys_kaslr_disabled_pin),
// SF_EFI_PRESENT (non-EFI only — EFI mixes in efi_kaslr_seed), SF_IMAGE_SIZE,
// and VIRT text/data leaks for the Path 2 gap. riscv64 only. The active path
// requires a kernel that has not yet consumed the FDT kaslr-seed cell — the
// kernel wipes the cell to 0 once it has used it, so a usable seed is visible
// only before that point.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"
#include "include/kasld/regions.h"

#include <limits.h>
#include <stdint.h>
#include <string.h>

int rule_riscv64_fdt_kaslr_seed(const struct evidence_set *ev,
                                const struct estimate *est,
                                struct constraint *out, int out_max) {
  (void)est;
#if (defined(__riscv) || defined(__riscv__)) && __riscv_xlen == 64
  if (out_max < 1)
    return 0;

  const unsigned long pud_size = 1ul << 30; /* 1 GiB */
  const unsigned long pmd_size = 2ul * 1024 * 1024;

  uint64_t seed = 0;
  unsigned long image_size = 0, min_text = ULONG_MAX, max_data = 0;
  int efi_present = 0;
  uint32_t src = 0;
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid)
      continue;
    if (o->value_kind == OBS_SCALAR) {
      if (o->scalar_fact == SF_FDT_KASLR_SEED) {
        seed = o->scalar_value;
        src = o->id;
      } else if (o->scalar_fact == SF_EFI_PRESENT)
        efi_present = (o->scalar_value != 0);
      else if (o->scalar_fact == SF_IMAGE_SIZE)
        image_size = o->scalar_value;
      continue;
    }
    if (o->eff_type == KASLD_TYPE_VIRT) {
      unsigned long a = obs_anchor(o);
      if (o->eff_region == REGION_KERNEL_TEXT ||
          o->eff_region == REGION_KERNEL_IMAGE) {
        if (a < min_text)
          min_text = a;
      } else if (o->eff_region == REGION_KERNEL_DATA ||
                 o->eff_region == REGION_KERNEL_BSS) {
        if (a > max_data)
          max_data = a;
      }
    }
  }
  if (seed == 0 || efi_present)
    return 0;

  /* Path 1: exact slot count from image_size -> pin. */
  if (image_size > 0 && image_size < pud_size) {
    unsigned long nr_pos = (pud_size - image_size) / pmd_size;
    if (nr_pos > 0) {
      unsigned long off = (unsigned long)((seed % (uint64_t)nr_pos) * pmd_size);
      unsigned long candidate = (unsigned long)KERNEL_LINK_ADDR + off;
      struct constraint *c = &out[0];
      memset(c, 0, sizeof(*c));
      c->q = Q_VIRT_IMAGE_BASE;
      c->op = C_EQUALS;
      c->value = candidate;
      c->conf = CONF_INFERRED;
      c->derived_from[0] = src;
      c->lineage_count = 1;
      snprintf(c->origin, ORIGIN_LEN, "riscv64_fdt_kaslr_seed");
      return 1;
    }
  }

  /* Path 2: gap fallback -> ceiling from the maximal candidate. */
  if (min_text == ULONG_MAX || max_data <= min_text)
    return 0;
  unsigned long gap = max_data - min_text;
  if (gap == 0 || gap >= pud_size)
    return 0;
  unsigned long nr_pos_max = (pud_size - gap) / pmd_size;
  if (nr_pos_max == 0)
    return 0;
  unsigned long max_cand = 0;
  for (unsigned long i = 1; i <= nr_pos_max; i++) {
    unsigned long cand = (unsigned long)KERNEL_LINK_ADDR +
                         (unsigned long)((seed % (uint64_t)i) * pmd_size);
    if (cand > max_cand)
      max_cand = cand;
  }
  if (max_cand <= (unsigned long)KERNEL_LINK_ADDR)
    return 0;
  struct constraint *c = &out[0];
  memset(c, 0, sizeof(*c));
  c->q = Q_VIRT_IMAGE_BASE;
  c->op = C_UPPER_BOUND;
  c->value = max_cand;
  c->conf = CONF_INFERRED;
  c->derived_from[0] = src;
  c->lineage_count = 1;
  snprintf(c->origin, ORIGIN_LEN, "riscv64_fdt_kaslr_seed");
  return 1;
#else
  (void)ev;
  (void)out;
  (void)out_max;
  return 0;
#endif
}
