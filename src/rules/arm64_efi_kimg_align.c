// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: arm64 physical KASLR granularity = EFI_KIMG_ALIGN, from page size.
//
// On arm64 the physical KASLR
// slot granularity is EFI_KIMG_ALIGN = max(THREAD_ALIGN, SEGMENT_ALIGN=64 KiB):
//
//   4K / 16K pages: THREAD_ALIGN <= 32 KiB -> EFI_KIMG_ALIGN = 64 KiB
//   64K pages:      THREAD_ALIGN = 128 KiB -> EFI_KIMG_ALIGN = 128 KiB
//
// The compile-time default (KASLR_VIRT_ALIGN = 64 KiB) is correct for 4K/16K;
// this raises Q_PHYS_KASLR_ALIGN to 128 KiB on 64K-page kernels. Virtual
// KASLR_VIRT_ALIGN (2 MiB) is page_size independent on arm64 and is left
// untouched.
//
// Reads SF_PAGE_SIZE (bridged from getpagesize). C_AT_LEAST_ALIGN; a value at
// or below the arch baseline is dominated by kaslr_align_arch_default.
//
// arm64 only; inert elsewhere.
// ---
// <bcoles@gmail.com>

#include "../include/kasld/engine_rules.h"

#include <string.h>

int rule_arm64_efi_kimg_align(const struct evidence_set *ev,
                              const struct estimate *est,
                              struct constraint *out, int out_max) {
  (void)est;
#if defined(__aarch64__)
  if (out_max < 1)
    return 0;

  unsigned long pagesize = 0;
  uint32_t src = 0;
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (o->valid && o->value_kind == OBS_SCALAR &&
        o->scalar_fact == SF_PAGE_SIZE) {
      pagesize = o->scalar_value;
      src = o->id;
      break;
    }
  }

  unsigned long efi_kimg_align;
  if (pagesize == 65536ul)
    efi_kimg_align = 131072ul; /* 128 KiB */
  else if (pagesize == 4096ul || pagesize == 16384ul)
    efi_kimg_align = 65536ul; /* 64 KiB */
  else
    return 0; /* unknown/absent page size */

  struct constraint *c = &out[0];
  memset(c, 0, sizeof(*c));
  c->q = Q_PHYS_KASLR_ALIGN;
  c->op = C_AT_LEAST_ALIGN;
  c->value = efi_kimg_align;
  c->conf = CONF_PARSED;
  c->derived_from[0] = src;
  c->lineage_count = src ? 1 : 0;
  snprintf(c->origin, ORIGIN_LEN, "arm64_efi_kimg_align");
  return 1;
#else
  (void)ev;
  (void)out;
  (void)out_max;
  return 0;
#endif
}
