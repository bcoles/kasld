// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: pin page_offset from CONFIG_PAGE_OFFSET on VMSPLIT arches.
//
// On x86_32 and arm32 the user/kernel split (CONFIG_PAGE_OFFSET / VMSPLIT) is a
// pure compile-time constant: the configured value IS the runtime page_offset,
// with no boot-time override. So reading CONFIG_PAGE_OFFSET (bridged as
// SF_CONFIG_PAGE_OFFSET) and pinning Q_PAGE_OFFSET to it is sound — unlike the
// compile-time DEFAULT, which only guesses the common 3G/1G split.
//
// Gated on PAGE_OFFSET_FROM_CONFIG, NOT a raw arch check: the macro encodes the
// soundness property "CONFIG_PAGE_OFFSET is authoritative here". It is
// deliberately 0 on riscv64 (CONFIG_PAGE_OFFSET reflects the built SATP mode
// but the kernel may boot a narrower one — a kernel built with SV57 may run as
// SV48 if the CPU does not support 5-level paging) and arm64 (VA_BITS), where
// only the runtime probe is sound.
//
// C_EQUALS at CONF_PARSED (a parsed, authoritative config value). The engine's
// monotone meet drops it if it would fall outside the current window. Once
// page_offset pins, the coupled-arch cross-quantity ceilings (highmem_32bit_-
// bound, virt_ceiling_from_memtotal, ...) fire on the next pass.
// ---
// <bcoles@gmail.com>

#include "../include/kasld/engine_rules.h"

#include <string.h>

int rule_page_offset_from_config(const struct evidence_set *ev,
                                 const struct estimate *est,
                                 struct constraint *out, int out_max) {
  (void)est;
#if PAGE_OFFSET_FROM_CONFIG
  if (out_max < 1)
    return 0;

  unsigned long po = 0;
  uint32_t src = 0;
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (o->valid && o->value_kind == OBS_SCALAR &&
        o->scalar_fact == SF_CONFIG_PAGE_OFFSET) {
      po = o->scalar_value;
      src = o->id;
      break;
    }
  }
  if (po == 0)
    return 0;

  struct constraint *c = &out[0];
  memset(c, 0, sizeof(*c));
  c->q = Q_PAGE_OFFSET;
  c->op = C_EQUALS;
  c->value = po;
  c->conf = CONF_PARSED;
  c->derived_from[0] = src;
  c->lineage_count = src ? 1 : 0;
  snprintf(c->origin, ORIGIN_LEN, "page_offset_from_config");
  return 1;
#else
  (void)ev;
  (void)out;
  (void)out_max;
  return 0;
#endif
}
