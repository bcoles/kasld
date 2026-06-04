// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: virtual KASLR-disabled text pin.
//
// When a detector emits SF_VIRT_KASLR_DISABLED=1 (nokaslr cmdline, kernel
// built without CONFIG_RANDOMIZE_BASE, riscv64 FDT with no kaslr-seed,
// dmesg "KASLR disabled", hibernation override, !KASLR_SUPPORTED synth,
// …) the kernel's virtual text base sits at the compile-time default for
// the arch. Pin Q_VIRT_TEXT_BASE to arch_default_text_base().
//
// Per-arch enable:
//   KASLR_DISABLED_PINS_VIRT_TEXT — 1 on arches where no-KASLR provably implies
//     the compile-time virt default (currently x86_64, arm64, riscv64,
//     loongarch64, s390). 0 elsewhere, where the bootloader can still
//     relocate the image.
//
// Soundness backstops:
//   1. Fires only on positive SF_VIRT_KASLR_DISABLED signal (no spurious
//      pin).
//   2. Window-containment check: the computed default must lie within the
//      current honest window — if not, arch_default_text_base() doesn't
//      model this kernel build (e.g. non-default CONFIG_ARM64_VA_BITS_MIN
//      on arm64) and we keep the wider window rather than pin to the
//      wrong value.
//   3. The resolver's conflict handling defers to a higher-confidence
//      real text leak if one exists.
// ---
// <bcoles@gmail.com>

#include "../include/kasld/engine_rules.h"

#include <string.h>

int rule_virt_kaslr_disabled_pin(const struct evidence_set *ev,
                                 const struct estimate *est,
                                 struct constraint *out, int out_max) {
#if !KASLR_DISABLED_PINS_VIRT_TEXT
  (void)ev;
  (void)est;
  (void)out;
  (void)out_max;
  return 0;
#else
  if (out_max < 1)
    return 0;

  uint32_t sig_id = 0;
  enum kasld_confidence sig_conf = CONF_UNKNOWN;
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->value_kind != OBS_SCALAR)
      continue;
    if (o->scalar_fact == SF_VIRT_KASLR_DISABLED && o->scalar_value != 0) {
      sig_id = o->id;
      sig_conf = o->conf;
      break;
    }
  }
  if (sig_id == 0)
    return 0;

  unsigned long v = arch_default_text_base();
  const struct estimate *vt = &est[Q_VIRT_TEXT_BASE];
  if (v == 0 || v < vt->lo || v > vt->hi)
    return 0;

  struct constraint *c = &out[0];
  memset(c, 0, sizeof(*c));
  c->q = Q_VIRT_TEXT_BASE;
  c->op = C_EQUALS;
  c->value = v;
  c->conf = sig_conf;
  c->derived_from[0] = sig_id;
  c->lineage_count = 1;
  snprintf(c->origin, ORIGIN_LEN, "virt_kaslr_disabled_pin");
  return 1;
#endif
}
