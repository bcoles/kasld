// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: KASLR-disabled text pin (generalized; virt and phys).
//
// When a detector emits SF_KASLR_DISABLED=1 (nokaslr cmdline, kernel built
// without CONFIG_RANDOMIZE_BASE, riscv64 FDT with no kaslr-seed, dmesg "KASLR
// disabled", hibernation override, …) the kernel sits at the compile-time
// default text base for the arch. Pin Q_VIRT_TEXT_BASE to
// arch_default_text_base(). On arches where the same SF_KASLR_DISABLED signal
// also proves the *physical* text base (i.e. the kernel's relocator/
// decompressor disables both virt and phys randomization under nokaslr),
// additionally pin Q_PHYS_TEXT_BASE to arch_default_phys_text_base().
//
// Per-arch enables:
//   KASLR_DISABLED_PINS_TEXT — virt pin. 1 on arches where no-KASLR provably
//     implies the compile-time virt default (currently x86_64, arm64,
//     riscv64, loongarch64, s390). 0 elsewhere, where the bootloader can
//     still relocate the image.
//   KASLR_DISABLED_PINS_PHYS — phys pin. 1 on arches where the kernel's own
//     code path (decompressor / relocate.c) keeps the image at its
//     compile-time physical default under nokaslr (currently x86_64,
//     loongarch64). 0 on arches where phys placement is bootloader / DT /
//     memstart-determined (arm64, riscv64, s390) or independently randomised.
// The two axes are orthogonal: SF_KASLR_DISABLED tells us about virt KASLR;
// phys may be linked (x86_64, loongarch64) or independent (arm64, riscv64,
// s390). Per-arch reality decides.
//
// Soundness backstops (apply per pin):
//   1. Fires only on positive SF_KASLR_DISABLED signal (no spurious pin).
//   2. Window-containment check: the computed default must lie within the
//      current honest window — if not, our arch_default_*_text_base() doesn't
//      model this kernel build (e.g. non-default CONFIG_PHYSICAL_START on
//      x86_64, non-default CONFIG_ARM64_VA_BITS_MIN on arm64) and we keep the
//      wider window rather than pin to the wrong value.
//   3. The resolver's conflict handling defers to a higher-confidence real
//      text leak if one exists. The physical_start_lower_bound rule emits a
//      higher-confidence phys-floor when a real SF_PHYSICAL_START is learned,
//      cleanly overriding this heuristic.
// ---
// <bcoles@gmail.com>

#include "../include/kasld/engine_rules.h"

#include <string.h>

int rule_kaslr_disabled_pin(const struct evidence_set *ev,
                            const struct estimate *est, struct constraint *out,
                            int out_max) {
#if !KASLR_DISABLED_PINS_TEXT && !KASLR_DISABLED_PINS_PHYS
  (void)ev;
  (void)est;
  (void)out;
  (void)out_max;
  return 0;
#else
  if (out_max < 1)
    return 0;

  /* (a) KASLR-off signal present? */
  uint32_t sig_id = 0;
  enum kasld_confidence sig_conf = CONF_UNKNOWN;
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->value_kind != OBS_SCALAR)
      continue;
    if (o->scalar_fact == SF_KASLR_DISABLED && o->scalar_value != 0) {
      sig_id = o->id;
      sig_conf = o->conf;
      break;
    }
  }
  if (sig_id == 0)
    return 0;

  int n = 0;

#if KASLR_DISABLED_PINS_TEXT
  /* Virt pin: compute and sanity-check within the current honest window. */
  {
    unsigned long v = arch_default_text_base();
    const struct estimate *vt = &est[Q_VIRT_TEXT_BASE];
    if (v != 0 && v >= vt->lo && v <= vt->hi && n < out_max) {
      struct constraint *c = &out[n++];
      memset(c, 0, sizeof(*c));
      c->q = Q_VIRT_TEXT_BASE;
      c->op = C_EQUALS;
      c->value = v;
      c->conf = sig_conf;
      c->derived_from[0] = sig_id;
      c->lineage_count = 1;
      snprintf(c->origin, ORIGIN_LEN, "kaslr_disabled_pin");
    }
  }
#endif

#if KASLR_DISABLED_PINS_PHYS
  /* Phys pin: independent per-arch decision; same window-containment shape.
   * Skipped if arch returns 0 (no useful default) or if the default falls
   * outside the current Q_PHYS_TEXT_BASE window (build with non-default
   * CONFIG_PHYSICAL_START where the static default doesn't model truth — the
   * physical_start_lower_bound rule's learned value covers that case). */
  {
    unsigned long p = arch_default_phys_text_base();
    const struct estimate *pt = &est[Q_PHYS_TEXT_BASE];
    if (p != 0 && p >= pt->lo && p <= pt->hi && n < out_max) {
      struct constraint *c = &out[n++];
      memset(c, 0, sizeof(*c));
      c->q = Q_PHYS_TEXT_BASE;
      c->op = C_EQUALS;
      c->value = p;
      c->conf = sig_conf;
      c->derived_from[0] = sig_id;
      c->lineage_count = 1;
      snprintf(c->origin, ORIGIN_LEN, "kaslr_disabled_pin");
    }
  }
#endif

  return n;
#endif
}
