// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: physical KASLR-disabled text pin.
//
// When a detector emits SF_PHYS_KASLR_DISABLED=1 (nokaslr cmdline,
// CONFIG_RANDOMIZE_BASE=n, riscv64 no FDT seed, hibernation override,
// !KASLR_SUPPORTED synth, or a future detector that proves only physical
// KASLR is off — e.g. EFI_RNG_PROTOCOL unavailable with virt KASLR intact
// via the DTB seed) the kernel's physical text base sits at
// CONFIG_PHYSICAL_START. Pin Q_PHYS_IMAGE_BASE to a LEARNED SF_PHYSICAL_START
// when available (a fact), else to arch_default_phys_text_base() (a guess).
//
// Per-arch enable:
//   KASLR_DISABLED_PINS_PHYS — 1 on arches where the kernel's own code
//     path (decompressor / relocate.c) keeps the image at its compile-time
//     physical default under nokaslr (currently x86_64, loongarch64). 0
//     on arches where phys placement is bootloader / DT / memstart-
//     determined (arm64, riscv64, s390) or independently randomized. Even
//     when SF_PHYS_KASLR_DISABLED is true on those arches, no pin fires
//     because the address isn't predictable from compile-time data.
//
// A learned SF_PHYSICAL_START is a parsed fact, pinned at CONF_INFERRED
// (correct for default AND non-default builds); the compile-time default is an
// assumed standard-config value, pinned at CONF_HEURISTIC (likely window only)
// so a non-default CONFIG_PHYSICAL_START build's true base is never excluded
// from the guaranteed window. A real phys-text leak outranks either by
// confidence.
//
// Soundness backstops:
//   1. Fires only on a positive SF_PHYS_KASLR_DISABLED signal.
//   2. Window-containment check: the value must lie within the current honest
//      window — if not, it is dropped.
//   3. Confidence: a real phys-text leak overrides the pin; the guess-tier
//      default only shapes the likely window.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"

#include <limits.h>
#include <string.h>

int rule_phys_kaslr_disabled_pin(const struct evidence_set *ev,
                                 const struct estimate *est,
                                 struct constraint *out, int out_max) {
#if !KASLR_DISABLED_PINS_PHYS
  (void)ev;
  (void)est;
  (void)out;
  (void)out_max;
  return 0;
#else
  /* Learned no-KASLR physical base = LOAD_PHYSICAL_ADDR =
   * ALIGN(CONFIG_PHYSICAL_START, CONFIG_PHYSICAL_ALIGN). The raw parsed
   * CONFIG_PHYSICAL_START is NOT the base when it is not align-aligned (the
   * kernel rounds it UP), so an exact C_EQUALS pin needs the alignment too.
   * SF_PHYS_KERNEL_ALIGN supplies it (config read + independent boot_params
   * source). Without a parsed, power-of-two alignment the exact base is
   * unknown, so pin nothing (physical_start_lower_bound still floors it from
   * the raw value); the assumed default then shapes only the likely window. */
  enum kasld_confidence ps_conf = CONF_UNKNOWN;
  uint32_t ps_src = 0;
  unsigned long ps =
      kasld_scalar_fact_value(ev, SF_PHYSICAL_START, &ps_conf, &ps_src);
  enum kasld_confidence al_conf = CONF_UNKNOWN;
  uint32_t al_src = 0;
  unsigned long align =
      kasld_scalar_fact_value(ev, SF_PHYS_KERNEL_ALIGN, &al_conf, &al_src);
  unsigned long learned_base = 0;
  enum kasld_confidence learned_ceiling = CONF_INFERRED;
  if (ps && align && (align & (align - 1)) == 0 &&
      ps <= ULONG_MAX - (align - 1)) {
    learned_base = (ps + align - 1) & ~(align - 1); /* LOAD_PHYSICAL_ADDR */
    learned_ceiling =
        kasld_conf_min(CONF_INFERRED, kasld_conf_min(ps_conf, al_conf));
  }
  return kasld_emit_kaslr_disabled_pin(
      ev, est, out, out_max, SF_PHYS_KASLR_DISABLED, Q_PHYS_IMAGE_BASE,
      learned_base, learned_ceiling, ps_src, al_src,
      arch_default_phys_text_base(), "phys_kaslr_disabled_pin");
#endif
}
