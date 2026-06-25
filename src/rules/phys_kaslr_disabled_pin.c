// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: physical KASLR-disabled text pin.
//
// When a detector emits SF_PHYS_KASLR_DISABLED=1 (nokaslr cmdline,
// CONFIG_RANDOMIZE_BASE=n, riscv64 no FDT seed, hibernation override,
// !KASLR_SUPPORTED synth, or a future detector that proves only physical
// KASLR is off — e.g. EFI_RNG_PROTOCOL unavailable with virt KASLR intact
// via the DTB seed) the kernel's physical text base sits at the compile-
// time default for the arch. Pin Q_PHYS_IMAGE_BASE to
// arch_default_phys_text_base().
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
// The pinned value is the arch's *assumed* standard-config default, not a fact
// read from the kernel, so it is emitted at CONF_INFERRED (capped to the
// disabled signal's own confidence). A real phys-text leak (parsed/derived)
// thus outranks it by confidence and wins deterministically, independent of the
// order evidence happens to be captured in.
//
// Soundness backstops:
//   1. Fires only on a positive SF_PHYS_KASLR_DISABLED signal.
//   2. Window-containment check: the computed default must lie within the
//      current honest window — if not, arch_default_phys_text_base()
//      doesn't model this kernel build (e.g. non-default
//      CONFIG_PHYSICAL_START on x86_64; the physical_start_lower_bound
//      rule's learned value covers that case).
//   3. Inferred confidence (above): any real phys-text leak overrides the pin.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"

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
  return kasld_emit_kaslr_disabled_pin(
      ev, est, out, out_max, SF_PHYS_KASLR_DISABLED, Q_PHYS_IMAGE_BASE,
      arch_default_phys_text_base(), "phys_kaslr_disabled_pin");
#endif
}
