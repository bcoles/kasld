// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: virtual KASLR-disabled text pin.
//
// When a detector emits SF_VIRT_KASLR_DISABLED=1 (nokaslr cmdline, kernel
// built without CONFIG_RANDOMIZE_BASE, riscv64 FDT with no kaslr-seed,
// dmesg "KASLR disabled", hibernation override, !KASLR_SUPPORTED synth,
// …) the kernel's virtual text base sits at the compile-time default for
// the arch. Pin Q_VIRT_IMAGE_BASE to arch_default_text_base().
//
// Per-arch enable:
//   KASLR_DISABLED_PINS_VIRT_TEXT — 1 on arches where no-KASLR implies the
//     compile-time virt default (x86_64, arm64, loongarch64, s390). 0
//     elsewhere: where the bootloader can still relocate the image (x86_32,
//     arm32, ppc, mips), or where the no-KASLR base is layout-dependent and
//     owned by a bespoke rule (riscv64 — see rule_riscv64_text_base).
//
// The pinned value is the arch's *assumed* standard-config default, not a fact
// read from the kernel, so it is emitted at CONF_INFERRED (capped to the
// disabled signal's own confidence). A real text leak (parsed/derived) thus
// outranks it by confidence and wins deterministically, independent of the
// order evidence happens to be captured in.
//
// Soundness backstops:
//   1. Fires only on a positive SF_VIRT_KASLR_DISABLED signal (no spurious
//   pin).
//   2. Window-containment check: the computed default must lie within the
//      CURRENT honest window — if other evidence (a real leak or bound) has
//      already narrowed the window past the compile-time default, the default
//      is dropped and the narrowed window kept rather than pinning to a value
//      the evidence excludes. NB this does NOT catch an arch whose default is
//      itself wrong but still inside the window (e.g. sub-48 VA_BITS_MIN on
//      arm64, where the default coincides with the floor — see arm64.h SCOPE
//      note).
//   3. Inferred confidence (above): any real text leak overrides the pin.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"

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
  return kasld_emit_kaslr_disabled_pin(
      ev, est, out, out_max, SF_VIRT_KASLR_DISABLED, Q_VIRT_IMAGE_BASE,
      arch_default_text_base(), "virt_kaslr_disabled_pin");
#endif
}
