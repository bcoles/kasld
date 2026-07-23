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
//     compile-time virt default (x86_64, loongarch64). 0 elsewhere: where the
//     bootloader can still relocate the image (x86_32, arm32, ppc, mips), or
//     where the no-KASLR base is layout-dependent and owned by a bespoke rule
//     (arm64 -> rule_arm64_text_base, riscv64 -> rule_riscv64_text_base, s390
//     -> rule_s390_image_base_from_config).
//
// The pinned value depends on whether the base is a FACT or a GUESS:
//   - When BOTH CONFIG_PHYSICAL_START and CONFIG_PHYSICAL_ALIGN are parsed
//     (SF_PHYSICAL_START from /boot/config or /proc/config.gz;
//     SF_PHYS_KERNEL_ALIGN from those or boot_params), the no-KASLR base is
//     exactly KERNEL_VIRT_TEXT_MIN + LOAD_PHYSICAL_ADDR + IMAGE_BASE_OFFSET,
//     where LOAD_PHYSICAL_ADDR = ALIGN(CONFIG_PHYSICAL_START,
//     CONFIG_PHYSICAL_ALIGN) (the kernel rounds an un-aligned
//     CONFIG_PHYSICAL_START UP) — a read fact, pinned at CONF_INFERRED (reaches
//     the guaranteed window, correct for default AND non-default builds).
//     Without a parsed alignment the raw value is only a floor
//     (physical_start_lower_bound), so no exact pin is emitted.
//   - Otherwise the compile-time arch_default_text_base() is an ASSUMED
//     standard-config value (a guess): pinned at CONF_HEURISTIC (likely window
//     only), so a build with a non-default CONFIG_PHYSICAL_START never has its
//     true base excluded from the guaranteed window.
// The shared helper applies the demotion; this rule supplies both candidate
// values. (Earlier the default reached CONF_INFERRED; the window-containment
// check only catches a default ABOVE a narrowed window, not a below-default
// build, so an assumed default at the sound floor was unsound there.)
//
// Soundness backstops:
//   1. Fires only on a positive SF_VIRT_KASLR_DISABLED signal (no spurious
//   pin).
//   2. Window-containment check: the value must lie within the CURRENT honest
//      window — if other evidence already narrowed past it, it is dropped.
//   3. Confidence: any real text leak (parsed/derived) outranks the pin; the
//      guess-tier default only shapes the likely window.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"

#include <limits.h>
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
  /* Learned CONFIG_PHYSICAL_START -> the exact no-KASLR virtual base. The
   * kernel loads at KERNEL_VIRT_TEXT_MIN (__START_KERNEL_map) +
   * LOAD_PHYSICAL_ADDR, where LOAD_PHYSICAL_ADDR = ALIGN(CONFIG_PHYSICAL_START,
   * CONFIG_PHYSICAL_ALIGN) — so the EXACT base needs the alignment, not the raw
   * parsed value (an un-aligned CONFIG_PHYSICAL_START rounds UP, leaving the
   * raw value BELOW the true base). SF_PHYS_KERNEL_ALIGN carries the alignment
   * (same config read plus an independent boot_params source), so it is present
   * whenever the base is. Without a parsed, power-of-two alignment the exact
   * base is unknown, so pin nothing here (learned_base stays 0 -> the assumed
   * default shapes only the likely window) — the raw value still floors the
   * guaranteed window via physical_start_lower_bound. Overflow-guard every sum.
   */
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
    unsigned long aligned =
        (ps + align - 1) & ~(align - 1); /* LOAD_PHYSICAL_ADDR */
    if (aligned <= ULONG_MAX - (unsigned long)KERNEL_VIRT_TEXT_MIN -
                       (unsigned long)IMAGE_BASE_OFFSET) {
      learned_base = (unsigned long)KERNEL_VIRT_TEXT_MIN + aligned +
                     (unsigned long)IMAGE_BASE_OFFSET;
      learned_ceiling =
          kasld_conf_min(CONF_INFERRED, kasld_conf_min(ps_conf, al_conf));
    }
  }
  return kasld_emit_kaslr_disabled_pin(
      ev, est, out, out_max, SF_VIRT_KASLR_DISABLED, Q_VIRT_IMAGE_BASE,
      learned_base, learned_ceiling, ps_src, al_src, arch_default_text_base(),
      "virt_kaslr_disabled_pin");
#endif
}
