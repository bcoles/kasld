// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Search kernel log for messages stating KASLR is disabled.
//
// Two distinct kernel-side states surface through nearly identical
// "KASLR disabled" / "KASLR is disabled" dmesg lines. The semantics are
// different and the engine consumes them via different scalar facts:
//
// (1) Definitive opt-out — kernel sits at KERNEL_VIRT_TEXT_DEFAULT.
//     Triggers: user passed nokaslr (or kernel forced it off for an
//     orthogonal reason like hibernation resume on x86, the kexec_file
//     path on loongarch, etc.). The boot stub honoured the request and
//     skipped relocation entirely.
//     Wire fact: SF_VIRT_KASLR_DISABLED.
//     Engine effect: virt_/phys_kaslr_disabled_pin pins Q_VIRT_TEXT_BASE (and
//     on coupled arches, Q_PHYS_TEXT_BASE) to the arch's compile-time default.
//
//   x86/x86_64:
//     KASLR disabled: 'kaslr' not on cmdline (hibernation selected).
//     KASLR disabled: 'nokaslr' on cmdline.
//   ARM64:
//     KASLR disabled on command line
//   LoongArch:
//     KASLR is disabled.
//
// (2) Randomization machinery failed — kernel was relocated by the
//     boot stub but no random offset was applied. The resulting
//     position is firmware-/boot-stub-deterministic but NOT the
//     link-time default, so the engine MUST NOT pin to default from
//     this signal.
//     Wire facts: SF_VIRT_KASLR_RANDOMIZATION_FAILED +
//     SF_PHYS_KASLR_RANDOMIZATION_FAILED. The four "KASLR disabled
//     due to/...: CPU has no PRNG/...: not enough memory" reasons
//     matched here fail both axes in the kernel's own boot stub, so
//     both facts are emitted.
//     Engine effect: hardening-report entropy downgrade (consumes
//     SF_VIRT, since the user-visible "0 entropy" claim is about
//     virt text), EFI loader-pool disambiguation tightening on EFI
//     arches (consumes SF_PHYS), s390-specific phys_text_base
//     inference (consumes SF_PHYS).
//
//   ARM64 (arch/arm64/kernel/setup.c / kaslr.c — EFI stub):
//     KASLR disabled due to lack of seed
//     KASLR disabled due to FDT remapping failure
//   S390 (arch/s390/boot/kaslr.c — boot stub):
//     KASLR disabled: CPU has no PRNG
//     KASLR disabled: not enough memory
//
// (3) EFI_RNG_PROTOCOL unavailable — PHYS-ONLY randomization failure.
//     The EFI stub couldn't get random bytes from EFI_RNG_PROTOCOL,
//     so phys placement falls back to the PE/COFF loader's choice
//     (firmware-determined per machine). VIRTUAL KASLR is independent
//     on EFI arm64 / riscv64 / loongarch64 — the DTB /chosen/kaslr-
//     seed (or arch RNG: riscv64 Zkr, arm64 RNDR) feeds the virt
//     offset separately and may have succeeded.
//     Wire fact: SF_PHYS_KASLR_RANDOMIZATION_FAILED alone.
//     Engine effect: efi_loader_kernel_pick disambiguates the phys
//     placement to the lowest EFI_LOADER_CODE entry. The hardening
//     posture does NOT downgrade (virt KASLR still has full entropy).
//
//   EFI stub (drivers/firmware/efi/libstub/kaslr.c):
//     EFI_RNG_PROTOCOL unavailable
//
// Introduced for ARM64 in kernel v5.5-rc1~22^2~11^9~1 on 2019-11-09:
// https://github.com/torvalds/linux/commit/294a9ddde6cdbf931a28b8c8c928d3f799b61cb5
//
// Detection component — does not leak an address.
//
// Requires:
// - kernel.dmesg_restrict = 0; or CAP_SYSLOG capabilities; or
//   readable /var/log/dmesg.
//
// References:
// https://elixir.bootlin.com/linux/v5.19.17/source/arch/arm64/kernel/kaslr.c#L197
// https://elixir.bootlin.com/linux/v5.19.17/source/arch/arm64/kernel/kaslr.c#L200
// https://elixir.bootlin.com/linux/v6.1.6/source/arch/arm64/kernel/kaslr.c#L45
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/s390/boot/kaslr.c#L35
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/s390/boot/kaslr.c#L201
// https://elixir.bootlin.com/linux/v6.8.5/source/arch/loongarch/kernel/relocate.c#L107
// ---
// <bcoles@gmail.com>

#define _GNU_SOURCE
#include "include/dmesg.h"
#include "include/kasld/api.h"
#include "include/kasld/cli.h"
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

KASLD_EXPLAIN("Searches dmesg for messages indicating KASLR was disabled or "
              "could not be enabled. Distinguishes three states: definitive "
              "opt-out (nokaslr / hibernation / arch override) where the "
              "kernel sits at the compile-time default text base; "
              "randomization failure (missing entropy seed, no PRNG, "
              "insufficient memory) where the kernel is at a firmware- or "
              "boot-stub-determined position on both axes; and EFI_RNG_"
              "PROTOCOL unavailable, where only PHYSICAL randomization "
              "failed (virt KASLR via DTB seed / arch RNG is independent "
              "and may have succeeded). Access is gated by dmesg_restrict.");

KASLD_META("method:detection\n"
           "phase:inference\n"
           "addr:none\n"
           "sysctl:dmesg_restrict>=1\n"
           "bypass:CAP_SYSLOG\n"
           "fallback:/var/log/dmesg\n");

struct match_ctx {
  bool opt_out;     /* KASLR definitively off; kernel at link-time default. */
  bool rand_failed; /* Boot stub tried, randomization did not run.          */
  bool efi_rng_unavailable; /* EFI stub couldn't get random bytes from        */
                            /* EFI_RNG_PROTOCOL — phys placement only,        */
                            /* virt KASLR independent via DTB seed/RNDR.      */
};

static int on_match(const char *line, void *ctx) {
  struct match_ctx *m = ctx;

  if (!strstr(line, "KASLR disabled") && !strstr(line, "KASLR is disabled"))
    return 1;

  /* Randomization-machinery-failed variants. The boot stub relocated the
   * kernel to a firmware-/boot-stub-determined position WITHOUT applying a
   * random offset. This is NOT a pin-to-default signal — the kernel is not
   * at KERNEL_VIRT_TEXT_DEFAULT. */
  if (strstr(line, "KASLR disabled due to lack of seed") ||
      strstr(line, "KASLR disabled due to FDT remapping failure") ||
      strstr(line, "KASLR disabled: CPU has no PRNG") ||
      strstr(line, "KASLR disabled: not enough memory")) {
    m->rand_failed = true;
    return 1;
  }

  /* Otherwise the line is a definitive opt-out: nokaslr cmdline,
   * hibernation resume on x86, the cmdline-confirming arm64 / loongarch
   * variants. The kernel sits at the arch's compile-time default text
   * base; the virt_/phys_kaslr_disabled_pin rule will act on this. */
  m->opt_out = true;
  return 1;
}

/* "EFI_RNG_PROTOCOL unavailable" — logged by the EFI stub when
 * efi_get_random_bytes() returns EFI_NOT_FOUND. The stub sets
 * efi_nokaslr = true, which disables PHYSICAL randomization only — the
 * kernel stays at its PE/COFF loader placement (firmware-determined per
 * machine, not the link-time default). VIRTUAL KASLR is independent on
 * the affected arches (arm64 / riscv64 / loongarch64 EFI) and may still
 * succeed via the DTB /chosen/kaslr-seed or an arch RNG (riscv64 Zkr,
 * arm64 RNDR), so we emit ONLY the phys-side fact. */
static int on_match_efi(const char *line, void *ctx) {
  struct match_ctx *m = ctx;
  if (strstr(line, "EFI_RNG_PROTOCOL unavailable"))
    m->efi_rng_unavailable = true;
  return 1;
}

int main(void) {
  struct match_ctx m = {false, false, false};

  kasld_info("searching dmesg for 'KASLR disabled' or 'KASLR is disabled' ...");
  int ds = dmesg_search("KASLR ", on_match, &m);

  kasld_info("searching dmesg for 'EFI_RNG_PROTOCOL unavailable' ...");
  int ds2 = dmesg_search("EFI_RNG_PROTOCOL ", on_match_efi, &m);

  if (!m.opt_out && !m.rand_failed && !m.efi_rng_unavailable) {
    if (ds < 0 && ds2 < 0)
      return KASLD_EXIT_NOPERM;
    kasld_err("KASLR disabled indicator not found in dmesg");
    return 0;
  }

  if (m.opt_out) {
    kasld_info("Kernel was booted with KASLR disabled");
    /* The dmesg "KASLR disabled" / "KASLR is disabled" lines fire from the
     * boot stub's nokaslr path (or equivalent), which disables both virtual
     * and physical randomisation on every arch that emits them. */
    kasld_emit_scalar(SF_VIRT_KASLR_DISABLED, 1, CONF_PARSED);
    kasld_emit_scalar(SF_PHYS_KASLR_DISABLED, 1, CONF_PARSED);
  }

  if (m.rand_failed) {
    kasld_info(
        "Kernel attempted KASLR but randomization did not run "
        "(firmware-/boot-stub-determined placement, not link-time default)");
    /* Distinct from SF_*_KASLR_DISABLED: the boot stub still relocated the
     * image, so we cannot pin to KERNEL_VIRT_TEXT_DEFAULT. Every dmesg-side
     * "KASLR disabled" reason matched here ("lack of seed", "FDT
     * remapping failure", "CPU has no PRNG", "not enough memory") fails
     * BOTH the virt and the phys randomization paths in the boot stub's
     * own code — neither axis got a random offset — so both facts are
     * emitted. */
    kasld_emit_scalar(SF_VIRT_KASLR_RANDOMIZATION_FAILED, 1, CONF_PARSED);
    kasld_emit_scalar(SF_PHYS_KASLR_RANDOMIZATION_FAILED, 1, CONF_PARSED);
  }

  if (m.efi_rng_unavailable) {
    kasld_info(
        "EFI stub could not get random bytes from EFI_RNG_PROTOCOL "
        "(physical placement is PE/COFF-loader-determined; virtual KASLR "
        "may have succeeded independently via DTB seed or arch RNG)");
    /* Phys-only randomisation failure: emit SF_PHYS_KASLR_RANDOMIZATION_FAILED
     * alone. virt-side facts are NOT emitted — virt KASLR on EFI arm64 /
     * riscv64 / loongarch64 is independent of EFI_RNG_PROTOCOL and may have
     * succeeded via the DTB seed. Consumed by efi_loader_kernel_pick (which
     * disambiguates phys placement via the lowest EFI_LOADER_CODE entry
     * when the stub fell back to deterministic allocation). */
    kasld_emit_scalar(SF_PHYS_KASLR_RANDOMIZATION_FAILED, 1, CONF_PARSED);
  }

  return 0;
}
