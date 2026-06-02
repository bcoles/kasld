// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Search kernel log for messages stating KASLR is disabled.
//
// Two distinct kernel-side states surface through nearly identical
// "KASLR disabled" / "KASLR is disabled" dmesg lines. The semantics are
// different and the engine consumes them via different scalar facts:
//
// (1) Definitive opt-out — kernel sits at KERNEL_TEXT_DEFAULT.
//     Triggers: user passed nokaslr (or kernel forced it off for an
//     orthogonal reason like hibernation resume on x86, the kexec_file
//     path on loongarch, etc.). The boot stub honoured the request and
//     skipped relocation entirely.
//     Wire fact: SF_KASLR_DISABLED.
//     Engine effect: kaslr_disabled_pin pins Q_VIRT_TEXT_BASE (and on
//     coupled arches, Q_PHYS_TEXT_BASE) to the arch's compile-time
//     default.
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
//     Wire fact: SF_KASLR_RANDOMIZATION_FAILED.
//     Engine effect (planned consumers): hardening-report entropy
//     downgrade, EFI loader-pool disambiguation tightening on EFI
//     arches, s390-specific phys_text_base inference from the
//     boot-stub's deterministic no-PRNG placement algorithm.
//
//   ARM64 (arch/arm64/kernel/setup.c / kaslr.c — EFI stub):
//     KASLR disabled due to lack of seed
//     KASLR disabled due to FDT remapping failure
//   S390 (arch/s390/boot/kaslr.c — boot stub):
//     KASLR disabled: CPU has no PRNG
//     KASLR disabled: not enough memory
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
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

KASLD_EXPLAIN("Searches dmesg for messages indicating KASLR was disabled or "
              "could not be enabled. Distinguishes two states: definitive "
              "opt-out (nokaslr / hibernation / arch override) where the "
              "kernel sits at the compile-time default text base, versus "
              "randomization failure (missing entropy seed, no PRNG, "
              "insufficient memory) where the kernel is at a firmware- or "
              "boot-stub-determined position. Access is gated by "
              "dmesg_restrict.");

KASLD_META("method:detection\n"
           "phase:inference\n"
           "addr:none\n"
           "sysctl:dmesg_restrict>=1\n"
           "bypass:CAP_SYSLOG\n"
           "fallback:/var/log/dmesg\n");

struct match_ctx {
  bool opt_out;     /* KASLR definitively off; kernel at link-time default. */
  bool rand_failed; /* Boot stub tried, randomization did not run.          */
};

static int on_match(const char *line, void *ctx) {
  struct match_ctx *m = ctx;

  if (!strstr(line, "KASLR disabled") && !strstr(line, "KASLR is disabled"))
    return 1;

  /* Randomization-machinery-failed variants. The boot stub relocated the
   * kernel to a firmware-/boot-stub-determined position WITHOUT applying a
   * random offset. This is NOT a pin-to-default signal — the kernel is not
   * at KERNEL_TEXT_DEFAULT. */
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
   * base; the kaslr_disabled_pin rule will act on this. */
  m->opt_out = true;
  return 1;
}

int main(void) {
  struct match_ctx m = {false, false};

  printf(
      "[.] searching dmesg for 'KASLR disabled' or 'KASLR is disabled' ...\n");
  int ds = dmesg_search("KASLR ", on_match, &m);

  if (!m.opt_out && !m.rand_failed) {
    if (ds < 0)
      return KASLD_EXIT_NOPERM;
    printf("[-] KASLR disabled indicator not found in dmesg\n");
    return 0;
  }

  if (m.opt_out) {
    printf("[.] Kernel was booted with KASLR disabled\n");
    /* Off-detection signal; the engine's kaslr_disabled_pin rule computes the
     * per-arch default text base and pins Q_VIRT_TEXT_BASE (gated by
     * KASLR_DISABLED_PINS_TEXT + window-containment). */
    kasld_emit_scalar(SF_KASLR_DISABLED, 1, CONF_PARSED);
  }

  if (m.rand_failed) {
    printf(
        "[.] Kernel attempted KASLR but randomization did not run "
        "(firmware-/boot-stub-determined placement, not link-time default)\n");
    /* Distinct from SF_KASLR_DISABLED: the boot stub still relocated the
     * image, so we cannot pin to KERNEL_TEXT_DEFAULT. Consumed by the
     * hardening report and (planned) by EFI loader-pool tightening and an
     * s390-specific boot-stub-placement inference rule. */
    kasld_emit_scalar(SF_KASLR_RANDOMIZATION_FAILED, 1, CONF_PARSED);
  }

  return 0;
}
