// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Detect `hugepages=` on /proc/cmdline and emit SF_CMDLINE_HUGEPAGES.
//
// Detection component — does not leak an address.
//   Purpose: presence of `hugepages=<N>` on the cmdline is one of three
//   triggers (mem=, memmap=, hugepages=) that the x86 EFI stub uses to zero
//   the physical-KASLR seed (drivers/firmware/efi/libstub/x86-stub.c
//   parse_options() + cmdline_memmap_override). The downstream rule
//   x86_64_efi_phys_seed_zero ORs this scalar with SF_PHYS_CMDLINE_MEM and the
//   REGION_CMDLINE_MEMMAP observation count to detect the seed-zero
//   condition. Value-only carrier — emitted with value=1 on presence.
//
// /proc/cmdline is world-readable (0444). Scope: x86 (the trigger only
// applies on the x86 EFI stub); the component returns 0 elsewhere so it
// does not pollute non-x86 evidence with a fact that has no consumer.
//
// References:
// https://elixir.bootlin.com/linux/v6.12/source/drivers/firmware/efi/libstub/x86-stub.c#L815
// ---
// <bcoles@gmail.com>

#include "include/cmdline.h"
#include "include/kasld/api.h"
#include "include/kasld/cli.h"
#include <stdio.h>

KASLD_EXPLAIN(
    "x86 only: emits SF_CMDLINE_HUGEPAGES=1 if `hugepages=` is on "
    "/proc/cmdline. Combined with SF_EFI_PRESENT and the other cmdline "
    "triggers (mem=/memmap=), the EFI stub zeroes the physical-KASLR seed; "
    "x86_64_efi_phys_seed_zero pins Q_PHYS_TEXT_BASE accordingly. "
    "/proc/cmdline is world-readable (0444).");

KASLD_META("method:detection\n"
           "phase:inference\n"
           "addr:none\n");

int main(void) {
#if defined(__x86_64__) || defined(__i386__)
  if (!cmdline_has_prefix("hugepages=")) {
    kasld_err("no `hugepages=` on /proc/cmdline");
    return 1;
  }
  kasld_info("cmdline carries `hugepages=` (EFI stub will zero phys seed)");
  kasld_emit_scalar(SF_CMDLINE_HUGEPAGES, 1, CONF_PARSED);
#endif
  return 0;
}
