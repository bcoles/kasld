// This file is part of KASLD - https://github.com/bcoles/kasld
//
// riscv64 KASLR-disabled detection: on a non-EFI riscv64 boot whose CPU lacks
// the 'zkr' ISA extension, the kernel sits at the compile-time default with no
// randomization when the FDT /chosen/kaslr-seed did not place it. Two runtime
// states show that: the seed cell is absent, or it is present but still holds a
// non-zero value. The kernel reads and zeroes the cell in one step when it
// consumes it (arch/riscv/kernel/pi/fdt_early.c), and the wiped blob is what is
// later unflattened into /proc/device-tree, so a visible non-zero cell proves
// the seed was never consumed and the kernel did not move. A present-but-zero
// cell is ambiguous (consumed then wiped, or a zero seed supplied) and is left
// inert. setup_vm() seeds KASLR from the Zkr `seed` CSR first and only falls
// back to the FDT property when Zkr returns 0, so the 'zkr' guard is required
// to avoid a false KASLR-off verdict on Zkr-capable hardware.
//
// The verdict holds on an EFI boot too, and the virtual axis is asserted there.
// setup_vm() derives the virtual offset from the seed alone
// (`virt_offset = (kaslr_seed % nr_pos) * PMD_SIZE`), and the EFI stub writes
// /chosen/kaslr-seed only when it actually obtained randomness
// (drivers/firmware/efi/libstub/fdt.c), so an absent cell is evidence about the
// stub rather than about EFI being present.
//
// The PHYSICAL axis does not follow on an EFI boot, and is gated accordingly.
// The stub draws a SEPARATE seed for the physical placement
// (efi_kaslr_get_phys_seed, drivers/firmware/efi/libstub/kaslr.c) and relocates
// with it, so an absent FDT cell does not establish an unrandomized physical
// base there. Off EFI the one seed feeds both, which is why the phys fact is
// emitted only when /sys/firmware/efi is genuinely absent. Emits
// SF_VIRT_KASLR_DISABLED always, SF_PHYS_KASLR_DISABLED off EFI. The virt pin
// is owned by riscv64_text_base, which pins Q_VIRT_IMAGE_BASE to
// arch_default_text_base() capped at CONF_INFERRED, not by
// virt_kaslr_disabled_pin (KASLR_DISABLED_PINS_VIRT_TEXT is 0 on riscv64); the
// phys pin is inert (KASLR_DISABLED_PINS_PHYS=0 — riscv64 phys placement is
// firmware-determined). riscv64 only — gated at compile time so non-riscv64
// builds skip via the Makefile's `cc-component` wrapper instead of shipping a
// no-op binary.
// ---
// <bcoles@gmail.com>
#if !defined(__riscv) && !defined(__riscv__)
#error "Architecture is not supported"
#endif

#include "include/kasld/api.h"
#include "include/kasld/cli.h"
#include "include/kasld/kaslr_default.h"

#include <errno.h>
#include <unistd.h>

KASLD_EXPLAIN(
    "On riscv64 with no 'zkr' ISA extension, virtual KASLR is off and "
    "the kernel sits at the compile-time default when the FDT "
    "/chosen/kaslr-seed did not place it: the cell is absent, or "
    "present but still non-zero (the kernel wipes it on consume, so a "
    "visible seed was never used). The virtual offset is derived from "
    "that seed alone, so the verdict holds whether or not the system "
    "booted through EFI. Emits SF_VIRT_KASLR_DISABLED, plus "
    "SF_PHYS_KASLR_DISABLED off EFI only -- the EFI stub draws its own "
    "seed for the physical placement. The Zkr seed CSR takes priority "
    "over the FDT seed, so a Zkr-capable CPU is excluded from the "
    "verdict. riscv64 only.");
KASLD_META("method:parsed\n"
           "phase:inference\n"
           "discloses:facts\n"
           "source:files\n");

int main(void) {
  kasld_info("checking /proc/device-tree/chosen for a kaslr-seed ...");
  if (kasld_kaslr_disabled_text_default()) {
    kasld_emit_scalar(SF_VIRT_KASLR_DISABLED, 1, CONF_PARSED);
    /* Physical placement follows the same seed only off EFI; the stub has its
       own. Only a genuine ENOENT rules EFI out, so the phys fact -- unlike the
       virt one -- is withheld from a vantage that cannot see /sys/firmware. */
    if (kasld_access("/sys/firmware/efi", F_OK) != 0 && errno == ENOENT)
      kasld_emit_scalar(SF_PHYS_KASLR_DISABLED, 1, CONF_PARSED);
  }
  return 0;
}
