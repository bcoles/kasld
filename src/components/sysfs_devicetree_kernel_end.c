// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Read the physical end of the kernel image from the device-tree chosen
// node (/sys/firmware/devicetree/base/chosen/linux,kernel-end). The
// PowerPC Open Firmware client interface stores this property when the
// firmware hands off control to the kernel: it is the address one byte
// past the last byte of the kernel image as loaded by the bootloader.
//
// On a system where the property is present, it is a hard upper bound on
// where the kernel image's last byte sits, so:
//
//   phys_text_base + image_size <= linux,kernel-end
//
// emits as a PHYS REGION_KERNEL_IMAGE observation with the TOP edge set
// (HAS_HI). The existing kernel_image_phys_bound rule consumes phys
// kernel-image observations to bound Q_PHYS_TEXT_BASE, and the
// text_base_coupling_synth rule projects the result onto Q_VIRT_TEXT_BASE
// on coupled arches. No new rule needed.
//
// Origin: arch/powerpc/kernel/prom.c sets the property from
//   prom_init.c's image-placement bookkeeping. World-readable (0444); no
//   sysctl gates it. Only PowerPC firmware writes this property —
//   absent on arm/arm64/riscv/mips devicetrees (those firmware paths use
//   their own conventions for kernel placement). Harmless on arches
//   that don't set it: file absent -> component returns no-result.
// ---
// <bcoles@gmail.com>

#include "include/kasld/api.h"
#include "include/kasld/devicetree.h"

KASLD_EXPLAIN(
    "Reads /sys/firmware/devicetree/base/chosen/linux,kernel-end — the "
    "physical address one byte past the loaded kernel image, set by "
    "PowerPC firmware on its handoff. Emits a PHYS kernel_image "
    "observation with the TOP edge; kernel_image_phys_bound consumes it "
    "to derive a tight upper bound on Q_PHYS_TEXT_BASE. World-readable; "
    "no sysctl gates it.");

KASLD_META("method:parsed\n"
           "phase:inference\n"
           "addr:physical\n"
           "config:CONFIG_OF\n");

int main(void) {
  const char *bases[] = {"/sys/firmware/devicetree/base/chosen",
                         "/proc/device-tree/chosen", NULL};
  char path[512];
  unsigned long kend = 0;
  int found = 0;

  for (int i = 0; bases[i]; i++) {
    snprintf(path, sizeof(path), "%s/linux,kernel-end", bases[i]);
    if (kasld_dt_read_be_auto(path, &kend)) {
      printf("[.] %s = 0x%lx\n", path, kend);
      found = 1;
      break;
    }
  }

  if (!found) {
    fprintf(stderr, "[-] linux,kernel-end not present (non-PowerPC platform "
                    "or no DT)\n");
    return KASLD_EXIT_UNAVAILABLE;
  }
  if (kend == 0) {
    fprintf(stderr, "[-] linux,kernel-end is zero\n");
    return 0;
  }

  /* Emit as the TOP edge of the kernel image. kernel_image_phys_bound
   * reads phys kernel-image observations with HAS_HI and derives a
   * tight upper bound on Q_PHYS_TEXT_BASE. */
  kasld_result_top(KASLD_TYPE_PHYS, REGION_KERNEL_IMAGE, kend, NULL,
                   CONF_PARSED);
  return 0;
}
