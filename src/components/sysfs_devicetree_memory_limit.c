// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Read the physical-RAM ceiling the kernel was instructed to honour from
// the device-tree chosen node (/sys/firmware/devicetree/base/chosen/
// linux,memory-limit). The PowerPC Open Firmware client interface sets
// this property when the user (or firmware) caps RAM via the `mem=`
// boot argument or an equivalent firmware override. It is the largest
// physical address the kernel will treat as usable RAM:
//
//   phys_ram_top <= linux,memory-limit  (when non-zero)
//
// A zero value means "no limit"; on those systems the file exists but
// holds 0, and we emit nothing. On systems where the cap is in effect
// (e.g. constrained pseries guests), emit as a PHYS REGION_RAM
// observation with the TOP edge set so dram_ceiling / phys_*_ceiling
// rules consume it as the authoritative RAM_TOP.
//
// Origin: arch/powerpc/kernel/prom.c parses CONFIG / cmdline / firmware
//   handoff and writes the property at boot. World-readable (0444); no
//   sysctl gates it. PowerPC-firmware-specific; absent on other DT
//   platforms.
// ---
// <bcoles@gmail.com>

#include "include/kasld/api.h"
#include "include/kasld/devicetree.h"

KASLD_EXPLAIN(
    "Reads /sys/firmware/devicetree/base/chosen/linux,memory-limit — the "
    "physical-RAM ceiling the kernel honours (mem= cmdline cap or "
    "firmware-imposed limit), set by PowerPC firmware on handoff. Emits "
    "a PHYS ram observation with the TOP edge when the limit is "
    "non-zero. World-readable; no sysctl gates it.");

KASLD_META("method:parsed\n"
           "phase:inference\n"
           "addr:physical\n"
           "config:CONFIG_OF\n");

int main(void) {
  const char *bases[] = {"/sys/firmware/devicetree/base/chosen",
                         "/proc/device-tree/chosen", NULL};
  char path[512];
  unsigned long limit = 0;
  int found = 0;

  for (int i = 0; bases[i]; i++) {
    snprintf(path, sizeof(path), "%s/linux,memory-limit", bases[i]);
    if (kasld_dt_read_be_auto(path, &limit)) {
      printf("[.] %s = 0x%lx\n", path, limit);
      found = 1;
      break;
    }
  }

  if (!found) {
    fprintf(stderr, "[-] linux,memory-limit not present (non-PowerPC platform "
                    "or no DT)\n");
    return KASLD_EXIT_UNAVAILABLE;
  }
  /* A zero value means "no limit imposed" — emit nothing. */
  if (limit == 0) {
    printf("[.] linux,memory-limit is 0 (no RAM cap imposed)\n");
    return 0;
  }

  /* Emit as a RAM TOP. The value is the highest phys address the kernel
   * will treat as usable, i.e. the inclusive upper edge minus 1; emit
   * (limit - 1) so HAS_HI carries the exact last-byte address. */
  kasld_result_top(KASLD_TYPE_PHYS, REGION_RAM, limit - 1, NULL, CONF_PARSED);
  return 0;
}
