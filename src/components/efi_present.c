// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Emit SF_EFI_PRESENT: 1 if /sys/firmware/efi exists (EFI boot), else 0. Always
// emitted so rules can distinguish "non-EFI" from "unknown".
// ---
// <bcoles@gmail.com>
#include "include/kasld/api.h"
#include <unistd.h>

KASLD_EXPLAIN("Checks for /sys/firmware/efi and emits SF_EFI_PRESENT (0 or 1). "
              "Several rules gate on EFI vs non-EFI boot. No privileges.");
KASLD_META("method:parsed\n"
           "phase:inference\n");

int main(void) {
  int present = (kasld_access("/sys/firmware/efi", F_OK) == 0) ? 1 : 0;
  kasld_emit_scalar(SF_EFI_PRESENT, (unsigned long)present, CONF_PARSED);
  return 0;
}
