// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Emit SF_EFI_PRESENT: 1 when /sys/firmware/efi is present (EFI boot), 0 when
// the access fails for any reason other than a permission denial (absent:
// non-EFI). On EACCES — a SELinux-confined process that cannot traverse
// /sys/firmware — emit NOTHING, so a consumer sees "unknown" (the fact absent)
// rather than a false "non-EFI": a denied read must not manufacture a fact that
// lets a rule narrow the window. Withholding ONLY on EACCES (not on every
// failure) keeps the emitted fact independent of the KASLD_SYSROOT prefix
// length, which sysroot containment requires. kaslr_default.h guards the same
// access() path.
// ---
// <bcoles@gmail.com>
#include "include/kasld/api.h"
#include <errno.h>
#include <unistd.h>

KASLD_EXPLAIN(
    "Checks for /sys/firmware/efi and emits SF_EFI_PRESENT: 1 present, "
    "0 genuinely absent, nothing when undeterminable (e.g. EACCES to a "
    "confined process). Several rules gate on EFI vs non-EFI boot. No "
    "privileges.");
KASLD_META("method:parsed\n"
           "phase:inference\n"
           "discloses:facts\n"
           "source:files\n");

int main(void) {
  if (kasld_access("/sys/firmware/efi", F_OK) == 0)
    kasld_emit_scalar(SF_EFI_PRESENT, 1, CONF_PARSED); /* EFI boot */
  else if (errno != EACCES)
    kasld_emit_scalar(SF_EFI_PRESENT, 0, CONF_PARSED); /* absent -> non-EFI */
  /* else (EACCES): access denied to this vantage (e.g. a SELinux-confined
     process that cannot traverse /sys/firmware) — emit nothing, leaving the
     fact absent so no consumer reads a false "non-EFI". */
  return 0;
}
