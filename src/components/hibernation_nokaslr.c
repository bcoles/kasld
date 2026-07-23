// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Check whether hibernation resume has disabled KASLR.
//
// Detection component — does not leak an address.
//   Purpose: on some architectures, the kernel silently skips KASLR
//   relocation when performing a hibernation resume (i.e. "resume="
//   is present on the command line and CONFIG_HIBERNATION=y is compiled
//   in).
//
// History:
//   x86/x86_64: affected before commit 65fe935dd238 in v4.8 (2016).
//               Fixed: KASLR is now hibernation-compatible on x86.
//   LoongArch:  still affected as of v6.17. arch/loongarch/kernel/
//               relocate.c kaslr_disabled() returns true when resume=
//               is present, CONFIG_HIBERNATION=y, and neither
//               nohibernate nor noresume cancels it.
//
// Detection (no privileges required):
//   /proc/cmdline — check for "resume=", absence of "nohibernate" and
//                   "noresume" (world-readable, 0444).
//   /boot/config-$(uname -r) — check CONFIG_HIBERNATION=y.
//
// References:
//   arch/loongarch/kernel/relocate.c (v6.17):
//     https://elixir.bootlin.com/linux/v6.17/source/arch/loongarch/kernel/relocate.c#L130
//   arch/x86 fix:
//     https://github.com/torvalds/linux/commit/65fe935dd2387a4faf15314c73f5e6d31ef0217e
// ---
// <bcoles@gmail.com>

#define _POSIX_C_SOURCE 200809L

#include "include/cmdline.h"
#include "include/kasld/api.h"
#include "include/kasld/bootconfig.h"
#include "include/kasld/cli.h"

#include <stdio.h>
#include <string.h>

KASLD_EXPLAIN(
    "Checks whether a hibernation resume has disabled KASLR. On some "
    "architectures (currently LoongArch; historically x86 before v4.8), "
    "the kernel silently skips KASLR relocation when 'resume=' is present "
    "on the command line and CONFIG_HIBERNATION=y is compiled in. No dmesg "
    "message is emitted for this path. Detection reads /proc/cmdline "
    "(world-readable) and the boot config file.");

KASLD_META("method:detection\n"
           "phase:inference\n"
           "addr:none\n");

/* Return 1 if CONFIG_HIBERNATION=y appears in an already-open config file. */
static int config_has_hibernation(FILE *fp) {
  const char *needle = "CONFIG_HIBERNATION=y";
  char buf[256];
  rewind(fp);
  while (fgets(buf, sizeof(buf), fp) != NULL) {
    if (strncmp(buf, needle, strlen(needle)) == 0)
      return 1;
  }
  return 0;
}

int main(void) {
  /* Only LoongArch still disables KASLR during hibernation resume (v6.17).
   * On x86/x86_64 this was fixed in kernel v4.8 (commit 65fe935dd238).
   * All other architectures are unaffected. The Makefile compiles every
   * component for every target, so this guard prevents false positives on
   * non-LoongArch builds. */
#if !defined(__loongarch__)
  return KASLD_EXIT_UNAVAILABLE;
#endif

  kasld_info("checking for hibernation-disabled KASLR ...");

  /* "resume=" must be present — this is the hibernation resume path. */
  if (!cmdline_has_prefix("resume=")) {
    kasld_err("resume= not found on cmdline.");
    return 1;
  }

  /* "nohibernate" or "noresume" on the cmdline cancels hibernation,
   * restoring normal KASLR. */
  if (cmdline_has_word("nohibernate") || cmdline_has_word("noresume")) {
    kasld_err("nohibernate/noresume present; hibernation cancelled.");
    return 1;
  }

  /* CONFIG_HIBERNATION=y must be compiled in for the kernel to act on
   * resume=. Without it the parameter is ignored and KASLR is not affected.
   * The shared reader tries release-keyed paths first and flags the unkeyed
   * /boot/config, which has no binding to the running kernel. */
  int is_unkeyed = 0;
  FILE *fp = kasld_open_boot_config(&is_unkeyed);
  if (!fp) {
    kasld_err("could not open boot config.");
    return KASLD_EXIT_UNAVAILABLE;
  }

  kasld_info("checking for CONFIG_HIBERNATION ...");
  int has_hib = config_has_hibernation(fp);
  fclose(fp);

  if (!has_hib) {
    kasld_err("CONFIG_HIBERNATION=y not set; resume= has no effect on KASLR.");
    return 1;
  }

  /* All conditions met: KASLR was disabled at boot for the hibernation
   * resume. The kernel loaded at the compile-time defaults; both axes are
   * off. virt_kaslr_disabled_pin / phys_kaslr_disabled_pin each gate by
   * its arch macro (KASLR_DISABLED_PINS_VIRT_TEXT / KASLR_DISABLED_PINS_PHYS) +
   * window-containment. A stale/foreign unkeyed /boot/config could carry
   * CONFIG_HIBERNATION=y while the running kernel differs, so its verdict is
   * held below the guaranteed floor (CONF_HEURISTIC) — it cannot forge the
   * pin-to-default C_EQUALS; a release-keyed config stays authoritative. */
  enum kasld_confidence conf = is_unkeyed ? CONF_HEURISTIC : CONF_PARSED;
  kasld_info("hibernation resume detected with CONFIG_HIBERNATION=y; KASLR "
             "disabled.");

  kasld_emit_scalar(SF_VIRT_KASLR_DISABLED, 1, conf);
  kasld_emit_scalar(SF_PHYS_KASLR_DISABLED, 1, conf);

  return 0;
}
