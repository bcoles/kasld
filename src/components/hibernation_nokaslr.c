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
#include "include/kasld.h"
#include "include/kasld_internal.h"

#include <stdio.h>
#include <string.h>
#include <sys/utsname.h>

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

/* Open the kernel boot config at well-known paths. Returns an open FILE*
 * or NULL. Mirrors the search order used by boot-config.c. */
static FILE *open_boot_config(const char *release) {
  const char *fixed_paths[] = {"/boot/config", NULL};
  for (int i = 0; fixed_paths[i]; i++) {
    FILE *fp = fopen(fixed_paths[i], "r");
    if (fp)
      return fp;
  }

  const char *release_fmts[] = {
      "/boot/config-%s",
      "/lib/modules/%s/build/.config",
      "/lib/modules/%s/config",
      NULL,
  };
  char path[256];
  for (int i = 0; release_fmts[i]; i++) {
    snprintf(path, sizeof(path), release_fmts[i], release);
    FILE *fp = fopen(path, "r");
    if (fp)
      return fp;
  }
  return NULL;
}

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

  printf("[.] checking for hibernation-disabled KASLR ...\n");

  /* "resume=" must be present — this is the hibernation resume path. */
  if (!cmdline_has_prefix("resume=")) {
    fprintf(stderr, "[-] resume= not found on cmdline.\n");
    return 1;
  }

  /* "nohibernate" or "noresume" on the cmdline cancels hibernation,
   * restoring normal KASLR. */
  if (cmdline_has_word("nohibernate") || cmdline_has_word("noresume")) {
    fprintf(stderr,
            "[-] nohibernate/noresume present; hibernation cancelled.\n");
    return 1;
  }

  /* CONFIG_HIBERNATION=y must be compiled in for the kernel to act on
   * resume=. Without it the parameter is ignored and KASLR is not affected. */
  struct utsname uts;
  if (uname(&uts) != 0) {
    fprintf(stderr, "[-] uname() failed.\n");
    return 1;
  }

  FILE *fp = open_boot_config(uts.release);
  if (!fp) {
    fprintf(stderr, "[-] could not open boot config.\n");
    return KASLD_EXIT_UNAVAILABLE;
  }

  printf("[.] checking for CONFIG_HIBERNATION ...\n");
  int has_hib = config_has_hibernation(fp);
  fclose(fp);

  if (!has_hib) {
    fprintf(
        stderr,
        "[-] CONFIG_HIBERNATION=y not set; resume= has no effect on KASLR.\n");
    return 1;
  }

  /* All conditions met: KASLR was disabled at boot. The kernel loaded at
   * the compile-time default text address (KERNEL_TEXT_DEFAULT). */
  printf("[.] hibernation resume detected with CONFIG_HIBERNATION=y; KASLR "
         "disabled.\n");

  unsigned long addr = (unsigned long)KERNEL_TEXT_DEFAULT;
  printf("common default kernel text for arch: %lx\n", addr);
  kasld_result(KASLD_ADDR_DEFAULT, KASLD_SECTION_NONE, addr,
               KASLD_REGION_KERNEL_TEXT, "nokaslr");

  return 0;
}
