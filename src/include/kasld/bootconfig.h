// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Kernel boot_config reader (/boot/config-*, /lib/modules/*/...), no
// privileges.
//
// Read by the engine bridge. Reads route through the kasld_* wrappers, so it is
// KASLD_SYSROOT-aware. Search order mirrors boot_config.c: release-keyed paths
// first (bound to the running kernel), the unkeyed /boot/config last and
// flagged, so callers can hold its facts below the guaranteed floor.
// ---
// <bcoles@gmail.com>

#ifndef KASLD_BOOTCONFIG_H
#define KASLD_BOOTCONFIG_H

#include "sysroot.h"

#include <errno.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>

/* Open the kernel config file. Release-keyed paths are tried FIRST — they are
 * installed by the running kernel's own package for this exact uname release,
 * so their Kconfig answers describe the running kernel. The unkeyed
 * /boot/config is tried LAST as a best-effort fallback: it carries no release
 * binding (it may be a leftover from another kernel or a rescue image), so when
 * it is the match, *is_unkeyed (if non-NULL) is set to 1 and callers demote its
 * facts below the guaranteed floor. */
/* Set when a candidate config existed but could not be read. /boot is mode
 * 0700 root on a number of distributions, so a denied config is a routine
 * outcome and a different fact from a kernel built without one. Read it after
 * kasld_open_boot_config returns NULL. */
__attribute__((unused)) static int kasld_boot_config_denied;

__attribute__((unused)) static FILE *kasld_open_boot_config(int *is_unkeyed) {
  if (is_unkeyed)
    *is_unkeyed = 0;
  kasld_boot_config_denied = 0;

  struct utsname uts;
  if (kasld_uname(&uts) == 0) {
    /* Split either side of the release rather than held as three format
     * strings: a format reaching snprintf through an array cannot be checked
     * against its argument, while one literal with the varying parts passed as
     * arguments is checked in full. */
    static const struct {
      const char *pre, *post;
    } cand[] = {
        {"/boot/config-", ""},
        {"/lib/modules/", "/build/.config"},
        {"/lib/modules/", "/config"},
    };
    char path[256];
    for (unsigned i = 0; i < sizeof(cand) / sizeof(cand[0]); i++) {
      snprintf(path, sizeof(path), "%s%s%s", cand[i].pre, uts.release,
               cand[i].post);
      FILE *fp = kasld_fopen(path, "r");
      if (fp)
        return fp;
      if (errno == EACCES || errno == EPERM)
        kasld_boot_config_denied = 1;
    }
  }

  /* Last resort: the unkeyed /boot/config (no release binding). */
  FILE *fp = kasld_fopen("/boot/config", "r");
  if (!fp && (errno == EACCES || errno == EPERM))
    kasld_boot_config_denied = 1;
  if (fp) {
    if (is_unkeyed)
      *is_unkeyed = 1;
    return fp;
  }
  return NULL;
}

/* Value of a "CONFIG_<KEY>=<number>" option (strtoul base 0, so decimal or
 * 0x-hex), or 0 if the config is unreadable or the option is absent/malformed.
 * `key` must include the trailing '=' (e.g. "CONFIG_PAGE_OFFSET="). Sets
 * *is_unkeyed per kasld_open_boot_config. */
__attribute__((unused)) static unsigned long
kasld_config_get_ulong(const char *key, int *is_unkeyed) {
  FILE *fp = kasld_open_boot_config(is_unkeyed);
  if (!fp)
    return 0;

  const size_t keylen = strlen(key);
  char buf[256];
  unsigned long out = 0;
  while (fgets(buf, sizeof(buf), fp) != NULL) {
    if (strncmp(buf, key, keylen) == 0) {
      char *end;
      unsigned long val = strtoul(buf + keylen, &end, 0);
      if (end != buf + keylen && val > 0) {
        out = val;
        break;
      }
    }
  }
  fclose(fp);
  return out;
}

/* CONFIG_RANDOMIZE_BASE_MAX_OFFSET (MIPS/LoongArch KASLR offset mask), or 0. */
__attribute__((unused)) static unsigned long
kasld_read_randomize_max_offset(int *is_unkeyed) {
  return kasld_config_get_ulong("CONFIG_RANDOMIZE_BASE_MAX_OFFSET=",
                                is_unkeyed);
}

/* CONFIG_PAGE_OFFSET (the configured virt_page_offset / VMSPLIT on arches where
 * it is a compile-time constant), or 0. Authoritative only on arches where
 * virt_page_offset cannot be overridden at runtime — the consuming rule gates
 * on PAGE_OFFSET_FROM_CONFIG, NOT this reader. */
__attribute__((unused)) static unsigned long
kasld_read_config_page_offset(int *is_unkeyed) {
  return kasld_config_get_ulong("CONFIG_PAGE_OFFSET=", is_unkeyed);
}

#endif /* KASLD_BOOTCONFIG_H */
