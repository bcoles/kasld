// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Kernel boot_config reader (/boot/config-*, /lib/modules/*/...), no
// privileges.
//
// Read by the engine bridge. Reads route through the kasld_* wrappers, so it is
// KASLD_SYSROOT-aware (replayable). Search order mirrors boot_config.c.
// ---
// <bcoles@gmail.com>

#ifndef KASLD_BOOTCONFIG_H
#define KASLD_BOOTCONFIG_H

#include "sysroot.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>

/* Open the kernel config file at well-known paths (release-specific last). */
__attribute__((unused)) static FILE *kasld_open_boot_config(void) {
  FILE *fp = kasld_fopen("/boot/config", "r");
  if (fp)
    return fp;

  struct utsname uts;
  if (kasld_uname(&uts) != 0)
    return NULL;

  const char *fmts[] = {
      "/boot/config-%s",
      "/lib/modules/%s/build/.config",
      "/lib/modules/%s/config",
      NULL,
  };
  char path[256];
  for (int i = 0; fmts[i]; i++) {
    snprintf(path, sizeof(path), fmts[i], uts.release);
    fp = kasld_fopen(path, "r");
    if (fp)
      return fp;
  }
  return NULL;
}

/* Value of a "CONFIG_<KEY>=<number>" option (strtoul base 0, so decimal or
 * 0x-hex), or 0 if the config is unreadable or the option is absent/malformed.
 * `key` must include the trailing '=' (e.g. "CONFIG_PAGE_OFFSET="). */
__attribute__((unused)) static unsigned long
kasld_config_get_ulong(const char *key) {
  FILE *fp = kasld_open_boot_config();
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
kasld_read_randomize_max_offset(void) {
  return kasld_config_get_ulong("CONFIG_RANDOMIZE_BASE_MAX_OFFSET=");
}

/* CONFIG_PAGE_OFFSET (the configured page_offset / VMSPLIT on arches where it
 * is a compile-time constant), or 0. Authoritative only on arches where
 * page_offset cannot be overridden at runtime — the consuming rule gates on
 * PAGE_OFFSET_FROM_CONFIG, NOT this reader. */
__attribute__((unused)) static unsigned long
kasld_read_config_page_offset(void) {
  return kasld_config_get_ulong("CONFIG_PAGE_OFFSET=");
}

#endif /* KASLD_BOOTCONFIG_H */
