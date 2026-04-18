// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Shared kernel config parsing helpers.
//
// Provides is_kconfig_set(), get_kconfig_page_offset(), and
// kconfig_has_kaslr() for use by boot-config.c and proc-config.c.
//
// All functions operate on an already-opened seekable FILE* — the caller
// is responsible for opening the config source (boot file, /proc/config.gz,
// etc.) and closing it afterwards.
// ---
// <bcoles@gmail.com>

#ifndef KASLD_KCONFIG_H
#define KASLD_KCONFIG_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Check if a kernel config option is set (CONFIG_FOO=y).
 * Rewinds fp before searching. Returns 1 if set, 0 otherwise. */
static int is_kconfig_set(FILE *fp, const char *config) {
  char pattern[BUFSIZ], buf[BUFSIZ];

  snprintf(pattern, sizeof(pattern), "%s=y", config);
  rewind(fp);

  printf("[.] checking for %s... \n", config);

  while (fgets(buf, sizeof(buf), fp) != NULL) {
    if (strncmp(buf, pattern, strlen(pattern)) == 0)
      return 1;
  }

  return 0;
}

/* Search for CONFIG_PAGE_OFFSET=0x... in the kernel config.
 * Falls back to CONFIG_VMSPLIT_* choices (x86_32, arm32).
 * Returns the value, or 0 if not found. */
static unsigned long get_kconfig_page_offset(FILE *fp) {
  const char *key = "CONFIG_PAGE_OFFSET=";
  size_t keylen = strlen(key);
  char buf[BUFSIZ];

  rewind(fp);

  while (fgets(buf, sizeof(buf), fp) != NULL) {
    if (strncmp(buf, key, keylen) == 0) {
      unsigned long val = strtoul(buf + keylen, NULL, 0);
      if (val)
        return val;
    }
  }

  /* Fallback: check CONFIG_VMSPLIT_* choices (x86_32, arm32) */
  const struct {
    const char *config;
    unsigned long page_offset;
  } vmsplit_map[] = {
      {"CONFIG_VMSPLIT_1G", 0x40000000ul},
      {"CONFIG_VMSPLIT_2G", 0x80000000ul},
      {"CONFIG_VMSPLIT_2G_OPT", 0x78000000ul},
      {"CONFIG_VMSPLIT_3G", 0xc0000000ul},
      {"CONFIG_VMSPLIT_3G_OPT", 0xb0000000ul},
      {NULL, 0},
  };

  for (int i = 0; vmsplit_map[i].config; i++) {
    if (is_kconfig_set(fp, vmsplit_map[i].config))
      return vmsplit_map[i].page_offset;
  }

  return 0;
}

/* Check if the kernel was compiled with KASLR support
 * (CONFIG_RELOCATABLE=y and CONFIG_RANDOMIZE_BASE=y).
 * Returns 1 if KASLR is enabled, 0 otherwise. */
static int kconfig_has_kaslr(FILE *fp) {
  return is_kconfig_set(fp, "CONFIG_RELOCATABLE") &&
         is_kconfig_set(fp, "CONFIG_RANDOMIZE_BASE");
}

#endif /* KASLD_KCONFIG_H */
