// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Check kernel config for CONFIG_RELOCATABLE, CONFIG_RANDOMIZE_BASE,
// and CONFIG_PAGE_OFFSET (32-bit vmsplit).
//
// References:
// https://lwn.net/Articles/444556/
// https://cateee.net/lkddb/web-lkddb/RANDOMIZE_BASE.html
// https://cateee.net/lkddb/web-lkddb/RELOCATABLE.html
// https://cateee.net/lkddb/web-lkddb/PAGE_OFFSET.html
// ---
// <bcoles@gmail.com>

#include "include/kasld.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>

static int open_boot_config(FILE **fpp) {
  struct utsname utsname;
  char path[256];

  if (uname(&utsname) == -1)
    return -1;

  /* Try multiple known locations for the kernel config file.
   * Availability depends on CONFIG_IKCONFIG, distro layout, and
   * whether kernel headers are installed. */
  const char *fixed_paths[] = {"/boot/config", NULL};

  for (int i = 0; fixed_paths[i]; i++) {
    *fpp = fopen(fixed_paths[i], "r");
    if (*fpp)
      return 0;
  }

  const char *release_fmts[] = {
      "/boot/config-%s",
      "/lib/modules/%s/build/.config",
      "/lib/modules/%s/config",
      NULL,
  };

  for (int i = 0; release_fmts[i]; i++) {
    snprintf(path, sizeof(path), release_fmts[i], utsname.release);
    *fpp = fopen(path, "r");
    if (*fpp)
      return 0;
  }

  fprintf(stderr, "[-] could not find kernel config\n");
  return -1;
}

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

static unsigned long get_kernel_addr_boot_config(FILE *fp) {
  int relocatable = is_kconfig_set(fp, "CONFIG_RELOCATABLE");
  int randomize_base = is_kconfig_set(fp, "CONFIG_RANDOMIZE_BASE");

  if (relocatable && randomize_base)
    return 0;

  printf("[.] Kernel appears to have been compiled without both "
         "CONFIG_RELOCATABLE and CONFIG_RANDOMIZE_BASE\n");

  return (unsigned long)KERNEL_TEXT_DEFAULT;
}

int main(void) {
  FILE *fp;
  if (open_boot_config(&fp) < 0)
    return 1;

  /* Detect PAGE_OFFSET (32-bit vmsplit) */
  unsigned long page_offset = get_kconfig_page_offset(fp);
  if (page_offset) {
    printf("[.] CONFIG_PAGE_OFFSET: %#lx\n", page_offset);
    kasld_result(KASLD_ADDR_VIRT, KASLD_SECTION_PAGEOFFSET, page_offset,
                 "boot-config:page_offset");
  }

  /* Detect KASLR disabled */
  unsigned long addr = get_kernel_addr_boot_config(fp);
  if (addr) {
    printf("common default kernel text for arch: %lx\n", addr);
    kasld_result(KASLD_ADDR_DEFAULT, KASLD_SECTION_NONE, addr,
                 "boot-config:nokaslr");
  }

  fclose(fp);

  return (page_offset || addr) ? 0 : 1;
}
