// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Check kernel config for CONFIG_RELOCATABLE, CONFIG_RANDOMIZE_BASE,
// and CONFIG_PAGE_OFFSET (32-bit vmsplit).
//
// Detection component — does not leak an address.
//   Purpose: reads /boot/config-$(uname -r) to determine whether
//   CONFIG_RANDOMIZE_BASE is set (KASLR compiled in) and what the
//   32-bit vmsplit (CONFIG_PAGE_OFFSET) is. Readable when /boot is
//   accessible (common on most distros).
//
// References:
// https://lwn.net/Articles/444556/
// https://cateee.net/lkddb/web-lkddb/RANDOMIZE_BASE.html
// https://cateee.net/lkddb/web-lkddb/RELOCATABLE.html
// https://cateee.net/lkddb/web-lkddb/PAGE_OFFSET.html
// ---
// <bcoles@gmail.com>

#include "include/kasld.h"
#include "include/kasld_internal.h"
#include "include/kconfig.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>

KASLD_EXPLAIN(
    "Reads /boot/config-$(uname -r) to check whether CONFIG_RANDOMIZE_BASE "
    "is set (KASLR compiled in) and determines the 32-bit vmsplit "
    "(CONFIG_PAGE_OFFSET). Readable when /boot is accessible.");

KASLD_META("method:detection\n"
           "phase:inference\n"
           "addr:none\n");

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

static unsigned long get_kernel_addr_boot_config(FILE *fp) {
  if (kconfig_has_kaslr(fp))
    return 0;

  printf("[.] Kernel appears to have been compiled without both "
         "CONFIG_RELOCATABLE and CONFIG_RANDOMIZE_BASE\n");

  return (unsigned long)KERNEL_TEXT_DEFAULT;
}

int main(void) {
  FILE *fp;
  if (open_boot_config(&fp) < 0)
    return KASLD_EXIT_UNAVAILABLE;

  /* Detect PAGE_OFFSET (32-bit vmsplit) */
  unsigned long page_offset = get_kconfig_page_offset(fp);
  if (page_offset) {
    printf("[.] CONFIG_PAGE_OFFSET: %#lx\n", page_offset);
    kasld_result(KASLD_ADDR_VIRT, KASLD_SECTION_PAGEOFFSET, page_offset,
                 KASLD_REGION_PAGE_OFFSET, NULL);
  }

  /* Detect KASLR disabled — emit a DEFAULT-type marker.
   * Region carries the standard KERNEL_TEXT (the address truly is the
   * default kernel text base); the "nokaslr" name is the state marker
   * detect_kaslr_state() looks for. */
  unsigned long addr = get_kernel_addr_boot_config(fp);
  if (addr) {
    printf("common default kernel text for arch: %lx\n", addr);
    kasld_result(KASLD_ADDR_DEFAULT, KASLD_SECTION_NONE, addr,
                 KASLD_REGION_KERNEL_TEXT, "nokaslr");
  }

  fclose(fp);

  return 0;
}
