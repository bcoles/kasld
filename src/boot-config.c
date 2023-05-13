// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Check kernel config for both CONFIG_RELOCATABLE and CONFIG_RANDOMIZE_BASE.
//
// References:
// https://lwn.net/Articles/444556/
// https://cateee.net/lkddb/web-lkddb/RANDOMIZE_BASE.html
// https://cateee.net/lkddb/web-lkddb/RELOCATABLE.html
// ---
// <bcoles@gmail.com>

#include "kasld.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>

// from:
// https://stackoverflow.com/questions/22240476/checking-linux-kernel-config-at-runtime
static int is_kconfig_set(const char *config) {
  int ret = 0;
  struct utsname utsname;
  char pattern[BUFSIZ], buf[BUFSIZ];
  FILE *fp = NULL;

  if (uname(&utsname) == -1)
    return -1;

  memset(pattern, 0, sizeof(pattern));
  memset(buf, 0, sizeof(buf));
  sprintf(pattern, "%s=y", config);
  sprintf(buf, "/boot/config-%s", utsname.release);

  printf("[.] checking %s for %s... \n", buf, config);

  fp = fopen(buf, "r");
  if (fp == NULL) {
    perror("[-] fopen");
    return -1;
  }

  while (fgets(buf, sizeof(buf), fp) != NULL) {
    if (strncmp(buf, pattern, strlen(pattern)) == 0) {
      ret = 1;
      break;
    }
  }

  fclose(fp);
  return ret;
}

unsigned long get_kernel_addr_boot_config() {
  int relocatable = is_kconfig_set("CONFIG_RELOCATABLE");
  if (relocatable == -1)
    return 0;

  int randomize_base = is_kconfig_set("CONFIG_RANDOMIZE_BASE");
  if (randomize_base == -1)
    return 0;

  if (relocatable && randomize_base)
    return 0;

  printf("[.] Kernel appears to have been compiled without both "
         "CONFIG_RELOCATABLE and CONFIG_RANDOMIZE_BASE\n");

  return (unsigned long)KERNEL_TEXT_DEFAULT;
}

int main() {
  unsigned long addr = get_kernel_addr_boot_config();
  if (!addr)
    return 1;

  printf("common default kernel text for arch: %lx\n", addr);

  return 0;
}
