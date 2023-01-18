// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Check kernel config for CONFIG_RELOCATABLE and CONFIG_RANDOMIZE_BASE
//
// Requires:
// - CONFIG_PROC_FS=y
// - CONFIG_IKCONFIG=y
// - CONFIG_IKCONFIG_PROC=y
//
// References:
// https://lwn.net/Articles/444556/
// https://cateee.net/lkddb/web-lkddb/RANDOMIZE_BASE.html
// https://cateee.net/lkddb/web-lkddb/RELOCATABLE.html
// ---
// <bcoles@gmail.com>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "kasld.h"

unsigned long get_kernel_addr_proc_config() {
  const char* path = "/proc/config.gz";
  printf("[.] checking %s ...\n", path);

  if (system("test -r /proc/config.gz") != 0) {
    fprintf(stderr, "[-] Could not read %s\n", path);
    return 0;
  }

  if (system("zgrep -q CONFIG_RELOCATABLE=y /proc/config.gz && "
             "zgrep -q CONFIG_RANDOMIZE_BASE=y /proc/config.gz") == 0)
    return 0;

  printf("[.] Kernel appears to have been compiled without CONFIG_RELOCATABLE "
         "and CONFIG_RANDOMIZE_BASE\n");

  return (unsigned long)KERNEL_TEXT_DEFAULT;
}

int main() {
  unsigned long addr = get_kernel_addr_proc_config();
  if (!addr)
    return 1;

  printf("common default kernel text for arch: %lx\n", addr);

  return 0;
}
