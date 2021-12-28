// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Check kernel command line /proc/cmdline for nokaslr flag
// ---
// <bcoles@gmail.com>

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "kasld.h"

unsigned long get_kernel_addr_cmdline() {
  FILE *f;
  const char *path = "/proc/cmdline";
  const char *flag = "nokaslr";
  char cmdline[1024];

  printf("[.] trying %s ...\n", path);

  f = fopen(path, "rb");
  if (f == NULL) {
    printf("[-] open/read(%s): %m\n", path);
    return 0;
  }

  if (fgets(cmdline, sizeof(cmdline), f) == NULL)
    printf("[-] fgets(%s): %m\n", path);

  fclose(f);

  if (memmem(&cmdline[0], sizeof(cmdline), flag, strlen(flag)) == NULL) {
    printf("[-] Kernel was not booted with nokaslr flag.\n");
    return 0;
  }

  printf("[.] Kernel booted with nokaslr flag.\n");

  return KERNEL_TEXT_DEFAULT;
}

int main(int argc, char **argv) {
  unsigned long addr = get_kernel_addr_cmdline();
  if (!addr)
    return 1;

  printf("common default kernel text for arch: %lx\n", addr);

  return 0;
}
