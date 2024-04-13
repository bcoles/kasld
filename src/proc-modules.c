// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Retrieve virtual address for loadable kernel modules from
// /proc/modules.
//
// Kernel module addresses are masked (unless `kptr_restrict = 0`).
//
// Requires:
// - kernel.kptr_restrict = 0 (Default on Debian <= 9 systems)
// ---
// <bcoles@gmail.com>

#define _GNU_SOURCE
#include "include/kasld.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned long get_addr_proc_modules() {
  FILE *f;
  char *endptr;
  char *line = 0;
  char *addr_buf;
  size_t size = 0;
  const char *path = "/proc/modules";
  unsigned long module_addr = 0;
  unsigned long addr = 0;

  printf("[.] reading %s ...\n", path);

  f = fopen(path, "r");

  if (f == NULL) {
    perror("[-] fopen");
    return 0;
  }

  while ((getline(&line, &size, f)) != -1) {
    addr_buf = strstr(line, " 0x");
    if (addr_buf == NULL)
      continue;

    module_addr = strtoul(addr_buf, &endptr, 16);
    if (!module_addr)
      continue;

    // modules may be mapped below kernel text for some architectures
    // (arm32/riscv64/ppc32/...)
    if (module_addr <= KERNEL_VAS_END) {
      // printf("Found module address: %lx\n", module_addr);
      if (!addr || module_addr < addr)
        addr = module_addr;
    }
  }

  free(line);
  fclose(f);

  return addr;
}

int main() {
  unsigned long addr = get_addr_proc_modules();
  if (!addr)
    return 1;

  printf("lowest leaked module text address: %lx\n", addr);

  if (addr < MODULES_START || addr > MODULES_END)
    printf("[!] warning: module located outside of defined MODULES_START and "
           "MODULES_END range (%lx - %lx)\n",
           MODULES_START, MODULES_END);

  return 0;
}
