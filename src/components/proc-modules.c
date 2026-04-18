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
#include "include/kasld_internal.h"
#include "include/kasld_types.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define module_range addr_range

struct module_range get_addr_proc_modules() {
  FILE *f;
  char *endptr;
  char *line = 0;
  char *addr_buf;
  size_t size = 0;
  const char *path = "/proc/modules";
  unsigned long module_addr = 0;
  struct module_range range = {0, 0};

  printf("[.] reading %s ...\n", path);

  f = fopen(path, "r");

  if (f == NULL) {
    perror("[-] fopen");
    return range;
  }

  while ((getline(&line, &size, f)) != -1) {
    addr_buf = strstr(line, " 0x");
    if (addr_buf == NULL)
      continue;

    module_addr = strtoul(addr_buf, &endptr, 16);
    if (!module_addr)
      continue;

    if (module_addr >= MODULES_START && module_addr <= MODULES_END) {
      if (!range.lo || module_addr < range.lo)
        range.lo = module_addr;
      if (module_addr > range.hi)
        range.hi = module_addr;
    }
  }

  free(line);
  fclose(f);

  return range;
}

int main(void) {
  /* Pre-check: can we access /proc/modules? */
  if (access("/proc/modules", R_OK) != 0)
    return (errno == EACCES || errno == EPERM) ? KASLD_EXIT_NOPERM
                                               : KASLD_EXIT_UNAVAILABLE;

  struct module_range range = get_addr_proc_modules();
  if (!range.lo) {
    printf("[-] no kernel address found in /proc/modules\n");
    return 0;
  }

  printf("lowest leaked module address:  %lx\n", range.lo);
  kasld_result(KASLD_ADDR_VIRT, KASLD_SECTION_MODULE, range.lo,
               "proc-modules:lo");

  if (range.hi != range.lo) {
    printf("highest leaked module address: %lx\n", range.hi);
    kasld_result(KASLD_ADDR_VIRT, KASLD_SECTION_MODULE, range.hi,
                 "proc-modules:hi");
  }

  return 0;
}
