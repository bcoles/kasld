// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Retrieve virtual address for loadable kernel modules from
// /proc/modules.
//
// Kernel module addresses are masked (unless `kptr_restrict = 0`).
//
// Requires:
// - kernel.kptr_restrict = 0 (Default on Debian <= 9 systems)
//
// Leak primitive:
//   Data leaked:      kernel module virtual load addresses
//   Kernel subsystem: kernel/module — /proc/modules
//   Data structure:   struct module → module_core (base address)
//   Address type:     virtual (kernel module text)
//   Method:           exact (proc file read)
//   Status:           gated by design (kptr_restrict)
//   Access check:     m_show() checks kptr_restrict via restricted_pointer();
//                     requires CAP_SYSLOG
//   Source:
//   https://elixir.bootlin.com/linux/v6.12/source/kernel/module/procfs.c
//
// Mitigations:
//   kernel.kptr_restrict >= 1 masks module addresses to 0x0.
//   Bypass requires CAP_SYSLOG or CAP_SYS_ADMIN.
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

KASLD_EXPLAIN(
    "Reads kernel module virtual load addresses from /proc/modules. "
    "Each line reports the module name, size, and base address. When "
    "kernel.kptr_restrict is 0 (or the reader has CAP_SYSLOG), raw "
    "addresses are shown. Module addresses fall in the modules region, "
    "which on some architectures is at a fixed offset from kernel "
    "text.");

KASLD_META("method:exact\n"
           "addr:virtual\n"
           "sysctl:kptr_restrict>=1\n"
           "bypass:CAP_SYSLOG\n");

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

  /* /proc/modules gives us a list of loaded module base addresses.
   * The component aggregates them into a min/max range — both endpoints
   * are within the module region. (A future version could enumerate
   * each module by name with kasld_result().) */
  printf("lowest leaked module address:  %lx\n", range.lo);
  kasld_result(KASLD_ADDR_VIRT, KASLD_SECTION_MODULE, range.lo,
               KASLD_REGION_MODULE_REGION, NULL);

  if (range.hi != range.lo) {
    printf("highest leaked module address: %lx\n", range.hi);
    kasld_result(KASLD_ADDR_VIRT, KASLD_SECTION_MODULE, range.hi,
                 KASLD_REGION_MODULE_REGION, NULL);
  }

  return 0;
}
