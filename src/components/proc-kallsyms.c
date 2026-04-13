// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Retrieve kernel _stext symbol from /proc/kallsyms
//
// Based on original code by spender:
// https://grsecurity.net/~spender/exploits/exploit.txt
//
// Requires:
// - kernel.kptr_restrict = 0 (Default on Debian <= 9 systems)
//
// On modern kernels, kptr_restrict = 0 alone is insufficient.
// /proc/kallsyms uses kallsyms_show_value() (evaluated at open time)
// to gate address visibility. This requires CAP_SYSLOG, or
// perf_event_paranoid <= 1 (with kptr_restrict = 0), to reveal
// addresses. Without these, all addresses appear as zero.
// ---
// <bcoles@gmail.com>

#include "include/kasld.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned long get_kernel_sym(char *name) {
  FILE *f;
  unsigned long addr = 0;
  char dummy;
  char sname[256];
  int ret = 0;
  const char *path = "/proc/kallsyms";

  printf("[.] checking %s...\n", path);

  f = fopen(path, "r");

  if (f == NULL) {
    perror("[-] fopen");
    return 0;
  }

  while (ret != EOF) {
    ret = fscanf(f, "%p %c %255s\n", (void **)&addr, &dummy, sname);

    if (ret == 0)
      continue;

    if (!strcmp(name, sname))
      break;

    addr = 0;
  }

  fclose(f);

  if (addr == 0) {
    fprintf(stderr, "[-] kernel symbol '%s' not found in %s\n", name, path);
    return 0;
  }

  if (addr >= KERNEL_VAS_START && addr <= KERNEL_VAS_END)
    return addr;

  return 0;
}

int main(void) {
  unsigned long addr = get_kernel_sym("_stext");
  if (!addr)
    return 1;

  printf("kernel text start: %lx\n", addr);
  printf("possible kernel base: %lx\n", addr & -KERNEL_ALIGN);
  kasld_result(KASLD_ADDR_VIRT, KASLD_SECTION_TEXT, addr, "proc-kallsyms");

  return 0;
}
