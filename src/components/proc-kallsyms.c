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
//
// Leak primitive:
//   Data leaked:      kernel symbol virtual addresses (_stext, etc.)
//   Kernel subsystem: kernel/kallsyms — /proc/kallsyms
//   Data structure:   kernel symbol table (struct kallsym_iter)
//   Address type:     virtual (kernel text / data)
//   Method:           exact (symbol table read)
//   Status:           gated by design (kptr_restrict)
//   Access check:     kallsyms_show_value() checks kptr_restrict + CAP_SYSLOG
//   Source: https://elixir.bootlin.com/linux/v6.12/source/kernel/kallsyms.c
//
// Mitigations:
//   kernel.kptr_restrict >= 1 (default since v5.10) masks addresses.
//   Bypass requires CAP_SYSLOG or (kptr_restrict=0 + perf_event_paranoid<=1).
//   On modern kernels, kallsyms_show_value() checks at open() time.
// ---
// <bcoles@gmail.com>

#include "include/kasld.h"
#include "include/kasld_internal.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

KASLD_EXPLAIN(
    "Reads kernel symbol virtual addresses from /proc/kallsyms. When "
    "kernel.kptr_restrict is 0 (or the reader has CAP_SYSLOG), symbol "
    "addresses are printed in full. The _stext symbol gives the kernel "
    "text base directly. Since v5.10, kptr_restrict defaults to 1, "
    "hiding addresses from unprivileged users.");

KASLD_META("method:exact\n"
           "addr:virtual\n"
           "sysctl:kptr_restrict>=1\n"
           "bypass:CAP_SYSLOG\n");

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
  /* Pre-check: can we access /proc/kallsyms? */
  FILE *f = fopen("/proc/kallsyms", "r");
  if (!f)
    return (errno == EACCES || errno == EPERM) ? KASLD_EXIT_NOPERM
                                               : KASLD_EXIT_UNAVAILABLE;

  /* Detect kptr_restrict: when restricted, ALL addresses are 0.
   * Some symbols (e.g. __per_cpu_start) are legitimately at address 0,
   * so check several lines — if every address is 0, we're restricted. */
  char buf[64];
  int all_zero = 1;
  for (int i = 0; i < 16 && fgets(buf, sizeof(buf), f); i++) {
    unsigned long test;
    if (sscanf(buf, "%lx", &test) == 1 && test != 0) {
      all_zero = 0;
      break;
    }
  }
  fclose(f);

  if (all_zero)
    return KASLD_EXIT_NOPERM;

  unsigned long addr = get_kernel_sym("_stext");
  if (!addr)
    return 0;

  printf("kernel text start: %lx\n", addr);
  printf("possible kernel base: %lx\n", addr & -KERNEL_ALIGN);
  kasld_result(KASLD_ADDR_VIRT, KASLD_SECTION_TEXT, addr, "proc-kallsyms");

  return 0;
}
