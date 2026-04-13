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
#include "include/dmesg.h"
#include "include/kasld.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *needle = "mmode_resv0@";

static int on_match(const char *line, void *ctx) {
  unsigned long *result = ctx;
  char *endptr;

  const char *p = strstr(line, needle);
  if (!p)
    return 1;

  /* mmode_resv0@80000000 */
  unsigned long addr = strtoul(p + strlen(needle), &endptr, 16);

  if (addr == 0 || addr >= KERNEL_VAS_END)
    return 1;

  printf("leaked OpenSBI DRAM physical address: 0x%016lx\n", addr);
  *result = addr;
  return 0;
}

int main(void) {
  unsigned long phys_addr = 0;

  printf("[.] searching dmesg for OpenSBI reserved memory regions ...\n");
  dmesg_search("mmode_resv0@", on_match, &phys_addr);

  if (!phys_addr)
    return 1;

  kasld_result(KASLD_ADDR_PHYS, KASLD_SECTION_DRAM, phys_addr,
               "dmesg_reserved_mem_opensbi:dram");

  /* On older firmware, mmode_resv0 started at DRAM_BASE and the kernel
   * loaded at DRAM_BASE + TEXT_OFFSET. On newer firmware, the reservation
   * may be placed at an arbitrary offset within DRAM. Only derive the
   * kernel text address if the reservation appears DRAM-base-aligned
   * (i.e. aligned to at least KERNEL_ALIGN). */
  if ((phys_addr & (KERNEL_ALIGN - 1)) != 0) {
    printf("note: mmode_resv0 at 0x%016lx is not %lu MiB aligned; "
           "skipping text derivation\n",
           phys_addr, KERNEL_ALIGN / MB);
    return 0;
  }

  unsigned long kernel_phys = phys_addr + TEXT_OFFSET;

  printf("possible kernel physical address: 0x%016lx\n", kernel_phys);
  kasld_result(KASLD_ADDR_PHYS, KASLD_SECTION_TEXT, kernel_phys,
               "dmesg_reserved_mem_opensbi:text");

#if !PHYS_VIRT_DECOUPLED
  unsigned long virt = phys_to_virt(kernel_phys);
  printf("possible kernel virtual address: 0x%016lx\n", virt);
  kasld_result(KASLD_ADDR_VIRT, KASLD_SECTION_DIRECTMAP, virt,
               "dmesg_reserved_mem_opensbi:directmap");
#else
  printf("note: phys and virt KASLR are decoupled on this arch; "
         "cannot derive kernel text virtual address from physical leak\n");
#endif

  return 0;
}
