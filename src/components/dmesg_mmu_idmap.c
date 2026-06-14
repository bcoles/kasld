// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Search kernel log for identity mappings created during kernel init.
//
// On arm systems with CONFIG_MMU=y, an identity mapping is created for
// the `__turn_mmu_on` function when enabling the MMU during kernel init.
//
// On 32-bit arm systems, `identity_mapping_add()` prints this mapping to
// the kernel log. The logged addresses are PHYSICAL: the function prints
// virt_to_idmap(__idmap_text_start/end), which equals virt_to_phys() on
// every platform without a custom idmap pv-offset. They are an interior
// physical address of the kernel image (within the "Kernel code" iomem
// range, e.g. == __pa(_stext)), NOT a virtual kernel-text address. Emitting
// them as virtual pollutes the virtual text inference on kernels whose
// PAGE_OFFSET differs from the 3G/1G default (a low false virtual-text
// point drags the inferred base below the real _text); emit physical.
//
// Leak primitive:
//   Data leaked:      physical address of the kernel idmap text (__idmap_text)
//   Kernel subsystem: arch/arm/mm/idmap — identity_mapping_add()
//   Data structure:   identity map page table entries (__idmap_text_start)
//   Address type:     physical (kernel image, ARM32)
//   Method:           parsed (dmesg string)
//   Status:           unfixed (printed unconditionally on ARM32 with MMU)
//   Access check:     do_syslog() → check_syslog_permissions(); gated by
//                     dmesg_restrict
//   Source:
//   https://elixir.bootlin.com/linux/v5.15.11/source/arch/arm/mm/idmap.c#L89
//
// Mitigations:
//   CONFIG_MMU=n disables (impractical — always enabled on ARM32 Linux).
//   Access gated by dmesg_restrict (see dmesg.h for shared access gate
//   details).
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
#include "include/kasld/api.h"
#include "include/kasld/cli.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

KASLD_EXPLAIN(
    "Searches dmesg for ARM32 identity_mapping_add() messages printed "
    "during early MMU setup. The logged range is the PHYSICAL address of "
    "the kernel idmap text (virt_to_phys(__idmap_text)) — an interior "
    "physical kernel-image address. Access is gated by dmesg_restrict.");

KASLD_META("method:parsed\n"
           "phase:inference\n"
           "addr:physical\n"
           "sysctl:dmesg_restrict>=1\n"
           "bypass:CAP_SYSLOG\n"
           "fallback:/var/log/dmesg\n");

static int on_match(const char *line, void *ctx) {
  unsigned long *result = ctx;
  char *endptr;
  char buf[BUFSIZ];
  char *ptr;

  /* Make a mutable copy for strtok */
  strncpy(buf, line, sizeof(buf) - 1);
  buf[sizeof(buf) - 1] = '\0';

  /* Message format is fixed:
   *   "Setting up static identity map for 0x<start> - 0x<end>"
   * Take the first "0x…" literal — the physical idmap text start. Selecting
   * by the "0x" prefix (rather than a virtual kernel-text window) is portable
   * and correct for any PHYS_OFFSET, including low-RAM boards whose physical
   * kernel base sits below the lowest possible virtual PAGE_OFFSET. */
  for (ptr = strtok(buf, " "); ptr != NULL; ptr = strtok(NULL, " ")) {
    if (strncmp(ptr, "0x", 2) != 0)
      continue;
    unsigned long addr = strtoul(ptr, &endptr, 16);
    if (addr != 0) {
      *result = addr;
      return 0;
    }
  }

  return 1;
}

int main(void) {
  unsigned long addr = 0;

  kasld_info("searching dmesg for ' static identity map for ' ...");
  int ds = dmesg_search(" static identity map for ", on_match, &addr);

  if (!addr) {
    if (ds < 0)
      return KASLD_EXIT_NOPERM;
    kasld_err("MMU identity map info not found in dmesg");
    return 0;
  }

  kasld_found("leaked idmap text (physical): %lx", addr);
  kasld_info("possible physical kernel base: %lx", addr & -KASLR_PHYS_ALIGN);
  /* The logged address is the PHYSICAL idmap text start (virt_to_phys of
   * __idmap_text, which contains __turn_mmu_on) — an interior point of the
   * kernel image in physical memory, corroborating Q_PHYS_IMAGE_BASE. */
  kasld_result_sample(KASLD_TYPE_PHYS, REGION_KERNEL_TEXT, addr,
                      "__turn_mmu_on", CONF_PARSED);

  return 0;
}
