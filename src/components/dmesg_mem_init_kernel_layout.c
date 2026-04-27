// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Search kernel log for virtual kernel memory layout.
//
// The `mem_init()` function prints the layout of the kernel segments
// to the kernel debug log, including kernel vas start, .text, .data,
// lowmem, modules, and memory sections.
//
// Sections extracted:
//   .text    -> V text      (kernel text virtual address)
//   .data    -> V data      (kernel data virtual address)
//   lowmem   -> V directmap (lowmem / direct-mapped region, x86_32/arm)
//   modules  -> V module    (kernel module region, arm/arm64)
//   memory   -> V directmap (linear memory map, arm64)
//
// x86:
// https://elixir.bootlin.com/linux/v5.6.19/source/arch/x86/mm/init_32.c
// Removed in kernel 5.7-rc1 on 2020-03-06:
// https://github.com/torvalds/linux/commit/681ff0181bbfb183e32bc6beb6ec076304470479#diff-3bfd62fd3cf596dbff9091b59a7168cdf8fb93ed342a633bd37fac9633e96025
//
// arm:
// https://elixir.bootlin.com/linux/v5.0.21/source/arch/arm/mm/init.c
// Removed in kernel 5.1-rc1 on 2019-03-16:
// https://github.com/torvalds/linux/commit/0be288630752e6358d02eba7b283c1783a5c7c38#diff-0ac47f754483fd3333a760d4285c7197ba5820b1ad1899f192270cd6a3a1e309
//
// arm64:
// https://elixir.bootlin.com/linux/v4.15.18/source/arch/arm64/mm/init.c
// Removed in kernel v4.16-rc1 on 2018-01-16:
// https://github.com/torvalds/linux/commit/071929dbdd865f779a89ba3f1e06ba8d17dd3743
//
// x86_64:
// This code was never present on x86_64.
//
// m68k:
// Due to a bug, this code always printed "ptrval", instead of segment
// addresses, and was later removed in kernel 4.17-rc1 on 2018-03-19:
// https://github.com/torvalds/linux/commit/31833332f79876366809ccb0614fee7df8afe9fe
//
// PA-RISC:
// https://elixir.bootlin.com/linux/v4.16-rc3/source/arch/parisc/mm/init.c
// Code was commented out in kernel 4.16-rc4 on 2018-03-02:
// https://github.com/torvalds/linux/commit/fd8d0ca2563151204f3fe555dc8ca4bcfe8677a3
//
// RISC-V:
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/riscv/mm/init.c#L127
// Kernel virtual memory layout is printed (excluding .text section),
// but requires kernel to be configured with CONFIG_DEBUG_VM.
//
// Xtensa:
// Code is still present as of 2023:
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/xtensa/mm/init.c#L134
//
// SuperH:
// Code is still present as of 2023:
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/sh/mm/init.c#L371
//
// Leak primitive:
//   Data leaked:      kernel virtual memory layout (.text, .data, lowmem,
//   modules) Kernel subsystem: arch/*/mm/init — mem_init() layout printout Data
//   structure:   kernel segment boundaries (virtual addresses) Address type:
//   virtual (kernel text, data, direct-map) Method:           parsed (dmesg
//   string) Status:           removed from most architectures (x86_32: v5.7,
//   ARM: v5.1,
//                     ARM64: v4.16). Still present on RISC-V (CONFIG_DEBUG_VM),
//                     Xtensa, and SuperH.
//   Access check:     do_syslog() → check_syslog_permissions(); gated by
//                     dmesg_restrict
//   Source:
//   https://elixir.bootlin.com/linux/v5.6.19/source/arch/x86/mm/init_32.c
//
// Mitigations:
//   Removed from most architectures. On RISC-V, requires CONFIG_DEBUG_VM.
//   Access gated by dmesg_restrict (see dmesg.h for shared access gate
//   details).
//
// Requires:
// - kernel.dmesg_restrict = 0; or CAP_SYSLOG capabilities; or
//   readable /var/log/dmesg.
// - CONFIG_DEBUG_VM on RISC-V systems
// ---
// <bcoles@gmail.com>

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
    "Parses the kernel virtual memory layout block printed by mem_init() "
    "during boot. This block shows virtual address ranges for .text, "
    ".data, lowmem, modules, and other sections. Removed from most "
    "architectures: ARM64 v4.16, ARM v5.1, x86_32 v5.7. Access is "
    "gated by dmesg_restrict.");

KASLD_META("method:parsed\n"
           "addr:virtual\n"
           "sysctl:dmesg_restrict>=1\n"
           "bypass:CAP_SYSLOG\n"
           "fallback:/var/log/dmesg\n");

/* Layout sections to extract from the kernel memory layout block.
 *
 * Needles match across architectures:
 *   x86_32: "      .text : 0x%08lx", "    lowmem  : 0x%08lx", etc.
 *   arm:    "      .text : 0x%p",    "    lowmem  : 0x%08lx",
 *           "    modules : 0x%08lx"
 *   arm64:  "      .text : 0x%p",    "    modules : 0x%16lx",
 *           "    memory  : 0x%16lx"
 */
struct layout_entry {
  const char *needle;
  char type;
  const char *section;
  const char *display;
  const char *region;
  unsigned long gate_min;
  unsigned long gate_max;
};

static const struct layout_entry entries[] = {
    {".text : 0x", KASLD_ADDR_VIRT, KASLD_SECTION_TEXT, "kernel .text start",
     KASLD_REGION_KERNEL_TEXT, KERNEL_BASE_MIN, KERNEL_BASE_MAX},
    {".data : 0x", KASLD_ADDR_VIRT, KASLD_SECTION_DATA, "kernel .data start",
     KASLD_REGION_KERNEL_DATA, KERNEL_VAS_START, KERNEL_VAS_END},
    {"lowmem  : 0x", KASLD_ADDR_VIRT, KASLD_SECTION_DIRECTMAP,
     "kernel lowmem start", KASLD_REGION_DIRECTMAP, KERNEL_VAS_START,
     KERNEL_VAS_END},
    {"modules : 0x", KASLD_ADDR_VIRT, KASLD_SECTION_MODULE,
     "kernel modules start", KASLD_REGION_MODULE_REGION, MODULES_START,
     MODULES_END},
    {"memory  : 0x", KASLD_ADDR_VIRT, KASLD_SECTION_DIRECTMAP,
     "kernel memory start", KASLD_REGION_DIRECTMAP, KERNEL_VAS_START,
     KERNEL_VAS_END},
    {NULL, 0, NULL, NULL, NULL, 0, 0},
};

#define NUM_ENTRIES (sizeof(entries) / sizeof(entries[0]) - 1)

/* Extract the first 0x-prefixed hex address from a string.
 * Returns 0 if no valid address found (handles ptrval gracefully). */
static unsigned long extract_addr(const char *s) {
  const char *p = strstr(s, "0x");
  if (!p)
    return 0;

  char *endptr;
  unsigned long addr = strtoul(p + 2, &endptr, 16);
  if (endptr == p + 2)
    return 0;

  return addr;
}

static void emit_result(int idx, unsigned long addr) {
  printf("%s: %lx\n", entries[idx].display, addr);

  if (strcmp(entries[idx].section, KASLD_SECTION_TEXT) == 0)
    printf("possible kernel base: %lx\n", addr & -KERNEL_ALIGN);

  if (strcmp(entries[idx].section, KASLD_SECTION_DIRECTMAP) == 0 &&
      addr < (unsigned long)KERNEL_VAS_START)
    printf("[!] warning: %s %lx below configured KERNEL_VAS_START %lx\n",
           entries[idx].display, addr, (unsigned long)KERNEL_VAS_START);

  kasld_result(entries[idx].type, entries[idx].section, addr,
               entries[idx].region, NULL);
#if !PHYS_VIRT_DECOUPLED
  if (strcmp(entries[idx].section, KASLD_SECTION_DIRECTMAP) == 0) {
    unsigned long phys = virt_to_phys(addr);
    printf("  possible physical address: 0x%016lx\n", phys);
    kasld_result(KASLD_ADDR_PHYS, KASLD_SECTION_DRAM, phys,
                 entries[idx].region, NULL);
  }
#endif
}

struct search_ctx {
  int found_mask; /* bitmask of which entries have been found */
};

static int on_match(const char *line, void *ctx) {
  struct search_ctx *sc = ctx;

  for (int i = 0; entries[i].needle; i++) {
    if (sc->found_mask & (1 << i))
      continue;

    if (strstr(line, entries[i].needle) == NULL)
      continue;

    unsigned long addr = extract_addr(line);
    if (!addr)
      continue;

    if (addr < entries[i].gate_min || addr > entries[i].gate_max)
      continue;

    emit_result(i, addr);
    sc->found_mask |= (1 << i);
  }

  return 1; /* keep scanning */
}

int main(void) {
  struct search_ctx ctx = {0};

  /* Use a broad needle to match any layout line */
  printf("[.] searching dmesg for kernel memory layout sections ...\n");
  int ds = dmesg_search(": 0x", on_match, &ctx);

  if (!ctx.found_mask) {
    if (ds < 0)
      return KASLD_EXIT_NOPERM;
    printf("[-] kernel memory layout sections not found in dmesg\n");
  }

  return 0;
}
