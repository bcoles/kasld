// This file is part of KASLD - https://github.com/bcoles/kasld
//
// arm64 VA_BITS detection via an mmap boundary probe, emitting PAGE_OFFSET.
//
// PROBING-phase component. On arm64
// TASK_SIZE = 1<<VA_BITS and PAGE_OFFSET = -(1<<VA_BITS), so an mmap(MAP_FIXED)
// at the VA_BITS=48 boundary distinguishes the configuration:
//
//   probe at 1<<48 fails (ENOMEM): VA_BITS <= 48  -> PAGE_OFFSET
//   0xffff000000000000 probe at 1<<48 succeeds:       VA_BITS >= 52  ->
//   PAGE_OFFSET 0xfff0000000000000
//
// PAGE_OFFSET is not randomised on arm64, so the detected value is exact; the
// engine pins Q_PAGE_OFFSET to it (page_offset_from_landmark). It is a PROBING
// component: the engine reads component results, and an active probe belongs
// behind the subprocess boundary.
//
// Leak primitive: virtual (kernel direct-map base) via the mmap syscall;
// unprivileged, no sysctl gate. arm64 only.
//
// Caveat: RLIMIT_AS exhaustion also returns ENOMEM. Unlikely at probe time;
// the same risk mmap-brute-vmsplit accepts.
// ---
// <bcoles@gmail.com>

#define _GNU_SOURCE
#include "include/kasld/api.h"
#include <errno.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

KASLD_EXPLAIN(
    "Probes mmap(MAP_FIXED) at 1<<48 on arm64: ENOMEM means VA_BITS<=48 "
    "(PAGE_OFFSET 0xffff000000000000), success means VA_BITS>=52 "
    "(PAGE_OFFSET 0xfff0000000000000). PAGE_OFFSET is not randomised "
    "on arm64, so the value is exact. arm64 only; unprivileged.");

KASLD_META("method:heuristic\n"
           "phase:probing\n"
           "addr:virtual\n");

int main(void) {
#if defined(__aarch64__)
#define ARM64_VA48_PAGE_OFFSET 0xffff000000000000ul
#define ARM64_VA52_PAGE_OFFSET 0xfff0000000000000ul
#define ARM64_VA_PROBE_ADDR ((void *)(1UL << 48))
#define ARM64_VA_PROBE_LEN 0x1000ul

  void *p = mmap(ARM64_VA_PROBE_ADDR, ARM64_VA_PROBE_LEN, PROT_READ,
                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  unsigned long page_offset;
  if (p == MAP_FAILED) {
    if (errno != ENOMEM)
      return 0;                           /* a different failure: don't infer */
    page_offset = ARM64_VA48_PAGE_OFFSET; /* VA_BITS <= 48 */
    printf("[.] mmap(1<<48) failed (ENOMEM): VA_BITS<=48\n");
  } else {
    munmap(p, ARM64_VA_PROBE_LEN);
    page_offset = ARM64_VA52_PAGE_OFFSET; /* VA_BITS >= 52 */
    printf("[.] mmap(1<<48) succeeded: VA_BITS>=52\n");
  }
  printf("PAGE_OFFSET: %#lx\n", page_offset);
  kasld_result_base(KASLD_TYPE_VIRT, REGION_PAGE_OFFSET, page_offset, NULL,
                    CONF_INFERRED);
  return 0;
#else
  return 0;
#endif
}
