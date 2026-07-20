// This file is part of KASLD - https://github.com/bcoles/kasld
//
// x86_64 active paging-level detection via an mmap boundary probe.
//
// PROBING-phase component. On x86_64 the user address space ends at ~1<<47
// under 4-level paging and ~1<<56 under 5-level (LA57); the kernel hands out
// addresses above the 47-bit default window only when the requested hint is
// itself above it. A one-page MAP_FIXED_NOREPLACE probe at 1<<48 therefore
// maps iff 5-level paging is ACTIVE — distinguishing it from a merely
// LA57-capable CPU that booted 4-level (where /proc/cpuinfo still reports 57).
//
// The result is published as SF_VIRT_ADDR_BITS = 48 or 57, a statement of the
// ACTIVE paging width (not the CPU capability). x86_64_va_bits_from_scalar pins
// Q_VA_BITS from it, which unlocks the RANDOMIZE_MEMORY budget bounds on
// LA57-capable hardware that exposes no direct-map leak.
//
// MAP_FIXED_NOREPLACE separates "beyond the user window" (ENOMEM/EINVAL -> the
// level is 4) from "occupied" (EEXIST -> addressable -> level 5), and never
// clobbers a live mapping. If the kernel ignores NOREPLACE (pre-v4.17) or
// returns an unexpected errno (RLIMIT_AS, seccomp) the probe emits nothing
// rather than guess.
//
// Leak primitive: none — a paging-level detection via the mmap syscall.
// Unprivileged, no sysctl gate. x86_64 only.
// ---
// <bcoles@gmail.com>

#define _GNU_SOURCE
#include "include/kasld/api.h"
#include "include/kasld/cli.h"
#include <errno.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

KASLD_EXPLAIN(
    "Probes mmap(MAP_FIXED_NOREPLACE) at 1<<48 on x86_64: it maps only when "
    "5-level paging is ACTIVE, distinguishing real LA57 from an LA57-capable "
    "CPU booted 4-level (where /proc/cpuinfo still shows 57). Publishes the "
    "active paging width. x86_64 only; unprivileged.");

KASLD_META("method:inferred\n"
           "phase:probing\n"
           "live:1\n"
           "addr:none\n");

int main(void) {
  if (kasld_skip_live_probe("x86_64 paging-level mmap"))
    return 0;
#if defined(__x86_64__) || defined(__amd64__)
  long pg = sysconf(_SC_PAGESIZE);
  unsigned long page = (pg > 0) ? (unsigned long)pg : 0x1000ul;

  /* 1<<48 is beyond the 4-level user window and inside the 5-level one. */
  void *want = (void *)(1UL << 48);
  unsigned long va_bits = 0;

  void *p = mmap(want, (size_t)page, PROT_NONE,
                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
  if (p == want) { /* mapped here -> 5-level active */
    munmap(p, (size_t)page);
    va_bits = 57;
  } else if (p != MAP_FAILED) { /* NOREPLACE not honoured -> unreliable */
    munmap(p, (size_t)page);
    kasld_info("mmap returned an unrequested address; probe unreliable");
    return 0;
  } else if (errno == EEXIST) { /* occupied -> addressable -> 5-level */
    va_bits = 57;
  } else if (errno == ENOMEM ||
             errno == EINVAL) { /* beyond user VAS -> 4-level */
    va_bits = 48;
  } else {
    kasld_info("mmap(1<<48): unexpected errno %d; not inferring", errno);
    return 0;
  }

  kasld_info("active paging level: %s (VA_BITS=%lu)",
             va_bits == 57 ? "5-level" : "4-level", va_bits);
  kasld_emit_scalar(SF_VIRT_ADDR_BITS, va_bits, CONF_INFERRED);
  return 0;
#else
  return 0;
#endif
}
