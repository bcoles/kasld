// This file is part of KASLD - https://github.com/bcoles/kasld
//
// arm64 VA_BITS detection via an mmap boundary probe, emitting PAGE_OFFSET.
//
// PROBING-phase component. On arm64 TASK_SIZE = 1<<VA_BITS and PAGE_OFFSET =
// -(1<<VA_BITS), both fixed (not randomized). A one-page probe at
// (1<<c) - PAGE_SIZE is mappable iff c <= VA_BITS, so probing the candidate
// ladder largest-first and taking the first that maps yields the exact VA_BITS,
// hence the exact PAGE_OFFSET (= arm64_page_offset_for(VA_BITS)). The engine
// pins Q_PAGE_OFFSET to it (page_offset_from_landmark).
//
// MAP_FIXED_NOREPLACE distinguishes "beyond TASK_SIZE" (ENOMEM/EINVAL → probe a
// smaller boundary) from "occupied" (EEXIST → the address is within TASK_SIZE)
// and never clobbers a live mapping. If the kernel returns an unrequested
// address (NOREPLACE not honoured, pre-v4.17) the probe is unreliable and emits
// nothing rather than guessing. Likewise an unexpected errno (RLIMIT_AS,
// seccomp) or a VA_BITS below the smallest supported candidate → no emission,
// leaving the engine's honest window (sound but wide).
//
// Leak primitive: virtual (kernel direct-map base) via the mmap syscall;
// unprivileged, no sysctl gate. arm64 only.
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
    "Probes mmap(MAP_FIXED_NOREPLACE) at the 1<<VA_BITS boundaries on arm64 "
    "(52/48/47/42/39): the largest that maps is VA_BITS, giving the exact "
    "PAGE_OFFSET = -(1<<VA_BITS) (not randomized on arm64). arm64 only; "
    "unprivileged.");

KASLD_META("method:heuristic\n"
           "phase:probing\n"
           "addr:virtual\n");

int main(void) {
#if defined(__aarch64__)
  /* VA_BITS candidates, largest first (must match VA_BITS_CANDIDATES). */
  static const unsigned long cands[] = {52ul, 48ul, 47ul, 42ul, 39ul};
  const int ncands = (int)(sizeof(cands) / sizeof(cands[0]));

  long pg = sysconf(_SC_PAGESIZE);
  unsigned long page = (pg > 0) ? (unsigned long)pg : 0x1000ul;

  unsigned long va_bits = 0;
  for (int i = 0; i < ncands; i++) {
    unsigned long c = cands[i];
    void *want = (void *)((1UL << c) - page);
    void *p = mmap(want, (size_t)page, PROT_NONE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (p == want) { /* mapped exactly here -> within TASK_SIZE */
      munmap(p, (size_t)page);
      va_bits = c;
      break;
    }
    if (p !=
        MAP_FAILED) { /* NOREPLACE not honoured (old kernel) -> unreliable */
      munmap(p, (size_t)page);
      kasld_info("mmap returned an unrequested address; probe unreliable");
      return 0;
    }
    if (errno == EEXIST) { /* occupied -> addressable -> within TASK_SIZE */
      va_bits = c;
      break;
    }
    if (errno == ENOMEM || errno == EINVAL)
      continue; /* beyond this boundary; try a smaller VA_BITS */
    kasld_info("mmap(1<<%lu): unexpected errno %d; not inferring", c, errno);
    return 0; /* RLIMIT_AS / seccomp / etc. — don't guess */
  }

  if (va_bits == 0) {
    kasld_info("VA_BITS below smallest supported candidate; not inferring");
    return 0;
  }

  unsigned long virt_page_offset = arm64_page_offset_for(va_bits);
  kasld_info("VA_BITS=%lu PAGE_OFFSET=%#lx", va_bits, virt_page_offset);
  kasld_result_base(KASLD_TYPE_VIRT, REGION_PAGE_OFFSET, virt_page_offset, NULL,
                    CONF_INFERRED);
  return 0;
#else
  return 0;
#endif
}
