// This file is part of KASLD - https://github.com/bcoles/kasld
//
// arm64 USERSPACE virtual address width detection via an mmap boundary probe.
//
// PROBING-phase component. A one-page probe at (1<<c) - PAGE_SIZE is mappable
// iff c is within TASK_SIZE, so probing the candidate ladder largest-first and
// taking the first that maps yields the exact width of the address space
// USERSPACE is given.
//
// That is the width of userspace, which is not always the width the kernel uses
// for its own mappings, so it is published as SF_USER_VIRT_ADDR_BITS and
// arm64_va_bits_from_user_width maps it onto Q_VA_BITS. A probe cannot do
// better: it maps pages, and mapping a page measures TASK_SIZE.
//
// The distinction is not academic on this architecture. A kernel can give
// userspace a 52-bit space while keeping 48 bits for itself -- TASK_SIZE_64 is
// built from the userspace width, and the kernel's own VA_BITS is a separate
// number -- so reading this probe as the kernel width pins a value the kernel
// does not use. It is the width PAGE_OFFSET and the text band are derived from,
// so a wrong one moves those too.
//
// Where the width lands on Q_VA_BITS, arm64_page_offset_from_va_bits derives
// the exact PAGE_OFFSET = -(1<<VA_BITS) (not randomized on arm64). Emitting a
// width — rather than the direct PAGE_OFFSET — resolves Q_VA_BITS leak-free,
// which a REGION_PAGE_OFFSET landmark alone does not.
//
// MAP_FIXED_NOREPLACE distinguishes "beyond TASK_SIZE" (ENOMEM/EINVAL → probe a
// smaller boundary) from "occupied" (EEXIST → the address is within TASK_SIZE)
// and never clobbers a live mapping. If the kernel returns an unrequested
// address (NOREPLACE not honoured, pre-v4.17) the probe is unreliable and emits
// nothing rather than guessing. Likewise an unexpected errno (RLIMIT_AS,
// seccomp) or a VA_BITS below the smallest supported candidate → no emission,
// leaving the engine's honest window (sound but wide).
//
// Detection via the mmap syscall; unprivileged, no sysctl gate. arm64 only.
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
    "(52/48/47/42/39/36): the largest that maps is the width USERSPACE is "
    "given, because mapping a page measures TASK_SIZE. Publishes that "
    "userspace width; a rule derives the width the kernel uses for its own "
    "mappings, which is the same number except on a 64K-page kernel that "
    "gives userspace 52 bits and keeps 48. The kernel width is what "
    "PAGE_OFFSET = -(1<<VA_BITS) follows from (not randomized on arm64). "
    "arm64 only; unprivileged.");

KASLD_META("method:inferred\n"
           "phase:probing\n"
           "discloses:facts\n"
           "source:live\n");

int main(void) {
  if (kasld_skip_live_probe("VA_BITS mmap"))
    return 0;
  /* Live mmap boundary probe of the running VA space. */
#if defined(__aarch64__)
  /* The architecture's own candidate set, walked LARGEST first: the widest
   * boundary that still maps is the active VA_BITS. Read from the header rather
   * than restated here: a second copy would be two lists obliged to agree, with
   * nothing to enforce it, and a width present in one and absent from the other
   * is probed by neither. */
  static const unsigned long cset[] = VA_BITS_CANDIDATES; /* smallest first */
  const int ncands = (int)(sizeof(cset) / sizeof(cset[0]));

  long pg = sysconf(_SC_PAGESIZE);
  unsigned long page = (pg > 0) ? (unsigned long)pg : 0x1000ul;

  unsigned long va_bits = 0;
  for (int i = ncands - 1; i >= 0; i--) {
    unsigned long c = cset[i];
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

  kasld_info("active VA_BITS=%lu (PAGE_OFFSET = %#lx)", va_bits,
             arm64_page_offset_for(va_bits));
  kasld_emit_scalar(SF_USER_VIRT_ADDR_BITS, va_bits, CONF_INFERRED);
  return 0;
#else
  return 0;
#endif
}
