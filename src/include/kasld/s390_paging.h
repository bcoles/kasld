// This file is part of KASLD - https://github.com/bcoles/kasld
//
// s390 paging-level detection via an mmap boundary probe (in-process).
//
// On s390x the user ASCE (Address Space Control Element) limit equals the
// kernel's page-table level, and the KASLR vmax = asce_limit:
//
//   3-level paging: asce_limit = _REGION2_SIZE = 1 << 42 = 4 TiB
//   4-level paging: asce_limit = _REGION1_SIZE = 1 << 53 = 8 PiB
//
// A single mmap(MAP_FIXED) at 1<<42 (the first byte at/above the 3-level limit)
// distinguishes them: it fails with ENOMEM on 3-level (address > asce_limit)
// and succeeds on 4-level. The detected level is returned as a VA-bits count
// (42 or 53); a rule turns that into the text-base ceiling (text < vmax).
//
// Read in-process by the engine bridge (engine_build_evidence): an active mmap
// probe with no addressable result has no wire form. Like the
// riscv64 kaslr-disabled / FDT detectors here, it replays from the host's own
// address space; under qemu it reports qemu's mode, not the captured kernel's.
//
// References:
//   arch/s390/boot/startup.c: vmax = adjust_to_uv_max(asce_limit)
//   arch/s390/include/asm/pgtable.h: _REGION1_SIZE, _REGION2_SIZE
// ---
// <bcoles@gmail.com>

#ifndef KASLD_S390_PAGING_H
#define KASLD_S390_PAGING_H

#if defined(__s390x__) || defined(__zarch__)

#include <errno.h>
#include <sys/mman.h>

/* Returns the s390 user-VA bit width (42 for 3-level, 53 for 4-level paging),
 * or 0 if it cannot be determined. */
__attribute__((unused)) static int kasld_s390_va_bits(void) {
  void *p = mmap((void *)(1UL << 42), 0x1000UL, PROT_READ,
                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  if (p == MAP_FAILED)
    return (errno == ENOMEM) ? 42 : 0; /* 3-level; other errors: unknown */
  munmap(p, 0x1000UL);
  return 53; /* probe mapped above the 3-level limit -> 4-level */
}

#else
__attribute__((unused)) static int kasld_s390_va_bits(void) { return 0; }
#endif /* s390x */

#endif /* KASLD_S390_PAGING_H */
