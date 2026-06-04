// This file is part of KASLD - https://github.com/bcoles/kasld
//
// s390 paging-level detection via an mmap boundary probe, emitted as
// SF_VIRT_ADDR_BITS (42 for 3-level, 53 for 4-level). A rule turns it into a
// text-base ceiling (text < 1<<VA_BITS). s390x only — gated at compile time so
// non-s390 builds skip via the Makefile's `cc-component` wrapper instead of
// shipping a binary whose helper `kasld_s390_va_bits()` returns 0
// unconditionally on the wrong arch.
// ---
// <bcoles@gmail.com>
#if !defined(__s390__) && !defined(__s390x__)
#error "Architecture is not supported"
#endif

#include "include/kasld/api.h"
#include "include/kasld/s390_paging.h"

KASLD_EXPLAIN("Probes the s390 user-address-space limit with a single "
              "mmap(MAP_FIXED) at 1<<42 and emits the detected VA-bit width as "
              "SF_VIRT_ADDR_BITS. Unprivileged, no sysctl gate. s390x only.");
KASLD_META("method:heuristic\n"
           "phase:probing\n");

int main(void) {
  int va = kasld_s390_va_bits();
  if (va > 0)
    kasld_emit_scalar(SF_VIRT_ADDR_BITS, (unsigned long)va, CONF_PARSED);
  return 0;
}
