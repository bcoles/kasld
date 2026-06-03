// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Emit memory-size scalar facts from /proc/meminfo and /proc/zoneinfo:
// SF_MEMTOTAL, SF_LOWMEM (highmem kernels), SF_MAX_PFN. These bound the
// physical KASLR window (the kernel image must fit within RAM).
// ---
// <bcoles@gmail.com>
#include "include/kasld/api.h"
#include "include/kasld/meminfo.h"

KASLD_EXPLAIN("Reads /proc/meminfo (MemTotal, LowTotal) and /proc/zoneinfo "
              "(spanned PFNs) and emits them as scalar system facts that bound "
              "the physical address window. World-readable, no privileges.");
KASLD_META("method:parsed\n"
           "phase:inference\n");

int main(void) {
  unsigned long v;
  if ((v = kasld_read_memtotal_bytes()))
    kasld_emit_scalar(SF_MEMTOTAL, v, CONF_PARSED);
  if ((v = kasld_read_lowmem_bytes()))
    kasld_emit_scalar(SF_LOWMEM, v, CONF_PARSED);
  if ((v = kasld_read_max_pfn()))
    kasld_emit_scalar(SF_MAX_PFN, v, CONF_PARSED);
  return 0;
}
