// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Emit SF_PHYS_ADDR_BITS from /proc/cpuinfo: the CPU's physical-address width,
// which caps the physical address space independent of installed RAM.
// ---
// <bcoles@gmail.com>
#include "include/kasld/api.h"
#include "include/kasld/cpuinfo.h"

KASLD_EXPLAIN("Reads the CPU physical-address width from /proc/cpuinfo and "
              "emits it as a scalar fact bounding the physical address space. "
              "World-readable, no privileges.");
KASLD_META("method:parsed\n"
           "phase:inference\n");

int main(void) {
  int bits = kasld_read_phys_addr_bits();
  if (bits > 0)
    kasld_emit_scalar(SF_PHYS_ADDR_BITS, (unsigned long)bits, CONF_PARSED);
  return 0;
}
