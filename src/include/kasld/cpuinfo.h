// This file is part of KASLD - https://github.com/bcoles/kasld
//
// CPU physical-address-width reader (/proc/cpuinfo), without privileges.
//
// Read by the engine bridge. Reads route through the kasld_* wrappers, so it is
// KASLD_SYSROOT-aware.
// ---
// <bcoles@gmail.com>

#ifndef KASLD_CPUINFO_H
#define KASLD_CPUINFO_H

#include "sysroot.h"

#include <stdio.h>
#include <string.h>

/* CPU maximum physical address width from /proc/cpuinfo: x86-64
 * ("address sizes\t: N bits physical, ...") and LoongArch ("Address Sizes").
 * Returns 0 if the field is absent (arm64, riscv64, MIPS, ...). All CPUs on a
 * shared die report the same width, so the first match is used. */
__attribute__((unused)) static int kasld_read_phys_addr_bits(void) {
  FILE *f = kasld_fopen("/proc/cpuinfo", "r");
  if (!f)
    return 0;

  char line[256];
  int phys_bits = 0;
  while (fgets(line, sizeof(line), f)) {
    if (strncmp(line, "address sizes", 13) != 0 &&
        strncmp(line, "Address Sizes", 13) != 0)
      continue;
    char *colon = strchr(line, ':');
    if (!colon)
      continue;
    if (sscanf(colon + 1, " %d bits physical", &phys_bits) == 1)
      break;
    phys_bits = 0; /* malformed line; keep scanning */
  }

  fclose(f);
  return phys_bits;
}

#endif /* KASLD_CPUINFO_H */
