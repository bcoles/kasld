// This file is part of KASLD - https://github.com/bcoles/kasld
//
// /proc/iomem address classifier: is a physical address System RAM?
//
// A component that reports an address as device MMIO is making a claim the
// kernel can contradict. /proc/iomem carries the resource tree, and its
// outermost range containing an address says authoritatively whether that
// address is "System RAM" or something else (PCI Bus, ACPI Reserved, a
// reserved carve-out, ...). Entries nest — a sub-range is listed after its
// parent — so the FIRST containing match is the outermost.
//
// The classification is three-valued on purpose. /proc/iomem masks every
// address to 0-0 without CAP_SYS_ADMIN, and may be absent entirely, so
// "no match" is not evidence of "not System RAM". A caller that collapsed the
// two would reclassify every address on a masked host. The safe default when
// the map cannot be read is to leave the caller's own label alone: labelling
// true MMIO as DRAM feeds the DRAM bounds a device window, which is the
// damaging direction, whereas labelling DRAM as MMIO only loses precision.
//
// Reads go through the kasld_* sysroot wrappers, so a captured fixture
// classifies against the captured map rather than the analysis host's.
// ---
// <bcoles@gmail.com>

#ifndef KASLD_IOMEM_H
#define KASLD_IOMEM_H

#include "api.h"
#include "sysroot.h"

#include <stdio.h>
#include <string.h>

enum kasld_iomem_class {
  /* No containing range: the map is absent, masked (every range reads 0-0),
   * or genuinely does not describe this address. Not a claim either way. */
  KASLD_IOMEM_UNKNOWN = 0,
  /* The outermost containing range is "System RAM". */
  KASLD_IOMEM_SYSTEM_RAM,
  /* The outermost containing range exists and is not System RAM. */
  KASLD_IOMEM_OTHER,
};

/* Classify `addr` against the outermost /proc/iomem range containing it. */
__attribute__((unused)) static enum kasld_iomem_class
kasld_iomem_classify(unsigned long addr) {
  FILE *f = kasld_fopen("/proc/iomem", "r");
  if (!f)
    return KASLD_IOMEM_UNKNOWN;

  char line[256];
  enum kasld_iomem_class cls = KASLD_IOMEM_UNKNOWN;
  while (fgets(line, sizeof(line), f)) {
    const char *p = line;
    while (*p == ' ' || *p == '\t')
      p++;
    unsigned long start, end;
    char name[128];
    const char *e;
    if (!kasld_addr_parse(p, 16, &start, &e) || *e != '-' ||
        !kasld_addr_parse(e + 1, 16, &end, &e))
      continue;
    if (sscanf(e, " : %127[^\n]", name) != 1)
      continue;
    if (addr < start || addr > end)
      continue;
    /* First containing match wins — the outermost, by iomem's
     * parent-before-child ordering. */
    cls =
        strstr(name, "System RAM") ? KASLD_IOMEM_SYSTEM_RAM : KASLD_IOMEM_OTHER;
    break;
  }
  fclose(f);
  return cls;
}

#endif /* KASLD_IOMEM_H */
