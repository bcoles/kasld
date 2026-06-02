// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Emit the firmware System RAM map (/sys/firmware/memmap) as PHYS RAM extents,
// one per System RAM span. This is the authoritative, complete physical memory
// topology; firmware_memmap_holes invalidates kernel-base candidates that fall
// in a gap between these extents. It keys on this component's origin, so the
// binary name ("firmware_memmap") is load-bearing. The orchestrator merge keeps
// the disjoint extents separate (ranges_disjoint), preserving the gaps.
// ---
// <bcoles@gmail.com>
#include "include/kasld/firmware_memmap.h"
#include "include/kasld/api.h"

KASLD_EXPLAIN("Reads /sys/firmware/memmap (the authoritative firmware System "
              "RAM map) and emits each System RAM span as a PHYS RAM extent. "
              "firmware_memmap_holes keys on this component's origin. "
              "World-readable, no privileges.");
KASLD_META("method:parsed\n"
           "phase:inference\n");

int main(void) {
  struct kasld_ram_extent ext[64];
  int n = kasld_load_ram_extents(ext, 64);
  for (int i = 0; i < n; i++)
    kasld_result_range(KASLD_TYPE_PHYS, REGION_RAM, ext[i].lo, ext[i].hi, NULL,
                       CONF_PARSED);
  return 0;
}
