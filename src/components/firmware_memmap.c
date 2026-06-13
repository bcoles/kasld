// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Emit the firmware System RAM map (/sys/firmware/memmap) as PHYS RAM extents
// (pos=extent), one per System RAM span. This is the authoritative, COMPLETE
// physical memory topology; firmware_memmap_holes and ram_map_phys_exclude read
// it from the engine's coverings[] — a per-source store the cross-source merge
// bypasses, so the gaps between extents are preserved faithfully. Both rules
// key on this component's origin, so the binary name ("firmware_memmap") is
// load-bearing. As a covering source the WHOLE map must be emitted (a partial
// map would synthesise false gaps); this is enforced by tests/check-extent-
// callers, which reviews every caller of kasld_result_extent.
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
    kasld_result_extent(KASLD_TYPE_PHYS, REGION_RAM, ext[i].lo, ext[i].hi, NULL,
                        CONF_PARSED);
  return 0;
}
