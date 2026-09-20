// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Emit memory-size scalar facts from /proc/meminfo and /proc/zoneinfo:
// SF_PHYS_MEMTOTAL, SF_PHYS_LOWMEM (highmem kernels), SF_PHYS_MAX_PFN. These
// bound the physical KASLR window (the kernel image must fit within RAM).
// ---
// <bcoles@gmail.com>
#include "include/cmdline.h"
#include "include/kasld/api.h"
#include "include/kasld/cli.h"
#include "include/kasld/meminfo.h"

KASLD_EXPLAIN("Reads /proc/meminfo (MemTotal, LowTotal) and /proc/zoneinfo "
              "(spanned PFNs) and emits them as scalar system facts that bound "
              "the physical address window. World-readable, no privileges.");
KASLD_META("method:parsed\n"
           "phase:inference\n"
           "discloses:facts\n"
           "source:files\n");

int main(void) {
  unsigned long v;
  kasld_info("reading memory sizes from /proc/meminfo and /proc/zoneinfo ...");
  if ((v = kasld_read_memtotal_bytes()))
    kasld_emit_scalar(SF_PHYS_MEMTOTAL, v, CONF_PARSED);
  if ((v = kasld_read_lowmem_bytes()))
    kasld_emit_scalar(SF_PHYS_LOWMEM, v, CONF_PARSED);
  if ((v = kasld_read_max_pfn()))
    kasld_emit_scalar(SF_PHYS_MAX_PFN, v, CONF_PARSED);
  if ((v = kasld_read_vmalloc_total_bytes()))
    kasld_emit_scalar(SF_VMALLOC_TOTAL, v, CONF_PARSED);
#if defined(__aarch64__)
  /* PAGE SIZE, from the default huge page size. Worth deriving because the
   * direct source cannot survive a capture: reading it from the running
   * process describes the machine doing the analysis, so that reader is a live
   * probe and is correctly suppressed against a staged tree -- leaving the
   * rules that need a page size with nothing on exactly the input they exist
   * to read.
   *
   * On this architecture the huge page is the PMD block, whose size is
   * 2^(2*PAGE_SHIFT - 3): 2 MiB, 32 MiB and 512 MiB for the three granules.
   * Three distinct values, so the mapping back is unambiguous.
   *
   * GATED ON THE COMMAND LINE, because the line reports the DEFAULT hstate
   * rather than the architecture's huge page: `default_hugepagesz=` replaces
   * it, and a kernel booted that way would report a size belonging to another
   * granule. Nothing else does -- `hugepagesz=` alone creates a pool without
   * becoming the default. An unreadable command line is not the same as a
   * clean one and is not treated as one: the derivation needs positive
   * evidence that the parameter is absent, which only a command line that
   * could actually be read provides.
   *
   * EMITTED BELOW THE SOUND FLOOR, because /proc/meminfo is container-
   * fakeable and no container-fakeable input may move the guaranteed window.
   * The page size is not inert there: it sets the image-base alignment, and a
   * forged granule raises that alignment and lowers the window's ceiling --
   * narrowing in the direction that can exclude the truth. Below the floor
   * the at-floor consumers stop seeing it and keep taking the page size from
   * the live reader, which is trustworthy because it cannot be replayed;
   * the width inversion, which is itself below the floor, still gets it and
   * that is where this derivation was needed. */
  {
    const unsigned long huge = kasld_read_hugepagesize_bytes();
    if (huge && cmdline_lookup("default_hugepagesz=") == 0) {
      const unsigned long ps = kasld_page_size_from_pmd_hugepage(huge);
      if (ps)
        kasld_emit_scalar(SF_PAGE_SIZE, ps, CONF_HEURISTIC);
    }
  }
#endif
  return 0;
}
