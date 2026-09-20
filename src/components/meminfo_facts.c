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
#if defined(HUGEPAGE_IS_PMD_BLOCK)
  /* PAGE SIZE, from the default huge page size. Worth deriving because the
   * direct source cannot survive a capture: reading it from the running
   * process describes the machine doing the analysis, so that reader is a live
   * probe and is correctly suppressed against a staged tree -- leaving the
   * rules that need a page size with nothing on exactly the input they exist
   * to read.
   *
   * On these architectures the huge page is the PMD block, whose size is
   * 2^(2*PAGE_SHIFT - 3): 2 MiB, 32 MiB and 512 MiB for the three granules.
   * Three distinct values, so the mapping back is unambiguous. Both spell the
   * same relation -- one as PMD_SHIFT, the other as PAGE_SHIFT + PAGE_SHIFT
   * minus the pointer log, which is 3 where a pointer is eight bytes. Where it
   * is not, the relation differs and the inversion refuses the figure: the
   * shift a four-byte pointer produces is odd, and the parity test in
   * kasld_page_size_from_pmd_hugepage rejects it. An architecture that
   * declares the property at that width does not reach either -- the check
   * beside the arch-header selection fails the build.
   *
   * NOT DONE ELSEWHERE, and the reason is the relation rather than the effort.
   * On powerpc the huge page is not a function of the granule at all: it is a
   * value chosen at runtime from the MMU's page-size table on the 64-bit book,
   * and a fixed 512 KiB or 4 MiB on the two 32-bit families -- so the figure
   * names no granule, which every captured powerpc kernel demonstrates by
   * reporting the same size whatever its configuration. On mips the relation
   * is the same as here, but the line is absent from real kernels because huge
   * page support is not built, so there is nothing to read. Both of those
   * still lack a page size on a capture; they need a different source.
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
