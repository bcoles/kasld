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
  /* PAGE SIZE. Not read directly, because the direct reader asks the running
   * process and so describes whoever is doing the analysis -- it is a live
   * probe and a staged tree correctly suppresses it. That leaves a replayed
   * capture with no page size at all, on exactly the input the rules needing
   * one exist to read.
   *
   * Two derivations, tried in order of how much a container can disturb them.
   *
   * BELOW THE SOUND FLOOR either way, because both read /proc/meminfo, which
   * is container-fakeable, and a page size at or above the floor sets the
   * image-base alignment -- a forged one would raise that alignment and lower
   * the guaranteed window's ceiling, narrowing in the direction that can
   * exclude the truth. The live reader keeps serving the at-floor consumers,
   * being trustworthy for the reason it cannot be replayed. */
  {
    unsigned long ps = 0;
#if defined(HUGEPAGE_IS_PMD_BLOCK)
    /* Preferred where the architecture has it. The huge page is the PMD block
     * there, so its size is 2^(2*PAGE_SHIFT - 3) -- 2 MiB, 32 MiB and 512 MiB
     * for the three granules -- and inverts unambiguously. It is preferred
     * because a container rewriting /proc/meminfo rewrites the RAM total the
     * other derivation divides, while leaving this line alone.
     *
     * GATED ON THE COMMAND LINE, because the line reports the DEFAULT huge
     * page, which `default_hugepagesz=` replaces; `hugepagesz=` alone does
     * not. An unreadable command line is not a clean one and is not treated as
     * one: absence has to be established, and a file that was never read
     * establishes nothing. */
    if (cmdline_lookup("default_hugepagesz=") == 0)
      ps = kasld_page_size_from_pmd_hugepage(kasld_read_hugepagesize_bytes());
#endif
    /* Otherwise the RAM total over the page count it was rendered from.
     * MemTotal is totalram shifted by PAGE_SHIFT - 10, and every zone's
     * managed pages sum to that same totalram, so the quotient is the page
     * size exactly -- no relation to invert and no architecture to know. This
     * is what reaches the architectures the huge page cannot describe: on
     * powerpc it is chosen at runtime from the MMU's page-size table, or fixed
     * independently of the granule, so the figure there names nothing. */
    if (!ps)
      ps = kasld_page_size_from_ram_totals(kasld_read_memtotal_bytes(),
                                           kasld_read_zone_managed());
    if (ps)
      kasld_emit_scalar(SF_PAGE_SIZE, ps, CONF_HEURISTIC);
  }
  return 0;
}
