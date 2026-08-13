// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Find the start of the kernel virtual address space on 32-bit systems by
// locating the lowest page that will not map.
//
// mmap refuses any address at or above TASK_SIZE, so the boundary can be
// measured from an unprivileged process: binary-search between an address the
// kernel itself handed out (mappable, therefore below the boundary) and the
// top of the 32-bit address space (never mappable), and the search converges on
// TASK_SIZE itself in about twenty probes.
//
// TASK_SIZE is not PAGE_OFFSET on every architecture, so what is emitted
// depends on the relation the architecture fixes:
//
//   TASK_SIZE == PAGE_OFFSET (x86_32) — the measurement IS the linear-map base,
//     emitted as an exact value.
//   TASK_SIZE < PAGE_OFFSET (arm32 leaves a 16 MiB module band, ppc32 a smaller
//     gap, riscv32 the whole fixmap/PCI-IO/vmemmap stack) — the measurement is
//     a LOWER bound on PAGE_OFFSET, emitted as the window it proves. Where the
//     split is also a build-time choice, the boundary rounded up to the VMSPLIT
//     stride is added as a best guess at the likely tier.
//
// Usually the split is at 3 GiB (0xc0000000); embedded and 2G/2G distribution
// kernels use a lower one.
//
// The search never displaces a live mapping (MAP_FIXED_NOREPLACE) and runs in a
// forked child, so neither a kernel that ignores the flag nor an unmodelled
// failure can damage the address space of the process doing the reporting.
// Where the flag is not honoured (pre-v4.17) a page-granular search is not
// possible and the coarse 256 MiB sweep supplies the best guess alone.
//
// Leak primitive:
//   Data leaked:      kernel/user address space split point
//   (CONFIG_PAGE_OFFSET) Kernel subsystem: mm — mmap syscall (virtual address
//   space probing) Data structure:   kernel virtual address space boundary
//   Address type:     virtual (kernel VAS start)
//   Method:           brute (mmap search across the 32-bit address space)
//   Status:           unfixed (fundamental to 32-bit VM split design)
//   Access check:     none (mmap syscall, unprivileged)
//   Source:           N/A (architectural inference — no specific kernel
//                     function)
//
// Mitigations:
//   None — 32-bit address space split is a fundamental architectural
//   property. No runtime sysctl can restrict access. Only applies to
//   32-bit systems.
//
// References:
// https://cateee.net/lkddb/web-lkddb/PAGE_OFFSET.html
// https://elixir.bootlin.com/linux/v5.10/source/arch/arm/Kconfig
// https://elixir.bootlin.com/linux/v5.10/source/arch/x86/Kconfig
// ---
// <bcoles@gmail.com>

#define _GNU_SOURCE
#include "include/kasld/api.h"
#include "include/kasld/cli.h"
#include "include/kasld/task_size.h"
#include <limits.h>
#include <stdio.h>

KASLD_EXPLAIN(
    "Binary-searches the 32-bit address space for the lowest page that mmap "
    "refuses, which is the kernel/user virtual address split (TASK_SIZE). On "
    "x86_32 that address is CONFIG_PAGE_OFFSET exactly; elsewhere it is a "
    "lower "
    "bound on it, and the boundary rounded up to the VMSPLIT stride is the "
    "best "
    "guess. Uses MAP_FIXED_NOREPLACE so an occupied address is reported rather "
    "than overwritten, and runs the search in a forked child so no probe can "
    "disturb the address space it reports from; falls back to a coarse sweep "
    "for the best guess alone where the kernel does not honour the flag "
    "(pre-v4.17). 32-bit only. No privilege or sysctl gate; the split is a "
    "fundamental architectural property.");

KASLD_META("method:brute\n"
           "phase:probing\n"
           "live:1\n"
           "addr:virtual\n");

/* Compiled under exactly the conditions main() reaches it: a 32-bit build, on
 * an architecture that admits more than one linear-map base. */
#if !defined(__LP64__) && !defined(_LP64) && PAGE_OFFSET_MIN != PAGE_OFFSET_MAX
/* The boundary rounded UP to the VMSPLIT stride: the best guess at PAGE_OFFSET
 * where the two differ by less than one stride. Exact for every 256
 * MiB-aligned VMSPLIT; an over-estimate for the rare x86 VMSPLIT_2G_OPT
 * (0x78000000), which the exact tier covers on that architecture anyway. */
static unsigned long round_to_stride(unsigned long addr) {
  if (addr > ULONG_MAX - (KASLD_VMSPLIT_STRIDE - 1))
    return addr;
  return (addr + KASLD_VMSPLIT_STRIDE - 1) & ~(KASLD_VMSPLIT_STRIDE - 1);
}
#endif

int main(void) {
  if (kasld_skip_live_probe("VMSPLIT mmap"))
    return 0;
  /* Live mmap probe of the running VA space. */
#if defined(__LP64__) || defined(_LP64)
  /* A 64-bit build cannot apply the 32-bit user/kernel split search -- the two
   * halves of the address space are astronomically apart and the top page is
   * past no boundary. Provably inapplicable, so it is absent (exit 69), not an
   * unexplained no_result -- the same disposition this file gives the 32-bit
   * binary on a 64-bit kernel below. */
  return kasld_disp_absent("a 64-bit build cannot measure a 32-bit VMSPLIT");
#else
  unsigned long addr = 0;
  int exact = 0;

  kasld_info("searching 32-bit address space for kernel virtual address space "
             "start ...");
  switch (kasld_task_size_probe(&addr)) {
  case KASLD_TS_EXACT:
    exact = 1;
    break;
  case KASLD_TS_APPROX:
    kasld_info("mmap does not honour MAP_FIXED_NOREPLACE (pre-v4.17); the "
               "split is located by hint placement, best-guess only");
    break;
  case KASLD_TS_POROUS:
    kasld_info("addresses above %lx still map, so it is a gap rather than the "
               "split; best-guess only",
               addr);
    break;
  case KASLD_TS_NOT_FOUND:
    kasld_err("Could not locate kernel virtual address space");
    kasld_disposition(DISP_INCONCLUSIVE, NULL,
                      "no user/kernel split found in the 32-bit sweep");
    return 0;
  case KASLD_TS_UNRELIABLE:
  default:
    kasld_info("the address-space search was refused; declining rather than "
               "guessing");
    kasld_disposition(DISP_INCONCLUSIVE, NULL,
                      "the address-space search could not be trusted");
    return 0;
  }

  /* Above every linear-map base the architecture admits, the boundary cannot be
   * this kernel's. A 32-bit process on a 64-bit kernel reports exactly that —
   * TASK_SIZE is 0xffffe000 for an i386 task on x86_64 and 0xfffff000 for an
   * armv7 task on arm64 — and the layout being measured is then a 64-bit one
   * this binary does not model. */
  if (addr > (unsigned long)PAGE_OFFSET_MAX) {
    kasld_info("virtual address start %lx is above the highest linear-map base "
               "this architecture admits (%lx); the kernel is not the one this "
               "build models",
               addr, (unsigned long)PAGE_OFFSET_MAX);
    return kasld_disp_absent("the running kernel is not a 32-bit kernel of "
                             "this architecture");
  }

  kasld_info("kernel virtual address start: %lx", addr);

  /* What the measurement PROVES about the linear-map base. Requires `exact`: a
   * hint-placed or gap-derived boundary might be wrong, and a bound that might
   * be wrong has no business in the guaranteed window. */
  if (exact) {
#if TASK_SIZE_IS_PAGE_OFFSET
    /* Where the mmap user/kernel split IS PAGE_OFFSET (x86_32: TASK_SIZE ==
     * __PAGE_OFFSET, no gap), the located boundary is the linear-map base
     * itself, with no alignment assumption: nothing maps at or above it and the
     * page below it does, so PAGE_OFFSET is that address.
     * page_offset_from_landmark pins Q_PAGE_OFFSET from it, moving the x86_32
     * (no-KASLR) page offset into the GUARANTEED window. */
    kasld_result_base(KASLD_TYPE_VIRT, REGION_PAGE_OFFSET, addr, NULL,
                      CONF_INFERRED);
#else
    /* Everywhere else the split sits BELOW PAGE_OFFSET by a distance the
     * architecture fixes and this probe cannot see (arm32 reserves 16 MiB for
     * modules, ppc32 a smaller gap, riscv32 the fixmap, PCI-IO and vmemmap
     * regions). The measurement is then a lower bound on the base, emitted as
     * the window it proves; the upper edge is the highest base the architecture
     * admits, which holds against any target. */
    kasld_result_range(KASLD_TYPE_VIRT, REGION_PAGE_OFFSET, addr,
                       (unsigned long)PAGE_OFFSET_MAX, NULL, CONF_INFERRED);
#endif
  }

#if PAGE_OFFSET_MIN != PAGE_OFFSET_MAX
  /* The split is a build-time choice this binary cannot read, so the rounded
   * boundary is worth a best guess at the likely tier — unless the tier above
   * already resolved the base, where a rounded value could only contradict a
   * measured one. Where the architecture admits a single base there is nothing
   * to guess. */
  if (!(exact && TASK_SIZE_IS_PAGE_OFFSET))
    kasld_result_base(KASLD_TYPE_VIRT, REGION_PAGE_OFFSET,
                      round_to_stride(addr), NULL, CONF_HEURISTIC);
#endif

  return 0;
#endif
}
