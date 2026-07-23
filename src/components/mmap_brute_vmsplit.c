// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Find start of kernel virtual address space (CONFIG_PAGE_OFFSET)
// on 32-bit systems by mapping a page at 0x10000000 increments
// across the entire 32-bit address space (until failure).
//
// Usually vmsplit is located at 3GB (0xc0000000) on 32-bit systems;
// however, embedded systems may make use of a lower vmsplit.
//
// The sweep steps 256 MiB, so it returns the split rounded UP to that stride.
// On x86_32 the mmap split IS PAGE_OFFSET exactly (TASK_SIZE == __PAGE_OFFSET),
// so the last-mapped and first-unmapped steps bracket PAGE_OFFSET in a SOUND
// 256 MiB band (emitted at inferred confidence, TASK_SIZE_IS_PAGE_OFFSET), on
// top of the rounded best-guess emitted at heuristic confidence.
//
// Leak primitive:
//   Data leaked:      kernel/user address space split point
//   (CONFIG_PAGE_OFFSET) Kernel subsystem: mm — mmap syscall (virtual address
//   space probing) Data structure:   kernel virtual address space boundary
//   Address type:     virtual (kernel VAS start)
//   Method:           brute (mmap sweep across the 32-bit address space)
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
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

KASLD_EXPLAIN("Probes the 32-bit address space by attempting mmap at 256 MiB "
              "increments until mapping fails. The first unmappable address is "
              "the kernel/user virtual address split (CONFIG_PAGE_OFFSET). "
              "32-bit only. No privilege or sysctl gate; the split is a "
              "fundamental architectural property.");

KASLD_META("method:brute\n"
           "phase:probing\n"
           "live:1\n"
           "addr:virtual\n");

/* Sweep the low 32-bit address space in 256 MiB steps. Return the first address
 * that will not map — the user/kernel split, where mmap rejects addr +
 * PAGE_SIZE > TASK_SIZE — and set *last_ok to the highest step that DID map
 * (strictly below the split). Returns 0 if the split was not located.
 *
 * MAP_FIXED (not MAP_FIXED_NOREPLACE): the latter is a Linux 4.17+ flag,
 * silently ignored as a plain hint on older kernels — mmap would then no longer
 * FAIL past TASK_SIZE and the sweep would run off the end. 32-bit targets
 * include pre-4.17 kernels, so the forcible flag is required. The 256 MiB
 * stride keeps every probe well below the stack (STACK_TOP == TASK_SIZE), so no
 * live mapping is clobbered. */
static unsigned long find_kernel_address_space_start(unsigned long *last_ok) {
  unsigned long i, prev = 0;
  kasld_info("searching 32-bit address space for kernel virtual address space "
             "start ...");

  for (i = 0x10000000; i < 0xf0000000; i += 0x10000000) {
    if (mmap((void *)i, PAGE_SIZE, PROT_READ,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0) == MAP_FAILED) {
      *last_ok = prev;
      return i;
    }
    munmap((void *)i, PAGE_SIZE);
    prev = i;
  }

  kasld_err("Could not locate kernel virtual address space");
  return 0;
}

int main(void) {
  if (kasld_skip_live_probe("VMSPLIT mmap"))
    return 0;
  /* Live mmap probe of the running VA space. */
  unsigned long last_ok = 0;
  unsigned long addr = find_kernel_address_space_start(&last_ok);
  if (!addr)
    return 0;

  kasld_info("kernel virtual address start: %lx", addr);

  /* Likely PAGE_OFFSET: the split rounded UP to the 256 MiB probe stride. Exact
   * for every 256 MiB-aligned VMSPLIT (1G/2G/3G_OPT/3G); an over-estimate only
   * for the rare x86 VMSPLIT_2G_OPT (0x78000000). Best guess for the likely
   * window. */
  kasld_result_base(KASLD_TYPE_VIRT, REGION_PAGE_OFFSET, addr, NULL,
                    CONF_HEURISTIC);

#if TASK_SIZE_IS_PAGE_OFFSET
  /* Where the mmap user/kernel split IS PAGE_OFFSET exactly (x86_32:
   * TASK_SIZE == __PAGE_OFFSET, no gap), the sweep bounds PAGE_OFFSET SOUNDLY
   * with no alignment assumption: it mapped at last_ok (so last_ok < TASK_SIZE
   * == PAGE_OFFSET) and failed at addr (so addr >= TASK_SIZE == PAGE_OFFSET),
   * giving PAGE_OFFSET in (last_ok, addr]. Emit that as a bounded range —
   * page_offset_from_landmark turns it into a C_LOWER_BOUND / C_UPPER_BOUND
   * pair at this inferred tier, moving the x86_32 (no-KASLR) page offset into
   * the GUARANTEED window. A 256 MiB band; exact when the split is 256
   * MiB-aligned.
   *
   * Only a coarse band, not the exact split: the fine boundary can't be
   * measured with MAP_FIXED because the stack sits just below PAGE_OFFSET
   * (STACK_TOP == TASK_SIZE), so a page-granular MAP_FIXED sweep would clobber
   * it. Gated off on arches where the split sits a gap below PAGE_OFFSET
   * (arm32: TASK_SIZE = PAGE_OFFSET - 16 MiB), where addr >= PAGE_OFFSET is not
   * implied. */
  if (last_ok)
    kasld_result_range(KASLD_TYPE_VIRT, REGION_PAGE_OFFSET, last_ok + 1, addr,
                       NULL, CONF_INFERRED);
#endif

#if KERNEL_VIRT_VAS_START /* vacuous where VAS_START is 0 (s390) */
  if (addr < (unsigned long)KERNEL_VIRT_VAS_START)
    kasld_err("warning: virtual address start %lx below configured "
              "KERNEL_VIRT_VAS_START %lx",
              addr, (unsigned long)KERNEL_VIRT_VAS_START);
#endif

  return 0;
}
