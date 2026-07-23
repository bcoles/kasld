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
// virt_page_offset_base. The file was world-readable (0444) but was restricted
// to root (0400) in v4.11; a privileged read still sees hashed values on
// v4.15+, since %p hashing is not lifted by CAP_SYSLOG.
//
// The '%p' → salted-hash change in v4.15 (commit ad67b74d) replaced all
// remaining raw pointer output including '.base:', making each value a
// uniform-random word on v4.15+ (unless no_hash_pointers). A real timer base is
// a per-CPU struct address, pointer-aligned; a hashed word is not. Pointer
// hashing is all-or-nothing per boot, so a single misaligned '.base:' condemns
// the read — decline rather than emit a forged direct-map address. The
// kernel-VA-range check alone does NOT catch hashing on 32-bit, where the VAS
// floor is the wide lowest-vmsplit value (0x40000000) and a hashed word passes
// it; the alignment gate below closes that (as proc_net_sock_ptr does).
//
// Leak primitive:
//   Data leaked:      per-CPU timer base pointer (direct-map address)
//   Kernel subsystem: kernel/time/timer_list.c — /proc/timer_list
//   Data structure:   struct timer_base (per-CPU)
//   Address type:     virtual (direct-map)
//   Method:           parsed (proc text file)
//   Status:           hashed in v4.15 (commit ad67b74d)
//   Access check:     root-only (mode 0400) since v4.11; was 0444 before
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
#include "include/kasld/api.h"
#include "include/kasld/cli.h"
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

KASLD_EXPLAIN(
    "Reads per-CPU timer base pointers from /proc/timer_list '.base:' lines. "
    "The struct timer_base pointer is printed via raw '%p' and resides in the "
    "direct-map range, bounding virt_page_offset_base. Root-only (0400) since "
    "v4.11. Hashed in v4.15 (commit ad67b74d); a misaligned '.base:' is a "
    "hashed id, so the read is declined rather than trusted.");

KASLD_META("method:parsed\n"
           "phase:inference\n"
           "addr:virtual\n"
           "patch:v4.15\n");

/* Minimum alignment a real per-CPU struct timer_base pointer is guaranteed to
 * have: the struct holds pointers, so its address is at least pointer-aligned.
 * A hashed %p word clears this only 1-in-sizeof(void*) of the time. Kept at
 * that conservative floor so a real read is never mistaken for hashed; the
 * all-or-nothing decline over the many '.base:' lines does the rest. */
#define TIMER_BASE_ALIGN sizeof(void *)

enum tb_class {
  TB_SKIP,      /* zero, or aligned non-kernel value */
  TB_CANDIDATE, /* aligned, in the direct-map / kernel VAS: a plausible pointer
                 */
  TB_HASHED     /* misaligned: a hashed %p id, not a real pointer */
};

/* Classify one parsed '.base:' value. Alignment is checked BEFORE the range
 * test, so a hashed id that lands inside the (wide, on 32-bit) kernel VAS is
 * still recognised as hashed rather than trusted as a direct-map address. */
static enum tb_class classify_timer_base(unsigned long val) {
  if (val == 0)
    return TB_SKIP;
  if (val & (TIMER_BASE_ALIGN - 1))
    return TB_HASHED;
  /* Direct-map range: PAGE_OFFSET to start of kernel text. On 32-bit or coupled
   * arches that window is empty (PAGE_OFFSET == KERNEL_VIRT_TEXT_MIN), so the
   * kernel-VAS fallback accepts any kernel VA. */
  if (kasld_addr_is_directmap(val) || kasld_addr_is_kernel_vas(val))
    return TB_CANDIDATE;
  return TB_SKIP;
}

int main(void) {
  const char *path = "/proc/timer_list";
  char line[512];
  int hashed = 0;
  unsigned long base = 0; /* first plausible '.base:' value */

  kasld_info("scanning %s for timer base addresses ...", path);

  FILE *f = kasld_fopen(path, "r");
  if (!f) {
    int e = errno;
    perror("[-] fopen");
    return (e == EACCES || e == EPERM) ? KASLD_EXIT_NOPERM
                                       : KASLD_EXIT_UNAVAILABLE;
  }

  /* Scan EVERY '.base:' line, not just the first: a single misaligned value
   * proves the pointers are hashed and condemns the whole read. */
  while (fgets(line, sizeof(line), f)) {
    const char *bp = strstr(line, ".base:");
    if (!bp)
      continue;
    const char *p = bp + strlen(".base:");
    while (*p == ' ')
      p++;
    char *endptr;
    unsigned long val = strtoul(p, &endptr, 16);
    if (endptr - p < (ptrdiff_t)(sizeof(void *) * 2))
      continue;
    switch (classify_timer_base(val)) {
    case TB_HASHED:
      hashed = 1;
      break;
    case TB_CANDIDATE:
      if (base == 0)
        base = val;
      break;
    case TB_SKIP:
      break;
    }
  }

  fclose(f);

  if (hashed) {
    kasld_err(
        "timer base pointers are hashed (%%p ids, not real addresses); "
        "boot no_hash_pointers or read a pre-v4.15 kernel for real values");
    return 0;
  }
  if (base == 0) {
    kasld_err("no timer base address found in %s", path);
    return 0;
  }

  kasld_info("timer base address: 0x%016lx", base);
  kasld_result_sample(KASLD_TYPE_VIRT, REGION_DIRECTMAP, base, NULL,
                      CONF_PARSED);
#ifdef directmap_virt_to_phys
  {
    unsigned long phys = directmap_virt_to_phys(base);
    kasld_info("  possible physical address: 0x%016lx", phys);
    kasld_result_sample(KASLD_TYPE_PHYS, REGION_DIRECTMAP, phys, NULL,
                        CONF_PARSED);
  }
#endif

  return 0;
}
