// This file is part of KASLD - https://github.com/bcoles/kasld
//
// riscv64 SATP mode detection via mmap boundary probes, emitting PAGE_OFFSET.
//
// PROBING-phase component. On riscv64
// TASK_SIZE = 1UL << (VA_BITS - 1), and the kernel rejects MAP_FIXED mappings
// at or above TASK_SIZE with ENOMEM. Two sequential probes distinguish all
// three supported SATP modes:
//
//   probe 1 at 1<<38 (SV39 boundary):
//     ENOMEM  -> SV39: PAGE_OFFSET is kernel-version dependent, one of
//                 0xffffffd600000000 (v6.12+) or 0xffffffd800000000
//                 (pre-v6.12). Emit the [LO, HI] window (a range, not a pin) —
//                 the exact value can't be resolved from the probe alone.
//     success -> SV48 or SV57; continue to probe 2.
//   probe 2 at 1<<47 (SV48 boundary):
//     ENOMEM  -> SV48: PAGE_OFFSET = 0xffffaf8000000000 exactly.
//     success -> SV57: PAGE_OFFSET = 0xff60000000000000 exactly.
//
// PAGE_OFFSET is not randomized on riscv64, so the SV48/SV57 values are exact;
// the engine pins Q_PAGE_OFFSET to them (page_offset_from_landmark), and treats
// the SV39 range as a [lower, upper] bound. It is a PROBING component: the
// engine reads component results, and an active probe belongs behind the
// subprocess boundary.
//
// Leak primitive: virtual (kernel direct-map base) via the mmap syscall;
// unprivileged, no sysctl gate. riscv64 only.
//
// Caveat: RLIMIT_AS exhaustion also returns ENOMEM. Unlikely at probe time;
// the same risk mmap_brute_vmsplit accepts.
// ---
// <bcoles@gmail.com>

#define _GNU_SOURCE
#include "include/kasld/api.h"
#include "include/kasld/cli.h"
#include <errno.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

KASLD_EXPLAIN(
    "Probes mmap(MAP_FIXED) at 1<<38 then 1<<47 on riscv64 to detect "
    "the SATP mode: ENOMEM at 1<<38 means SV39 (PAGE_OFFSET window "
    "[0xffffffd600000000, 0xffffffd800000000]); ENOMEM at 1<<47 means "
    "SV48 (PAGE_OFFSET 0xffffaf8000000000); success at both means SV57 "
    "(PAGE_OFFSET 0xff60000000000000). PAGE_OFFSET is not randomized "
    "on riscv64, so SV48/SV57 are exact. riscv64 only; unprivileged.");

KASLD_META("method:inferred\n"
           "phase:probing\n"
           "live:1\n"
           "addr:virtual\n");

#if defined(__riscv) && __riscv_xlen == 64
/* PAGE_OFFSET values from arch/riscv/include/asm/page.h */
#define RISCV_PAGE_OFFSET_SV57                                                 \
  0xff60000000000000ul                              /* SV57 (compile default)  \
                                                     */
#define RISCV_PAGE_OFFSET_SV48 0xffffaf8000000000ul /* SV48 */
/* SV39 changed in v6.12 (linear map 160 GiB -> 168 GiB): _LO is v6.12+, _HI is
 * pre-v6.12. Without a version check, report the [_LO, _HI] window. */
#define RISCV_PAGE_OFFSET_SV39_LO 0xffffffd600000000ul /* v6.12+ */
#define RISCV_PAGE_OFFSET_SV39_HI 0xffffffd800000000ul /* pre-v6.12 */
#define RISCV_TASK_SIZE_SV39 ((void *)(1UL << 38))
#define RISCV_TASK_SIZE_SV48 ((void *)(1UL << 47))
#define RISCV_PROBE_LEN 0x1000ul

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

/* Is `want` inside this process's address space?
 *
 * MAP_FIXED_NOREPLACE rather than MAP_FIXED: the forcible flag does not decline
 * on a collision, it destroys whatever is mapped there. Both boundaries probed
 * here are legitimate user addresses whenever the active mode is wider than the
 * one being tested (1<<38 is an ordinary address under SV48), so the risk is
 * not hypothetical, merely unlikely. NOREPLACE also answers more precisely:
 * EEXIST means occupied, which is itself proof the address is below TASK_SIZE.
 *
 * The flag is v4.17+ and is ignored as a plain hint before that, which shows up
 * as a mapping at some other address; that is treated as unusable rather than
 * guessed at. RISC-V is not a practical concern there — the port predates the
 * flag by two releases and no real riscv64 system runs a kernel that old — but
 * declining costs nothing and keeps the rule uniform with the other probes. */
enum probe_r { PROBE_WITHIN, PROBE_BEYOND, PROBE_UNUSABLE };

static enum probe_r probe_boundary(void *want) {
  void *p = mmap(want, RISCV_PROBE_LEN, PROT_NONE,
                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
  if (p == want) {
    munmap(p, RISCV_PROBE_LEN);
    return PROBE_WITHIN;
  }
  if (p != MAP_FAILED) {
    munmap(p, RISCV_PROBE_LEN); /* displaced: the flag was not honoured */
    return PROBE_UNUSABLE;
  }
  if (errno == EEXIST)
    return PROBE_WITHIN;
  if (errno == ENOMEM)
    return PROBE_BEYOND;
  return PROBE_UNUSABLE;
}
#endif /* riscv64 */

int main(void) {
  if (kasld_skip_live_probe("VA_BITS mmap"))
    return 0;
  /* Live mmap boundary probe of the running VA space. */
#if defined(__riscv) && __riscv_xlen == 64

  /* --- probe 1: SV39 boundary (1<<38) --- */
  switch (probe_boundary(RISCV_TASK_SIZE_SV39)) {
  case PROBE_BEYOND:
    kasld_info("mmap(1<<38) rejected: SV39");
    kasld_info("PAGE_OFFSET: [%#lx, %#lx]", RISCV_PAGE_OFFSET_SV39_LO,
               RISCV_PAGE_OFFSET_SV39_HI);
    kasld_result_range(KASLD_TYPE_VIRT, REGION_PAGE_OFFSET,
                       RISCV_PAGE_OFFSET_SV39_LO, RISCV_PAGE_OFFSET_SV39_HI,
                       NULL, CONF_INFERRED);
    return 0;
  case PROBE_UNUSABLE:
    return 0; /* cannot tell; leave the engine its honest window */
  case PROBE_WITHIN:
    break;
  }

  /* --- probe 2: SV48 boundary (1<<47) --- */
  unsigned long virt_page_offset;
  switch (probe_boundary(RISCV_TASK_SIZE_SV48)) {
  case PROBE_BEYOND:
    virt_page_offset = RISCV_PAGE_OFFSET_SV48; /* SV48 */
    kasld_info("mmap(1<<47) rejected: SV48");
    break;
  case PROBE_WITHIN:
    virt_page_offset = RISCV_PAGE_OFFSET_SV57; /* SV57 */
    kasld_info("mmap(1<<47) accepted: SV57");
    break;
  default:
    return 0;
  }
  kasld_info("PAGE_OFFSET: %#lx", virt_page_offset);
  kasld_result_base(KASLD_TYPE_VIRT, REGION_PAGE_OFFSET, virt_page_offset, NULL,
                    CONF_INFERRED);
  return 0;
#else
  return 0;
#endif
}
