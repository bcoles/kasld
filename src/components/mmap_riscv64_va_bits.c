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
// PAGE_OFFSET is not randomised on riscv64, so the SV48/SV57 values are exact;
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
#include <errno.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

KASLD_EXPLAIN(
    "Probes mmap(MAP_FIXED) at 1<<38 then 1<<47 on riscv64 to detect "
    "the SATP mode: ENOMEM at 1<<38 means SV39 (PAGE_OFFSET window "
    "[0xffffffd600000000, 0xffffffd800000000]); ENOMEM at 1<<47 means "
    "SV48 (PAGE_OFFSET 0xffffaf8000000000); success at both means SV57 "
    "(PAGE_OFFSET 0xff60000000000000). PAGE_OFFSET is not randomised "
    "on riscv64, so SV48/SV57 are exact. riscv64 only; unprivileged.");

KASLD_META("method:heuristic\n"
           "phase:probing\n"
           "addr:virtual\n");

int main(void) {
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

  /* --- probe 1: SV39 boundary (1<<38) --- */
  void *p1 = mmap(RISCV_TASK_SIZE_SV39, RISCV_PROBE_LEN, PROT_READ,
                  MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  if (p1 == MAP_FAILED) {
    if (errno != ENOMEM)
      return 0; /* a different failure: don't infer */
    printf("[.] mmap(1<<38) failed (ENOMEM): SV39\n");
    printf("PAGE_OFFSET: [%#lx, %#lx]\n", RISCV_PAGE_OFFSET_SV39_LO,
           RISCV_PAGE_OFFSET_SV39_HI);
    kasld_result_range(KASLD_TYPE_VIRT, REGION_PAGE_OFFSET,
                       RISCV_PAGE_OFFSET_SV39_LO, RISCV_PAGE_OFFSET_SV39_HI,
                       NULL, CONF_INFERRED);
    return 0;
  }
  munmap(p1, RISCV_PROBE_LEN);

  /* --- probe 2: SV48 boundary (1<<47) --- */
  void *p2 = mmap(RISCV_TASK_SIZE_SV48, RISCV_PROBE_LEN, PROT_READ,
                  MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  unsigned long virt_page_offset;
  if (p2 == MAP_FAILED) {
    if (errno != ENOMEM)
      return 0;
    virt_page_offset = RISCV_PAGE_OFFSET_SV48; /* SV48 */
    printf("[.] mmap(1<<47) failed (ENOMEM): SV48\n");
  } else {
    munmap(p2, RISCV_PROBE_LEN);
    virt_page_offset = RISCV_PAGE_OFFSET_SV57; /* SV57 */
    printf("[.] mmap(1<<47) succeeded: SV57\n");
  }
  printf("PAGE_OFFSET: %#lx\n", virt_page_offset);
  kasld_result_base(KASLD_TYPE_VIRT, REGION_PAGE_OFFSET, virt_page_offset, NULL,
                    CONF_INFERRED);
  return 0;
#else
  return 0;
#endif
}
