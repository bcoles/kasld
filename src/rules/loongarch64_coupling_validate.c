// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Verdict: LoongArch64 regional VA-band validation (sibling of
// coupling_validate.c for x86_64, arm64_coupling_validate.c for arm64,
// and riscv64_coupling_validate.c for riscv64).
//
// LoongArch64 splits the kernel VAS into two hardware-defined macro
// ranges plus the kernel-image window:
//
//   XKPRANGE  [0x8000_0000_0000_0000, 0xa000_0000_0000_0000)
//     Hardware direct-mapped windows (DMW0/1/2). Linear map / lowmem;
//     PAGE_OFFSET = 0x9000_0000_0000_0000 (CACHE_BASE = DMW1 entry).
//   XKVRANGE  [0xc000_0000_0000_0000, ...)
//     Paged virtual range: vmalloc, modules, vmemmap, kfence, fixmap.
//     vm_map_base = 0 - (1 << cpu_vabits) — for VABITS_48 (typical):
//     0xffff_0000_0000_0000. Modules at vm_map_base + small_offset;
//     vmalloc just above modules; vmemmap above vmalloc.
//
// Per-region bands (using KASLR-invariant boundaries):
//
//   KERNEL_TEXT / KERNEL_IMAGE in [KERNEL_VIRT_TEXT_MIN, KERNEL_VIRT_TEXT_MAX]
//     (XKPRANGE DMW1 + 8 GiB headroom for the KASLR slide)
//   MODULE / MODULE_REGION    in [MODULES_START, MODULES_END]
//     (the XKVRANGE module-and-vmalloc span)
//   VMALLOC                   in [MODULES_START, MODULES_END]
//     (lives in the XKVRANGE span alongside modules; cpu_vabits-dependent
//      exact bounds are unknown statically, so use the same conservative
//      union)
//   VMEMMAP                   in [MODULES_START, MODULES_END]
//     (also XKVRANGE-resident)
//   DIRECTMAP / PAGE_OFFSET   in [KERNEL_VIRT_VAS_START, XKVRANGE)
//     (XKPRANGE span: 0x8000_..., 0xa000_..._fffffffe)
//
// The bands are KASLR-invariant — KASLR randomizes only the kernel text
// slot within KERNEL_VIRT_TEXT_MIN/MAX; the band containers are fixed by
// hardware DMW windows or by vm_map_base which is set from cpu_vabits at
// boot and never moves. An observation whose eff_region claims one band
// but whose address falls in another is misclassified — typically a
// heap pointer, percpu offset, or stack pointer mistakenly tagged.
//
// IMPORTANT: KERNEL_TEXT / KERNEL_IMAGE uses KERNEL_VIRT_TEXT_MIN/MAX (the
// validation range across all in-scope kernel-version layouts), not a
// narrower per-formula KASLR-window subset — same role distinction as
// the parallel x86_64 / arm64 / riscv64 rules. See api.h MODULES_*
// validation-union contract for the underlying pattern.
//
// The ruling is a pure function of the observation's own region and anchor
// versus compile-time geometry — no cross-observation or estimate dependency.
//
// loongarch64 only; inert elsewhere. Defensive insurance against a mistagged
// observation; matches the pattern used on x86_64, arm64, and riscv64.
//
// References:
// arch/loongarch/include/asm/addrspace.h  (XKPRANGE/XKVRANGE)
// arch/loongarch/include/asm/pgtable.h    (VMALLOC/VMEMMAP/MODULES layout)
// arch/loongarch/kernel/cpu-probe.c       (vm_map_base initialization)
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"

#include <string.h>

/* Boundary between XKPRANGE (hardware direct-map / linear map) and
 * XKVRANGE (paged kernel virtual range: vmalloc/modules/vmemmap). */
#define LOONGARCH_XKVRANGE_FLOOR 0xc000000000000000ul

#if defined(__loongarch__) && __loongarch_grlen == 64
static int loongarch64_va_band_bad(enum kasld_region region, unsigned long a) {
  switch (region) {
  case REGION_DIRECTMAP:
  case REGION_PAGE_OFFSET:
    /* Linear map lives in XKPRANGE (hardware DMW). Below XKVRANGE floor and
     * above KERNEL_VIRT_VAS_START. */
    return (a < (unsigned long)KERNEL_VIRT_VAS_START) ||
           (a >= LOONGARCH_XKVRANGE_FLOOR);
  case REGION_VMALLOC:
  case REGION_VMEMMAP:
  case REGION_MODULE:
  case REGION_MODULE_REGION:
    /* All XKVRANGE-resident; share the modules-band union as a conservative
     * bound (the exact per-cpu_vabits split between modules/vmalloc/vmemmap is
     * not statically known). */
    return (a < (unsigned long)MODULES_START) ||
           (a > (unsigned long)MODULES_END);
  case REGION_KERNEL_TEXT:
  case REGION_KERNEL_IMAGE:
    /* Inside the validation range (covers KASLR slide + headroom). */
    return (a < (unsigned long)KERNEL_VIRT_TEXT_MIN) ||
           (a > (unsigned long)KERNEL_VIRT_TEXT_MAX);
  default:
    return 0; /* no band check for this region kind */
  }
}
#endif

int rule_loongarch64_coupling_validate(const struct evidence_set *ev,
                                       struct verdict *out, int out_max) {
#if defined(__loongarch__) && __loongarch_grlen == 64
  return kasld_emit_va_band_verdicts(ev, out, out_max, loongarch64_va_band_bad,
                                     "loongarch64_coupling_validate");
#else
  (void)ev;
  (void)out;
  (void)out_max;
  return 0;
#endif
}
