// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Verdict: riscv64 regional VA-band validation (sibling of
// coupling_validate.c for x86_64 and arm64_coupling_validate.c for arm64).
//
// Each region in the modern (v5.10+) riscv64 VAS lives in a fixed band
// anchored to the SATP-mode-dependent PAGE_OFFSET:
//
//   KERNEL_TEXT / KERNEL_IMAGE in [KERNEL_VIRT_TEXT_MIN, KERNEL_VIRT_TEXT_MAX]
//     (the validation range — top 2 GiB at KERNEL_LINK_ADDR for modern,
//      plus the wider pre-v5.10 legacy floor)
//   MODULE / MODULE_REGION    in [MODULES_START, MODULES_END]
//     (relative to text; static union covers both v5.10+ and legacy)
//   VMALLOC                   in [KERNEL_VIRT_VAS_START,
//   PAGE_OFFSET_SV39_LEGACY) VMEMMAP                   in
//   [KERNEL_VIRT_VAS_START, PAGE_OFFSET_SV39_LEGACY)
//     (both lie immediately below PAGE_OFFSET on every SATP mode; the
//      highest plausible PAGE_OFFSET is the strict upper bound)
//   DIRECTMAP / PAGE_OFFSET   in [PAGE_OFFSET_SV57, KERNEL_VIRT_VAS_END]
//     (linear map starts at PAGE_OFFSET; the lowest plausible PAGE_OFFSET
//      across SATP modes is SV57, giving the widest accepting floor)
//
// The bands themselves are KASLR-invariant — the kernel image's KASLR slot
// inside the KASLR window is the only randomised position; the band
// containers are fixed (modulo SATP mode, which the bands above absorb by
// using the widest plausible edges). An observation whose eff_region claims
// one band but whose address falls in a different band's range is
// misclassified — typically a heap pointer, percpu offset, or stack pointer
// mistakenly tagged. The verdict rule emits V_INVALID for such observations
// so they do not pollute downstream rules.
//
// The ruling is a pure function of the observation's own region and anchor
// versus compile-time geometry — no cross-observation or estimate dependency.
// Same shape as coupling_validate / arm64_coupling_validate.
//
// IMPORTANT: the KERNEL_TEXT / KERNEL_IMAGE check uses KERNEL_VIRT_TEXT_MIN/MAX
// (the validation range across all in-scope kernel-version layouts), NOT a
// per-formula KASLR-window subset — same role distinction as the parallel
// x86_64 / arm64 rules; see api.h MODULES_* validation-union contract
// for the underlying pattern.
//
// riscv64 only; inert elsewhere. Defensive insurance against a mistagged
// observation; matches the pattern used on x86_64 and arm64.
//
// References:
// arch/riscv/include/asm/page.h     (PAGE_OFFSET_L3/L4/L5)
// arch/riscv/include/asm/pgtable.h  (VMALLOC/VMEMMAP/MODULES layout)
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"

#include <string.h>

/* PAGE_OFFSET values across SATP modes. Sorted ascending. */
#define RISCV64_PAGE_OFFSET_SV57 0xff60000000000000ul /* PAGE_OFFSET_L5 */
/* Highest plausible PAGE_OFFSET across SATP modes and kernel versions:
 * SV39 PAGE_OFFSET_L3 was 0xffffffd800000000 pre-v6.12, then moved to
 * 0xffffffd600000000 v6.12+. The legacy (higher) value gives the wider
 * accepting upper bound for "must be below PAGE_OFFSET" checks. */
#define RISCV64_PAGE_OFFSET_HIGHEST 0xffffffd800000000ul

int rule_riscv64_coupling_validate(const struct evidence_set *ev,
                                   struct verdict *out, int out_max) {
#if (defined(__riscv) || defined(__riscv__)) && __riscv_xlen == 64
  int n = 0;
  for (int i = 0; i < ev->n_obs && n < out_max; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->value_kind != OBS_ADDRESS ||
        o->eff_type != KASLD_TYPE_VIRT)
      continue;

    unsigned long a = obs_anchor(o);
    if (a == 0)
      continue;

    int bad = 0;
    switch (o->eff_region) {
    case REGION_DIRECTMAP:
    case REGION_PAGE_OFFSET:
      /* Linear map lives at or above PAGE_OFFSET. Lowest plausible
       * PAGE_OFFSET across SATP modes (SV57) is the widest accepting
       * floor. Upper bound: kernel VAS end. */
      bad = (a < RISCV64_PAGE_OFFSET_SV57) ||
            (a > (unsigned long)KERNEL_VIRT_VAS_END);
      break;
    case REGION_VMALLOC:
    case REGION_VMEMMAP:
      /* Both regions sit immediately below PAGE_OFFSET on every SATP mode.
       * The highest plausible PAGE_OFFSET across modes/versions is the
       * strict upper bound; widest accepting lower bound is the kernel VAS
       * floor. */
      bad = (a >= RISCV64_PAGE_OFFSET_HIGHEST) ||
            (a < (unsigned long)KERNEL_VIRT_VAS_START);
      break;
    case REGION_KERNEL_TEXT:
    case REGION_KERNEL_IMAGE:
      /* Inside the validation range (KERNEL_VIRT_TEXT_MIN/MAX covers both
       * modern top-2-GiB layout and pre-v5.10 linear-map text). */
      bad = (a < (unsigned long)KERNEL_VIRT_TEXT_MIN) ||
            (a > (unsigned long)KERNEL_VIRT_TEXT_MAX);
      break;
    case REGION_MODULE:
    case REGION_MODULE_REGION:
      /* Inside the module-band union (modern relative-to-text + legacy). */
      bad = (a < (unsigned long)MODULES_START) ||
            (a > (unsigned long)MODULES_END);
      break;
    default:
      continue; /* no band check for this region kind */
    }

    if (!bad)
      continue;

    struct verdict *v = &out[n++];
    memset(v, 0, sizeof(*v));
    v->observation_id = o->id;
    v->kind = V_INVALID;
    v->conf = o->conf;
    v->derived_from[0] = o->id;
    v->lineage_count = 1;
    snprintf(v->origin, ORIGIN_LEN, "riscv64_coupling_validate");
  }
  return n;
#else
  (void)ev;
  (void)out;
  (void)out_max;
  return 0;
#endif
}
