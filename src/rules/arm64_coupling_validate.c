// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Verdict: arm64 regional VA-band validation (sibling of
// coupling_validate.c for x86_64).
//
// Each region in the arm64 modern (v5.4+) VAS lives in a fixed sub-band
// anchored to VA_BITS_MIN = 48 constants:
//
//   DIRECTMAP / PAGE_OFFSET   in [PAGE_OFFSET,    _PAGE_END(48)) = [...,
//   0xffff800000000000) MODULE / MODULE_REGION    in [MODULES_START,
//   MODULES_END]   (union over kernel-version layouts) KERNEL_TEXT /
//   KERNEL_IMAGE in [KERNEL_VIRT_TEXT_MIN, KERNEL_VIRT_TEXT_MAX] (the
//   validation range) VMEMMAP                   in [VMEMMAP_START,
//   0xffffffffc0000000) (VA48 floor; ~0xfffffdffc0000000)
//
// IMPORTANT: the KERNEL_TEXT / KERNEL_IMAGE check uses KERNEL_VIRT_TEXT_MIN/MAX
// (the *validation* range that covers every in-scope kernel-version layout),
// NOT KASLR_VIRT_TEXT_MIN/MAX (the narrower *per-formula KASLR randomization
// window* derived from kaslr_early.c at one specific kernel version). The
// kernel's KASLR algorithm has shifted across versions (v6.6 vs v6.12);
// pinning the validation band to one formula's window would reject legitimate
// text leaks produced by any other version sitting inside the wider arch VAS.
// Same shape as the modules-window union widening — see api.h MODULES_*
// validation-union contract.
//
// The bands themselves are KASLR-invariant — the kernel image's KASLR slot
// inside the KASLR window is the only randomized position; the band
// containers are fixed. An observation whose eff_region claims one band
// but whose address falls in a different band's range is misclassified —
// typically a heap pointer, percpu offset, or stack pointer mistakenly
// tagged. The verdict rule emits V_INVALID for such observations so they
// do not pollute downstream rules (e.g., a heap pointer mistagged as
// DIRECTMAP would otherwise feed directmap_page_offset_bounds an unsound
// floor).
//
// The ruling is a pure function of the observation's own region and anchor
// versus compile-time geometry — no cross-observation or estimate dependency.
// Same shape as coupling_validate.
//
// arm64 only; inert elsewhere. Defensive insurance against a mistagged
// observation; matches the pattern used on x86_64.
//
// References:
// arch/arm64/include/asm/memory.h    (band constants)
// arch/arm64/include/asm/pgtable.h   (VMEMMAP_END = -SZ_1G)
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"

#include <string.h>

/* The linear map sits in [PAGE_OFFSET, _PAGE_END), both functions of VA_BITS.
 * The widest accepting ceiling is _PAGE_END of the SMALLEST supported VA_BITS
 * (highest _PAGE_END) — arm64_page_end_for(ARM64_VA_BITS_MIN_SUPPORTED) — so a
 * sub-48 PAGE_OFFSET (e.g. 39-bit 0xffffff8000000000) is admitted, not flagged
 * as out-of-band. Trade-off: the gap between the 48-bit and smallest-VA_BITS
 * _PAGE_END values is no longer policed pre-resolution (a 48-bit heap pointer
 * mistagged DIRECTMAP there is admitted); the directmap consumers narrow once
 * PAGE_OFFSET resolves. */
#define ARM64_VMEMMAP_END 0xffffffffc0000000ul /* −SZ_1G */
/* VA_BITS=48 VMEMMAP floor; conservative for both VA48 and VA52 (VA52's
 * VMEMMAP extends further down, so any address < VA48 floor is consistent
 * with VA52 vmemmap — we don't invalidate it). Matches the threshold the
 * arm64_va_bits_from_vmemmap rule uses. */
#define ARM64_VA48_VMEMMAP_START 0xfffffdffc0000000ul

#if defined(__aarch64__)
static int arm64_va_band_bad(enum kasld_region region, unsigned long a) {
  switch (region) {
  case REGION_DIRECTMAP:
  case REGION_PAGE_OFFSET:
    /* Linear map lives in [PAGE_OFFSET, _PAGE_END), both VA_BITS-dependent.
     * Widest accepting bounds: floor at the lowest PAGE_OFFSET (VA52's,
     * KERNEL_VIRT_VAS_START); ceiling at the highest _PAGE_END (smallest
     * supported VA_BITS). */
    return (a >= arm64_page_end_for(ARM64_VA_BITS_MIN_SUPPORTED)) ||
           (a < (unsigned long)KERNEL_VIRT_VAS_START);
  case REGION_MODULE:
  case REGION_MODULE_REGION:
    /* Modules sit in the fixed [MODULES_START, MODULES_END] band. */
    return (a < (unsigned long)MODULES_START) ||
           (a > (unsigned long)MODULES_END);
  case REGION_KERNEL_TEXT:
  case REGION_KERNEL_IMAGE:
    /* Inside the *validation* range — KERNEL_VIRT_TEXT_MIN/MAX (the arch's
     * widest plausible text-base window) rather than KASLR_VIRT_TEXT_MIN/MAX
     * (one specific KASLR formula's narrower randomization window). The latter
     * would reject legitimate text leaks from kernel versions whose
     * kaslr_early.c algorithm produces slots outside the current header's
     * modelled window. */
    return (a < (unsigned long)KERNEL_VIRT_TEXT_MIN) ||
           (a > (unsigned long)KERNEL_VIRT_TEXT_MAX);
  case REGION_VMEMMAP:
    /* Above VA48 vmemmap floor *or* anywhere below it (VA52 territory); either
     * way, must be below VMEMMAP_END (= −SZ_1G). The arm64 va_bits-from-vmemmap
     * rule cares about the *floor* discriminator; this verdict only rejects the
     * unambiguously-out-of-range case. */
    return (a >= ARM64_VMEMMAP_END);
  default:
    return 0; /* no band check for this region kind */
  }
}
#endif

int rule_arm64_coupling_validate(const struct evidence_set *ev,
                                 struct verdict *out, int out_max) {
#if defined(__aarch64__)
  return kasld_emit_va_band_verdicts(ev, out, out_max, arm64_va_band_bad,
                                     "arm64_coupling_validate");
#else
  (void)ev;
  (void)out;
  (void)out_max;
  return 0;
#endif
}
