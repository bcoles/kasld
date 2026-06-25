// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Curation rule: x86-64 directmap/text coupling validation.
//
// Two
// classes of virtual observation are misclassified by construction on x86-64
// and are invalidated (V_INVALID):
//
//   - a DIRECTMAP observation at or above KERNEL_VIRT_TEXT_MIN: the direct map
//   never
//     reaches __START_KERNEL_map, so such an address is not directmap;
//   - a kernel-text/image observation below KERNEL_VIRT_TEXT_MIN: below the
//   kernel
//     image map's floor (__START_KERNEL_map), so not a valid text base.
//
// IMPORTANT: the text-floor check uses KERNEL_VIRT_TEXT_MIN (the *validation*
// range — the kernel image map's architectural floor), NOT KASLR_VIRT_TEXT_MIN
// (the per-build *KASLR randomization window*'s lower edge, which bakes in
// CONFIG_PHYSICAL_START at its compile-time default). On x86_64 a kernel built
// with a non-default CONFIG_PHYSICAL_START legitimately places text below
// KASLR_VIRT_TEXT_MIN — using it here would invalidate that real text leak,
// defeating the wide-floor inference (KASLR_VIRT_TEXT_MIN_WIDE) downstream.
//
// Emits verdicts rather than mutating: the engine applies them via
// evidence_resolve() so the constraint rules see the curated evidence. The
// ruling is a pure function of each observation's own region and anchor
// versus compile-time geometry — no cross-observation or estimate
// dependency.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"

#include <string.h>

#if defined(__x86_64__)
/* The direct map never reaches __START_KERNEL_map, and the kernel image map's
 * floor is KERNEL_VIRT_TEXT_MIN (the validation range — see file header for why
 * NOT KASLR_VIRT_TEXT_MIN). */
static int x86_64_va_band_bad(enum kasld_region region, unsigned long a) {
  return (region == REGION_DIRECTMAP &&
          a >= (unsigned long)KERNEL_VIRT_TEXT_MIN) ||
         ((region == REGION_KERNEL_TEXT || region == REGION_KERNEL_IMAGE) &&
          a < (unsigned long)KERNEL_VIRT_TEXT_MIN);
}
#endif

int rule_coupling_validate(const struct evidence_set *ev, struct verdict *out,
                           int out_max) {
#if defined(__x86_64__)
  return kasld_emit_va_band_verdicts(ev, out, out_max, x86_64_va_band_bad,
                                     "coupling_validate");
#else
  (void)ev;
  (void)out;
  (void)out_max;
  return 0;
#endif
}
