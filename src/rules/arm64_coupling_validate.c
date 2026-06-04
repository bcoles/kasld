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
// Same shape as the modules-window union widening — see kasld.h MODULES_*
// validation-union contract.
//
// The bands themselves are KASLR-invariant — the kernel image's KASLR slot
// inside the KASLR window is the only randomised position; the band
// containers are fixed. An observation whose eff_region claims one band
// but whose address falls in a different band's range is misclassified —
// typically a heap pointer, percpu offset, or stack pointer mistakenly
// tagged. The verdict rule emits V_INVALID for such observations so they
// do not pollute downstream rules (e.g., a heap pointer mistagged as
// DIRECTMAP would otherwise feed directmap_page_offset_bounds an unsound
// floor).
//
// Settles in pass 1: the ruling is a pure function of the observation's
// own region and anchor versus compile-time geometry — no cross-observation
// or estimate dependency. Same shape as coupling_validate.
//
// arm64 only; inert elsewhere. Currently dormant — no production component
// is known to mistag, but the rule is cheap insurance against future leak
// sources and matches the defensive pattern already used on x86_64.
//
// References:
// arch/arm64/include/asm/memory.h    (band constants)
// arch/arm64/include/asm/pgtable.h   (VMEMMAP_END = -SZ_1G)
// ---
// <bcoles@gmail.com>

#include "../include/kasld/engine_rules.h"

#include <string.h>

/* VA_BITS_MIN=48 anchored constants — see arm64.h for derivations. */
#define ARM64_PAGE_END_VAMIN 0xffff800000000000ul /* _PAGE_END(48) */
#define ARM64_VMEMMAP_END 0xffffffffc0000000ul    /* −SZ_1G */
/* VA_BITS=48 VMEMMAP floor; conservative for both VA48 and VA52 (VA52's
 * VMEMMAP extends further down, so any address < VA48 floor is consistent
 * with VA52 vmemmap — we don't invalidate it). Matches the threshold the
 * arm64_va_bits_from_vmemmap rule uses. */
#define ARM64_VA48_VMEMMAP_START 0xfffffdffc0000000ul

int rule_arm64_coupling_validate(const struct evidence_set *ev,
                                 struct verdict *out, int out_max) {
#if defined(__aarch64__)
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
      /* Must be below _PAGE_END(48). The lower edge varies with VA_BITS
       * (PAGE_OFFSET = −(1<<VA_BITS)); use the widest plausible floor
       * (VA52's, KERNEL_VIRT_VAS_START) as the lower bound. */
      bad = (a >= ARM64_PAGE_END_VAMIN) ||
            (a < (unsigned long)KERNEL_VIRT_VAS_START);
      break;
    case REGION_MODULE:
    case REGION_MODULE_REGION:
      /* Modules sit in the fixed [MODULES_START, MODULES_END] band. */
      bad = (a < (unsigned long)MODULES_START) ||
            (a > (unsigned long)MODULES_END);
      break;
    case REGION_KERNEL_TEXT:
    case REGION_KERNEL_IMAGE:
      /* Inside the *validation* range — KERNEL_VIRT_TEXT_MIN/MAX (the arch's
       * widest plausible text-base window) rather than KASLR_VIRT_TEXT_MIN/MAX
       * (one specific KASLR formula's narrower randomization window). The
       * latter would reject legitimate text leaks from kernel versions
       * whose kaslr_early.c algorithm produces slots outside the
       * current header's modelled window. */
      bad = (a < (unsigned long)KERNEL_VIRT_TEXT_MIN) ||
            (a > (unsigned long)KERNEL_VIRT_TEXT_MAX);
      break;
    case REGION_VMEMMAP:
      /* Above VA48 vmemmap floor *or* anywhere below it (VA52 territory);
       * either way, must be below VMEMMAP_END (= −SZ_1G). The arm64
       * va_bits-from-vmemmap rule cares about the *floor* discriminator;
       * this verdict only rejects the unambiguously-out-of-range case. */
      bad = (a >= ARM64_VMEMMAP_END);
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
    snprintf(v->origin, ORIGIN_LEN, "arm64_coupling_validate");
  }
  return n;
#else
  (void)ev;
  (void)out;
  (void)out_max;
  return 0;
#endif
}
