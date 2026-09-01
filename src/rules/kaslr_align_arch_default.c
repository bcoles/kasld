// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: arch-default KASLR alignment baseline (axiomatic).
//
// The Q_VIRT_KASLR_ALIGN / Q_PHYS_KASLR_ALIGN lattices are LK_MAXALIGN, whose
// honest top is "aligned to 1 byte" (least information) — the arch's minimum
// KASLR granularity is a constant floor that must arrive as a constraint, not
// as a dependent top. KASLR on a given arch always aligns the kernel
// base to at least KASLR_VIRT_ALIGN (KASLR_VIRT_ALIGN by default), so this is
// axiomatic and carries no lineage. It establishes the arch baseline alignment;
// config-derived rules (boot_params kernel_alignment, arm64 EFI_KIMG_ALIGN)
// raise it further.
//
// Which OP that baseline takes is the architecture's own answer, declared as
// KASLR_ALIGN_FIXED (see api.h). Where the placement code steps by a constant
// with no config in it, the arch value is the granularity itself and is stated
// as one; where a build can choose a coarser step, it is a floor and nothing
// more. The floor is the default, so an architecture that has not been read
// says the weaker thing.
//
// Physical alignment is emitted only where physical KASLR exists
// (KASLR_PHYS_MIN defined) — matching the orchestrator's _PHYS_KASLR_ALIGN
// guard.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"

#include <string.h>

int rule_kaslr_align_arch_default(const struct evidence_set *ev,
                                  const struct estimate *est,
                                  struct constraint *out, int out_max) {
  (void)ev;
  (void)est;
  int n = 0;

  /* One decision, applied to both axes: the architecture either fixes its
   * granularity or it does not, and a header claiming the first has been read
   * for the physical base as well as the virtual one. Spelled out at each
   * emission rather than hoisted into a variable -- the op a rule emits is what
   * a source scan looks for, and an indirection hides a collapsing constraint
   * from the review it is meant to attract. */

  if (n < out_max) {
    struct constraint *c = &out[n++];
    memset(c, 0, sizeof(*c));
    c->q = Q_VIRT_KASLR_ALIGN;
#if KASLR_ALIGN_FIXED
    c->op = C_EQUALS;
#else
    c->op = C_AT_LEAST_ALIGN;
#endif
    c->value = (unsigned long)KASLR_VIRT_ALIGN;
    c->conf = CONF_PARSED; /* arch-static constant: certain */
    c->lineage_count = 0;  /* axiomatic */
    snprintf(c->origin, ORIGIN_LEN, "kaslr_align_arch_default");
  }

#if defined(KASLR_PHYS_MIN)
  if (n < out_max) {
    struct constraint *c = &out[n++];
    memset(c, 0, sizeof(*c));
    c->q = Q_PHYS_KASLR_ALIGN;
#if KASLR_ALIGN_FIXED
    c->op = C_EQUALS;
#else
    c->op = C_AT_LEAST_ALIGN;
#endif
    c->value = (unsigned long)KASLR_PHYS_ALIGN;
    c->conf = CONF_PARSED;
    c->lineage_count = 0;
    snprintf(c->origin, ORIGIN_LEN, "kaslr_align_arch_default");
  }
#endif

  return n;
}
