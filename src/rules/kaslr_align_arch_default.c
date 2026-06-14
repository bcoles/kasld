// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: arch-default KASLR alignment baseline (axiomatic).
//
// The Q_VIRT_KASLR_ALIGN / Q_PHYS_KASLR_ALIGN lattices are LK_MAXALIGN, whose
// honest top is "aligned to 1 byte" (least information) — the arch's minimum
// KASLR granularity is a constant floor that must arrive as a constraint, not
// as a dependent top (see §0.3). KASLR on a given arch always aligns the kernel
// base to at least KASLR_VIRT_ALIGN (KASLR_VIRT_ALIGN by default), so this is
// an axiomatic C_AT_LEAST_ALIGN with no lineage. It establishes the arch
// baseline alignment; config-derived rules (boot_params kernel_alignment, arm64
// EFI_KIMG_ALIGN) raise it further.
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

  if (n < out_max) {
    struct constraint *c = &out[n++];
    memset(c, 0, sizeof(*c));
    c->q = Q_VIRT_KASLR_ALIGN;
    c->op = C_AT_LEAST_ALIGN;
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
    c->op = C_AT_LEAST_ALIGN;
    c->value = (unsigned long)KASLR_PHYS_ALIGN;
    c->conf = CONF_PARSED;
    c->lineage_count = 0;
    snprintf(c->origin, ORIGIN_LEN, "kaslr_align_arch_default");
  }
#endif

  return n;
}
