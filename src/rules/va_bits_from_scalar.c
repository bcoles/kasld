// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: pin Q_VA_BITS to an observed address-space width.
//
// A component probes the running kernel's virtual address width and publishes
// it as SF_VIRT_ADDR_BITS -- from /proc/cpuinfo on x86 and riscv, from an mmap
// boundary probe on arm64 and s390, from TLB fault timing on arm64. This turns
// that observation into a pin on Q_VA_BITS, which the page_offset and text-base
// rules then read.
//
// The width is accepted only if it is one the architecture admits, per its
// VA_BITS_CANDIDATES set. That is the same list the quantity's finite-set
// lattice is built from, so a value outside it could not be represented as a
// live candidate anyway; rejecting it here makes a nonsense reading (a parse
// slip, a hostile /proc) fall through to no constraint rather than to a
// constraint the meet must discard.
//
// Architecture-independent: the admissible set comes from the arch header, so
// an architecture gains this rule by declaring VA_BITS_CANDIDATES and needs no
// code here. Inert where none is declared -- the quantity then carries the
// single reserved 0 candidate, which is no width at all.
//
// Soundness: C_EQUALS at the observation's own confidence, carrying its id as
// lineage. An adversarial scalar cannot push the estimate past truth, because
// a value the architecture does not admit is dropped before any constraint is
// built, and one it does admit is a member of the honest top the estimate
// started from.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"

#include <stdio.h>
#include <string.h>

int rule_va_bits_from_scalar(const struct evidence_set *ev,
                             const struct estimate *est, struct constraint *out,
                             int out_max) {
  (void)est;
#if defined(VA_BITS_CANDIDATES)
  if (out_max < 1)
    return 0;

  static const unsigned long cands[] = VA_BITS_CANDIDATES;
  const int ncands = (int)(sizeof(cands) / sizeof(cands[0]));

  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->value_kind != OBS_SCALAR)
      continue;
    if (o->scalar_fact != SF_VIRT_ADDR_BITS)
      continue;

    unsigned long v = o->scalar_value;
    int admissible = 0;
    for (int k = 0; k < ncands; k++)
      if (cands[k] == v) {
        admissible = 1;
        break;
      }
    if (!admissible)
      continue;

    struct constraint *c = &out[0];
    memset(c, 0, sizeof(*c));
    c->q = Q_VA_BITS;
    c->op = C_EQUALS;
    c->value = v;
    c->conf = o->conf;
    c->derived_from[0] = o->id;
    c->lineage_count = 1;
    snprintf(c->origin, ORIGIN_LEN, "va_bits_from_scalar");
    return 1;
  }
  return 0;
#else
  (void)ev;
  (void)out;
  (void)out_max;
  return 0;
#endif
}
