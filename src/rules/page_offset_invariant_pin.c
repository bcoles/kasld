// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: pin page_offset on arches where it is architecturally invariant.
//
// On some arches the kernel's direct-map / VAS origin is a hard architectural
// constant that cannot vary by config, paging mode, or randomisation:
//   MIPS  — PAGE_OFFSET is CKSEG0, fixed by the ISA.
//   ppc64 — book3s64 linear-mapping base 0xc000000000000000, not configurable.
// On such arches (PAGE_OFFSET_INVARIANT == 1) the compile-time PAGE_OFFSET is
// the guaranteed runtime value, so pinning Q_PAGE_OFFSET to it is not a
// heuristic default-commit but an architectural certainty — sound with no
// evidence. Applied ONLY where the commit is provably correct.
//
// Deliberately inert where PAGE_OFFSET is config/mode-dependent (x86_32/arm32
// VMSPLIT, arm64 VA_BITS, riscv64 SATP, x86_64/s390 randomisation): there the
// compile-time default is a guess the runtime can contradict (e.g. a riscv64
// kernel built CONFIG_PAGE_OFFSET=SV57 but booted SV48), so the engine keeps
// the honest window and defers to a landmark/probe. C_EQUALS; emits nothing
// when PAGE_OFFSET_INVARIANT is 0.
// ---
// <bcoles@gmail.com>

#include "../include/kasld/engine_rules.h"

#include <string.h>

int rule_page_offset_invariant_pin(const struct evidence_set *ev,
                                   const struct estimate *est,
                                   struct constraint *out, int out_max) {
  (void)ev;
  (void)est;
#if PAGE_OFFSET_INVARIANT
  if (out_max < 1)
    return 0;
  struct constraint *c = &out[0];
  memset(c, 0, sizeof(*c));
  c->q = Q_PAGE_OFFSET;
  c->op = C_EQUALS;
  c->value = (unsigned long)PAGE_OFFSET;
  c->conf =
      CONF_DERIVED;     /* architectural certainty, not a leaked observation */
  c->lineage_count = 0; /* axiomatic */
  snprintf(c->origin, ORIGIN_LEN, "page_offset_invariant_pin");
  return 1;
#else
  (void)out;
  (void)out_max;
  return 0;
#endif
}
