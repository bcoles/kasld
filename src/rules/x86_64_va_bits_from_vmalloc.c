// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: resolve Q_VA_BITS on x86_64 from /proc/meminfo's VmallocTotal.
//
// Sibling of arm64_va_bits_from_vmalloc.c. The vmalloc span here is chosen at
// RUNTIME by the paging level (asm/pgtable_64_types.h):
//
//   VMALLOC_SIZE_TB = pgtable_l5_enabled() ? 12800 : 32
//   VMEMORY_END     = VMALLOC_START + (VMALLOC_SIZE_TB << 40) - 1
//   VMALLOC_END     = VMEMORY_END                      [!CONFIG_KMSAN]
//
// so VMALLOC_TOTAL is (VMALLOC_SIZE_TB << 40) - 1: 32 TiB at four levels
// against 12800 TiB at five, a factor of four hundred.
//
// That the selector is a runtime check and not a build option is the point.
// /proc/cpuinfo reports the CPU's address-width CAPABILITY, so an LA57-capable
// part booted with four levels advertises 57 there; the probe that proves the
// ACTIVE level is a live probe, which a replayed capture correctly does not
// run. This is the only route to the active level that a capture carries, and
// it needs neither a leak nor a readable config.
//
// A KMSAN build quarters the span, and is not modelled: that value reproduces
// no level here, so the rule says nothing on one. KMSAN is a debugging build
// and the failure is silence, which is the safe direction.
//
// CAPPED AT CONF_HEURISTIC, as the arm64 sibling is and for the same reason:
// /proc/meminfo is container-fakeable, no container-fakeable input may move the
// guaranteed window, and vmalloc has no host-true counterpart the way zoneinfo
// is host-true for RAM. The pin shapes the LIKELY window only; the sound routes
// -- the mmap probe live, a directmap leak on a capture -- keep the guaranteed
// one to themselves.
//
// Which architectures have a rule of this kind, and why s390 has none
// though it declares a width, is recorded in the arm64 sibling.
//
// x86_64 only; inert elsewhere.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"
#include "include/kasld/quantity.h"

#include <string.h>

int rule_x86_64_va_bits_from_vmalloc(const struct evidence_set *ev,
                                     const struct estimate *est,
                                     struct constraint *out, int out_max) {
  (void)est;
#if defined(__x86_64__)
  if (out_max < 1)
    return 0;

  enum kasld_confidence conf = CONF_UNKNOWN;
  uint32_t src = 0;
  const unsigned long observed =
      kasld_scalar_fact_value(ev, SF_VMALLOC_TOTAL, &conf, &src);
  if (!observed)
    return 0;

  /* The width each level gives, paired with the span the kernel reserves for
   * it. Four levels and five are the only ones x86_64 has had, so this mirrors
   * VA_BITS_CANDIDATES -- it is spelled out rather than read from it because a
   * width is meaningless here without the span beside it, and a level added to
   * the arch header without a span added here simply goes unmatched. */
  static const struct {
    unsigned long va_bits;
    unsigned long size_tb;
  } levels[] = {{48ul, 32ul}, {57ul, 12800ul}};

  unsigned long found = 0;
  int n_found = 0;
  for (size_t i = 0; i < sizeof(levels) / sizeof(levels[0]); i++) {
    /* Compared at kB, the resolution the kernel published. VmallocTotal is
     * printed as (VMALLOC_END - VMALLOC_START) >> 10, so up to 1023 bytes are
     * floored away before the figure is ever read and a byte-exact test against
     * the modelled span cannot succeed on a span that is not 1024-aligned. */
    const unsigned long span = levels[i].size_tb << 40;
    if ((observed >> 10) == (span >> 10) ||
        (observed >> 10) == ((span - 1) >> 10)) {
      found = levels[i].va_bits;
      n_found++;
    }
  }
  if (n_found != 1)
    return 0;

  struct constraint *c = &out[0];
  memset(c, 0, sizeof(*c));
  c->q = Q_VA_BITS;
  c->op = C_EQUALS;
  c->value = found;
  c->conf = kasld_conf_min(conf, CONF_HEURISTIC);
  if (src) {
    c->derived_from[0] = src;
    c->lineage_count = 1;
  }
  snprintf(c->origin, ORIGIN_LEN, "x86_64_va_bits_from_vmalloc");
  return 1;
#else
  (void)ev;
  (void)out;
  (void)out_max;
  return 0;
#endif
}
