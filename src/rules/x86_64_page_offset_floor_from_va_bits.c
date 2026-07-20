// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: x86_64 virt_page_offset floor from a resolved Q_VA_BITS.
//
// proc_cpuinfo emits the direct-map floor from the cpuinfo virtual width, which
// is the CPU CAPABILITY: on an LA57-capable part booted 4-level it reports 57
// and so emits the L5 floor 0xff11000000000000 — a sound but loose lower bound
// on the true (L4) page_offset. Once the ACTIVE level is resolved (Q_VA_BITS,
// pinned from the mmap probe by x86_64_va_bits_from_scalar, or from a directmap
// leak), the tighter canonical floor for that level is known:
//
//   L4 (VA_BITS=48): virt_page_offset >= 0xffff800000000000
//   L5 (VA_BITS=57): virt_page_offset >= 0xff11000000000000
//
// The L4 value is the canonical half boundary — the same floor proc_cpuinfo
// uses for a 48-bit read — chosen (not __PAGE_OFFSET_BASE_L4) so low
// static-layout addresses (LDT remap) are not excluded. Sound: page_offset only
// randomizes upward from the compile-time base, which is at or above the floor.
//
// C_LOWER_BOUND on Q_PAGE_OFFSET, capped at CONF_INFERRED. x86_64 only; inert
// until Q_VA_BITS narrows to a single value.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"
#include "include/kasld/quantity.h"

#include <string.h>

int rule_x86_64_page_offset_floor_from_va_bits(const struct evidence_set *ev,
                                               const struct estimate *est,
                                               struct constraint *out,
                                               int out_max) {
  (void)ev;
#if defined(__x86_64__)
  if (out_max < 1)
    return 0;

  unsigned long va_bits = 0;
  if (!estimate_finset_value(&quantities[Q_VA_BITS], &est[Q_VA_BITS], &va_bits))
    return 0;

  unsigned long floor;
  if (va_bits == 48)
    floor = 0xffff800000000000ul;
  else if (va_bits == 57)
    floor = 0xff11000000000000ul;
  else
    return 0;

  struct constraint *c = &out[0];
  memset(c, 0, sizeof(*c));
  c->q = Q_PAGE_OFFSET;
  c->op = C_LOWER_BOUND;
  c->value = floor;
  c->conf = CONF_INFERRED;
  c->lineage_count = 0;
  snprintf(c->origin, ORIGIN_LEN, "x86_64_page_offset_floor_from_va_bits");
  return 1;
#else
  (void)est;
  (void)out;
  (void)out_max;
  return 0;
#endif
}
