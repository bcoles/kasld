// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: resolve Q_VA_BITS on riscv64 from /proc/meminfo's VmallocTotal.
//
// Sibling of arm64_va_bits_from_vmalloc.c and x86_64_va_bits_from_vmalloc.c,
// and the simplest of the three, because riscv64's vmalloc span is a pure
// function of the paging mode:
//
//   VMALLOC_SIZE  = KERN_VIRT_SIZE >> 1                  (asm/pgtable.h)
//   KERN_VIRT_SIZE = (PTRS_PER_PGD / 2 * PGDIR_SIZE) / 2
//
// RISC-V has only a 4 KiB base page, so PTRS_PER_PGD is 512 on every mode and
// PGDIR_SHIFT is VA_BITS - 9. The whole expression collapses to
//
//   VMALLOC_TOTAL = 2^(VA_BITS - 3)
//
// which is 64 GiB on sv39, 32 TiB on sv48 and 16 PiB on sv57 -- three values
// that no rounding can confuse. A second era reports one byte less, where
// VMALLOC_END is the last address of the span rather than one past it; the kB
// conversion floors that to a figure one kilobyte lower, so both are matched.
//
// Worth having even though /proc/cpuinfo carries an `mmu` field naming the mode
// outright, because a capture can lack it: one in the corpus does, and the
// width there is otherwise unresolved. The cpuinfo route stays the better one
// where it exists -- it states the mode rather than implying it.
//
// CAPPED AT CONF_HEURISTIC, as the arm64 sibling is and for the same reason:
// /proc/meminfo is container-fakeable, no container-fakeable input may move the
// guaranteed window, and vmalloc has no host-true counterpart the way zoneinfo
// is host-true for RAM. The pin shapes the LIKELY window only.
//
// Which architectures have a rule of this kind, and why s390 has none
// though it declares a width, is recorded in the arm64 sibling.
//
// riscv64 only; inert elsewhere.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"
#include "include/kasld/quantity.h"

#include <string.h>

int rule_riscv64_va_bits_from_vmalloc(const struct evidence_set *ev,
                                      const struct estimate *est,
                                      struct constraint *out, int out_max) {
  (void)est;
#if defined(__riscv) && __riscv_xlen == 64
  if (out_max < 1)
    return 0;

  enum kasld_confidence conf = CONF_UNKNOWN;
  uint32_t src = 0;
  const unsigned long observed =
      kasld_scalar_fact_value(ev, SF_VMALLOC_TOTAL, &conf, &src);
  if (!observed)
    return 0;

  static const unsigned long widths[] = VA_BITS_CANDIDATES;
  unsigned long found = 0;
  int n_found = 0;
  for (size_t w = 0; w < sizeof(widths) / sizeof(widths[0]); w++) {
    if (widths[w] < 4 || widths[w] > 63)
      continue;
  /* Compared at kB, the resolution the kernel published. VmallocTotal is
   * printed as (VMALLOC_END - VMALLOC_START) >> 10, so up to 1023 bytes are
   * floored away before the figure is ever read and a byte-exact test against
   * the modelled span cannot succeed on a span that is not 1024-aligned. */
    const unsigned long span = 1ul << (widths[w] - 3);
    /* Both spellings of the span's end. */
    if ((observed >> 10) == (span >> 10) ||
        (observed >> 10) == ((span - 1) >> 10)) {
      found = widths[w];
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
  snprintf(c->origin, ORIGIN_LEN, "riscv64_va_bits_from_vmalloc");
  return 1;
#else
  (void)ev;
  (void)out;
  (void)out_max;
  return 0;
#endif
}
