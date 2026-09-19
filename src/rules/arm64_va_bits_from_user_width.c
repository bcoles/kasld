// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: constrain Q_VA_BITS on arm64 from the measured USERSPACE width.
//
// A userspace probe maps a page, and mapping a page measures TASK_SIZE, so what
// it learns is the width of the address space userspace was given. Q_VA_BITS is
// the width the KERNEL uses for its own mappings. On most architectures those
// are the same number and the distinction never surfaces; on arm64 they are
// not, and treating them as one pins a width the kernel does not use.
//
// TASK_SIZE_64 is built from the userspace width. A kernel can set that to 52
// while keeping 48 bits for itself, in which case the probe reads 52 and the
// kernel's linear map, vmemmap and text band are all still laid out for 48. The
// width is what PAGE_OFFSET and the text band are derived from, so reading the
// probe as the kernel width moves those to an address space the kernel is not
// using -- and it does so at the probe's own confidence, which is above the
// sound floor. That is a guaranteed window stated around a false value, which
// is the one outcome the two-window split exists to prevent.
//
// THE MAP FROM USERSPACE WIDTH TO KERNEL WIDTH.
//
// Exactly one arrangement hands userspace a wider space than the kernel keeps:
// the 52-bit-user option, which gives userspace 52 and leaves the kernel at 48.
// Its help text says so outright -- "The kernel will continue to use 48-bit
// virtual addresses for its own mappings" -- and the width choice resolves
// ARM64_VA_BITS to 48 when it is selected, so the kernel width there is 48 and
// never another value. Every other configuration hands both the same number.
//
// So a reading OTHER than 52 is conclusive and the rule pins it, and a reading
// of 52 is the only one that needs care. Two different kernels produce it: the
// split arrangement, where the kernel is at 48; and a kernel running 52
// throughout. Both present an identical TASK_SIZE.
//
// THE PAGE SIZE SEPARATES THEM, where it is known. The split option depends on
// ARM64_64K_PAGES, so a 52 measured on a 4K- or 16K-page kernel cannot have
// come from it and is conclusive -- those widths are reached through the
// large-physical-address extension, which the kernel uses for its own mappings
// too. A 52 on a 64K-page kernel remains ambiguous, and so does a 52 with the
// page size unobserved: unknown is not 64K-by-elimination, and treating it as
// anything else would pin from a fact not in evidence.
//
// Where it stays ambiguous the rule states the bound that holds under either
// kernel -- the width is at least 48 -- which on a finite set trims the
// candidates below and leaves the pair. A later observation of a KERNEL address
// settles it, because the two put the linear map in different places.
//
// arm64_page_offset_from_va_bits makes this same argument for the layout it
// selects, from the same Kconfig dependency and the same page-size accessor.
//
// Soundness: the constraint is emitted at the observation's own confidence,
// which is where the probe put it. Nothing is capped and nothing is widened --
// the pin case is as strong as it ever was, and the ambiguous case states a
// weaker fact rather than a wrong one. A value the architecture does not admit
// is dropped before any constraint is built, so a hostile or garbled reading
// falls through to no constraint rather than to one the meet must discard.
//
// arm64 only; inert elsewhere. Other architectures publish the kernel width
// directly, which is correct for them: where a userspace width determines the
// kernel width -- one value, not a set -- there is nothing for a rule like
// this to do.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"

#include <stdio.h>
#include <string.h>

int rule_arm64_va_bits_from_user_width(const struct evidence_set *ev,
                                       const struct estimate *est,
                                       struct constraint *out, int out_max) {
  (void)est;
#if defined(__aarch64__) && defined(VA_BITS_CANDIDATES)
  if (out_max < 1)
    return 0;

  static const unsigned long cands[] = VA_BITS_CANDIDATES;
  const int ncands = (int)(sizeof(cands) / sizeof(cands[0]));

  /* The two widths of the split arrangement, named because that is what they
   * are: the width it gives userspace, and the width the kernel keeps. They
   * are fixed by the Kconfig choice -- the 52-bit-user option resolves
   * ARM64_VA_BITS to 48 -- and are not "the largest candidate" and "the one
   * below it". Deriving them from positions in the ladder would re-point them
   * at different widths if one were ever added, and the rule would then pin a
   * value that excludes the truth, which is the failure it exists to prevent.
   *
   * Both must be widths this architecture admits, or the ladder is not the one
   * this arrangement belongs to and the rule says nothing. */
  const unsigned long split_user_width = 52ul;
  const unsigned long split_kernel_width = 48ul;
  int have_user = 0, have_kernel = 0;
  for (int k = 0; k < ncands; k++) {
    if (cands[k] == split_user_width)
      have_user = 1;
    if (cands[k] == split_kernel_width)
      have_kernel = 1;
  }
  if (!have_user || !have_kernel)
    return 0;

  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->value_kind != OBS_SCALAR)
      continue;
    if (o->scalar_fact != SF_USER_VIRT_ADDR_BITS)
      continue;

    const unsigned long v = o->scalar_value;
    int admissible = 0;
    for (int k = 0; k < ncands; k++)
      if (cands[k] == v) {
        admissible = 1;
        break;
      }
    if (!admissible)
      continue;

    /* A page size the architecture admits and that is not 64K rules the split
     * arrangement out. Unobserved (0) leaves it in, which is the wide answer
     * and the safe one. */
    int ambiguous = 0;
    if (v == split_user_width) {
      const unsigned long ps = kasld_page_size_observed(ev, NULL, NULL);
      ambiguous = (ps == 0 || ps == 64ul * 1024);
    }

    struct constraint *c = &out[0];
    memset(c, 0, sizeof(*c));
    c->q = Q_VA_BITS;
    if (ambiguous) {
      c->op = C_LOWER_BOUND;
      c->value = split_kernel_width;
    } else {
      c->op = C_EQUALS;
      c->value = v;
    }
    c->conf = o->conf;
    c->derived_from[0] = o->id;
    c->lineage_count = 1;
    snprintf(c->origin, ORIGIN_LEN, "arm64_va_bits_from_user_width");
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
