// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: the KASLR slot granularity, from the resolved physical base alone.
//
// Where the kernel was randomized, the physical base is a multiple of
// CONFIG_PHYSICAL_ALIGN whatever the build set CONFIG_PHYSICAL_START to: the
// boot stub aligns each usable memory region to the constant before stepping
// through it, and returns region start + i * the constant. The largest power of
// two dividing such a base is therefore a ceiling on the granularity. No origin
// is involved -- unlike a slide, which is measured from a compile-time default
// that a non-standard CONFIG_PHYSICAL_START moves -- so the ceiling rests on
// nothing but the base itself.
//
// Without randomization the base is not that clean, and the difference is worth
// stating rather than glossing. A relocatable kernel takes
// max(ALIGN_UP(load address, boot_params.hdr.kernel_alignment),
// LOAD_PHYSICAL_ADDR) (head_64.S): LOAD_PHYSICAL_ADDR is the floor rather than
// the value, and the rounding uses the boot_params field, which a loader may
// have lowered. So a base can be aligned more finely than CONFIG_PHYSICAL_ALIGN
// there, and the divisibility above does not hold.
//
// The conclusion survives that, because of what this rule is willing to say. It
// states only KASLR_PHYS_ALIGN -- the architecture's own minimum -- and only
// when the base's lowest set bit is exactly that. A granularity claimed at the
// minimum can never be coarser than the truth, so every error reachable here
// counts more placements than the kernel had, never fewer.
//
// A ceiling alone changes no count: a coarser granularity means FEWER
// placements, so leaving it unstated is the generous direction and there is
// nothing for a consumer to do with it. It is worth stating only where it meets
// the architecture's own minimum from above, and the two together fix the
// granularity at that minimum. That is the one case emitted, as C_EQUALS.
//
// Where the ceiling lands ABOVE the minimum the granularity is genuinely open
// between them and nothing is emitted; a base that is not a multiple of the
// minimum contradicts the architecture and is left to the rules that own the
// base rather than answered here.
//
// This is what a vantage with no readable CONFIG_PHYSICAL_ALIGN has: no
// boot_params, no kernel config, no image -- just a physical base some other
// component resolved. Where those sources ARE readable they state the
// granularity outright and dominate this (boot_params_kaslr_align).
//
// x86 only: the divisibility comes from x86's own placement code. The
// conclusion is carried to the virtual granularity as well, which on x86 is the
// same CONFIG_PHYSICAL_ALIGN driving the same slot arithmetic -- asserted
// below, so an architecture whose two granularities diverge cannot inherit it
// silently.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"

#include <string.h>

#if defined(__x86_64__) || defined(__i386__)
/* One constant drives both axes here; see the header note. An architecture
 * whose two granularities diverge cannot inherit the conclusion silently. */
__extension__ _Static_assert((unsigned long)KASLR_VIRT_ALIGN ==
                                 (unsigned long)KASLR_PHYS_ALIGN,
                             "x86 virt and phys slot granularity are one "
                             "constant; the phys-derived pin carries to both");
#endif

int rule_kaslr_align_from_phys_base(const struct evidence_set *ev,
                                    const struct estimate *est,
                                    struct constraint *out, int out_max) {
  (void)ev; /* reads only the resolved estimates, never raw evidence */
#if defined(__x86_64__) || defined(__i386__)
  const unsigned long floor = (unsigned long)KASLR_PHYS_ALIGN;
  const struct estimate *pe = &est[Q_PHYS_IMAGE_BASE];
  unsigned long base = 0, ceiling;
  int n = 0;

  if (!quantity_pinned(Q_PHYS_IMAGE_BASE, pe, &base) || base == 0)
    return 0;
  /* The largest power of two dividing the base. */
  ceiling = base & (~base + 1ul);
  if (ceiling != floor)
    return 0;

  const enum kasld_quantity qs[] = {Q_VIRT_KASLR_ALIGN, Q_PHYS_KASLR_ALIGN};
  for (size_t i = 0; i < sizeof(qs) / sizeof(qs[0]) && n < out_max; i++) {
    struct constraint *c = &out[n++];
    memset(c, 0, sizeof(*c));
    c->q = qs[i];
    c->op = C_EQUALS;
    c->value = floor;
    /* Rests entirely on the resolved base, so it can be no more trusted than
     * the edge that pinned it. */
    c->conf = pe->lo_conf;
    c->derived_from[0] = pe->lo_binding;
    c->lineage_count = pe->lo_binding ? 1 : 0;
    snprintf(c->origin, ORIGIN_LEN, "kaslr_align_from_phys_base");
  }
  return n;
#else
  (void)est;
  (void)out;
  (void)out_max;
  return 0;
#endif
}
