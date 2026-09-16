// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: arm64 virt_page_offset from a resolved Q_VA_BITS.
//
// On arm64 the linear-map virtual base is not randomized — the boot seed shifts
// memstart_addr, the PHYSICAL anchor of the linear map, not its virtual base —
// so it is a function of the runtime paging width alone. WHICH function depends
// on the VA-space layout:
//
//   flipped layout:  PAGE_OFFSET = -(1 << VA_BITS)
//   older layout:    PAGE_OFFSET = -(1 << (VA_BITS - 1))
//
// and a width measured from the address space says nothing about which of them
// is in force: TASK_SIZE is 1 << VA_BITS under both, so the probe reads the
// same number either way. Resolving the width therefore narrows the base to two
// candidates rather than pinning it. Emitting the flipped value as a pin puts
// the linear map a canonical bit low on an older kernel, and every rule that
// treats a resolved PAGE_OFFSET as proof of the layout then floors the image
// base half an address space above the real one — the truth-outside-the-window
// failure the sound floor exists to prevent.
//
// So the sound floor gets both candidates, with the span between them carved
// out; the modern value is named below the floor, where being wrong on an older
// kernel costs a worse guess rather than an unsound window. A directmap or
// vmemmap observation pins the base outright on either layout, and the meet
// collapses this pair to that pin, so nothing is lost where a leak exists.
//
// arm64_va_bits_from_directmap / arm64_va_bits_from_vmemmap already pin
// virt_page_offset as a side effect of a DIRECTMAP or VMEMMAP leak. This rule
// closes the gap when Q_VA_BITS is resolved by a leak-free path instead — e.g.
// mmap-probing (mmap_arm64_va_bits) on a hardened target with no linear-map
// leak — so the base is narrowed from the width alone.
//
// Reads only est[Q_VA_BITS] (cross-quantity, acyclic: Q_VA_BITS never derives
// from Q_PAGE_OFFSET). At VA_BITS=52 the lower edge is the architectural VAS
// floor and a no-op.
//
// arm64 only; inert when Q_VA_BITS has not narrowed to a single candidate.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"
#include "include/kasld/quantity.h"

#include <string.h>

int rule_arm64_page_offset_from_va_bits(const struct evidence_set *ev,
                                        const struct estimate *est,
                                        struct constraint *out, int out_max) {
#if defined(__aarch64__)
  if (out_max < 2)
    return 0;

  unsigned long va_bits = 0;
  if (!estimate_finset_value(&quantities[Q_VA_BITS], &est[Q_VA_BITS], &va_bits))
    return 0;
  if (va_bits == 0 || va_bits >= sizeof(unsigned long) * 8)
    return 0;

  const unsigned long po = arm64_page_offset_for(va_bits);
  /* The base the OLD layout placed at this width -- except at 52, which it
   * never placed at all. Pre-flip, the only way to present a 52-bit USER VA was
   * CONFIG_ARM64_USER_VA_BITS_52, and that option left the kernel at 48:
   * arch/arm64/Kconfig set `default 48 if ARM64_VA_BITS_48 ||
   * ARM64_USER_VA_BITS_52`. So the pre-flip partner of a measured 52 is the
   * 48-bit base. Deriving it from the measured width instead would name
   * -(1 << 51), a base no kernel has ever used, and -- because the true one
   * sits ABOVE it -- would leave the truth outside the window rather than
   * merely mis-describing the alternative. */
  const unsigned long po_old =
      arm64_page_offset_preflip_for(va_bits == 52ul ? 48ul : va_bits);

  /* A measured WIDTH does not say which layout produced it. Before the VA-space
   * flip the same VA_BITS put the linear map one canonical bit higher, so a
   * width alone admits two bases and pinning the modern one would place the
   * guaranteed window on the wrong half of the address space.
   *
   * A width of 52 is the one case where the width can settle it, because the
   * old layout offered kernel widths {36,39,42,47,48} and never 52. But the
   * probe measures the USER address space, and pre-flip a 64K-page kernel could
   * offer userspace 52 bits while keeping 48 for itself -- the Kconfig help
   * says so outright: "The kernel will continue to use 48-bit virtual addresses
   * for its own mappings." That option `depends on ARM64_64K_PAGES`, so a 52
   * measured on a 4K- or 16K-page kernel could not have come from it and does
   * prove the flipped layout.
   *
   * Hence the page size, observed, decides it. Unobserved is not 64K-by-
   * elimination: an unknown page size leaves both layouts admissible, which is
   * the wide answer and the safe one. */
  enum kasld_confidence ps_conf = CONF_UNKNOWN;
  uint32_t ps_src = 0;
  int one_layout = 0;
  if (va_bits == 52ul) {
    const unsigned long ps = kasld_page_size_observed(ev, &ps_conf, &ps_src);
    one_layout = (ps != 0 && ps != 64ul * 1024);
  }

  int n = 0;
  if (n < out_max) {
    struct constraint *c = &out[n++];
    memset(c, 0, sizeof(*c));
    c->q = Q_PAGE_OFFSET;
    c->op = C_LOWER_BOUND;
    c->value = po;
    /* Exact given the width, but no more trustworthy than the derivation that
     * resolved Q_VA_BITS; cap at the sound-band floor. */
    c->conf = CONF_INFERRED;
    snprintf(c->origin, ORIGIN_LEN, "arm64_page_offset_from_va_bits");
  }
  if (n < out_max) {
    struct constraint *c = &out[n++];
    memset(c, 0, sizeof(*c));
    c->q = Q_PAGE_OFFSET;
    c->op = C_UPPER_BOUND;
    c->value = one_layout ? po : po_old;
    /* This edge is what collapses the pair to a pin, and where it does so it
     * rests on the page size as well as the width -- so it is no better than
     * the weaker of the two. The lower edge below needs no such cap: po is the
     * lowest base either layout admits, so it holds whatever the page size
     * turns out to be. */
    c->conf =
        one_layout ? kasld_conf_min(CONF_INFERRED, ps_conf) : CONF_INFERRED;
    if (one_layout && ps_src) {
      c->derived_from[0] = ps_src;
      c->lineage_count = 1;
    }
    snprintf(c->origin, ORIGIN_LEN, "arm64_page_offset_from_va_bits");
  }
  if (one_layout)
    return n;

  /* Two bases, not the interval between them: carve the span so the estimate
   * reads as the two candidates it actually is. Without this the linear-map
   * base would report a half-address-space window where only two values are
   * possible. */
  if (n < out_max && po_old > po + 1) {
    struct constraint *c = &out[n++];
    memset(c, 0, sizeof(*c));
    c->q = Q_PAGE_OFFSET;
    c->op = C_EXCLUDE;
    c->value = po + 1;
    c->value2 = po_old - 1;
    c->conf = CONF_INFERRED;
    snprintf(c->origin, ORIGIN_LEN, "arm64_page_offset_from_va_bits");
  }

  /* Below the sound floor, name the modern base outright. Every kernel still
   * receiving fixes carries the flipped layout, so this is the answer a reader
   * wants; it shapes the likely window and cannot touch the guaranteed one,
   * where both bases stay admitted. */
  if (n < out_max) {
    struct constraint *c = &out[n++];
    memset(c, 0, sizeof(*c));
    c->q = Q_PAGE_OFFSET;
    c->op = C_EQUALS;
    c->value = po;
    c->conf = CONF_HEURISTIC;
    snprintf(c->origin, ORIGIN_LEN, "arm64_page_offset_from_va_bits");
  }
  return n;
#else
  (void)ev;
  (void)est;
  (void)out;
  (void)out_max;
  return 0;
#endif
}
