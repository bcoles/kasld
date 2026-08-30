// This file is part of KASLD - https://github.com/bcoles/kasld
//
// One-line summary renderer (--oneline / -1). Whitespace-separated
// key=value pairs intended for log scrapes and CI banners.
//
// FIXED SCHEMA: every key below appears on every line, in this order, so a
// scraper can rely on `field=` being present and match it unconditionally. This
// mirrors the always-present contract of the JSON `environment` object, and
// deliberately diverges from the human formats' "omit unresolved rows"
// philosophy: oneline is a machine surface where a stable key set matters more
// than terseness.
//
// VALUE GRAMMAR: a key naming a quantity reports one of three things, and never
// anything else —
//
//   0xADDR          the engine resolved it to this address; act on it
//   [0xLO..0xHI]    it bounded it to this window; a missing edge is omitted,
//                   as `[..0xHI]`
//   na              nothing is known
//
// A bare address is the signal a consumer wants, and the absence of a `[` is
// how to test for it. No fabricated, defaulted or leaked value is ever
// asserted: a window's floor is NOT the base, so it appears as part of the
// window rather than alone under a key named for the base — reporting it alone
// asserted a value the engine had merely bounded, and arithmetic on it is wrong
// rather than approximate. A finite set lists its values (`48,57`), because
// those ARE the answer set and endpoints would imply everything between them.
//
// Keys carrying a measurement or a property of the run rather than an answer to
// an unknown — arch, kaslr, entropy, pentropy, dram, results — are always
// present and follow the forms described below.
//
// Keys, in order:
//   arch      kernel machine (uname), or `unknown`
//   kaslr     on | off | unsupported | failed  (failed = randomization failed
//             at boot: effective 0 bits, deterministic per boot — distinct from
//             off, a deliberate opt-out at the link-time default)
//   text      virtual image base (_text), per the value grammar above; never a
//             raw leak consensus
//   stext     virtual _stext, when it differs from the image base
//   slide     virtual KASLR slide, signed: ±0xHEX(decimal)
//   entropy   virtual residual entropy over the guaranteed window, `Nbits`;
//             present whenever a window was resolved (an unpinned window
//             reports its N bits; a pin reports 0bits). `na` only when KASLR is
//             off/unsupported (no window).
//   ptext     physical image base (_text), per the value grammar
//   pstext    physical _stext, when it differs from the physical image base
//   pslide    physical KASLR slide (decoupled arches only)
//   pentropy  physical residual entropy (same window/`na` rule as entropy)
//   dmap      direct-map base (PAGE_OFFSET), per the value grammar; never the
//             compile-time constant
//   vmalloc   vmalloc base, same
//   vmemmap   vmemmap base, same
//   module    module region base, same
//   vabits    address-space size in bits (the paging level): the value once one
//             candidate remains, else the candidates as a comma list
//   dram      physical DRAM extent: [0xLO..0xHI]
//   results   count of merged result records (post-merge wire records — not
//             the raw component count, nor a distinct "leaks" tally)
//
// Cross-file helpers (section_consensus, section_range) are
// declared in include/kasld/render_internal.h and defined in render.c.
// ---
// <bcoles@gmail.com>

#include "include/kasld/internal.h"
#include "include/kasld/render_internal.h"
#include "include/kasld/report.h"

#include <stdio.h>
#include <sys/utsname.h>

/* One quantity, in the line's value grammar.
 *
 * Three states, one rule, and the same rule for every quantity key:
 *
 *   0xADDR              the engine resolved the quantity to this address
 *   [0xLO..0xHI]        it bounded the quantity to this window
 *   na                  it knows nothing
 *
 * A bare address means "act on this"; a bracket means "not yet, but it lies in
 * here". The distinction is the signal a consumer most wants, and the absence
 * of a `[` is how they test for it. The bracket form is the one `dram=` already
 * uses, so this adds no shape a scraper does not already parse.
 *
 * The window matters because withholding it says less than the tool knows. A
 * floor alone was reported here once, under a key named for the base -- that
 * asserted a value the engine had merely bounded, and arithmetic on it is wrong
 * rather than approximate. Reporting the window instead asserts nothing false
 * and keeps what was learned; a half-bounded window omits the edge it does not
 * have.
 *
 * A finite set is not a window: its values are listed, because they ARE the
 * answer set, and squeezing them into endpoints would name two values that
 * happen to be extremes as though everything between them were admissible. */
static void oneline_quantity(const char *key,
                             const struct kasld_report_quantity *q) {
  const struct kasld_report_window *w = q ? &q->guaranteed : NULL;

  unsigned long v;

  if (!w || !w->present) {
    printf(" %s=na", key);
    return;
  }
  /* A set is handled before anything else because its values are not
   * ADDRESSES: a paging level is a count of bits, and printing 48 through the
   * address path yields `0x30`. The shape has to be read before the value is
   * formatted, not after. */
  if (w->shape == RSHAPE_SET) {
    if (w->n_values <= 0) {
      printf(" %s=na", key);
      return;
    }
    printf(" %s=", key);
    for (int i = 0; i < w->n_values; i++)
      printf("%s%lu", i ? "," : "", w->values[i]);
    return;
  }
  /* The resolved address, asked for the one way it is asked anywhere: the model
   * answers only where a resolution admits exactly this address, so what comes
   * back is an answer and not a guess dressed as one. Testing the windows here
   * instead would be a second copy of that judgement, free to drift from the
   * one every other format uses. */
  if (kasld_report_value(q, &v)) {
    printf(" %s=0x%lx", key, v);
    return;
  }
  if (w->has_lo && w->has_hi) {
    printf(" %s=[0x%lx..0x%lx]", key, w->lo, w->hi);
    return;
  }
  if (w->has_hi) {
    printf(" %s=[..0x%lx]", key, w->hi);
    return;
  }
  if (w->has_lo) {
    printf(" %s=[0x%lx..]", key, w->lo);
    return;
  }
  printf(" %s=na", key);
}

void render_oneline(const struct summary *s) {
  struct utsname u = kasld_env.uts;
  int have_uname = kasld_env.have_uts;

  /* arch */
  printf("arch=%s", have_uname ? u.machine : "unknown");

  /* KASLR state. `failed` is the randomization-failed posture (boot stub
   * attempted KASLR but produced no random offset — effective slot entropy 0,
   * position deterministic per boot); distinct from `off` (deliberate opt-out,
   * kernel at the link-time default). Priority matches the hardening posture:
   * unsupported > off > failed > on. */
  if (s->kaslr.unsupported)
    printf(" kaslr=unsupported");
  else if (s->kaslr.disabled)
    printf(" kaslr=off");
  else if (s->kaslr.randomization_failed)
    printf(" kaslr=failed");
  else
    printf(" kaslr=on");

  /* Virtual image base (_text), _stext, slide, residual entropy — grouped so
   * each `slide=` is unambiguously associated with the preceding text base. On
   * decoupled arches where virt and phys have independent slides, the placement
   * disambiguates which side the slide applies to. The base is the
   * engine-resolved base (a pin, or a concrete base reconciled against the
   * likely window) — never a raw leak consensus, so an interior text sample
   * cannot surface here. `na` when unresolved. */
  const struct kasld_report *rep = render_report();
  const struct kasld_report_quantity *qv =
      kasld_report_find(rep, Q_VIRT_IMAGE_BASE);
  const struct kasld_report_quantity *qp =
      kasld_report_find(rep, Q_PHYS_IMAGE_BASE);

  oneline_quantity("text", qv);

  /* Only where the image base itself resolved. _stext is that base plus the
   * architecture's head gap, or an observation of the same region -- so with
   * the base unresolved there is nothing to add the gap to, and asserting an
   * address here while `text=` shows a window states more than was
   * established. */
  if (qv && qv->has_stext)
    printf(" stext=0x%lx", qv->stext);
  else
    printf(" stext=na");

  if (qv && qv->has_point && qv->has_slide) {
    long abs_vs = qv->slide < 0 ? -qv->slide : qv->slide;
    printf(" slide=%s0x%lx(%ld)", qv->slide < 0 ? "-" : "+",
           (unsigned long)abs_vs, qv->slide);
  } else {
    printf(" slide=na");
  }

  /* Residual entropy over the guaranteed window — the bits of the base the
   * evidence could not strip. Shown whenever the engine resolved a window with
   * candidates in it: the unpinned windowed case (where the residual is the
   * whole point) reports its N bits, and a pin reports 0 bits. Matches the JSON
   * inferred.entropy_bits. `na` only when there is no window — KASLR
   * off/unsupported zero the slot count. (In the `failed` posture the window is
   * still the proven residual; `kaslr=failed` is the effective-zero signal.) */
  if (qv && qv->guaranteed.present && qv->guaranteed.candidates > 0)
    printf(" entropy=%dbits", qv->guaranteed.bits);
  else
    printf(" entropy=na");

  /* Physical image base + _stext + slide + residual entropy — sibling block.
   * Same rule: the engine-resolved base only, never a leak consensus. */
  oneline_quantity("ptext", qp);

  if (qp && qp->has_stext)
    printf(" pstext=0x%lx", qp->stext);
  else
    printf(" pstext=na");

  if (s->kaslr.has_phys && qp && qp->has_point && qp->has_slide) {
    long abs_ps = qp->slide < 0 ? -qp->slide : qp->slide;
    printf(" pslide=%s0x%lx(%ld)", qp->slide < 0 ? "-" : "+",
           (unsigned long)abs_ps, qp->slide);
  } else {
    printf(" pslide=na");
  }

  if (qp && qp->guaranteed.present && qp->guaranteed.candidates > 0)
    printf(" pentropy=%dbits", qp->guaranteed.bits);
  else
    printf(" pentropy=na");

  /* Direct-map base (PAGE_OFFSET): the address once the engine resolves the
   * region to one, never an interior linear-map sample and never the
   * compile-time constant.
   *
   * A proven FLOOR is not the base. Reporting one here asserted, in the
   * machine-readable mode, a base the engine had merely bounded -- and a floor
   * is not a weaker answer but a wrong input, since translating an address
   * through it lands somewhere the kernel never mapped. Where the architecture
   * admits a single base the engine pins it and the value appears; where it
   * does not, `na`. arm32 and x86_32 are DIRECTMAP_STATIC yet their PAGE_OFFSET
   * varies with VMSPLIT, so "KASLR does not move the base" was never licence to
   * state one.
   *
   * From the model rather than layout.virt_page_offset, which is seeded from
   * the compile-time constant and only replaced once the engine pins the
   * quantity -- so on a kernel whose split differs from the build default it is
   * a stale constant rather than a measurement. */
  oneline_quantity("dmap", kasld_report_find(rep, Q_PAGE_OFFSET));

  /* The remaining resolved quantities, on the same terms as the keys above: a
   * key per unknown this machine has, `na` where the run resolved nothing.
   *
   * They were absent while this renderer read the summary field by field, which
   * meant a scraper could see the direct-map base but not the vmalloc or
   * vmemmap bases beside it, nor the module region, nor the paging level -- all
   * of which the engine had resolved. A key is emitted for every quantity the
   * model carries, so what appears here follows what the machine HAS rather
   * than which fields this renderer happened to name.
   *
   * A value is stated only where the quantity RESOLVED to one, and `na`
   * otherwise -- the rule every other value key on this line follows, and the
   * one the schema above promises: no fabricated, defaulted or leaked value.
   *
   * A window's floor is not that value. It was emitted here, under a key named
   * for the base, on a window that commonly admits tens of thousands of
   * placements; a scraper reading `vmalloc=` as the vmalloc base got a lower
   * bound, and arithmetic on it -- translating an address through the direct
   * map, say -- is wrong rather than approximate. The floor is a window EDGE,
   * and the formats that can express a window keep it: the readout row, the
   * markdown table, and json's per-region min/max/slots. A single scalar is the
   * one place it cannot be said correctly. */
  {
    static const struct {
      enum kasld_quantity q;
      const char *key;
    } extra[] = {{Q_VMALLOC_BASE, "vmalloc"},
                 {Q_VMEMMAP_BASE, "vmemmap"},
                 {Q_MODULE_BASE, "module"},
                 {Q_VA_BITS, "vabits"}};
    for (size_t i = 0; i < sizeof(extra) / sizeof(extra[0]); i++)
      oneline_quantity(extra[i].key, kasld_report_find(rep, extra[i].q));
  }

  /* Physical DRAM extent, in the same bracket form every other span uses. Gate
   * on either edge being set, not on pdram_lo alone: DRAM legitimately starts
   * at phys 0 (x86, s390), so a zero base is a real range, not an absent one.
   * section_range zeroes both edges when nothing matched.
   *
   * The span's size is not printed beside it. It carried a space -- "(13.0
   * GiB)" -- which made this the one value on a whitespace-separated line that
   * a consumer could not split into a key and a value: the obvious tokenizer
   * yielded a trailing "GiB)" with no `=` in it. The figure is also derivable
   * from the edges, so nothing is lost that a reader cannot recover, and the
   * human formats print it where there is room to. */
  unsigned long pdram_lo, pdram_hi;
  section_range(KASLD_TYPE_PHYS, "dram", REGION_UNKNOWN, &pdram_lo, &pdram_hi);
  if (pdram_lo || pdram_hi)
    printf(" dram=[0x%lx..0x%lx]", pdram_lo, pdram_hi ? pdram_hi : pdram_lo);
  else
    printf(" dram=na");

  /* Count of merged result records (always present). */
  printf(" results=%d", num_results);

  printf("\n");
}
