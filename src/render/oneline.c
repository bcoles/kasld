// This file is part of KASLD - https://github.com/bcoles/kasld
//
// One-line summary renderer (--oneline / -1). Whitespace-separated
// key=value pairs intended for log scrapes and CI banners.
//
// FIXED SCHEMA: every key below appears on every line, in this order, so a
// scraper can rely on `field=` being present and match it unconditionally. A
// value that is unresolved, or not applicable to the arch/run, renders the
// sentinel `na` — never a fabricated, defaulted, or leaked value. This mirrors
// the always-present contract of the JSON `environment` object, and
// deliberately diverges from the human formats' "omit unresolved rows"
// philosophy: oneline is a machine surface where a stable key set matters more
// than terseness. `na` for a base/slide/window is the exact soundness
// guarantee the human forms express by omission — no value is asserted.
//
// Keys, in order:
//   arch      kernel machine (uname), or `unknown`
//   kaslr     on | off | unsupported | failed  (failed = randomization failed
//             at boot: effective 0 bits, deterministic per boot — distinct from
//             off, a deliberate opt-out at the link-time default)
//   text      virtual image base (_text); engine-resolved base, never a leak
//   stext     virtual _stext, when it differs from the image base
//   slide     virtual KASLR slide, signed: ±0xHEX(decimal)
//   entropy   virtual residual entropy over the guaranteed window, `Nbits`;
//             present whenever a window was resolved (an unpinned window
//             reports its N bits; a pin reports 0bits). `na` only when KASLR is
//             off/unsupported (no window).
//   ptext     physical image base (_text)
//   pstext    physical _stext, when it differs from the physical image base
//   pslide    physical KASLR slide (decoupled arches only)
//   pentropy  physical residual entropy (same window/`na` rule as entropy)
//   dmap      direct-map base (PAGE_OFFSET); engine-resolved floor/pin
//   vmalloc   vmalloc base -- the proven floor, as `dmap` reports its own
//   vmemmap   vmemmap base
//   module    module region base
//   vabits    resolved address-space size in bits (the paging level), once one
//             candidate remains
//   dram      physical DRAM extent: [0xLO..0xHI](size)
//   results   count of merged result records (post-merge wire records — not
//             the raw component count, nor a distinct "leaks" tally)
//
// Cross-file helpers (section_consensus, section_range, human_size) are
// declared in include/kasld/render_internal.h and defined in render.c.
// ---
// <bcoles@gmail.com>

#include "include/kasld/internal.h"
#include "include/kasld/render_internal.h"
#include "include/kasld/report.h"

#include <stdio.h>
#include <sys/utsname.h>

void render_oneline(const struct summary *s) {
  struct utsname u;
  int have_uname = (kasld_uname(&u) == 0);

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

  if (qv && qv->has_point)
    printf(" text=0x%lx", qv->point);
  else
    printf(" text=na");

  if (s->kaslr.vtext && s->kaslr.vstext && s->kaslr.vstext != s->kaslr.vtext)
    printf(" stext=0x%lx", s->kaslr.vstext);
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
   * evidence could not strip. Shown whenever the engine resolved a window
   * (vslots > 0): the unpinned windowed case (where the residual is the whole
   * point) reports its N bits, and a pin reports 0 bits. Matches the JSON
   * inferred.entropy_bits. `na` only when there is no window — KASLR
   * off/unsupported zero the slot count. (In the `failed` posture the window is
   * still the proven residual; `kaslr=failed` is the effective-zero signal.) */
  if (qv && qv->guaranteed.present && qv->guaranteed.candidates > 0)
    printf(" entropy=%dbits", qv->guaranteed.bits);
  else
    printf(" entropy=na");

  /* Physical image base + _stext + slide + residual entropy — sibling block.
   * Same rule: the engine-resolved base only, never a leak consensus. */
  if (qp && qp->has_point)
    printf(" ptext=0x%lx", qp->point);
  else
    printf(" ptext=na");

  if (s->kaslr.ptext && s->kaslr.pstext && s->kaslr.pstext != s->kaslr.ptext)
    printf(" pstext=0x%lx", s->kaslr.pstext);
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

  /* Direct-map base (PAGE_OFFSET): the engine-resolved base — a pinned value or
   * the proven aligned floor — not an interior linear-map sample. On randomized
   * arches show it once the engine has established it (via a directmap leak);
   * where the compile-time value is the guaranteed runtime one, a directmap
   * leak confirms the linear map and that constant IS the base. `na` otherwise.
   *
   * The licence for the second clause is kasld_page_offset_if_known(), which
   * yields the constant only where a single base is admissible and 0 otherwise.
   * "KASLR does not move the base" is NOT that licence — it is a different
   * claim from knowing where the base is: arm32 and x86_32 are DIRECTMAP_STATIC
   * yet their PAGE_OFFSET varies with VMSPLIT, and printing the constant there
   * asserts, in the machine-readable mode, a base the engine had merely
   * bounded.
   *
   * The value comes from the ENGINE, not from layout.virt_page_offset. That
   * field is only assigned on a coupled arch once the engine PINS the base, so
   * reading it where the engine had merely established a floor yields the
   * compile-time seed again -- the same wrong answer by a second route. */
  unsigned long dmap = s->kaslr.virt_page_offset_min;
  if (!dmap && section_consensus(KASLD_TYPE_VIRT, "directmap", REGION_UNKNOWN))
    dmap = kasld_page_offset_if_known();
  if (dmap)
    printf(" dmap=0x%lx", dmap);
  else
    printf(" dmap=na");

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
   * A window reports its proven floor, as `dmap` does: the lowest address the
   * quantity can occupy. A finite set reports its value once one remains. */
  {
    static const struct {
      enum kasld_quantity q;
      const char *key;
    } extra[] = {{Q_VMALLOC_BASE, "vmalloc"},
                 {Q_VMEMMAP_BASE, "vmemmap"},
                 {Q_MODULE_BASE, "module"},
                 {Q_VA_BITS, "vabits"}};
    for (size_t i = 0; i < sizeof(extra) / sizeof(extra[0]); i++) {
      const struct kasld_report_quantity *q =
          kasld_report_find(rep, extra[i].q);
      const struct kasld_report_window *w = q ? &q->guaranteed : NULL;
      if (!w || !w->present) {
        printf(" %s=na", extra[i].key);
      } else if (w->shape == RSHAPE_SET) {
        if (w->n_values == 1)
          printf(" %s=%lu", extra[i].key, w->values[0]);
        else
          printf(" %s=na", extra[i].key);
      } else if (w->has_lo) {
        printf(" %s=0x%lx", extra[i].key, w->lo);
      } else {
        printf(" %s=na", extra[i].key);
      }
    }
  }

  /* Physical DRAM range. Gate on either edge being set, not on pdram_lo alone:
   * DRAM legitimately starts at phys 0 (x86, s390), so a zero base is a real
   * range, not an absent one. section_range zeroes both edges when nothing
   * matched. `na` when nothing matched. */
  unsigned long pdram_lo, pdram_hi;
  section_range(KASLD_TYPE_PHYS, "dram", REGION_UNKNOWN, &pdram_lo, &pdram_hi);
  if (pdram_lo || pdram_hi) {
    char hbuf[32];
    unsigned long top = pdram_hi ? pdram_hi : pdram_lo;
    printf(" dram=[0x%lx..0x%lx](%s)", pdram_lo, top,
           human_size(top - pdram_lo, hbuf, sizeof(hbuf)));
  } else {
    printf(" dram=na");
  }

  /* Count of merged result records (always present). */
  printf(" results=%d", num_results);

  printf("\n");
}
