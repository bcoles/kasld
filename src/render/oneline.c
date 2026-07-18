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
//   kaslr     on | off | unsupported
//   text      virtual image base (_text); engine-resolved base, never a leak
//   stext     virtual _stext, when it differs from the image base
//   slide     virtual KASLR slide, signed: ±0xHEX(decimal)
//   entropy   virtual residual entropy over the guaranteed window, `Nbits`
//   ptext     physical image base (_text)
//   pstext    physical _stext, when it differs from the physical image base
//   pslide    physical KASLR slide (decoupled arches only)
//   pentropy  physical residual entropy
//   dmap      direct-map base (PAGE_OFFSET); engine-resolved floor/pin
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

#include <stdio.h>
#include <sys/utsname.h>

void render_oneline(const struct summary *s) {
  struct utsname u;
  int have_uname = (kasld_uname(&u) == 0);

  /* arch */
  printf("arch=%s", have_uname ? u.machine : "unknown");

  /* KASLR state */
  if (s->kaslr.unsupported)
    printf(" kaslr=unsupported");
  else if (s->kaslr.disabled)
    printf(" kaslr=off");
  else
    printf(" kaslr=on");

  /* Virtual image base (_text), _stext, slide, residual entropy — grouped so
   * each `slide=` is unambiguously associated with the preceding text base. On
   * decoupled arches where virt and phys have independent slides, the placement
   * disambiguates which side the slide applies to. The base is the
   * engine-resolved base (a pin, or a concrete base reconciled against the
   * likely window) — never a raw leak consensus, so an interior text sample
   * cannot surface here. `na` when unresolved. */
  if (s->kaslr.vtext)
    printf(" text=0x%lx", s->kaslr.vtext);
  else
    printf(" text=na");

  if (s->kaslr.vtext && s->kaslr.vstext && s->kaslr.vstext != s->kaslr.vtext)
    printf(" stext=0x%lx", s->kaslr.vstext);
  else
    printf(" stext=na");

  if (s->kaslr.vtext) {
    long abs_vs = s->kaslr.vslide < 0 ? -s->kaslr.vslide : s->kaslr.vslide;
    printf(" slide=%s0x%lx(%ld)", s->kaslr.vslide < 0 ? "-" : "+",
           (unsigned long)abs_vs, s->kaslr.vslide);
  } else {
    printf(" slide=na");
  }

  if (s->kaslr.vtext && s->kaslr.vbits > 0)
    printf(" entropy=%dbits", s->kaslr.vbits);
  else
    printf(" entropy=na");

  /* Physical image base + _stext + slide + residual entropy — sibling block.
   * Same rule: the engine-resolved base only, never a leak consensus. */
  if (s->kaslr.ptext)
    printf(" ptext=0x%lx", s->kaslr.ptext);
  else
    printf(" ptext=na");

  if (s->kaslr.ptext && s->kaslr.pstext && s->kaslr.pstext != s->kaslr.ptext)
    printf(" pstext=0x%lx", s->kaslr.pstext);
  else
    printf(" pstext=na");

  if (s->kaslr.has_phys && s->kaslr.ptext) {
    long abs_ps = s->kaslr.pslide < 0 ? -s->kaslr.pslide : s->kaslr.pslide;
    printf(" pslide=%s0x%lx(%ld)", s->kaslr.pslide < 0 ? "-" : "+",
           (unsigned long)abs_ps, s->kaslr.pslide);
  } else {
    printf(" pslide=na");
  }

  if (s->kaslr.has_phys && s->kaslr.ptext && s->kaslr.pbits > 0)
    printf(" pentropy=%dbits", s->kaslr.pbits);
  else
    printf(" pentropy=na");

  /* Direct-map base (PAGE_OFFSET): the engine-resolved base — a pinned value or
   * the proven aligned floor — not an interior linear-map sample. On randomized
   * arches show it once the engine has established it (via a directmap leak);
   * where the base is architecturally fixed, a directmap leak confirms the
   * linear map and the base is the compile-time PAGE_OFFSET. `na` otherwise. */
  int have_dmap =
      s->kaslr.virt_page_offset_min ||
      (DIRECTMAP_STATIC &&
       section_consensus(KASLD_TYPE_VIRT, "directmap", REGION_UNKNOWN));
  if (have_dmap && layout.virt_page_offset)
    printf(" dmap=0x%lx", layout.virt_page_offset);
  else
    printf(" dmap=na");

  /* Physical DRAM range. Gate on either edge being set, not on pdram_lo alone:
   * DRAM legitimately starts at phys 0 (x86, s390), so a zero base is a real
   * range, not an absent one. section_range zeroes both edges when nothing
   * matched. `na` when nothing matched. */
  unsigned long pdram_lo, pdram_hi;
  section_range(KASLD_TYPE_PHYS, "dram", &pdram_lo, &pdram_hi);
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
