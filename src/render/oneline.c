// This file is part of KASLD - https://github.com/bcoles/kasld
//
// One-line summary renderer (--oneline / -1). Whitespace-separated
// key=value pairs intended for log scrapes and CI banners.
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

  /* Virtual text consensus + slide + residual entropy — grouped so each
   * "slide" is unambiguously associated with the preceding text base.
   * Previously `slide=` followed `ptext=`, making it unclear which side
   * it applied to (especially on decoupled arches where virt and phys
   * have independent slides). */
  unsigned long vtext =
      section_consensus(KASLD_TYPE_VIRT, "text", REGION_UNKNOWN);
  if (vtext)
    printf(" text=0x%lx", vtext);
  if (s->kaslr.vtext) {
    long abs_vs = s->kaslr.vslide < 0 ? -s->kaslr.vslide : s->kaslr.vslide;
    printf(" slide=%s0x%lx(%ld)", s->kaslr.vslide < 0 ? "-" : "+",
           (unsigned long)abs_vs, s->kaslr.vslide);
  }
  if (s->kaslr.vtext && s->kaslr.vbits > 0)
    printf(" entropy=%dbits", s->kaslr.vbits);

  /* Physical text consensus + slide + residual entropy — sibling block. */
  unsigned long ptext =
      section_consensus(KASLD_TYPE_PHYS, "text", REGION_UNKNOWN);
  if (ptext)
    printf(" ptext=0x%lx", ptext);
  if (s->kaslr.has_phys && s->kaslr.ptext) {
    long abs_ps = s->kaslr.pslide < 0 ? -s->kaslr.pslide : s->kaslr.pslide;
    printf(" pslide=%s0x%lx(%ld)", s->kaslr.pslide < 0 ? "-" : "+",
           (unsigned long)abs_ps, s->kaslr.pslide);
  }
  if (s->kaslr.has_phys && s->kaslr.ptext && s->kaslr.pbits > 0)
    printf(" pentropy=%dbits", s->kaslr.pbits);

  /* Direct map */
  unsigned long vdmap =
      section_consensus(KASLD_TYPE_VIRT, "directmap", REGION_UNKNOWN);
  if (vdmap)
    printf(" dmap=0x%lx", vdmap);

  /* Physical DRAM range */
  unsigned long pdram_lo, pdram_hi;
  section_range(KASLD_TYPE_PHYS, "dram", &pdram_lo, &pdram_hi);
  if (pdram_lo) {
    char hbuf[32];
    unsigned long top = pdram_hi ? pdram_hi : pdram_lo;
    printf(" dram=[0x%lx..0x%lx](%s)", pdram_lo, top,
           human_size(top - pdram_lo, hbuf, sizeof(hbuf)));
  }

  /* Number of results */
  printf(" results=%d", num_results);

  printf("\n");
}
