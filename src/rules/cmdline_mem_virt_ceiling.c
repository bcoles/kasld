// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: virtual KASLR ceiling from `mem=N` cmdline (coupled arches).
//
// The coupled-arch counterpart to cmdline_mem_phys_ceiling. On x86_32 (the
// only `mem=`-respecting coupled arch in scope) phys_to_directmap_virt() links
// physical DRAM to the virtual text window, so the kernel-image-fits-`mem` cap
// maps to
//
//   virt_ceiling = PAGE_OFFSET_runtime + cmdline_mem - image_size +
//   IMAGE_BASE_OFFSET
//
// aligned down to the resolved virtual KASLR granularity. Cross-quantity:
// fires only once Q_PAGE_OFFSET has collapsed to a point (VMSPLIT resolved by
// page_offset_from_config / a landmark), otherwise emits nothing — sound
// under the "no-input → no-constraint" principle.
//
// Reads SF_PHYS_CMDLINE_MEM (cmdline_mem.c) + SF_IMAGE_SIZE_MIN + Q_PAGE_OFFSET
// pinned; emits nothing when any is absent.
//
// References:
// https://elixir.bootlin.com/linux/v6.12/source/arch/x86/boot/compressed/kaslr.c#L260
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"

#include <string.h>

int rule_cmdline_mem_virt_ceiling(const struct evidence_set *ev,
                                  const struct estimate *est,
                                  struct constraint *out, int out_max) {
#if !TEXT_TRACKS_DIRECTMAP
  (void)ev;
  (void)est;
  (void)out;
  (void)out_max;
  return 0; /* decoupled arches use cmdline_mem_phys_ceiling */
#else
  if (out_max < 1)
    return 0;

  /* virt_page_offset must be pinned (VMSPLIT or landmark resolved). */
  const struct estimate *po = &est[Q_PAGE_OFFSET];
  if (po->lo != po->hi)
    return 0;
  unsigned long virt_page_offset = po->lo;

  unsigned long mem = 0;
  enum kasld_confidence mconf = CONF_UNKNOWN, kconf = CONF_UNKNOWN;
  uint32_t msrc = 0, ksrc = 0;
  unsigned long ksize = evidence_image_size_min(ev, &kconf, &ksrc);
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->value_kind != OBS_SCALAR)
      continue;
    if (o->scalar_fact == SF_PHYS_CMDLINE_MEM) {
      mem = o->scalar_value;
      mconf = o->conf;
      msrc = o->id;
    }
  }
  if (mem == 0 || ksize == 0 || ksize >= mem)
    return 0;

  unsigned long span = mem - ksize;
  /* A 32-bit highmem `mem=` names more RAM than the linear map covers, so
   * page_offset + span projects above the address space and wraps to a phantom
   * low ceiling that would wrongly reject the true (higher) text base -- emit
   * none. Inert on 64-bit, where the sum never wraps. Mirrors the guard
   * virt_ceiling_from_memtotal carries. */
  if (span > ULONG_MAX - virt_page_offset - (unsigned long)IMAGE_BASE_OFFSET)
    return 0;
  unsigned long ceiling =
      virt_page_offset + span + (unsigned long)IMAGE_BASE_OFFSET;
  /* Align to the resolved Q_VIRT_KASLR_ALIGN (>= compile-time
   * KASLR_VIRT_ALIGN). */
  unsigned long valign = est[Q_VIRT_KASLR_ALIGN].lo;
  if (valign < (unsigned long)KASLR_VIRT_ALIGN)
    valign = (unsigned long)KASLR_VIRT_ALIGN;
  ceiling = kasld_floor_virt_text_bound(ceiling, valign);
  if (ceiling <= KASLR_VIRT_TEXT_MIN)
    return 0;

  struct constraint *c = &out[0];
  memset(c, 0, sizeof(*c));
  c->q = Q_VIRT_IMAGE_BASE;
  c->op = C_UPPER_BOUND;
  c->value = ceiling;
  c->conf = (mconf < kconf) ? mconf : kconf;
  c->derived_from[0] = msrc;
  c->derived_from[1] = ksrc;
  c->lineage_count = 2;
  snprintf(c->origin, ORIGIN_LEN, "cmdline_mem_virt_ceiling");
  return 1;
#endif
}
