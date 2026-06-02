// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: physical KASLR ceiling from `mem=N` cmdline (decoupled arches).
//
// x86's KASLR placer caps the physical base at the value of `mem=` on the
// cmdline: arch/x86/boot/compressed/kaslr.c find_random_phys_addr() bails when
// `minimum + image_size > mem_limit`. The kernel image therefore satisfies
//
//   phys_base + image_size <= cmdline_mem
//
// → C_UPPER_BOUND on Q_PHYS_TEXT_BASE at `cmdline_mem - image_size`, aligned
// down to the resolved physical KASLR granularity. Decoupled arches only
// (Q_PHYS_TEXT_BASE exists); the coupled-arch counterpart is
// cmdline_mem_virt_ceiling.
//
// Reads SF_CMDLINE_MEM (emitted by cmdline-mem.c) + SF_IMAGE_SIZE; emits
// nothing when either is absent — sound.
//
// References:
// https://elixir.bootlin.com/linux/v6.12/source/arch/x86/boot/compressed/kaslr.c#L260
// https://elixir.bootlin.com/linux/v6.12/source/arch/x86/boot/compressed/kaslr.c#L812
// ---
// <bcoles@gmail.com>

#include "../include/kasld/engine_rules.h"

#include <string.h>

int rule_cmdline_mem_phys_ceiling(const struct evidence_set *ev,
                                  const struct estimate *est,
                                  struct constraint *out, int out_max) {
#if TEXT_TRACKS_DIRECTMAP
  (void)ev;
  (void)est;
  (void)out;
  (void)out_max;
  return 0; /* coupled arches use cmdline_mem_virt_ceiling */
#else
  if (out_max < 1)
    return 0;

  unsigned long mem = 0, ksize = 0;
  enum kasld_confidence mconf = CONF_UNKNOWN, kconf = CONF_UNKNOWN;
  uint32_t msrc = 0, ksrc = 0;
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->value_kind != OBS_SCALAR)
      continue;
    if (o->scalar_fact == SF_CMDLINE_MEM) {
      mem = o->scalar_value;
      mconf = o->conf;
      msrc = o->id;
    } else if (o->scalar_fact == SF_IMAGE_SIZE) {
      ksize = o->scalar_value;
      kconf = o->conf;
      ksrc = o->id;
    }
  }
  if (mem == 0 || ksize == 0 || ksize >= mem)
    return 0;

  unsigned long ceiling = mem - ksize;
  /* Align to the resolved physical KASLR granularity (>= compile-time). */
  unsigned long palign = est[Q_PHYS_KASLR_ALIGN].lo;
  if (palign < (unsigned long)KASLR_PHYS_ALIGN)
    palign = (unsigned long)KASLR_PHYS_ALIGN;
  if (palign > 0)
    ceiling &= ~(palign - 1);
  if (ceiling <= KASLR_PHYS_MIN)
    return 0;

  struct constraint *c = &out[0];
  memset(c, 0, sizeof(*c));
  c->q = Q_PHYS_TEXT_BASE;
  c->op = C_UPPER_BOUND;
  c->value = ceiling;
  c->conf = (mconf < kconf) ? mconf : kconf;
  c->derived_from[0] = msrc;
  c->derived_from[1] = ksrc;
  c->lineage_count = 2;
  snprintf(c->origin, ORIGIN_LEN, "cmdline_mem_phys_ceiling");
  return 1;
#endif
}
