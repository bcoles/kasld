// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: arm64 page_offset ceiling snapped to ARM64_MEMSTART_ALIGN.
//
// PAGE_OFFSET on arm64 is aligned
// to ARM64_MEMSTART_ALIGN (512 MiB for 64K pages, 1 GiB for 4K/16K), and it is
// at most the lowest leaked DIRECTMAP address, so:
//
//   page_offset <= align_down(min directmap leak, ARM64_MEMSTART_ALIGN)
//
// Reads SF_PAGE_SIZE (bridged from getpagesize) + VIRT DIRECTMAP leaks; emits a
// C_UPPER_BOUND on Q_PAGE_OFFSET. arm64 only; dormant offline (no directmap
// leak) — LIVE-TEST list.
// ---
// <bcoles@gmail.com>

#include "../include/kasld/engine_rules.h"
#include "../include/kasld/regions.h"

#include <limits.h>
#include <string.h>

int rule_arm64_memstart_align(const struct evidence_set *ev,
                              const struct estimate *est,
                              struct constraint *out, int out_max) {
  (void)est;
#if defined(__aarch64__)
  if (out_max < 1)
    return 0;

  unsigned long pagesize = 0;
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (o->valid && o->value_kind == OBS_SCALAR &&
        o->scalar_fact == SF_PAGE_SIZE) {
      pagesize = o->scalar_value;
      break;
    }
  }
  unsigned long align;
  if (pagesize == 65536ul)
    align = 512ul * 1024 * 1024; /* PMD_SHIFT=29 */
  else if (pagesize == 4096ul || pagesize == 16384ul)
    align = 1024ul * 1024 * 1024; /* PUD/CONT_PMD_SHIFT=30 */
  else
    return 0;

  unsigned long v_min = ULONG_MAX;
  uint32_t src = 0;
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->value_kind != OBS_ADDRESS ||
        o->eff_type != KASLD_TYPE_VIRT || o->eff_region != REGION_DIRECTMAP)
      continue;
    unsigned long a = obs_anchor(o);
    if (a < v_min) {
      v_min = a;
      src = o->id;
    }
  }
  if (v_min == ULONG_MAX)
    return 0;

  unsigned long new_max = v_min & ~(align - 1);
  if (new_max == 0)
    return 0;

  struct constraint *c = &out[0];
  memset(c, 0, sizeof(*c));
  c->q = Q_PAGE_OFFSET;
  c->op = C_UPPER_BOUND;
  c->value = new_max;
  c->conf = CONF_INFERRED;
  c->derived_from[0] = src;
  c->lineage_count = src ? 1 : 0;
  snprintf(c->origin, ORIGIN_LEN, "arm64_memstart_align");
  return 1;
#else
  (void)ev;
  (void)out;
  (void)out_max;
  return 0;
#endif
}
