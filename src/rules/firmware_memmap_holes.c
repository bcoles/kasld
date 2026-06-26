// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Verdict: invalidate PHYS kernel-base candidates outside firmware System RAM.
//
// The firmware E820 map
// (/sys/firmware/memmap) is the authoritative System RAM topology; a leaked
// PHYS kernel-base candidate that does not lie wholly within a System RAM
// interval cannot be the real base and is curated out:
//
//   for each PHYS kernel-base candidate W:
//     drop W if no System RAM interval contains [W, W + min_image)
//
// Consumes the firmware-memmap RAM map from ev->coverings[] (origin
// "firmware_memmap" — a complete single-source covering, never a partial RAM
// leak). V_INVALID. Inert without the map or without PHYS candidate leaks.
// x86 only.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"
#include "include/kasld/regions.h"

#include <string.h>

int rule_firmware_memmap_holes(const struct evidence_set *ev,
                               struct verdict *out, int out_max) {
#if defined(__x86_64__) || defined(__i386__)
  /* The authoritative System RAM map is a covering tagged "firmware_memmap". */
  int have_map = 0;
  for (int i = 0; i < ev->n_coverings; i++) {
    if (strcmp(ev->coverings[i].origin, "firmware_memmap") == 0) {
      have_map = 1;
      break;
    }
  }
  if (!have_map)
    return 0;

  const unsigned long min_image = evidence_image_size_min_or_floor(ev);
  int n = 0;
  for (int i = 0; i < ev->n_obs && n < out_max; i++) {
    const struct observation *c = &ev->obs[i];
    if (!c->valid || c->value_kind != OBS_ADDRESS ||
        c->eff_type != KASLD_TYPE_PHYS)
      continue;
    /* Only TEXT/DATA/IMAGE phys candidates locate the base (not BSS, not RAM
     * landmarks, not MMIO). */
    if (c->eff_region != REGION_KERNEL_TEXT &&
        c->eff_region != REGION_KERNEL_DATA &&
        c->eff_region != REGION_KERNEL_IMAGE)
      continue;
    unsigned long a = obs_anchor(c);
    if (a == 0)
      continue;

    /* Does some System RAM extent contain [a, a + min_image)? */
    int fits = 0;
    for (int j = 0; j < ev->n_coverings; j++) {
      const struct covering *m = &ev->coverings[j];
      if (strcmp(m->origin, "firmware_memmap") != 0)
        continue;
      unsigned long last = (a > m->hi - (min_image - 1))
                               ? a /* avoid overflow; straddle check below */
                               : a + min_image - 1;
      if (a >= m->lo && last <= m->hi) {
        fits = 1;
        break;
      }
    }
    if (fits)
      continue;

    struct verdict *v = &out[n++];
    memset(v, 0, sizeof(*v));
    v->observation_id = c->id;
    v->kind = V_INVALID;
    v->conf = c->conf;
    v->derived_from[0] = c->id;
    v->lineage_count = 1;
    snprintf(v->origin, ORIGIN_LEN, "firmware_memmap_holes");
  }
  return n;
#else
  (void)ev;
  (void)out;
  (void)out_max;
  return 0;
#endif
}
