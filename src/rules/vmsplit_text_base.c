// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: vmsplit_text_base
//
// On an architecture whose PAGE_OFFSET is a compile-time VMSPLIT choice and
// which has no KASLR (ARM32: arch/arm/Kconfig VMSPLIT_3G/3G_OPT/2G/1G), the
// kernel image sits at PAGE_OFFSET + TEXT_OFFSET, with TEXT_OFFSET >=
// IMAGE_BASE_OFFSET (the classic 0x8000 minimum; some configs/platforms/loaders
// place it higher, e.g. 0x208000 on the Alpine multi-platform kernels). The
// exact TEXT_OFFSET is not reliably knowable unprivileged, so this rule does
// NOT pin the text base — it determines PAGE_OFFSET (the valuable part) and
// floors the image base. ANY observed kernel virtual text address V gives:
//
//   B               = largest VMSPLIT boundary <= V   (V lies in the image,
//                     which spans [PAGE_OFFSET + TEXT_OFFSET, PAGE_OFFSET +
//                     1G))
//   PAGE_OFFSET    in [B, min(V)]   (the lowest witness upper-bounds it
//   directly
//                     on a coupled arch; see the ceiling note below)
//   virt text base >= B + IMAGE_BASE_OFFSET             (lower bound; the exact
//                     base comes from an observed text witness via
//                     text_pin_from_observation)
//
// This is the runtime "vmsplit adjustment" the arm32 header promises. Without
// it the engine keeps the compile-time PAGE_OFFSET (0xc0000000) default, which
// on a non-3G/1G kernel (e.g. a 2G/2G distro build) is wrong.
//
// We gather every virtual kernel-text witness, snap each to its boundary, and
// take the boundary with the strongest support (highest confidence, then most
// independent witnesses). The witness count becomes the constraint's lineage.
// Pinning the text base to PAGE_OFFSET + IMAGE_BASE_OFFSET would be UNSOUND on
// a kernel whose TEXT_OFFSET exceeds 0x8000 (it excludes the real _text); a
// lower bound at that value is sound for every TEXT_OFFSET.
//
// BOUNDS on PAGE_OFFSET, not an equality, and that is the whole difference
// between this rule and an unsound one. `C_EQUALS` on the snap would exclude
// the truth whenever the split is one the list omits — a kernel built there
// snaps to the next listed boundary DOWN. Completeness cannot be established
// from inside this repo (the list mirrors a Kconfig choice a vendor can
// extend), so the rule emits a window.
//
// Ceiling: the lowest witness. On a coupled arch every kernel-text address is
// at or above PAGE_OFFSET, so PAGE_OFFSET <= min(V) directly — no argument
// about boundary spacing, tighter than the next listed candidate above the snap
// (which the witness already sits below), and independent of the list.
//
// Floor: the snapped boundary, a lower bound on the true base PROVIDED no
// listed candidate sits strictly between that base and the witness — then the
// largest listed candidate <= V is at or below the base. That holds where the
// list is complete AND the image does not span a listed boundary (the witness
// stays within one gap of the base): arm32's four VMSPLIT options are the whole
// Kconfig choice, and a kernel image is far below the 256 MiB minimum gap. It
// is NOT the unconditional "snapping only rounds down" it may look like: an
// UNLISTED base just under a listed boundary, with text spanning across it,
// would snap above the truth. The floor rests on that completeness; the ceiling
// above does not.
//
// The !KASLR_SUPPORTED gate is separate and still required. The floor assumes
// the witness sits within one gap of the base; with KASLR the image can be
// placed far higher, so the snap can land on a different boundary entirely and
// the floor would then exclude the truth just as an equality would.
//
// The candidate set is the architecture's own PAGE_OFFSET_CANDIDATES, so there
// is no second list to keep in step; the rule is inert where that set has a
// single entry, since there is then no split to determine.
//
// NOT the same as api.h's kasld_floor_text_base(), and deliberately not built
// on it: this snaps to the 1 GiB VMSPLIT boundary to *determine PAGE_OFFSET*,
// whereas the helper floors to KASLR_VIRT_ALIGN (2 MiB on arm32). The coarser
// boundary is essential here (a 2 MiB floor cannot tell which VMSPLIT is in
// use, and undershoots the boundary for a leak >2 MiB above the base).
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"
#include "include/kasld/regions.h"
#include <string.h>

int rule_vmsplit_text_base(const struct evidence_set *ev,
                           const struct estimate *est, struct constraint *out,
                           int out_max) {
  (void)est;
#if PAGE_OFFSET_IS_FINITE && !PAGE_OFFSET_KNOWN_AT_BUILD && !KASLR_SUPPORTED
  static const unsigned long cand[] = PAGE_OFFSET_CANDIDATES; /* high -> low */
  const int ncand = (int)(sizeof(cand) / sizeof(cand[0]));

  unsigned long best_po = 0;
  enum kasld_confidence best_conf = CONF_UNKNOWN;
  int best_votes = 0;
  uint32_t best_src[MAX_LINEAGE];
  int best_nsrc = 0;
  unsigned long best_min_v = 0; /* lowest witness for the winning boundary */

  for (int c = 0; c < ncand; c++) {
    enum kasld_confidence conf = CONF_UNKNOWN;
    int votes = 0;
    uint32_t src[MAX_LINEAGE];
    int nsrc = 0;
    unsigned long min_v = 0;

    for (int i = 0; i < ev->n_obs; i++) {
      const struct observation *o = &ev->obs[i];
      if (!o->valid || o->value_kind != OBS_ADDRESS ||
          o->eff_type != KASLD_TYPE_VIRT)
        continue;
      if (o->eff_region != REGION_KERNEL_TEXT &&
          o->eff_region != REGION_KERNEL_IMAGE)
        continue;
      unsigned long v = obs_anchor(o);
      if (v == 0)
        continue;

      /* snap v to its VMSPLIT boundary: the largest candidate <= v. A witness
       * below every boundary (a stray low value) snaps to nothing and is
       * ignored, so it cannot vote. */
      unsigned long snap = 0;
      for (int k = 0; k < ncand; k++) {
        if (v >= cand[k]) {
          snap = cand[k];
          break;
        }
      }
      if (snap != cand[c])
        continue;

      votes++;
      if (min_v == 0 || v < min_v)
        min_v = v; /* PAGE_OFFSET <= every witness on a coupled arch */
      if (o->conf > conf)
        conf = o->conf;
      if (nsrc < MAX_LINEAGE)
        src[nsrc++] = o->id;
    }

    /* Prefer the strongest-supported boundary: higher confidence, then more
     * independent witnesses. */
    if (votes > 0 && (best_votes == 0 || conf > best_conf ||
                      (conf == best_conf && votes > best_votes))) {
      best_po = cand[c];
      best_conf = conf;
      best_votes = votes;
      best_nsrc = nsrc;
      best_min_v = min_v;
      memcpy(best_src, src, sizeof(uint32_t) * (size_t)nsrc);
    }
  }

  if (best_votes == 0)
    return 0;
  if (out_max < 3)
    return 0;

  int n = 0;

  struct constraint *lo_c = &out[n++];
  memset(lo_c, 0, sizeof(*lo_c));
  lo_c->q = Q_PAGE_OFFSET;
  lo_c->op = C_LOWER_BOUND;
  lo_c->value = best_po;
  lo_c->conf = best_conf;
  for (int i = 0; i < best_nsrc; i++)
    lo_c->derived_from[i] = best_src[i];
  lo_c->lineage_count = best_nsrc;
  snprintf(lo_c->origin, ORIGIN_LEN, "vmsplit_text_base");

  /* The lowest witness is itself an upper bound: on a coupled arch every text
   * address is at or above PAGE_OFFSET, so PAGE_OFFSET <= min(V). Tighter than
   * the next listed boundary above the snap (which the witness already sits
   * below), and independent of the candidate list. best_min_v >= best_po since
   * a witness snaps to best_po only when it is at or above it, so the window
   * never inverts. */
  struct constraint *hi_c = &out[n++];
  memset(hi_c, 0, sizeof(*hi_c));
  hi_c->q = Q_PAGE_OFFSET;
  hi_c->op = C_UPPER_BOUND;
  hi_c->value = best_min_v;
  hi_c->conf = best_conf;
  for (int i = 0; i < best_nsrc; i++)
    hi_c->derived_from[i] = best_src[i];
  hi_c->lineage_count = best_nsrc;
  snprintf(hi_c->origin, ORIGIN_LEN, "vmsplit_text_base");

  /* Floor the image base at PAGE_OFFSET + IMAGE_BASE_OFFSET (the smallest
   * TEXT_OFFSET). A lower bound, NOT an exact pin: TEXT_OFFSET varies by
   * config/platform and pinning the minimum would exclude a kernel placed
   * higher. The exact base is supplied by text_pin_from_observation from the
   * observed _text/_stext witness; this only guarantees a sound floor. */
  struct constraint *vt = &out[n++];
  memset(vt, 0, sizeof(*vt));
  vt->q = Q_VIRT_IMAGE_BASE;
  vt->op = C_LOWER_BOUND;
  vt->value = best_po + (unsigned long)IMAGE_BASE_OFFSET;
  vt->conf = best_conf;
  for (int i = 0; i < best_nsrc; i++)
    vt->derived_from[i] = best_src[i];
  vt->lineage_count = best_nsrc;
  snprintf(vt->origin, ORIGIN_LEN, "vmsplit_text_base");

  return n;
#else
  (void)ev;
  (void)out;
  (void)out_max;
  return 0;
#endif
}
