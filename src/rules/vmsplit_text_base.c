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
//   PAGE_OFFSET     = largest VMSPLIT boundary <= V   (V lies in the image,
//                     which spans [PAGE_OFFSET + TEXT_OFFSET, PAGE_OFFSET +
//                     1G))
//   virt text base >= PAGE_OFFSET + IMAGE_BASE_OFFSET  (lower bound; the exact
//                     base comes from an observed text witness via
//                     text_pin_from_observation)
//
// This is the runtime "vmsplit adjustment" the arm32 header promises. Without
// it the engine keeps the compile-time PAGE_OFFSET (0xc0000000) default, which
// on a non-3G/1G kernel (e.g. a 2G/2G distro build) is wrong.
//
// We gather every virtual kernel-text witness, snap each to its boundary, and
// take the boundary with the strongest support (highest confidence, then most
// independent witnesses). The witness count becomes the PAGE_OFFSET pin's
// lineage. Pinning the text base to PAGE_OFFSET + IMAGE_BASE_OFFSET would be
// UNSOUND on a kernel whose TEXT_OFFSET exceeds 0x8000 (it excludes the real
// _text); a lower bound at that value is sound for every TEXT_OFFSET.
//
// Sound for any TEXT_OFFSET >= IMAGE_BASE_OFFSET, hence the !KASLR_SUPPORTED
// gate and the per-arch VMSPLIT_PAGE_OFFSETS opt-in.
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
#if defined(HAVE_VMSPLIT_PAGE_OFFSET) && !KASLR_SUPPORTED
  if (out_max < 2)
    return 0;

  static const unsigned long cand[] = VMSPLIT_PAGE_OFFSETS; /* high -> low */
  const int ncand = (int)(sizeof(cand) / sizeof(cand[0]));

  unsigned long best_po = 0;
  enum kasld_confidence best_conf = CONF_UNKNOWN;
  int best_votes = 0;
  uint32_t best_src[MAX_LINEAGE];
  int best_nsrc = 0;

  for (int c = 0; c < ncand; c++) {
    enum kasld_confidence conf = CONF_UNKNOWN;
    int votes = 0;
    uint32_t src[MAX_LINEAGE];
    int nsrc = 0;

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
      memcpy(best_src, src, sizeof(uint32_t) * (size_t)nsrc);
    }
  }

  if (best_votes == 0)
    return 0;

  int n = 0;

  struct constraint *po = &out[n++];
  memset(po, 0, sizeof(*po));
  po->q = Q_PAGE_OFFSET;
  po->op = C_EQUALS;
  po->value = best_po;
  po->conf = best_conf;
  for (int i = 0; i < best_nsrc; i++)
    po->derived_from[i] = best_src[i];
  po->lineage_count = best_nsrc;
  snprintf(po->origin, ORIGIN_LEN, "vmsplit_text_base");

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
