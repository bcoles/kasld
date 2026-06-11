// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: vmsplit_text_base
//
// On an architecture whose PAGE_OFFSET is a compile-time VMSPLIT choice and
// which has no KASLR (ARM32: arch/arm/Kconfig VMSPLIT_3G/3G_OPT/2G/1G), the
// kernel image base is fixed at PAGE_OFFSET + TEXT_OFFSET. Therefore ANY
// observed kernel virtual text address V determines the whole virtual layout:
//
//   PAGE_OFFSET     = largest VMSPLIT boundary <= V   (V lies in the image,
//                     which spans [PAGE_OFFSET + TEXT_OFFSET, PAGE_OFFSET +
//                     1G))
//   virt text base  = PAGE_OFFSET + TEXT_OFFSET        (== _text, exactly)
//
// This is the runtime "vmsplit adjustment" the arm32 header promises. Without
// it the engine keeps the compile-time PAGE_OFFSET (0xc0000000) default, which
// on a non-3G/1G kernel (e.g. a 2G/2G distro build) is wrong — and the raw
// _stext pin overshoots the real _text by the head/init sections.
//
// We gather every virtual kernel-text witness, snap each to its boundary, and
// take the boundary with the strongest support (highest confidence, then most
// independent witnesses). The witness count becomes the constraint lineage, so
// an agreeing set of leaks outranks a single raw _stext pin in the resolver
// (estimate.c prio_before: confidence DESC, then lineage_count DESC).
//
// Sound only where text == PAGE_OFFSET + TEXT_OFFSET deterministically, hence
// the !KASLR_SUPPORTED gate and the per-arch VMSPLIT_PAGE_OFFSETS opt-in.
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

  struct constraint *vt = &out[n++];
  memset(vt, 0, sizeof(*vt));
  vt->q = Q_VIRT_TEXT_BASE;
  vt->op = C_EQUALS;
  vt->value = best_po + (unsigned long)TEXT_OFFSET;
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
