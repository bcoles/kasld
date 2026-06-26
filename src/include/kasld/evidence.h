// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Evidence set: the observation store plus curation verdicts.
//
// Observations are immutable. Curation rules do NOT mutate observations —
// they emit *verdicts*. evidence_resolve() applies the
// verdicts each round to recompute the per-observation `valid` bit and
// effective region/type. This keeps the source immutable, makes
// invalidation traceable (lineage on the verdict), and keeps curation in
// the same pure-recompute shape as estimate resolution.
// ---
// <bcoles@gmail.com>

#ifndef KASLD_EVIDENCE_H
#define KASLD_EVIDENCE_H

#include "constraint.h" /* MAX_LINEAGE, ORIGIN_LEN */
#include "observation.h"

#include <stdint.h>

#ifndef MAX_OBSERVATIONS
#define MAX_OBSERVATIONS 4096
#endif
#ifndef MAX_VERDICTS
#define MAX_VERDICTS 256
#endif
/* Coverings are a projection of results[] (one per pos=extent result), so they
 * are bounded by the same stream as observations. Size the store to match
 * MAX_OBSERVATIONS so a covering can never be truncated — dropping a map extent
 * would carve a false gap. results[] saturates upstream long before this is
 * reached, making evidence_add_covering's drop-guard defensive only. */
#ifndef MAX_COVERINGS
#define MAX_COVERINGS MAX_OBSERVATIONS
#endif

/* One extent of a COMPLETE, single-source covering of a region — an entry in a
 * whole RAM map (an E820 region, a device-tree /memory node, a hotplug block
 * run). A covering is a fundamentally different kind of evidence from an
 * observation:
 *   - NOT corroboratable / NOT merged. Two sources' maps must never be mixed:
 *     a runtime-offlined block is RAM in the boot E820 but a hole in a hotplug
 *     view, so unioning would melt a real gap or synthesize a false one. Each
 *     map is independently complete for its own substrate.
 *   - The VALUE is in the GAPS between extents, not at any single edge — which
 *     is why covering members carry no positional claim (pos=extent).
 * Observations flow through the cross-source merge (merge_results); coverings
 * bypass it entirely and live here, attributed to the single emitting `origin`.
 * Map rules (ram_map_phys_exclude, firmware_memmap_holes) read coverings[]. */
struct covering {
  uint32_t id;             /* lineage handle; shares the obs id space */
  char origin[ORIGIN_LEN]; /* the single source that emitted this whole map */
  enum kasld_addr_type type;
  enum kasld_region region;
  unsigned long lo, hi; /* inclusive extent */
  enum kasld_confidence conf;
};

/* Curation verdict. Currently only invalidation; the enum is kept so a future
 * curation kind is an additive change. (A region/type *relabel* was considered
 * — V_RECLASSIFY — but its only use, MIPS64 XKPHYS, is a value decode handled
 * at the observation boundary instead; see kasld_addr_is_xkphys.) */
enum verdict_kind {
  V_INVALID = 0, /* drop the observation from the effective set */
};

struct verdict {
  uint32_t observation_id; /* target observation */
  enum verdict_kind kind;
  enum kasld_confidence conf;
  uint32_t derived_from[MAX_LINEAGE];
  uint8_t lineage_count;
  char origin[ORIGIN_LEN]; /* emitting curation rule */
};

struct evidence_set {
  struct observation obs[MAX_OBSERVATIONS];
  int n_obs;
  struct verdict verdicts[MAX_VERDICTS];
  int n_verdicts;
  struct covering coverings[MAX_COVERINGS];
  int n_coverings;
  uint32_t next_id; /* monotonic id source; never recycles */
};

/* Reset to empty (next_id starts at 1; 0 is reserved "no observation"). */
void evidence_init(struct evidence_set *ev);

/* Append an observation (copied). Assigns and returns a fresh id; sets the
 * effective view to the source and valid=1. Returns 0 if full. */
uint32_t evidence_add(struct evidence_set *ev, const struct observation *src);

/* Append a covering extent (copied). Assigns and returns a fresh id from the
 * same id space as observations. Coverings carry no effective view or valid
 * bit — they are not curated, only grouped by origin and read by map rules.
 * Returns 0 if full. */
uint32_t evidence_add_covering(struct evidence_set *ev,
                               const struct covering *src);

/* Append a verdict (copied). Returns 1 on success, 0 if full. */
int evidence_add_verdict(struct evidence_set *ev, const struct verdict *v);

/* Recompute the effective view of every observation from its source plus
 * the verdict list. Pure and idempotent: removing a verdict and resolving
 * again un-applies it. Verdicts targeting unknown ids are ignored. */
void evidence_resolve(struct evidence_set *ev);

/* Convenience: is this observation part of the current effective set? */
static inline int evidence_active(const struct observation *o) {
  return o->valid;
}

/* The kernel image footprint is a two-ended interval [size_min, size_max].
 * These two accessors are the ONLY sanctioned way for a rule to read size; the
 * raw SF_IMAGE_SIZE_MIN / SF_IMAGE_SIZE_MAX facts are never scanned in a rule
 * (enforced by tests/check-image-size). See kasld/kernel_image.h for the
 * sources and which end each one feeds.
 *
 * evidence_image_size_min — the tightest proven LOWER bound on the footprint
 * (max over SF_IMAGE_SIZE_MIN), or 0 if none. The ceiling / exclusion / match
 * rules subtract size from a window edge, so they need a value <= the true
 * footprint; the largest such value is tightest and still sound. *conf / *src
 * (each may be NULL) receive the winning observation's confidence and id. */
static inline unsigned long
evidence_image_size_min(const struct evidence_set *ev,
                        enum kasld_confidence *conf, uint32_t *src) {
  unsigned long best = 0;
  enum kasld_confidence c = CONF_UNKNOWN;
  uint32_t s = 0;
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->value_kind != OBS_SCALAR ||
        o->scalar_fact != SF_IMAGE_SIZE_MIN)
      continue;
    if (o->scalar_value > best) {
      best = o->scalar_value;
      c = o->conf;
      s = o->id;
    }
  }
  if (conf)
    *conf = c;
  if (src)
    *src = s;
  return best;
}

/* evidence_image_size_max — the tightest proven UPPER bound on the in-image
 * extent (min over SF_IMAGE_SIZE_MAX), or 0 if none. The image-base floor rule
 * needs a value no in-image leak can exceed (>= _end - _text); the smallest
 * such value gives the tightest sound floor. Only EXACT sources emit this. */
static inline unsigned long
evidence_image_size_max(const struct evidence_set *ev,
                        enum kasld_confidence *conf, uint32_t *src) {
  unsigned long best = 0;
  enum kasld_confidence c = CONF_UNKNOWN;
  uint32_t s = 0;
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->value_kind != OBS_SCALAR ||
        o->scalar_fact != SF_IMAGE_SIZE_MAX)
      continue;
    if (best == 0 || o->scalar_value < best) {
      best = o->scalar_value;
      c = o->conf;
      s = o->id;
    }
  }
  if (conf)
    *conf = c;
  if (src)
    *src = s;
  return best;
}

/* Minimum plausible kernel image size in bytes: every real kernel image is at
 * least this large, so it is always a sound lower bound on the footprint — the
 * conservative floor used when nothing tighter was observed. */
#define KASLD_MIN_IMAGE_SIZE (4UL * 1024 * 1024)

/* evidence_image_size_min(), floored at KASLD_MIN_IMAGE_SIZE. For ceiling rules
 * that subtract a kernel-size lower bound from a window edge: returns the
 * observed lower bound when present (tighter), the conservative floor
 * otherwise, so the rule fires soundly even with no size fact. Always
 * >= KASLD_MIN_IMAGE_SIZE. Rules that must distinguish observed-vs-assumed (for
 * confidence or to skip entirely) call evidence_image_size_min() instead. */
static inline unsigned long
evidence_image_size_min_or_floor(const struct evidence_set *ev) {
  unsigned long v = evidence_image_size_min(ev, NULL, NULL);
  return v > KASLD_MIN_IMAGE_SIZE ? v : KASLD_MIN_IMAGE_SIZE;
}

#endif /* KASLD_EVIDENCE_H */
