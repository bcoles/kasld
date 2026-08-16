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
  /* 0 when conf is below the floor the run resolved at. Coverings are not
   * curated -- no verdict targets them -- so unlike an observation's `valid`
   * this carries only the floor gate. It exists so that gate is structural
   * here rather than a habit each consuming rule has to keep: a rule that
   * forgot to propagate covering confidence into what it emits would
   * otherwise admit a below-floor map into the guaranteed window. Read it
   * through covering_active(). */
  int valid;
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
  /* Lineage and reporting only. evidence_resolve() applies every verdict
   * regardless of this value, so unlike an observation's or a covering's conf
   * it is NOT a floor gate -- a curation rule cannot make a retraction
   * conditional on the run's floor by setting it, and nothing else reads it.
   *
   * Wiring it to the floor is not a small change, because the writers do not
   * currently agree on what it means: most set it to the confidence of the
   * observation being invalidated, while firmware_memmap_holes sets it to the
   * confidence of the evidence justifying the retraction. Only the second
   * reading makes a floor test meaningful, so gating on the field as written
   * would produce arbitrary results. Settle the semantics across every writer
   * first.
   *
   * Coverings are gated at the input instead (see covering_active), which is
   * what keeps a below-floor map out of the guaranteed window on the verdict
   * path without depending on this. */
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
 * same id space as observations, and sets valid=1. Coverings carry no
 * effective view — they are not curated, only grouped by origin and read by
 * map rules — but they do carry the floor gate's verdict on their confidence.
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

/* The same question for a covering. Every rule reading coverings[] must ask it
 * before using the extent, exactly as it would evidence_active() for an
 * observation: below the run's floor, the map is out of scope. */
static inline int covering_active(const struct covering *c) { return c->valid; }

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

/* evidence_lowest_dram_base — the base of physical RAM: the LOWEST observed
 * phys REGION_RAM POS_BASE. Returns 1 and sets *out when one was observed, 0
 * otherwise.
 *
 * Found-ness is the RETURN value, not a sentinel in *out, because 0 is a
 * perfectly ordinary DRAM base — mips, ppc and x86_32 all start RAM there. An
 * accessor returning 0 for "none" would read as "absent" on exactly the coupled
 * architectures whose linear map this anchors.
 *
 * The one sanctioned way for a rule to ask where DRAM starts. Three rules need
 * it and each is entitled to assume the other two got the same answer:
 * dram_floor_bound trusts it as a physical floor, while phys_virt_synth and
 * text_base_coupling_synth anchor the LINEAR MAP on it — on the coupled arches
 * the kernel sets its physical offset from the base of DRAM, so this value is
 * the address that maps to PAGE_OFFSET. Two rules disagreeing about it would
 * anchor the linear map differently and shift a guaranteed window, so the
 * agreement their comments claim is made structural here rather than left to
 * three copies of one loop staying in step.
 *
 * POS_BASE on REGION_RAM only: that is the kernel's own account of its memory
 * (/proc/iomem "System RAM"), not firmware's account of the board, which may
 * describe banks the kernel never took. *conf / *src (each may be NULL) receive
 * the winning observation's confidence and id, so a caller can attribute a
 * constraint to the witness that established the base. */
static inline int evidence_lowest_dram_base(const struct evidence_set *ev,
                                            unsigned long *out,
                                            enum kasld_confidence *conf,
                                            uint32_t *src) {
  unsigned long best = 0;
  int found = 0;
  enum kasld_confidence c = CONF_UNKNOWN;
  uint32_t s = 0;
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->value_kind != OBS_ADDRESS ||
        o->eff_type != KASLD_TYPE_PHYS)
      continue;
    if (o->eff_region != REGION_RAM || o->pos != POS_BASE)
      continue;
    unsigned long a = obs_anchor(o);
    if (!found || a < best) {
      best = a;
      found = 1;
      c = o->conf;
      s = o->id;
    }
  }
  if (!found)
    return 0;
  if (out)
    *out = best;
  if (conf)
    *conf = c;
  if (src)
    *src = s;
  return 1;
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
