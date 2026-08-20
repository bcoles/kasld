// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Observation: a measurement produced by a component (Layer 1 / evidence).
//
// An observation is immutable input: what a component leaked, with the
// trust level of the method that produced it. Inference never mutates an
// observation's source fields — curation (invalidate) is applied as a
// recomputed *effective* view (see evidence.h), keeping the source genuinely
// immutable.
//
// Depends only on api.h, so the evidence layer builds standalone. The set-mask
// bits and NAME_LEN are #ifndef-guarded against redefinition by internal.h.
// ---
// <bcoles@gmail.com>

#ifndef KASLD_OBSERVATION_H
#define KASLD_OBSERVATION_H

#include "api.h"        /* NAME_LEN, ORIGIN_LEN wire-field widths */
#include "constraint.h" /* enum kasld_quantity, enum constraint_op (OBS_CONSTRAINT) */

#include <stdint.h>

/* Which extent fields carry meaning (optionality via flags, never sentinel
 * values — lo=0 and hi=ULONG_MAX are both legitimate addresses). */
#ifndef KASLD_SET_BITS_DEFINED
#define KASLD_SET_BITS_DEFINED 1
enum kasld_set_bits {
  LO_SET = 1u << 0,
  HI_SET = 1u << 1,
  SAMPLE_SET = 1u << 2,
  BASE_ALIGN_SET = 1u << 3,
};
#endif

#ifndef HAS_LO
#define HAS_LO(r) ((r)->set_mask & LO_SET)
#define HAS_HI(r) ((r)->set_mask & HI_SET)
#define HAS_SAMPLE(r) ((r)->set_mask & SAMPLE_SET)
#define HAS_BASE_ALIGN(r) ((r)->set_mask & BASE_ALIGN_SET)
#endif

/* An observation carries one of three input kinds. Components are the sole
 * inference I/O boundary, so each is something a component must be able to
 * state:
 *   - OBS_ADDRESS: a region + extent (the leak/landmark shape).
 *   - OBS_SCALAR: a bare measurement with a named meaning that is NOT an
 *     address (MemTotal, physical-address bits, image size, VA bits). A rule
 *     reads it by `scalar_fact` and turns it into constraints.
 *   - OBS_CONSTRAINT: an inequality bound on a named quantity the component
 *     computed but cannot state as a located address (perf's lowest sampled IP
 *     is a lower bound on the text base that sits below _text). It carries a
 *     quantity, a bound operator (>= or <=), and a value; a passthrough rule
 *     emits it as that C_* directly. Because it is not an address, the ~44
 *     anchor rules (which gate on OBS_ADDRESS) never read it — a below-base
 *     bound cannot be misread as a text anchor.
 * Keeping non-address facts raw on the observation preserves measure/reason
 * separation (components measure; rules interpret). */
enum obs_value_kind {
  OBS_ADDRESS = 0, /* region + lo/hi/sample (default) */
  OBS_SCALAR,      /* scalar_fact + scalar_value */
  OBS_CONSTRAINT,  /* c_quantity + c_op + scalar_value (reused as the value) */
};

/* enum kasld_scalar_fact + its wire table live in api.h (the component-facing
 * contract; api.h is included above), so a component can emit scalar facts. */

struct observation {
  uint32_t id; /* monotonic, assigned by evidence_add() */

  enum obs_value_kind value_kind; /* OBS_ADDRESS (default) or OBS_SCALAR */

  /* --- source fields (immutable after evidence_add) --- */
  /* OBS_ADDRESS: */
  enum kasld_addr_type type;
  enum kasld_region region;
  char name[NAME_LEN]; /* "" if no specific instance */
  kasld_addr_t lo, hi, sample, base_align;
  uint32_t set_mask;
  enum kasld_position pos;
  /* OBS_SCALAR: */
  enum kasld_scalar_fact scalar_fact;
  unsigned long
      scalar_value; /* OBS_CONSTRAINT reuses this as the bound value */
  /* OBS_CONSTRAINT: */
  enum kasld_quantity c_quantity;
  enum constraint_op c_op;
  /* all kinds: */
  enum kasld_confidence conf;
  char origin[ORIGIN_LEN]; /* producing component */

  /* --- effective view (recomputed each round by evidence_resolve) --- */
  enum kasld_addr_type eff_type; /* OBS_ADDRESS only */
  enum kasld_region eff_region;  /* OBS_ADDRESS only */
  int valid; /* 0 if invalidated by a verdict this round (both kinds) */
};

/* The single address an address-observation anchors to, preferring a known
 * base, then a sample, then either extent. The observation-shaped twin of
 * internal.h's anchor_addr(struct result *); rules consume observations. */
__attribute__((unused)) static unsigned long
obs_anchor(const struct observation *o) {
  if (o->pos == POS_BASE && HAS_LO(o))
    return o->lo;
  if (HAS_SAMPLE(o))
    return o->sample;
  if (HAS_LO(o))
    return o->lo;
  if (HAS_HI(o))
    return o->hi;
  return 0;
}

#endif /* KASLD_OBSERVATION_H */
