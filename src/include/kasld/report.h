// This file is part of KASLD - https://github.com/bcoles/kasld
//
// The report model: one finished description of a run, built once, rendered by
// every format.
//
// A format is a pure function from this model to bytes. It chooses glyphs,
// colour, column widths, quoting and wrapping -- how a thing LOOKS. It does not
// choose which items exist, compute or alter a value, assign a grade, or
// acquire a fact. Everything a format needs to draw is decided here, before any
// of them run, so two formats cannot describe one run differently.
//
// Built from the ENGINE -- estimates and the constraints behind them -- never
// from what some other format happens to print. A model derived from existing
// output encodes each renderer's decisions as though they were facts about the
// target, which is the defect this layer exists to remove.
//
// ---
// <bcoles@gmail.com>

#ifndef KASLD_REPORT_H
#define KASLD_REPORT_H

#include "constraint.h"
#include "estimate.h"
#include "quantity.h"

/* How many excluded sub-ranges an item retains for display. The engine may
 * carve more (bounded by ESTIMATE_MAX_WORK); `n_excluded` counts them all, so a
 * format can always say how many exist even when it cannot list them. Sized for
 * the realistic case: a live x86_64 run carves 7 physical reservations. */
#define KASLD_REPORT_MAX_EXCLUDED 16

/* What kind of set a resolved window describes.
 *
 * The engine has three lattice kinds and the model must express all three, or a
 * quantity gets flattened into a shape it does not have. RSHAPE_SET exists for
 * Q_VA_BITS (a paging level is not a location), and it is why the count of
 * remaining possibilities is called "candidates" everywhere rather than slots
 * or placements -- those words assume the thing being counted sits somewhere.
 */
enum kasld_report_shape {
  RSHAPE_INTERVAL, /* [lo, hi] on a grid, less any excluded sub-ranges */
  RSHAPE_SET,      /* an explicit set of admissible values */
  RSHAPE_FLOOR     /* at least this value; no upper bound is claimed */
};

/* Where a concrete value came from.
 *
 * A base WITNESS states the region's first address. An INTERIOR sample states
 * only that the region contains that address, so the base lies at or below it
 * -- a bound, not an answer. Recorded here because by the time a format sees an
 * address it is only a number, and presenting an interior-derived value as the
 * base overstates by however far the sample sits above it. */
enum kasld_anchor_kind {
  RANCHOR_NONE = 0,
  RANCHOR_BASE,    /* a witness to the region's base */
  RANCHOR_INTERIOR /* a point inside the region; the base is at or below it */
};

/* One excluded sub-range carved out of a window's hull. */
struct kasld_report_hole {
  unsigned long lo, hi; /* inclusive */
};

/* One resolved window over a quantity.
 *
 * `lo`/`hi` are the convex HULL. They are not the candidate set: interior holes
 * are carved and a stride may thin what remains, which is why `candidates` can
 * be far smaller than the hull's width suggests and cannot be derived from the
 * endpoints. A format that prints the hull without saying so leaves a reader
 * unable to reconcile the two numbers beside each other. */
struct kasld_report_window {
  int present; /* 0 = this grade resolved nothing for the quantity */
  enum kasld_report_shape shape;

  unsigned long lo, hi;
  int has_lo, has_hi; /* a half-bound states one edge and claims nothing of
                       * the other; hi == 0 is not "zero", it is "unstated" */

  /* The live value satisfies (v % stride) == stride_offset as well as lying in
   * the hull. Zero stride means no congruence is known. Reported, not merely
   * counted: which candidates to skip is directly actionable, and it is a
   * second reason `candidates` disagrees with the hull's width. */
  unsigned long stride, stride_offset;

  /* RSHAPE_SET only: the values still admissible, decoded from the estimate's
   * live-candidate bitmask. A set has no endpoints and no grid, so `lo`/`hi`
   * and `align_min` say nothing about it -- reading a bitmask as though it were
   * an address is exactly the flattening this shape exists to prevent. */
  unsigned long values[KASLD_FINSET_MAX_CANDIDATES];
  int n_values;

  struct kasld_report_hole excluded[KASLD_REPORT_MAX_EXCLUDED];
  int n_excluded;      /* total carved, including any past the array */
  int excluded_listed; /* how many of them the array holds */

  /* Candidates remaining, holes carved and stride applied. Taken from the
   * engine; never recomputed by a consumer, which could only produce the
   * hull-blind number. */
  unsigned long candidates;
};

/* One unknown about the target, with everything proven about it.
 *
 * An item is a QUANTITY, not a row. The two windows are two statements about
 * one unknown, resolved at two confidence floors -- so "grade" is which window
 * is being read, not a property to store. A format decides whether that becomes
 * one row or two; the model does not carry a row shape.
 *
 * Membership is per machine: an architecture that has no such unknown carries
 * no item for it, because there is nothing to report. Identical output across
 * architectures is neither achievable nor wanted -- what is identical is the
 * vocabulary and the rules, not the contents. */
struct kasld_report_quantity {
  enum kasld_quantity q;
  const char *key;   /* machine name, stable: "virt_image_base" */
  const char *label; /* human name: "Virtual Image Base" */

  /* The grain candidates are counted on, and a LOWER BOUND: the engine resolves
   * alignment with C_AT_LEAST_ALIGN and nothing caps it, so the true alignment
   * may be coarser and the true candidate count correspondingly smaller. The
   * count is therefore an upper bound -- the conservative direction, since the
   * residual bounds the target's protection from above. Zero only where the
   * quantity sits on no modelled grid at all. */
  unsigned long align_min;

  /* Two denominators, because there are two different "out of how many" and
   * they are not interchangeable.
   *
   * `entropy_top` is what the KERNEL chose among: the window its own KASLR
   * draws from. This is the denominator a reader wants -- "8 of 505" means 8 of
   * the places the kernel could have put itself. Zero where the architecture
   * defines no such window for this quantity, which is not the same as having
   * no candidates.
   *
   * `search_top` is what the ENGINE was willing to consider, and is
   * deliberately wider: the kernel window bakes in build options this binary
   * cannot see, so starting there would let a legitimately-configured kernel
   * fall outside the resolved window -- the one direction this tool must never
   * be wrong in. On x86_64 that margin is 7 slots (an unknown
   * CONFIG_PHYSICAL_START); on riscv64 it is 127x, because two different text
   * layouts must both fit.
   *
   * Because the engine searches wider than the kernel picks, a resolved count
   * CAN exceed `entropy_top`. Both are carried so a format can notice that and
   * present a bare count instead of an incoherent ratio -- a presentation rule,
   * which is why it lives in the formats and not here.
   *
   * Narrowing is `candidates < search_top`: read from the counts, never stored,
   * because a copy of a derived fact goes stale. */
  unsigned long entropy_top;
  unsigned long search_top;

  struct kasld_report_window guaranteed; /* sound floor: contains the truth */
  struct kasld_report_window likely; /* all signals: a subset, may be wrong */

  /* The single concrete value, where one was picked, with the provenance that
   * says how much it is worth. A RANCHOR_INTERIOR point is a ceiling on the
   * base, not the base. */
  int has_point;
  unsigned long point;
  enum kasld_anchor_kind anchor;
  long slide; /* displacement from the un-randomized base */
  int has_slide;
};

/* What kind of system this is, with respect to randomization.
 *
 * A field, not a branch. Formats state it in words and then draw the same items
 * they always draw -- the posture changes what the values ARE, never which
 * items exist, so a reader who has seen one posture recognises the next and two
 * runs across a reboot that changed it remain comparable. */
enum kasld_posture {
  RPOSTURE_RANDOMIZED = 0, /* KASLR ran */
  RPOSTURE_DISABLED,    /* deliberately off: nokaslr, RANDOMIZE_BASE=n, ... */
  RPOSTURE_UNSUPPORTED, /* the architecture has no KASLR */
  RPOSTURE_FAILED       /* the stub ran with no randomness to place with */
};

/* A concrete value picked for a quantity, supplied by the caller.
 *
 * Not derivable from the estimates: the headline base is chosen by scanning the
 * observations and reconciling that pick against the engine, which is the
 * orchestrator's job. The model records it, and records HOW it was witnessed --
 * an interior sample bounds the base from above rather than being it, and that
 * distinction is lost the moment the value becomes a bare address. */
struct kasld_report_point {
  int present;
  unsigned long value;
  enum kasld_anchor_kind anchor;
  long slide;
  int has_slide;
};

/* The report. Sections are added as the migration proceeds; quantities and
 * posture are the first, and the rest (target identity, evidence, map,
 * components, environment, notes) follow the same rule -- decided here, drawn
 * there. */
struct kasld_report {
  enum kasld_posture posture;
  struct kasld_report_quantity quantities[Q__COUNT];
  int n_quantities;
};

/* A read-only view of one resolution: the estimates, and the constraints the
 * candidate counts and hole carving are taken from.
 *
 * Taken as plain data rather than as `struct engine` so the builder is callable
 * -- and testable -- without the engine-only translation unit. */
struct kasld_resolution_view {
  const struct estimate *est; /* Q__COUNT entries */
  const struct constraint *cs;
  int n_cs;
  /* The confidence floor this resolution was run at. Carried with the data
   * rather than assumed by the builder: the engine is floor-agnostic and the
   * two-window POLICY -- which floors, and what they mean -- belongs to the
   * caller that chose them. It is also what the candidate count and the hole
   * carving must be taken at, so a view describes a resolution completely. */
  enum kasld_confidence floor;
};

/* Build the model from the two resolutions the orchestrator holds: the floored
 * run (guaranteed) and the all-signals run (likely). `likely.est` may be NULL,
 * in which case every item's likely window is absent. */
/* `points` is indexed by quantity and may be NULL; entries whose `present` is 0
 * contribute nothing. `posture` is the caller's, for the same reason the floors
 * are: it is policy, not something the estimates state. */
void kasld_report_build(struct kasld_resolution_view guaranteed,
                        struct kasld_resolution_view likely,
                        const struct kasld_report_point *points,
                        enum kasld_posture posture, struct kasld_report *out);

#endif /* KASLD_REPORT_H */
