// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Constraint: a single claim about a quantity, with confidence and lineage.
//
// Constraints are the source of truth in the inference engine. Rules emit
// them; estimates are a pure, conflict-aware fold of the constraint set
// (see estimate.h). Every constraint names exactly one quantity and one
// relational operator, so there is no overloading of region records to
// express bounds — observations (evidence) and constraints (conclusions)
// are different types in different stores.
//
// Invariant (enforced at emission, asserted in debug builds): a derived
// constraint's confidence is <= min of its lineage's confidences — you
// cannot be more certain than your least-certain input. The sole sanctioned
// exception is the independent-corroboration fusion rule.
// ---
// <bcoles@gmail.com>

#ifndef KASLD_CONSTRAINT_H
#define KASLD_CONSTRAINT_H

#include "api.h"
#include "quantity.h"

#include <stdint.h>

/* Cap on lineage entries per constraint: an engine-side termination bound on
 * per-constraint provenance depth. Independent of the display-side
 * MAX_PROVENANCE (which now equals MAX_COMPONENTS). */
#ifndef MAX_LINEAGE
#define MAX_LINEAGE 8
#endif

/* ORIGIN_LEN (the emitting-rule name width) is defined once in api.h. */

enum constraint_op {
  C_LOWER_BOUND = 0, /* q >= value            (interval: raise lo)        */
  C_UPPER_BOUND,     /* q <= value            (interval: lower hi)        */
  C_EQUALS,          /* q == value            (collapse to a point)       */
  C_AT_LEAST_ALIGN,  /* q divisible by value  (max-align: raise alignment)*/
  C_EXCLUDE,         /* q not in [value,value2] (interval: end-trim only) */
  C_STRIDE,          /* q ≡ value (mod value2) (interval: stride annot;   *
                      *                         CRT combines repeats)     */
};

struct constraint {
  enum kasld_quantity q;
  enum constraint_op op;
  unsigned long value;  /* primary operand. op-specific role:
                         *   C_LOWER_BOUND / C_UPPER_BOUND / C_EQUALS: the value
                         *   C_AT_LEAST_ALIGN: the required alignment
                         *   C_EXCLUDE: range lo (paired with value2)
                         *   C_STRIDE: the residue r in q ≡ r (mod m) */
  unsigned long value2; /* op-specific second operand:
                         *   C_EXCLUDE: range hi (inclusive)
                         *   C_STRIDE: the modulus m
                         *   other ops: unused (must be 0) */
  enum kasld_confidence conf;

  /* Lineage: ids of the observations/constraints this was derived from.
   * Empty (lineage_count == 0) is legal only for axiomatic constraints
   * (e.g. an arch-static ceiling); derived constraints must justify. */
  uint32_t derived_from[MAX_LINEAGE];
  uint8_t lineage_count;

  char origin[ORIGIN_LEN]; /* emitting rule name */
  uint32_t id;             /* monotonic, assigned at emission */
};

#endif /* KASLD_CONSTRAINT_H */
