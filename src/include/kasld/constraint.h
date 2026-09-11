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
// Invariant: a constraint's confidence is <= the least confident entry in its
// lineage — a claim cannot be more certain than what it rests on. Lineage is
// what the claim rests on rather than what the rule happened to read, so an
// emission carrying an architectural value alone records none and is not
// capped.
//
// The engine holds it where constraints are received (cap_conf_to_lineage in
// engine.c) rather than each rule holding it alone. A rule grades what it
// emits by the provenance it reasoned about, and cannot see the other factor:
// which observations can arrive weakly is a fact about the component set, so a
// new technique reporting an existing region would otherwise promote the output
// of rules that were correct before it landed. A rule that caps earlier states
// a tighter ceiling of its own and is unaffected.
//
// It governs trust REPORTING and resolver priority, not the soundness of the
// floored window. A below-floor observation is invalidated before any rule runs
// (see resolve_evidence in engine.c), so every lineage a floored run can name
// is already at or above the floor and the cap cannot change what that window
// admits.
// ---
// <bcoles@gmail.com>

#ifndef KASLD_CONSTRAINT_H
#define KASLD_CONSTRAINT_H

#include "api.h"
#include "quantity.h"

#include <stdint.h>

/* Cap on lineage entries per constraint: an engine-side termination bound on
 * per-constraint provenance depth. Independent of the display-side provenance
 * a result carries (a bitset over the discovered components; see
 * struct origin_set in internal.h). */
#ifndef MAX_LINEAGE
#define MAX_LINEAGE 8
#endif

/* ORIGIN_LEN (the emitting-rule name width) is defined once in api.h. */

/* Constraint ids are drawn from a space disjoint from the EVIDENCE ids that
 * evidence_set.next_id issues to observations and coverings. Both counters
 * start at 1 and neither knows about the other, so without a mark the nth
 * observation and the nth constraint are the same number.
 *
 * That matters because derived_from below holds either kind and carries no
 * other tag: a lineage entry naming constraint n is indistinguishable from one
 * naming observation n, and a consumer asking "does this rest on an
 * observation the run threw out?" answers on a numeric coincidence rather than
 * on provenance. Marking the constraint space closes that off at the source,
 * where one branch cannot forget it, rather than at each consumer.
 *
 * The mark is a high bit, so the ordinal stays readable in a debugger and an
 * id remains a plain value to compare — nothing orders, prints or does
 * arithmetic on one. 0 stays "no id" under both spaces. */
#define KASLD_CONSTRAINT_ID_BIT 0x80000000u
#define KASLD_CONSTRAINT_ID(n) ((uint32_t)(n) | KASLD_CONSTRAINT_ID_BIT)

/* Which store an id belongs to. A lineage entry is one or the other; there is
 * no third kind, so the negative answer is "evidence", not "unknown". */
static inline int kasld_id_is_constraint(uint32_t id) {
  return (id & KASLD_CONSTRAINT_ID_BIT) != 0;
}
static inline int kasld_id_is_evidence(uint32_t id) {
  return id != 0 && !kasld_id_is_constraint(id);
}

enum constraint_op {
  C_LOWER_BOUND = 0, /* q >= value            (interval: raise lo)        */
  C_UPPER_BOUND,     /* q <= value            (interval: lower hi)        */
  C_EQUALS,          /* q == value            (collapse to a point)       */
  C_AT_LEAST_ALIGN,  /* q divisible by value  (max-align: raise alignment)*/
  C_EXCLUDE,         /* q not in [value,value2] (interval: end-trim only) */
  C_STRIDE,          /* q ≡ value (mod value2) (interval: stride annot;   *
                      *                         CRT combines repeats)     */
};

/* constraint_op <-> wire token. Total over the enum so the mapping round-trips
 * both ways (the engine emits every op internally); the direct-constraint input
 * channel (kasld_emit_constraint) only *carries* the two inequality-bound ops.
 */
static const char *const kasld_constraint_op_wire_table[] = {
    [C_LOWER_BOUND] = ">=",  [C_UPPER_BOUND] = "<=",
    [C_EQUALS] = "==",       [C_AT_LEAST_ALIGN] = "align>=",
    [C_EXCLUDE] = "exclude", [C_STRIDE] = "stride",
};

static inline const char *kasld_constraint_op_wire(enum constraint_op op) {
  unsigned n = sizeof(kasld_constraint_op_wire_table) / sizeof(char *);
  if ((unsigned)op >= n)
    return NULL;
  return kasld_constraint_op_wire_table[op];
}

/* Returns 1 and sets *out on a known token; 0 otherwise. */
static inline int kasld_constraint_op_from_wire(const char *s,
                                                enum constraint_op *out) {
  unsigned n = sizeof(kasld_constraint_op_wire_table) / sizeof(char *);
  for (unsigned i = 0; i < n; i++)
    if (kasld_constraint_op_wire_table[i] &&
        strcmp(s, kasld_constraint_op_wire_table[i]) == 0) {
      *out = (enum constraint_op)i;
      return 1;
    }
  return 0;
}

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

  /* Lineage: ids of the observations/constraints this was derived from, each
   * tagged by its store (see KASLD_CONSTRAINT_ID above), so a reader can tell
   * which it is holding. Empty (lineage_count == 0) is legal only for axiomatic
   * constraints (e.g. an arch-static ceiling); derived constraints must
   * justify. lineage_count is read as a corroboration key when two constraints
   * tie on confidence (prio_before in estimate.c), so which entries a rule
   * records is not bookkeeping alone. */
  uint32_t derived_from[MAX_LINEAGE];
  uint8_t lineage_count;

  char origin[ORIGIN_LEN]; /* emitting rule name */
  uint32_t id; /* monotonic within the run, assigned at emission, carrying
                * KASLD_CONSTRAINT_ID_BIT */
};

/* Emit one direct constraint on a quantity:
 *   C <quantity> <op> conf=<c> value=0x<hex>
 *
 * For a component that has *computed a bound on a known quantity* but cannot
 * state it as a located address (the motivating case is perf's lowest sampled
 * IP, a lower bound on the text base that lands below _text). The channel
 * carries inequality bounds only (>=, <=); the orchestrator turns each into
 * that C_* constraint for the meet. It is not an address, so the anchor rules
 * never read it — a below-base bound cannot be misread as a text anchor. An
 * exact value is deliberately NOT on this channel: a located address uses the
 * positional emitters (kasld_result_base/sample/...), where it also
 * corroborates and classifies; an exact non-address measurement uses the scalar
 * channel. This channel is for a computed bound and nothing else. */
static inline int kasld_emit_constraint(enum kasld_quantity q,
                                        enum constraint_op op,
                                        unsigned long value,
                                        enum kasld_confidence c) {
  const char *qw = kasld_quantity_wire(q);
  const char *ow = kasld_constraint_op_wire(op);
  if (!qw) {
    fprintf(stderr,
            "kasld_emit_constraint: invalid quantity %d; nothing "
            "emitted\n",
            (int)q);
    return 0;
  }
  if (op != C_LOWER_BOUND && op != C_UPPER_BOUND) {
    fprintf(stderr,
            "kasld_emit_constraint: op %s not carried on this channel "
            "(inequality bounds only); nothing emitted\n",
            ow ? ow : "?");
    return 0;
  }
  if (c == CONF_UNKNOWN) {
    fprintf(stderr,
            "kasld_emit_constraint: CONF_UNKNOWN for %s; nothing "
            "emitted\n",
            qw);
    return 0;
  }
  printf("C %s %s conf=%s value=0x%lx\n", qw, ow, kasld_conf_wire(c), value);
  return 1;
}

#endif /* KASLD_CONSTRAINT_H */
