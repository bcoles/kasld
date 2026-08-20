// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: fold a direct constraint (OBS_CONSTRAINT) into the meet.
//
// A component that has computed a bound on a known quantity — but cannot state
// it as a located address — emits it on the constraint channel
// (kasld_emit_constraint), which the orchestrator bridges to an OBS_CONSTRAINT
// observation carrying (quantity, op, value). This rule is the one-shot ingest:
// each valid OBS_CONSTRAINT becomes exactly that C_* constraint on its named
// quantity, at its own confidence. No translation, no positional inference —
// the component already spoke in the engine's own vocabulary.
//
// The motivating producer is perf: its lowest sampled instruction pointer is a
// lower bound on the virtual text base that lands at or one slot below _text
// (Q_VIRT_IMAGE_BASE C_LOWER_BOUND). Expressed as a positional address it would
// sit below _text and corrupt the anchor rules that read a base witness as a
// located address; expressed as a constraint it never touches them — an
// OBS_CONSTRAINT is not an address, so the anchor rules (which gate on
// OBS_ADDRESS) never see it.
//
// Soundness:
//   * Only inequality bounds (>=, <=) are carried; the emit helper and the wire
//     parser both reject every other op, and this rule re-checks the shape
//     rather than trust it. An exact value belongs on the positional channel (a
//     located address) or the scalar channel, not here.
//   * Confidence inherits from the observation. A meet is monotone in the
//     constraint set, so adding a sound bound can only narrow — never unsound.
//   * Agreeing bounds from independent components intersect at the meet (an
//     exact pin that matches a bracket endpoint collapses it to that slot).
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"

#include <string.h>

int rule_constraint_passthrough(const struct evidence_set *ev,
                                const struct estimate *est,
                                struct constraint *out, int out_max) {
  (void)est;
  int n = 0;
  for (int i = 0; i < ev->n_obs && n < out_max; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->value_kind != OBS_CONSTRAINT)
      continue;
    if (o->c_op != C_LOWER_BOUND && o->c_op != C_UPPER_BOUND)
      continue;
    if ((unsigned)o->c_quantity >= Q__COUNT)
      continue;

    struct constraint *c = &out[n];
    memset(c, 0, sizeof(*c));
    c->q = o->c_quantity;
    c->op = o->c_op;
    c->value = o->scalar_value;
    c->conf = o->conf;
    c->derived_from[0] = o->id;
    c->lineage_count = 1;
    snprintf(c->origin, ORIGIN_LEN, "constraint_passthrough");
    n++;
  }
  return n;
}
