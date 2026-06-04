// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: restore the Q_*_TEXT_BASE floor after the conservative honest-top
// widening for CONFIG_PHYSICAL_START variability (x86).
//
// quantities.c widens the honest-top floors of Q_VIRT_TEXT_BASE and
// Q_PHYS_TEXT_BASE on x86_64 (KASLR_VIRT_TEXT_MIN_WIDE, KASLR_PHYS_MIN_WIDE) so
// kernels built with a smaller-than-default CONFIG_PHYSICAL_START remain
// inside the engine's window — soundness across config variants. The
// widening admits values that *most* real kernels never reach; this rule
// pushes the floor back up via a constraint, at confidence reflecting how
// well we know the value:
//
//   - SF_PHYSICAL_START present (parsed from /boot/config or /proc/config.gz):
//       C_LOWER_BOUND at the *learned* value, CONF_PARSED. Tight + correct.
//   - SF_PHYSICAL_START absent: C_LOWER_BOUND at the compile-time default
//       (KASLR_VIRT_TEXT_MIN), CONF_HEURISTIC. Same window as the pre-widening
//       behaviour on default-config kernels — but overridable: a real
//       text leak below the heuristic floor would force-bottom the
//       heuristic, the resolver discards it (lower confidence), the leak
//       wins. Soundness preserved.
//
// x86_64 only — the only arch that widens today. Other arches whose
// KASLR_VIRT_TEXT_MIN doesn't embed configurable knobs get
// KASLR_VIRT_TEXT_MIN_WIDE == KASLR_VIRT_TEXT_MIN at default and this rule has
// nothing to do.
// ---
// <bcoles@gmail.com>

#include "../include/kasld/engine_rules.h"

#include <string.h>

int rule_physical_start_lower_bound(const struct evidence_set *ev,
                                    const struct estimate *est,
                                    struct constraint *out, int out_max) {
  (void)est;
#if !defined(__x86_64__)
  (void)ev;
  (void)out;
  (void)out_max;
  return 0;
#else
  if (out_max < 2)
    return 0;

  /* Look for a learned CONFIG_PHYSICAL_START. */
  unsigned long learned = 0;
  uint32_t learned_src = 0;
  enum kasld_confidence learned_conf = CONF_UNKNOWN;
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->value_kind != OBS_SCALAR ||
        o->scalar_fact != SF_PHYSICAL_START || o->scalar_value == 0)
      continue;
    learned = o->scalar_value;
    learned_src = o->id;
    learned_conf = o->conf;
    break;
  }

  unsigned long virt_floor, phys_floor;
  enum kasld_confidence emit_conf;
  uint32_t lineage = 0;
  if (learned) {
    virt_floor = (unsigned long)KERNEL_VIRT_TEXT_MIN + learned;
    phys_floor = learned;
    emit_conf = learned_conf;
    lineage = learned_src;
  } else {
    /* Heuristic fallback — same value as the pre-widening KASLR_*_MIN. A
     * real leak below this is allowed to win via the resolver's
     * confidence-priority handling of bottom-forcing constraints. */
    virt_floor = (unsigned long)KASLR_VIRT_TEXT_MIN;
    phys_floor = (unsigned long)KASLR_PHYS_MIN;
    emit_conf = CONF_HEURISTIC;
  }

  int n = 0;
  /* Don't emit if the floor wouldn't actually narrow — skips the no-op
   * case where the arch never widened in the first place. */
  if (virt_floor > (unsigned long)KASLR_VIRT_TEXT_MIN_WIDE && n < out_max) {
    struct constraint *c = &out[n++];
    memset(c, 0, sizeof(*c));
    c->q = Q_VIRT_TEXT_BASE;
    c->op = C_LOWER_BOUND;
    c->value = virt_floor;
    c->conf = emit_conf;
    c->derived_from[0] = lineage;
    c->lineage_count = lineage ? 1 : 0;
    snprintf(c->origin, ORIGIN_LEN, "physical_start_lower_bound");
  }
  if (phys_floor > (unsigned long)KASLR_PHYS_MIN_WIDE && n < out_max) {
    struct constraint *c = &out[n++];
    memset(c, 0, sizeof(*c));
    c->q = Q_PHYS_TEXT_BASE;
    c->op = C_LOWER_BOUND;
    c->value = phys_floor;
    c->conf = emit_conf;
    c->derived_from[0] = lineage;
    c->lineage_count = lineage ? 1 : 0;
    snprintf(c->origin, ORIGIN_LEN, "physical_start_lower_bound");
  }
  return n;
#endif
}
