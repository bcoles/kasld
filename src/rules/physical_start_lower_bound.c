// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: restore the Q_*_TEXT_BASE floor after the conservative honest-top
// widening for CONFIG_PHYSICAL_START variability (x86).
//
// quantities.c widens the honest-top floors of Q_VIRT_IMAGE_BASE and
// Q_PHYS_IMAGE_BASE on x86_64 (VIRT_TEXT_MIN_ANY_CONFIG, PHYS_MIN_ANY_CONFIG)
// so kernels built with a smaller-than-default CONFIG_PHYSICAL_START remain
// inside the engine's window — soundness across config variants. The
// widening admits values that *most* real kernels never reach; this rule
// pushes the floor back up via a constraint, at confidence reflecting how
// well the value is known:
//
//   - SF_PHYSICAL_START present (parsed from /boot/config or /proc/config.gz):
//       C_LOWER_BOUND at the *learned* value, CONF_PARSED. Tight + correct.
//   - SF_PHYSICAL_START absent: C_LOWER_BOUND at the compile-time default
//       (VIRT_TEXT_MIN_DEFAULT_CONFIG), CONF_HEURISTIC. Same window as the
//       pre-widening behaviour on default-config kernels — but overridable: a
//       real text leak below the heuristic floor would force-bottom the
//       heuristic, the resolver discards it (lower confidence), the leak
//       wins. Soundness preserved.
//
// x86_64 only, though not because it is the only arch whose invariant floor
// sits below its default-build floor: arm64, riscv64 and s390 all widen theirs.
// What separates them is the CAUSE of the gap.
//
// Here it is a build option carrying a documented default that almost no build
// changes, so assuming the default is a claim about the kernel's build system
// and stands at heuristic confidence. There it is layout and era variation --
// several text placements, several VA layouts -- where the same move would be a
// bet on which kernel is running, and the layout is recoverable from evidence
// instead: rule_arm64_text_base and rule_riscv64_text_base re-narrow once it
// resolves. s390 widens for neither reason; its floor has no derivable value to
// restore, so there is nothing for a rule of this shape to put back.
//
// On the arches whose VIRT_TEXT_MIN_DEFAULT_CONFIG embeds no configurable knob,
// VIRT_TEXT_MIN_ANY_CONFIG == VIRT_TEXT_MIN_DEFAULT_CONFIG and this rule has
// nothing to do.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"

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
    virt_floor = (unsigned long)VIRT_TEXT_PLAUSIBLE_MIN + learned;
    phys_floor = learned;
    emit_conf = learned_conf;
    lineage = learned_src;
  } else {
    /* Heuristic fallback — same value as the pre-widening KASLR_*_MIN. A
     * real leak below this is allowed to win via the resolver's
     * confidence-priority handling of bottom-forcing constraints. */
    virt_floor = (unsigned long)VIRT_TEXT_MIN_DEFAULT_CONFIG;
    phys_floor = (unsigned long)KERNEL_PHYS_DEFAULT;
    emit_conf = CONF_HEURISTIC;
  }

  int n = 0;
  /* Don't emit if the floor wouldn't actually narrow — skips the no-op
   * case where the arch never widened in the first place. */
  if (virt_floor > (unsigned long)VIRT_TEXT_MIN_ANY_CONFIG && n < out_max) {
    struct constraint *c = &out[n++];
    memset(c, 0, sizeof(*c));
    c->q = Q_VIRT_IMAGE_BASE;
    c->op = C_LOWER_BOUND;
    c->value = virt_floor;
    c->conf = emit_conf;
    c->derived_from[0] = lineage;
    c->lineage_count = lineage ? 1 : 0;
    snprintf(c->origin, ORIGIN_LEN, "physical_start_lower_bound");
  }
  if (phys_floor > (unsigned long)PHYS_MIN_ANY_CONFIG && n < out_max) {
    struct constraint *c = &out[n++];
    memset(c, 0, sizeof(*c));
    c->q = Q_PHYS_IMAGE_BASE;
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
