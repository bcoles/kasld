// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Hardening assessment renderer (--hardening / -H), text and JSON flavours.
// Reads the same component metadata in both flavours, so they live together
// rather than be split across the text/json mode files.
//
// json_print_escaped() and the cross-file helpers are declared in
// include/kasld/render_internal.h.
// ---
// <bcoles@gmail.com>

#include "include/kasld/internal.h"
#include "include/kasld/render_internal.h"

#include <stdio.h>
#include <string.h>

/* Enforcement surfaces for the two suggestions that are not gate_suggestions[]
 * entries (those carry their own .surface): kernel lockdown is an LSM, and the
 * dmesg fallback-file restriction is a filesystem-permissions change. Named
 * once here so the text, JSON, and markdown renderers agree on the label. */
#define HR_SURFACE_LOCKDOWN "lsm"
#define HR_SURFACE_DMESG_FALLBACK "file_permissions"
/* Kernel lockdown and a MAC policy are both LSMs but are different levers —
 * one is a boot-time mode, the other a policy an administrator writes — so
 * they carry distinct surfaces rather than sharing "lsm". */
#define HR_SURFACE_MAC "mac"

/* Known sysctl gates */
struct sysctl_gate {
  const char *name;    /* meta value prefix, e.g. "dmesg_restrict" */
  const char *display; /* display string, e.g. "kernel.dmesg_restrict" */
  const char *surface; /* enforcement lever, e.g. "sysctl" / "boot_param" */
  int *value_ptr;      /* pointer to stored runtime value */
  int threshold;       /* blocking threshold (value >= threshold blocks) */
};

/* Single source of truth for the gate table, shared by the text and JSON
 * renderers. Named indices below let callers refer to a specific gate
 * without relying on the row order. */
enum {
  GATE_KPTR_RESTRICT = 0,
  GATE_DMESG_RESTRICT,
  GATE_PERF_EVENT_PARANOID,
  GATE_UNPRIVILEGED_BPF,
  GATE_HASHED_POINTERS,
  GATE__COUNT,
};
static const struct sysctl_gate gates[GATE__COUNT] = {
    [GATE_KPTR_RESTRICT] = {"kptr_restrict", "kernel.kptr_restrict", "sysctl",
                            &kasld_env.hardening.kptr_restrict, 1},
    [GATE_DMESG_RESTRICT] = {"dmesg_restrict", "kernel.dmesg_restrict",
                             "sysctl", &kasld_env.hardening.dmesg_restrict, 1},
    [GATE_PERF_EVENT_PARANOID] = {"perf_event_paranoid",
                                  "kernel.perf_event_paranoid", "sysctl",
                                  &kasld_env.hardening.perf_event_paranoid, 2},
    /* 0 = unprivileged bpf() allowed, >=1 disables it (blocks the unprivileged
     * bpf leak components), so the "value >= threshold blocks" model fits with
     * threshold 1. */
    [GATE_UNPRIVILEGED_BPF] = {"unprivileged_bpf_disabled",
                               "kernel.unprivileged_bpf_disabled", "sysctl",
                               &kasld_env.hardening.unprivileged_bpf_disabled,
                               1},
    /* Not a /proc/sys knob — boot-time (no_hash_pointers) — but the same gate
     * plumbing fits: a runtime-readable mitigation that gates %pK address
     * leaks (hashed by default => low-priv readers get an id, not the addr). */
    [GATE_HASHED_POINTERS] = {"hashed_pointers", "kernel pointer hashing (%pK)",
                              "boot_param",
                              &kasld_env.hardening.hashed_pointers, 1},
};
static const int ngates = GATE__COUNT;

static int sysctl_gate_active(const struct sysctl_gate *g) {
  /* value_ptr can be NULL if its load-time relocation was not applied; treat an
   * unreadable gate as inactive rather than dereferencing it. */
  return g->value_ptr && kasld_hardening_known(*g->value_ptr) &&
         *g->value_ptr >= g->threshold;
}

/* Check if a component's sysctl meta matches a given gate */
static int component_has_gate(const struct component_log *cl,
                              const struct sysctl_gate *g) {
  const char *vals[8];
  int nvals = meta_get_all(&cl->meta, "sysctl", vals, 8);
  for (int v = 0; v < nvals; v++) {
    /* meta value is like "dmesg_restrict>=1" — match the name prefix */
    size_t nlen = strlen(g->name);
    if (strncmp(vals[v], g->name, nlen) == 0 && vals[v][nlen] == '>')
      return 1;
  }
  return 0;
}

/* Check if a component has any mitigation key — a known way the leak is gated.
 * "bypass" (a required capability, e.g. bypass:CAP_SYS_ADMIN) counts: a
 * capability-gated leak is mitigated by not granting that capability, so it is
 * not a "no known mitigation" vector even though no sysctl blocks it. */
/* Two disclosure kinds are the same group when both are absent or both name the
 * same thing. An absent kind groups only with other absent ones -- it is not a
 * wildcard, which is how "not physical" once came to mean "virtual". Shared by
 * the two sections that group by disclosure, so they cannot split or order
 * their groups differently. */
static int disclosure_eq(const char *a, const char *b) {
  if (!a || !b)
    return a == b;
  return strcmp(a, b) == 0;
}

static int has_mitigation_keys(const struct component_meta *m) {
  static const char *mitigation_keys[] = {"sysctl", "config",   "patch",
                                          "cve",    "hardware", "lockdown",
                                          "bypass", NULL};
  for (int k = 0; mitigation_keys[k]; k++) {
    if (meta_get(m, mitigation_keys[k]))
      return 1;
  }
  return 0;
}

/* Walk the component logs / scalar facts / sysctl gates once and populate the
 * hardening model. The text/json/markdown renderers below all consume this, so
 * the section-derivation logic lives here only. The collection order matches
 * the source arrays (comp_logs order, gate order) so each renderer's output
 * order is preserved. */
/* Attribute a perf denial to a seccomp filter rather than perf_event_paranoid:
 * the component was access-denied and declares a `perf_event_paranoid>=N` gate,
 * a seccomp filter is active, and the host paranoid value is below N — so
 * paranoid would NOT have blocked it (the filter did). Uses the real host
 * paranoid value because each perf component has its own threshold (>=1 / >=2),
 * finer than the gate's single "active" level. */
static int seccomp_blocked_perf(const struct component_log *cl, int seccomp,
                                int host_paranoid) {
  if (cl->outcome != OUTCOME_ACCESS_DENIED || seccomp <= 0 ||
      !kasld_hardening_known(host_paranoid))
    return 0;
  const char *vals[8];
  int n = meta_get_all(&cl->meta, "sysctl", vals, 8);
  for (int i = 0; i < n; i++) {
    int thr;
    if (sscanf(vals[i], "perf_event_paranoid>=%d", &thr) == 1)
      return host_paranoid < thr;
  }
  return 0;
}

/* True when the component declares at least one sysctl knob and none of them
 * was at a blocking level on this host — so whatever denied it, the knobs it
 * knows about did not.
 *
 * A component declaring no knob returns 0: nothing is known about what should
 * have gated it, so its denial is not attributable. That exclusion keeps an
 * ordinary DAC denial — a file whose mode or group excludes this uid — from
 * being credited to a policy. */
static int declared_sysctl_gates_permit(const struct component_log *cl) {
  const char *vals[8];
  int n = meta_get_all(&cl->meta, "sysctl", vals, 8);
  if (n == 0)
    return 0;
  int checked = 0;
  for (int i = 0; i < n; i++) {
    for (int g = 0; g < ngates; g++) {
      size_t nlen = strlen(gates[g].name);
      if (strncmp(vals[i], gates[g].name, nlen) != 0 || vals[i][nlen] != '>')
        continue;
      int thr;
      if (sscanf(vals[i] + nlen, ">=%d", &thr) != 1)
        continue;
      if (!gates[g].value_ptr)
        return 0;
      /* A knob that is merely absent leaves the denial unexplained, so nothing
       * can be attributed. A knob whose read was REFUSED is different: these
       * files are world-readable, so the refusal is itself the policy acting on
       * this vantage — the knob's value stays unknown, but the mechanism no
       * longer is. */
      if (*gates[g].value_ptr == KASLD_SYSCTL_DENIED) {
        checked++;
        continue;
      }
      if (!kasld_hardening_known(*gates[g].value_ptr))
        return 0;
      if (*gates[g].value_ptr >= thr)
        return 0; /* this knob was blocking — it explains the denial */
      checked++;
    }
  }
  return checked > 0;
}

/* Attribute an access denial to mandatory access control: the component was
 * denied, a MAC policy is enforcing, none of the sysctls it declares was at a
 * blocking level, and a seccomp filter has not already claimed it (a syscall
 * filter is the more specific answer). A denial is credited to the policy only
 * when nothing the component declares explains it; an unobservable LSM is
 * never credited. */
static int mac_blocked(const struct component_log *cl,
                       const struct kasld_vantage *v, int host_paranoid) {
  return cl->outcome == OUTCOME_ACCESS_DENIED &&
         kasld_vantage_mac_enforcing(v) &&
         !seccomp_blocked_perf(cl, v->seccomp, host_paranoid) &&
         declared_sysctl_gates_permit(cl);
}

/* Leave-one-out projection: re-resolve the guaranteed window with every
 * suggestion's silenced leaks removed EXCEPT this one's (i.e. exclude the full
 * hardened union `all` minus this suggestion's set `sub`). The bits forfeited
 * by omitting the suggestion are then (all_vbits - out->vbits). */
static void project_skipping(const char *const *all, int nall,
                             const char *const *sub, int nsub,
                             struct projected_posture *out) {
  const char *ex[MAX_COMPONENTS];
  int n = 0;
  for (int i = 0; i < nall; i++) {
    int in_sub = 0;
    for (int j = 0; j < nsub; j++)
      if (strcmp(all[i], sub[j]) == 0) {
        in_sub = 1;
        break;
      }
    if (!in_sub && n < MAX_COMPONENTS)
      ex[n++] = all[i];
  }
  kasld_project_posture(ex, n, out);
}

void build_hardening_report(struct hardening_report *r) {
  memset(r, 0, sizeof(*r));

  /* Container confinement, for attributing perf denials to seccomp (below).
   * From the snapshot taken before the components ran, so the confinement
   * weighed here is the confinement they ran under. */
  const struct kasld_vantage *vant = &kasld_env.vantage;
  int host_paranoid = kasld_env.hardening.perf_event_paranoid;

  /* Exposure: non-detection components carrying metadata. */
  for (int i = 0; i < num_components; i++) {
    if (!comp_logs[i].ran)
      continue;
    const char *method = meta_get(&comp_logs[i].meta, "method");
    if (!method || strcmp(method, "detection") == 0)
      continue;
    r->total++;
    if (comp_logs[i].outcome == OUTCOME_SUCCESS)
      r->succeeded++;
  }

  /* KASLR posture: collect randomization-failure witnesses (raw origins) and
   * note a deliberate virt opt-out, then resolve the prioritised state
   * (unsupported > disabled > randomization_failed > active). */
  int opt_out = 0;
  for (int i = 0; i < num_scalar_facts; i++) {
    if (scalar_facts[i].value == 0)
      continue;
    if (scalar_facts[i].fact == SF_VIRT_KASLR_RANDOMIZATION_FAILED) {
      if (r->n_rand_detectors < HR_NAME_MAX)
        r->rand_detectors[r->n_rand_detectors++] =
            kasld_origin_name(scalar_facts[i].origin);
    } else if (scalar_facts[i].fact == SF_VIRT_KASLR_DISABLED) {
      opt_out = 1;
    }
  }
  if (!KASLR_SUPPORTED) {
    r->posture = HR_POSTURE_UNSUPPORTED;
    r->slot_entropy_zero = 1;
    r->kernel_at_default = 0;
  } else if (opt_out) {
    r->posture = HR_POSTURE_DISABLED;
    r->slot_entropy_zero = 1;
    r->kernel_at_default = 1;
  } else if (r->n_rand_detectors > 0) {
    r->posture = HR_POSTURE_RANDOMIZATION_FAILED;
    r->slot_entropy_zero = 1;
    r->kernel_at_default = 0;
  } else {
    r->posture = HR_POSTURE_ACTIVE;
    r->slot_entropy_zero = 0;
    r->kernel_at_default = 0;
  }

  /* Kernel-text function ordering: highest-confidence SF_TEXT_ORDER wins
   * (config supersedes the kallsyms heuristic); 0 if neither fired. */
  r->text_order = resolve_text_order(&r->text_order_conf);

  /* Active defenses: one row per readable gate with >= 1 gated component.
   * Full counts and the (capped) name lists are kept separately so text can
   * say "blocked N of M" while json dumps the arrays. */
  for (int g = 0; g < ngates; g++) {
    if (!gates[g].value_ptr || !kasld_hardening_known(*gates[g].value_ptr))
      continue;
    struct hr_gate hg;
    memset(&hg, 0, sizeof(hg));
    hg.display = gates[g].display;
    hg.surface = gates[g].surface;
    hg.value = *gates[g].value_ptr;
    hg.threshold = gates[g].threshold;
    hg.active = sysctl_gate_active(&gates[g]);
    for (int i = 0; i < num_components; i++) {
      if (!comp_logs[i].ran)
        continue;
      if (!component_has_gate(&comp_logs[i], &gates[g]))
        continue;
      hg.gated++;
      if (hg.n_gated_names < HR_NAME_MAX)
        hg.gated_names[hg.n_gated_names++] = comp_logs[i].name;
      if (comp_logs[i].outcome == OUTCOME_ACCESS_DENIED &&
          !(g == GATE_PERF_EVENT_PARANOID &&
            seccomp_blocked_perf(&comp_logs[i], vant->seccomp,
                                 host_paranoid)) &&
          !mac_blocked(&comp_logs[i], vant, host_paranoid)) {
        /* Credit a knob only when it actually blocked the component. A
         * seccomp-blocked perf denial goes to the seccomp gate below, and a
         * denial no declared knob explains goes to the MAC gate, rather than
         * either being blamed on a knob that was not at a blocking level. */
        hg.blocked++;
        if (hg.n_blocked_names < HR_NAME_MAX)
          hg.blocked_names[hg.n_blocked_names++] = comp_logs[i].name;
      } else if (comp_logs[i].outcome == OUTCOME_SUCCESS) {
        hg.bypassed++;
        if (hg.n_bypassed_names < HR_NAME_MAX)
          hg.bypassed_names[hg.n_bypassed_names++] = comp_logs[i].name;
        if (meta_get(&comp_logs[i].meta, "fallback")) {
          hg.fallback++;
        } else if (hg.n_silenced < HR_NAME_MAX) {
          /* No fallback source, so enabling the gate actually removes this leak
           * — the exclude set for the counterfactual projection. */
          hg.silenced_names[hg.n_silenced++] = comp_logs[i].name;
        }
      }
    }
    if (hg.gated == 0)
      continue;
    if (r->n_gates < HR_GATES_MAX)
      r->gates[r->n_gates++] = hg;
  }

  /* Seccomp: credit the syscall filter for each perf component it (not a
   * permissive perf_event_paranoid) blocked — the honest "what blocked this
   * here" that the report otherwise lacks. Raising perf_event_paranoid stays a
   * valid *host*-hardening suggestion; only the current-run attribution was
   * wrong. Such a component is still counted in the paranoid gate's `gated`
   * total (so the "set perf_event_paranoid=2" impact includes it) — intended:
   * on the host, raising paranoid would also block it. It is only omitted from
   * the paranoid gate's *blocked* credit (above), so no component is double-
   * counted as blocked. */
  if (vant->seccomp > 0) {
    struct hr_gate sg;
    memset(&sg, 0, sizeof(sg));
    sg.display = "seccomp syscall filter";
    sg.surface = "seccomp";
    sg.active = 1;
    sg.value = vant->seccomp;
    for (int i = 0; i < num_components; i++) {
      if (!comp_logs[i].ran)
        continue;
      if (!seccomp_blocked_perf(&comp_logs[i], vant->seccomp, host_paranoid))
        continue;
      sg.gated++;
      sg.blocked++;
      if (sg.n_gated_names < HR_NAME_MAX)
        sg.gated_names[sg.n_gated_names++] = comp_logs[i].name;
      if (sg.n_blocked_names < HR_NAME_MAX)
        sg.blocked_names[sg.n_blocked_names++] = comp_logs[i].name;
    }
    if (sg.gated > 0 && r->n_gates < HR_GATES_MAX)
      r->gates[r->n_gates++] = sg;
  }

  /* Mandatory access control, on the same synthetic-gate footing as seccomp.
   * Its members are exactly the denials no declared sysctl accounts for, so
   * `gated` and `blocked` are the same set: the report claims a policy denial
   * only where it can rule the alternatives out. */
  if (kasld_vantage_mac_enforcing(vant)) {
    struct hr_gate mg;
    memset(&mg, 0, sizeof(mg));
    mg.display = vant->selinux == SELINUX_ENFORCING ? "SELinux policy"
                                                    : "AppArmor profile";
    mg.surface = HR_SURFACE_MAC;
    mg.active = 1;
    mg.value = 1;
    for (int i = 0; i < num_components; i++) {
      if (!comp_logs[i].ran)
        continue;
      if (!mac_blocked(&comp_logs[i], vant, host_paranoid))
        continue;
      mg.gated++;
      mg.blocked++;
      if (mg.n_gated_names < HR_NAME_MAX)
        mg.gated_names[mg.n_gated_names++] = comp_logs[i].name;
      if (mg.n_blocked_names < HR_NAME_MAX)
        mg.blocked_names[mg.n_blocked_names++] = comp_logs[i].name;
    }
    if (mg.gated > 0 && r->n_gates < HR_GATES_MAX)
      r->gates[r->n_gates++] = mg;
  }

  r->lockdown = kasld_env.hardening.lockdown;

  /* Available hardening. Gate suggestions (inactive gate with gated
   * components), the lockdown suggestion, and the dmesg-fallback suggestion.
   *
   * Projected posture uses a leave-one-out framing: first resolve the
   * current posture and the fully-hardened ceiling (every suggestion's leaks
   * removed), then re-resolve for each suggestion with all-but-itself removed.
   * The bits it is worth are (all_vbits - skip_vbits) — how much of the fully-
   * hardened entropy is forfeited by omitting it. This exposes leaks that are
   * masked by another (a marginal-from-current delta would read them as 0). */
  {
    struct projected_posture cur;
    kasld_project_posture(NULL, 0, &cur);
    if (cur.available) {
      r->has_projection = 1;
      r->cur_vbits = cur.vbits;
      r->cur_pbits = cur.pbits;
    }
  }

  /* Each suggestion's silenced set is accumulated into the hardened union `all`
   * (deduped below); the lockdown/dmesg sets are kept for the leave-one-out
   * pass. All sets are bounded by the component count. */
  /* Only the first nall entries carry a name, and only the first nuniq of those
   * survive the dedup below -- but the whole array is handed to
   * kasld_project_posture as a pointer, where the count is the only thing
   * bounding the read. Defined in full so the call is well-formed at any count,
   * including the empty one. */
  const char *all[MAX_COMPONENTS] = {0};
  int nall = 0;
  const char *ld_sil[MAX_COMPONENTS];
  int n_ld = 0;
  const char *dm_sil[MAX_COMPONENTS];
  int n_dm = 0;

  for (int i = 0; i < r->n_gates; i++) {
    if (r->gates[i].active)
      continue;
    if (r->n_gate_suggestions < HR_SUGG_MAX) {
      struct hr_suggestion *sg = &r->gate_suggestions[r->n_gate_suggestions++];
      sg->display = r->gates[i].display;
      sg->surface = r->gates[i].surface;
      sg->threshold = r->gates[i].threshold;
      sg->impact = r->gates[i].gated;
      sg->silences = r->gates[i].n_silenced;
    }
    for (int k = 0; k < r->gates[i].n_silenced; k++)
      if (nall < MAX_COMPONENTS)
        all[nall++] = r->gates[i].silenced_names[k];
  }

  /* Lockdown suggestion. A lockdown-gated leak reads a kernel-memory interface
   * kernel lockdown closes, such as /proc/kcore (LOCKDOWN_KCORE, a
   * confidentiality-level restriction). Recommend the strongest mode the gated
   * leaks require, from the level each declares -- so the mode and the impact
   * count below rest on the same set, and a gated leak that ran without
   * succeeding still names the mode that would close it. */
  if (kasld_env.hardening.lockdown < LOCKDOWN_INTEGRITY) {
    int lockdown_gated = 0;
    int suggest_mode = LOCKDOWN_INTEGRITY;
    for (int i = 0; i < num_components; i++) {
      if (!comp_logs[i].ran)
        continue;
      const char *ld = meta_get(&comp_logs[i].meta, "lockdown");
      if (!ld)
        continue;
      lockdown_gated++;
      if (strcmp(ld, "confidentiality") == 0)
        suggest_mode = LOCKDOWN_CONFIDENTIALITY;
      if (comp_logs[i].outcome == OUTCOME_SUCCESS &&
          !meta_get(&comp_logs[i].meta, "fallback") && n_ld < MAX_COMPONENTS)
        ld_sil[n_ld++] = comp_logs[i].name;
    }
    if (lockdown_gated > 0) {
      r->suggest_lockdown = 1;
      r->lockdown_suggest_mode = suggest_mode;
      r->lockdown_impact = lockdown_gated;
      r->lockdown_silences = n_ld;
      for (int k = 0; k < n_ld; k++)
        if (nall < MAX_COMPONENTS)
          all[nall++] = ld_sil[k];
    }
  }

  /* dmesg-fallback suggestion. It silences exactly the dmesg leaks that
   * succeeded VIA a fallback log file — restricting those files to root removes
   * them (the sysctl itself already blocks the syscall path). */
  if (kasld_env.hardening.dmesg_restrict >= 1) {
    for (int i = 0; i < num_components; i++) {
      if (!comp_logs[i].ran)
        continue;
      if (comp_logs[i].outcome != OUTCOME_SUCCESS)
        continue;
      if (!component_has_gate(&comp_logs[i], &gates[GATE_DMESG_RESTRICT]))
        continue;
      if (!meta_get(&comp_logs[i].meta, "fallback"))
        continue;
      if (n_dm < MAX_COMPONENTS)
        dm_sil[n_dm++] = comp_logs[i].name;
    }
    if (n_dm > 0) {
      r->suggest_dmesg_fallback = 1;
      r->dmesg_fallback_count = n_dm;
      r->dmesg_fallback_silences = n_dm;
      for (int k = 0; k < n_dm; k++)
        if (nall < MAX_COMPONENTS)
          all[nall++] = dm_sil[k];
    }
  }

  /* Ceiling posture: re-resolve with the deduped union of every suggestion's
   * silenced set removed at once. */
  int nuniq = 0;
  if (r->has_projection) {
    for (int i = 0; i < nall; i++) {
      int dup = 0;
      for (int m = 0; m < nuniq; m++)
        if (strcmp(all[m], all[i]) == 0) {
          dup = 1;
          break;
        }
      if (!dup)
        all[nuniq++] = all[i];
    }
    struct projected_posture pa;
    kasld_project_posture(all, nuniq, &pa);
    if (pa.available) {
      r->all_vbits = pa.vbits;
      r->all_pbits = pa.pbits;
      r->all_impact = nuniq;
    }
  }

  /* Leave-one-out pass: for each suggestion, the posture with all OTHER
   * suggestions applied. skip_vbits < all_vbits means this suggestion is
   * load-bearing (its leaks are not fully covered by the rest). */
  if (r->has_projection) {
    int k = 0; /* gate_suggestions[] are the inactive gates, in order */
    for (int i = 0; i < r->n_gates && k < r->n_gate_suggestions; i++) {
      if (r->gates[i].active)
        continue;
      struct hr_suggestion *sg = &r->gate_suggestions[k++];
      struct projected_posture pp;
      project_skipping(all, nuniq, r->gates[i].silenced_names,
                       r->gates[i].n_silenced, &pp);
      if (pp.available) {
        sg->has_projection = 1;
        sg->skip_vbits = pp.vbits;
        sg->skip_pbits = pp.pbits;
      }
    }
    if (r->suggest_lockdown) {
      struct projected_posture pp;
      project_skipping(all, nuniq, ld_sil, n_ld, &pp);
      if (pp.available) {
        r->lockdown_has_projection = 1;
        r->lockdown_skip_vbits = pp.vbits;
        r->lockdown_skip_pbits = pp.pbits;
      }
    }
    if (r->suggest_dmesg_fallback) {
      struct projected_posture pp;
      project_skipping(all, nuniq, dm_sil, n_dm, &pp);
      if (pp.available) {
        r->dmesg_fallback_has_projection = 1;
        r->dmesg_fallback_skip_vbits = pp.vbits;
        r->dmesg_fallback_skip_pbits = pp.pbits;
      }
    }

    /* Rank the gate suggestions by their leave-one-out forfeit (all_vbits -
     * skip_vbits) so Available hardening reads as a prioritised plan — the most
     * load-bearing fix first. Effort is uniform across the sysctl gates (all
     * runtime), so bits alone order them. Stable insertion sort (equal forfeits
     * keep gate-table order); n <= HR_SUGG_MAX. */
    for (int i = 1; i < r->n_gate_suggestions; i++) {
      struct hr_suggestion key = r->gate_suggestions[i];
      int key_forfeit = r->all_vbits - key.skip_vbits;
      int j = i - 1;
      while (j >= 0 &&
             r->all_vbits - r->gate_suggestions[j].skip_vbits < key_forfeit) {
        r->gate_suggestions[j + 1] = r->gate_suggestions[j];
        j--;
      }
      r->gate_suggestions[j + 1] = key;
    }
  }

  /* Patched vulnerabilities: total vuln-tagged components + the succeeded
   * (possibly unpatched) subset. */
  for (int i = 0; i < num_components; i++) {
    if (!comp_logs[i].ran)
      continue;
    const char *patch = meta_get(&comp_logs[i].meta, "patch");
    const char *cve = meta_get(&comp_logs[i].meta, "cve");
    if (!patch && !cve)
      continue;
    r->vuln_total++;
    if (comp_logs[i].outcome == OUTCOME_SUCCESS && r->n_vulns < HR_VULNS_MAX) {
      r->vulns[r->n_vulns].name = comp_logs[i].name;
      r->vulns[r->n_vulns].cve = cve;
      r->vulns[r->n_vulns].patch = patch;
      r->n_vulns++;
    }
  }

  /* Compile-time attack surface: succeeded components with config= keys. */
  for (int i = 0; i < num_components; i++) {
    if (!comp_logs[i].ran)
      continue;
    if (comp_logs[i].outcome != OUTCOME_SUCCESS)
      continue;
    const char *configs[4];
    int ncfg = meta_get_all(&comp_logs[i].meta, "config", configs, 4);
    if (ncfg == 0)
      continue;
    /* Observed only. The loop above already skipped everything that is not
     * OUTCOME_SUCCESS, and that outcome means the component emitted a record
     * the orchestrator attributed to it -- so there is always something to
     * read here and a `discloses:` fallback could never fire. NULL remains
     * possible in the type and the renderers handle it, rather than the report
     * depending on two loops agreeing forever. */
    const char *d = component_disclosed(i);
    for (int j = 0; j < ncfg && r->n_surface < HR_SURFACE_MAX; j++) {
      r->surface[r->n_surface].name = comp_logs[i].name;
      r->surface[r->n_surface].config = configs[j];
      r->surface[r->n_surface].discloses = d;
      r->n_surface++;
    }
  }

  /* Hardware side-channels: non-detection components with a hardware= key. */
  for (int i = 0; i < num_components; i++) {
    if (!comp_logs[i].ran)
      continue;
    const char *hw = meta_get(&comp_logs[i].meta, "hardware");
    if (!hw)
      continue;
    const char *method = meta_get(&comp_logs[i].meta, "method");
    if (!method || strcmp(method, "detection") == 0)
      continue;
    if (r->n_hw < HR_HW_MAX) {
      r->hw[r->n_hw].name = comp_logs[i].name;
      r->hw[r->n_hw].hardware = hw;
      {
        const char *hd = component_disclosed(i);
        if (!hd)
          hd = disclosure_descr(meta_get(&comp_logs[i].meta, "discloses"));
        r->hw[r->n_hw].discloses = hd;
      }
      r->hw[r->n_hw].succeeded = (comp_logs[i].outcome == OUTCOME_SUCCESS);
      r->n_hw++;
      if (comp_logs[i].outcome == OUTCOME_SUCCESS)
        r->hw_succeeded++;
    }
  }

  /* No known mitigation: succeeded non-detection components with no
   * mitigation key. */
  for (int i = 0; i < num_components; i++) {
    if (!comp_logs[i].ran)
      continue;
    if (comp_logs[i].outcome != OUTCOME_SUCCESS)
      continue;
    const char *method = meta_get(&comp_logs[i].meta, "method");
    if (!method || strcmp(method, "detection") == 0)
      continue;
    if (has_mitigation_keys(&comp_logs[i].meta))
      continue;
    if (r->n_nomit < HR_NOMIT_MAX) {
      r->nomit[r->n_nomit].name = comp_logs[i].name;
      /* Every component reaching here is OUTCOME_SUCCESS, so it disclosed
       * something the orchestrator parsed and attributed. Read the kind off
       * those records rather than off the component's own `addr:` claim, which
       * is optional and unvalidated: a missing one rendered as the section
       * heading repeated back ("no mitigation"), and `addr:none` rendered as
       * "leaks none addresses". */
      r->nomit[r->n_nomit].discloses = component_disclosed(i);
      r->n_nomit++;
    }
  }

  /* Confirmed active mitigations: controls a component observed to foil its
   * leak this run (a `mitigation` disposition). Runtime observation, not the
   * static "this leak could be gated by X" inference the sysctl gates and meta
   * carry. */
  for (int i = 0; i < num_components && r->n_confirmed < HR_NAME_MAX; i++) {
    if (!comp_logs[i].ran)
      continue;
    const struct component_disposition *d = &comp_logs[i].disposition;
    if (d->category != DISP_MITIGATION)
      continue;
    r->confirmed[r->n_confirmed].component = comp_logs[i].name;
    r->confirmed[r->n_confirmed].gate = d->gate;
    r->confirmed[r->n_confirmed].message = d->message[0] ? d->message : NULL;
    r->n_confirmed++;
  }
}

/* Kernel-text function-ordering labels (shared by the text/json renderers). */
static const char *text_order_label(enum kasld_text_order o) {
  switch (o) {
  case TEXT_ORDER_CANONICAL:
    return "canonical";
  case TEXT_ORDER_STATIC:
    return "reordered (static)";
  case TEXT_ORDER_DYNAMIC:
    return "reordered (per-boot)";
  default:
    return "unknown";
  }
}
/* The actionable consequence: whether a System.map resolves symbols from the
 * KASLR slide, and which map. This is what extra/ksymoff keys on. */
static const char *symbol_resolution_label(enum kasld_text_order o) {
  switch (o) {
  case TEXT_ORDER_CANONICAL:
    return "generic System.map OK";
  case TEXT_ORDER_STATIC:
    return "needs this build's System.map";
  case TEXT_ORDER_DYNAMIC:
    return "no static System.map resolves (one leak pins one symbol)";
  default:
    return "unknown";
  }
}
/* Provenance from the resolved confidence: config is definitive, the kallsyms
 * heuristic is the config-locked fallback. */
static const char *text_order_source(enum kasld_confidence c) {
  return c == CONF_HEURISTIC ? "kallsyms heuristic" : "config";
}
/* JSON-token forms of the two facts (machine consumers / extra/ksymoff). */
static const char *text_order_json_class(enum kasld_text_order o) {
  switch (o) {
  case TEXT_ORDER_CANONICAL:
    return "canonical";
  case TEXT_ORDER_STATIC:
    return "reordered_static";
  case TEXT_ORDER_DYNAMIC:
    return "reordered_dynamic";
  default:
    return "unknown";
  }
}
static const char *symbol_resolution_json(enum kasld_text_order o) {
  switch (o) {
  case TEXT_ORDER_CANONICAL:
    return "generic_ok";
  case TEXT_ORDER_STATIC:
    return "exact_build_only";
  case TEXT_ORDER_DYNAMIC:
    return "none";
  default:
    return "unknown";
  }
}

/* One suggestion's leave-one-out verdict row, indented under it. `silences` is
 * how many base-leaks it removes; skip_* is the posture with every OTHER
 * suggestion applied, so all_* - skip_* is the entropy forfeited by omitting
 * it. `exposure` is set when the guaranteed base is recoverable at all (all_*
 * beats the current posture) — when it is not, a forfeit of 0 means the
 * silenced leaks are speculative-window only, not that another change covers
 * them. */
static void print_necessity(int silences, int exposure, int all_v, int skip_v,
                            int all_p, int skip_p) {
  int fv = all_v - skip_v, fp = all_p - skip_p;
  if (silences == 0) {
    printf("    no base-leak behind this - recovers nothing\n");
  } else if (fv > 0 || fp > 0) {
    if (fp > 0 && fv > 0)
      printf(
          "    load-bearing - omitting forfeits %d bits virtual, %d physical\n",
          fv, fp);
    else
      printf("    load-bearing - omitting forfeits %d %s bits\n",
             fv > 0 ? fv : fp, fv > 0 ? "virtual" : "physical");
  } else if (!exposure) {
    printf("    silences %d leak%s - speculative window only, no guaranteed "
           "bits\n",
           silences, silences == 1 ? "" : "s");
  } else {
    printf("    silences %d leak%s but 0 guaranteed bits - not required (the "
           "rest reach the same posture)\n",
           silences, silences == 1 ? "" : "s");
  }
}

/* Emit the JSON "projected" object for one suggestion in the leave-one-out
 * framing: the posture with every other suggestion applied (skip_*), and the
 * bits forfeited by omitting this one (all_* - skip_*). Trailing content only,
 * so the caller adds the preceding comma. */
static void json_print_projected(int silences, int all_v, int skip_v, int all_p,
                                 int skip_p) {
  printf("        \"silences\": %d,\n", silences);
  printf("        \"projected\": {\n");
  printf("          \"virt_base_entropy_if_omitted_bits\": %d,\n", skip_v);
  printf("          \"virt_base_entropy_forfeited\": %d,\n", all_v - skip_v);
  printf("          \"phys_base_entropy_if_omitted_bits\": %d,\n", skip_p);
  printf("          \"phys_base_entropy_forfeited\": %d\n", all_p - skip_p);
  printf("        }\n");
}

/* Markdown single-line leave-one-out verdict clause appended to a suggestion
 * bullet (no leading separator for the "recovers nothing" case, which reads as
 * a dash continuation). */
static void md_print_necessity(int silences, int exposure, int all_v,
                               int skip_v, int all_p, int skip_p) {
  int fv = all_v - skip_v, fp = all_p - skip_p;
  if (silences == 0)
    printf(" - recovers nothing (no base-leak behind it)");
  else if (fv > 0 || fp > 0)
    printf("; load-bearing - omitting forfeits %d %s bits", fv > 0 ? fv : fp,
           fv > 0 ? "virtual" : "physical");
  else if (!exposure)
    printf("; speculative window only (no guaranteed bits)");
  else
    printf(
        "; 0 guaranteed bits (not required - the rest reach the same posture)");
}

void render_hardening_text(void) {
  printf("\n%s========================================%s\n", c(C_BOLD),
         c(C_RESET));
  printf("%s Hardening Assessment%s\n", c(C_BOLD), c(C_RESET));
  printf("%s========================================%s\n\n", c(C_BOLD),
         c(C_RESET));

  struct hardening_report rep;
  build_hardening_report(&rep);

  printf("Hardening assessment: %s%d of %d%s leak techniques succeeded "
         "against current defenses.\n\n",
         rep.succeeded > 0 ? c(C_YELLOW) : c(C_GREEN), rep.succeeded, rep.total,
         c(C_RESET));

  /* Confirmed active mitigations: controls a component observed to defeat its
   * leak this run (mitigation dispositions). Positive posture — printed only
   * when present, keyed by the confirmed control. */
  if (rep.n_confirmed > 0) {
    printf("%sConfirmed active mitigations%s (observed to defeat a leak):\n",
           c(C_BOLD), c(C_RESET));
    for (int i = 0; i < rep.n_confirmed; i++) {
      printf("  %s%s%s — %s", c(C_YELLOW), rep.confirmed[i].gate, c(C_RESET),
             rep.confirmed[i].component);
      if (rep.confirmed[i].message)
        printf(" %s(%s)%s", c(C_DIM), rep.confirmed[i].message, c(C_RESET));
      printf("\n");
    }
    printf("\n");
  }

  /* ---- Section 0: KASLR posture downgrade ----
   *
   * Surfaces SF_VIRT_KASLR_RANDOMIZATION_FAILED: the kernel attempted
   * virtual KASLR at boot but could not produce a random offset (no
   * entropy seed, no PRNG, insufficient memory). The boot stub still
   * relocated the image but skipped the random component, leaving the
   * kernel at a firmware-/boot-stub-deterministic virt position.
   * Effective KASLR slot entropy is 0 bits — same address on every
   * boot of this (firmware, kernel build, hardware) tuple. The banner
   * fires whenever any witness reported the failure (build_hardening_report
   * collects them into rep.rand_detectors), independent of the prioritised
   * posture state json reports. Distinct from SF_VIRT_KASLR_DISABLED
   * (deliberate opt-out → kernel at link-time default), shown by the main
   * results banner. */
  if (rep.n_rand_detectors > 0) {
    printf("%sKASLR posture:%s\n", c(C_BOLD), c(C_RESET));
    printf("  %s** KASLR randomization failed - random offset not applied "
           "at boot **%s\n",
           c(C_YELLOW), c(C_RESET));
    printf("  Detected by:\n");
    for (int i = 0; i < rep.n_rand_detectors; i++)
      printf("    %s\n",
             rep.rand_detectors[i][0] ? rep.rand_detectors[i] : "(unknown)");
    printf("  Effective KASLR slot entropy: %s0 bits%s "
           "(kernel at firmware-determined position).\n",
           c(C_YELLOW), c(C_RESET));
    printf("  %sNote: the kernel is NOT at the link-time default. The "
           "position is deterministic per (firmware, kernel build, "
           "hardware) - an operator with a previously-captured slide on "
           "this machine can re-use it on subsequent boots without "
           "re-leaking.%s\n",
           c(C_DIM), c(C_RESET));
    printf("\n");
  }

  /* Kernel-text function ordering + what it means for symbol resolution.
   * Shown only when determined; absence means "be conservative". */
  if (rep.text_order) {
    printf("%sFunction layout:%s\n", c(C_BOLD), c(C_RESET));
    printf("  text ordering:      %-30s [%s]\n",
           text_order_label(rep.text_order),
           text_order_source(rep.text_order_conf));
    printf("  symbol resolution:  %s\n",
           symbol_resolution_label(rep.text_order));
    printf("\n");
  }

  /* ---- Section 1: Active Defenses ---- */
  printf("%sActive defenses:%s\n", c(C_BOLD), c(C_RESET));

  int any_active = 0;

  for (int gi = 0; gi < rep.n_gates; gi++) {
    const struct hr_gate *hg = &rep.gates[gi];
    int blocked = hg->blocked, bypassed = hg->bypassed, gated = hg->gated;
    int nfallback = hg->fallback;

    if (hg->active) {
      any_active = 1;
      /* Active but every gated component still leaked = the control is set yet
       * fully circumvented (e.g. dmesg_restrict on, but the logs are readable
       * as files). Mark it ⚠, not ✓. */
      int circumvented = (blocked == 0 && bypassed > 0);
      /* Sysctl gates show "= N" (the knob value vs its threshold); the
       * synthetic seccomp gate has no such level (threshold 0) so its value
       * column is blank rather than a meaningless mode number. */
      char vcol[12];
      if (hg->threshold > 0)
        snprintf(vcol, sizeof(vcol), "= %-4d", hg->value);
      else
        snprintf(vcol, sizeof(vcol), "%-6s", "");
      printf("  %-34s %s %s%s%s  ", hg->display, vcol,
             circumvented ? c(C_YELLOW) : c(C_GREEN),
             circumvented ? GLYPH_WARN : GLYPH_OK, c(C_RESET));
      if (blocked > 0 && blocked <= 5) {
        printf("blocked ");
        for (int n = 0; n < hg->n_blocked_names; n++) {
          if (n > 0)
            printf(", ");
          printf("%s", hg->blocked_names[n]);
        }
      } else if (blocked > 0) {
        printf("blocked %d of %d gated components", blocked, gated);
      }
      if (bypassed > 0) {
        if (blocked > 0)
          printf("; ");
        if (nfallback == bypassed)
          printf("%d bypassed via fallback files", bypassed);
        else if (nfallback > 0)
          printf("%d bypassed (%d via fallback files)", bypassed, nfallback);
        else
          printf("%d bypassed", bypassed);
      }
      if (blocked == 0 && bypassed == 0)
        printf("%d gated component%s", gated, gated == 1 ? "" : "s");
      printf("\n");
    } else if (bypassed > 0) {
      /* Permissive gate actively bypassed — the most actionable exposure, so
       * surface it here (as lockdown is shown even when inactive) rather than
       * silently omit it. */
      any_active = 1;
      printf("  %-34s = %-4d %s%s%s  permissive - ", hg->display, hg->value,
             c(C_YELLOW), GLYPH_FAIL, c(C_RESET));
      if (hg->n_bypassed_names > 0 && bypassed <= 5) {
        for (int n = 0; n < hg->n_bypassed_names; n++) {
          if (n > 0)
            printf(", ");
          printf("%s", hg->bypassed_names[n]);
        }
        printf(" leak%s", bypassed == 1 ? "s" : "");
      } else {
        printf("%d component%s leak", bypassed, bypassed == 1 ? "" : "s");
      }
      printf(" (set >= %d)\n", hg->threshold);
    }
  }

  /* Lockdown status */
  const char *lockdown_str = NULL;
  switch (rep.lockdown) {
  case LOCKDOWN_INTEGRITY:
    lockdown_str = "integrity";
    break;
  case LOCKDOWN_CONFIDENTIALITY:
    lockdown_str = "confidentiality";
    break;
  default:
    break;
  }
  if (lockdown_str) {
    any_active = 1;
    printf("  %-34s        %s%s%s  %s mode\n", "Kernel lockdown", c(C_GREEN),
           GLYPH_OK, c(C_RESET), lockdown_str);
  } else {
    printf("  %-34s        %s%s%s  inactive\n", "Kernel lockdown", c(C_DIM),
           GLYPH_FAIL, c(C_RESET));
  }

  if (!any_active)
    printf("  %s(no active runtime defenses)%s\n", c(C_DIM), c(C_RESET));

  printf("\n");

  /* ---- Section 2: Available Hardening ---- */
  printf("%sAvailable hardening:%s\n", c(C_BOLD), c(C_RESET));

  /* Anchor: the current vs fully-hardened guaranteed posture. Each suggestion
   * below is then scored by how much of that gap it is load-bearing for (its
   * leave-one-out forfeit), not a marginal-from-here delta. `exposure` is set
   * when hardening can recover any guaranteed bits at all. */
  int exposure = rep.all_vbits > rep.cur_vbits || rep.all_pbits > rep.cur_pbits;
  if (rep.has_projection && exposure)
    printf("  %sbase recoverable: %d bits now %s %d bits with all of "
           "the "
           "below applied%s\n",
           c(C_DIM), rep.cur_vbits, GLYPH_ARROW, rep.all_vbits, c(C_RESET));
  else if (rep.has_projection)
    printf("  %sguaranteed base already at %d bits; the below silence "
           "speculative-only leaks%s\n",
           c(C_DIM), rep.cur_vbits, c(C_RESET));

  int any_suggestions = 0;

  for (int i = 0; i < rep.n_gate_suggestions; i++) {
    any_suggestions = 1;
    /* Enforcement surface trails the action, so a reader routes the change to
     * the lever it lives on (a sysctl differs from a boot parameter). */
    printf("  %s%s%s Set %s = %d", c(C_CYAN), GLYPH_ARROW, c(C_RESET),
           rep.gate_suggestions[i].display, rep.gate_suggestions[i].threshold);
    if (rep.gate_suggestions[i].surface)
      printf("  [%s]", rep.gate_suggestions[i].surface);
    printf("\n");
    printf("    affects %d component%s\n", rep.gate_suggestions[i].impact,
           rep.gate_suggestions[i].impact == 1 ? "" : "s");
    if (rep.gate_suggestions[i].has_projection)
      print_necessity(rep.gate_suggestions[i].silences, exposure, rep.all_vbits,
                      rep.gate_suggestions[i].skip_vbits, rep.all_pbits,
                      rep.gate_suggestions[i].skip_pbits);
  }

  if (rep.suggest_lockdown) {
    any_suggestions = 1;
    printf("  %s%s%s Enable kernel lockdown (%s mode)  [%s]\n", c(C_CYAN),
           GLYPH_ARROW, c(C_RESET),
           rep.lockdown_suggest_mode >= LOCKDOWN_CONFIDENTIALITY
               ? "confidentiality"
               : "integrity",
           HR_SURFACE_LOCKDOWN);
    printf("    blocks the kernel-memory interfaces these leaks read\n");
    if (rep.lockdown_has_projection)
      print_necessity(rep.lockdown_silences, exposure, rep.all_vbits,
                      rep.lockdown_skip_vbits, rep.all_pbits,
                      rep.lockdown_skip_pbits);
  }

  if (rep.suggest_dmesg_fallback) {
    any_suggestions = 1;
    printf("  %s%s%s Restrict dmesg fallback files to root  [%s]\n", c(C_CYAN),
           GLYPH_ARROW, c(C_RESET), HR_SURFACE_DMESG_FALLBACK);
    printf("    %d dmesg component%s may have succeeded via log files\n",
           rep.dmesg_fallback_count, rep.dmesg_fallback_count == 1 ? "" : "s");
    if (rep.dmesg_fallback_has_projection)
      print_necessity(rep.dmesg_fallback_silences, exposure, rep.all_vbits,
                      rep.dmesg_fallback_skip_vbits, rep.all_pbits,
                      rep.dmesg_fallback_skip_pbits);
  }

  if (!any_suggestions)
    printf("  All available runtime hardening is active.\n");

  printf("\n");

  /* ---- Section 3: Patched Vulnerabilities ---- */
  printf("%sPatched vulnerabilities:%s\n", c(C_BOLD), c(C_RESET));

  if (rep.vuln_total == 0) {
    printf("  No vulnerability-based components in metadata.\n");
  } else {
    printf("  %d of %d vulnerability-based components did not leak "
           "(likely patched or blocked).\n",
           rep.vuln_total - rep.n_vulns, rep.vuln_total);
    if (rep.n_vulns > 0) {
      printf("  %s%d component%s succeeded%s - kernel may lack fixes for:\n",
             c(C_YELLOW), rep.n_vulns, rep.n_vulns == 1 ? "" : "s", c(C_RESET));
      for (int i = 0; i < rep.n_vulns; i++) {
        printf("    %s", rep.vulns[i].name);
        if (rep.vulns[i].cve)
          printf(" (%s", rep.vulns[i].cve);
        if (rep.vulns[i].patch)
          printf("%sfixed %s", rep.vulns[i].cve ? ", " : "(",
                 rep.vulns[i].patch);
        if (rep.vulns[i].cve || rep.vulns[i].patch)
          printf(")");
        printf("\n");
      }
    }
  }

  printf("\n");

  /* ---- Section 4: Compile-Time Attack Surface ---- */
  printf("%sCompile-time attack surface:%s\n", c(C_BOLD), c(C_RESET));

  if (rep.n_surface == 0) {
    printf("  No compile-time surface exposed.\n");
  } else {
    /* Group by what the components disclose, one heading per distinct kind in
     * first-appearance order. The split used to be "physical, or else virtual",
     * which put a component that disclosed no address -- or declared nothing at
     * all -- in the virtual bucket and told the operator it leaked virtual
     * addresses. A kind nothing states is now its own group, named as unstated
     * rather than folded into one of the others. */
    const char *kinds[HR_SURFACE_MAX];
    int nkinds = 0, phys_count = 0;
    for (int i = 0; i < rep.n_surface; i++) {
      const char *d = rep.surface[i].discloses;
      int seen = 0;
      for (int k = 0; k < nkinds; k++)
        if (disclosure_eq(kinds[k], d)) {
          seen = 1;
          break;
        }
      if (!seen && nkinds < HR_SURFACE_MAX)
        kinds[nkinds++] = d;
      /* Exact, as the physical/virtual split was before: this gates the note
       * about physical addresses ALONE, so a component disclosing both is not
       * one of them. A substring test would count it. */
      if (d && strcmp(d, DISCLOSE_PHYS) == 0)
        phys_count++;
    }
    for (int k = 0; k < nkinds; k++) {
      int n = 0;
      for (int i = 0; i < rep.n_surface; i++)
        if (disclosure_eq(kinds[k], rep.surface[i].discloses))
          n++;
      if (kinds[k])
        printf("  %d component%s disclose%s %s via compiled-in features:\n", n,
               n == 1 ? "" : "s", n == 1 ? "s" : "", kinds[k]);
      else
        printf("  %d component%s do%s not state what they disclose, via "
               "compiled-in features:\n",
               n, n == 1 ? "" : "s", n == 1 ? "es" : "");
      for (int i = 0; i < rep.n_surface; i++)
        if (disclosure_eq(kinds[k], rep.surface[i].discloses))
          printf("    %-28s %s\n", rep.surface[i].name, rep.surface[i].config);
    }
    if (phys_count > 0 && sizeof(unsigned long) >= 8)
      printf("  %sNote: on 64-bit architectures with decoupled KASLR, "
             "physical addresses alone cannot derive the kernel virtual text "
             "base.%s\n",
             c(C_DIM), c(C_RESET));
  }

  printf("\n");

  /* ---- Section 5: Hardware Side-Channels ---- */
  printf("%sHardware side-channels:%s\n", c(C_BOLD), c(C_RESET));

  if (rep.n_hw == 0) {
    printf("  No hardware-mitigated components.\n");
  } else if (rep.hw_succeeded == 0) {
    printf("  %d hardware-gated component%s did not succeed (CPU mitigations "
           "active or attack not applicable).\n",
           rep.n_hw, rep.n_hw == 1 ? "" : "s");
  } else {
    printf("  %s%d of %d%s hardware-gated components succeeded:\n", c(C_YELLOW),
           rep.hw_succeeded, rep.n_hw, c(C_RESET));
    for (int i = 0; i < rep.n_hw; i++) {
      if (!rep.hw[i].succeeded)
        continue;
      /* Lead with the technique and what it leaks; the hardware field is the
       * requirement (e.g. "TSX required", "prefetch side-channel (mitigated by
       * KPTI)"), labelled so it does not read as the subject that leaks. */
      printf("    %-28s ", rep.hw[i].name);
      if (rep.hw[i].discloses)
        printf("discloses %s; ", rep.hw[i].discloses);
      printf("hardware: %s\n", rep.hw[i].hardware);
    }
    if (rep.hw_succeeded < rep.n_hw) {
      printf("  %d of %d hardware-gated component%s did not succeed.\n",
             rep.n_hw - rep.hw_succeeded, rep.n_hw,
             rep.n_hw - rep.hw_succeeded == 1 ? "" : "s");
    }
  }

  printf("\n");

  /* ---- Section 6: No Known Mitigation ---- */
  printf("%sNo known mitigation:%s\n", c(C_BOLD), c(C_RESET));

  if (rep.n_nomit == 0) {
    printf("  All components have at least one mitigation key.\n");
  } else {
    /* Grouped by disclosure, the same shape the compile-time surface section
     * uses: the sentence carries the relationship and the rows carry only the
     * names. A bare "name  physical addresses" column leaves the reader to
     * guess what the two have to do with each other, and repeats the same
     * phrase once per row. */
    const char *kinds[HR_NOMIT_MAX];
    int nkinds = 0;
    for (int i = 0; i < rep.n_nomit; i++) {
      int seen = 0;
      for (int k = 0; k < nkinds; k++)
        if (disclosure_eq(kinds[k], rep.nomit[i].discloses)) {
          seen = 1;
          break;
        }
      if (!seen && nkinds < HR_NOMIT_MAX)
        kinds[nkinds++] = rep.nomit[i].discloses;
    }
    for (int k = 0; k < nkinds; k++) {
      int n = 0;
      for (int i = 0; i < rep.n_nomit; i++)
        if (disclosure_eq(kinds[k], rep.nomit[i].discloses))
          n++;
      if (kinds[k])
        printf("  %d component%s disclose%s %s:\n", n, n == 1 ? "" : "s",
               n == 1 ? "s" : "", kinds[k]);
      else
        printf("  %d component%s do%s not state what they disclose:\n", n,
               n == 1 ? "" : "s", n == 1 ? "es" : "");
      for (int i = 0; i < rep.n_nomit; i++)
        if (disclosure_eq(kinds[k], rep.nomit[i].discloses))
          printf("    %s\n", rep.nomit[i].name);
    }
  }

  printf("\n");
}

void render_hardening_json(void) {
  printf("  \"hardening\": {\n");

  struct hardening_report rep;
  build_hardening_report(&rep);

  /* Exposure summary */
  printf("    \"exposure\": {\n");
  printf("      \"succeeded\": %d,\n", rep.succeeded);
  printf("      \"total\": %d,\n", rep.total);
  printf("      \"note\": \"Detection-only components excluded\"\n");
  printf("    },\n");

  /* Confirmed active mitigations: controls a component observed to defeat its
   * leak this run (mitigation dispositions). Runtime observation, distinct from
   * the gates below (sysctl levers read from their values). */
  printf("    \"confirmed_mitigations\": [");
  for (int i = 0; i < rep.n_confirmed; i++) {
    printf("%s\n      {\"gate\": ", i ? "," : "");
    json_print_escaped(rep.confirmed[i].gate);
    printf(", \"component\": ");
    json_print_escaped(rep.confirmed[i].component);
    if (rep.confirmed[i].message) {
      printf(", \"message\": ");
      json_print_escaped(rep.confirmed[i].message);
    }
    printf("}");
  }
  printf("%s],\n", rep.n_confirmed ? "\n    " : "");

  /* Kernel-text function ordering — gates System.map symbol resolution. */
  printf("    \"text_order\": {\n");
  printf("      \"class\": \"%s\",\n", text_order_json_class(rep.text_order));
  printf("      \"source\": \"%s\",\n",
         rep.text_order ? text_order_source(rep.text_order_conf) : "none");
  printf("      \"symbol_resolution\": \"%s\"\n",
         symbol_resolution_json(rep.text_order));
  printf("    },\n");

  /* KASLR posture: distinguishes randomization-failed from active /
   * disabled / unsupported. See render_hardening_text() Section 0 for
   * the rationale. The state field is mutually exclusive (priorities:
   * unsupported > disabled > randomization_failed > active) so JSON
   * consumers can switch on it directly. detected_by lists the
   * randomization-failure witnesses regardless of the resolved state. */
  const char *state;
  switch (rep.posture) {
  case HR_POSTURE_UNSUPPORTED:
    state = "unsupported";
    break;
  case HR_POSTURE_DISABLED:
    state = "disabled";
    break;
  case HR_POSTURE_RANDOMIZATION_FAILED:
    state = "randomization_failed";
    break;
  default:
    state = "active";
    break;
  }

  printf("    \"kaslr_posture\": {\n");
  printf("      \"state\": \"%s\",\n", state);
  printf("      \"slot_entropy_zero\": %s,\n",
         rep.slot_entropy_zero ? "true" : "false");
  printf("      \"kernel_at_link_time_default\": %s,\n",
         rep.kernel_at_default ? "true" : "false");
  printf("      \"detected_by\": [");
  for (int i = 0; i < rep.n_rand_detectors && i < 16; i++) {
    if (i > 0)
      printf(", ");
    json_print_escaped(rep.rand_detectors[i][0] ? rep.rand_detectors[i]
                                                : "unknown");
  }
  printf("]\n");
  printf("    },\n");

  /* Active defenses */
  printf("    \"active_defenses\": [\n");
  int first_def = 1;
  for (int gi = 0; gi < rep.n_gates; gi++) {
    const struct hr_gate *hg = &rep.gates[gi];

    if (!first_def)
      printf(",\n");
    first_def = 0;

    printf("      {\n");
    printf("        \"gate\": \"%s\",\n", hg->display);
    printf("        \"surface\": \"%s\",\n", hg->surface ? hg->surface : "");
    printf("        \"value\": %d,\n", hg->value);
    printf("        \"threshold\": %d,\n", hg->threshold);
    printf("        \"active\": %s,\n", hg->active ? "true" : "false");

    printf("        \"components_gated\": [");
    for (int i = 0; i < hg->n_gated_names; i++) {
      if (i > 0)
        printf(", ");
      json_print_escaped(hg->gated_names[i]);
    }
    printf("],\n");

    printf("        \"components_blocked\": [");
    for (int i = 0; i < hg->n_blocked_names; i++) {
      if (i > 0)
        printf(", ");
      json_print_escaped(hg->blocked_names[i]);
    }
    printf("],\n");

    printf("        \"components_bypassed\": [");
    for (int i = 0; i < hg->n_bypassed_names; i++) {
      if (i > 0)
        printf(", ");
      json_print_escaped(hg->bypassed_names[i]);
    }
    printf("]\n");
    printf("      }");
  }
  printf("\n    ],\n");

  /* Lockdown */
  const char *lockdown_str;
  switch (rep.lockdown) {
  case LOCKDOWN_INTEGRITY:
    lockdown_str = "integrity";
    break;
  case LOCKDOWN_CONFIDENTIALITY:
    lockdown_str = "confidentiality";
    break;
  case LOCKDOWN_NONE:
    lockdown_str = "none";
    break;
  default:
    lockdown_str = "unavailable";
    break;
  }
  printf("    \"lockdown\": {\n");
  printf("      \"mode\": \"%s\",\n", lockdown_str);
  printf("      \"active\": %s\n",
         rep.lockdown >= LOCKDOWN_INTEGRITY ? "true" : "false");
  printf("    },\n");

  /* Available hardening (all suggestions, incl. dmesg-fallback, for tooling) */
  printf("    \"available_hardening\": [\n");
  int first_sug = 1;
  for (int i = 0; i < rep.n_gate_suggestions; i++) {
    if (!first_sug)
      printf(",\n");
    first_sug = 0;
    printf("      {\n");
    printf("        \"action\": \"Set %s = %d\",\n",
           rep.gate_suggestions[i].display, rep.gate_suggestions[i].threshold);
    printf("        \"surface\": \"%s\",\n",
           rep.gate_suggestions[i].surface ? rep.gate_suggestions[i].surface
                                           : "");
    printf("        \"impact\": %d,\n", rep.gate_suggestions[i].impact);
    printf("        \"detail\": \"Blocks unprivileged access for %d "
           "component%s\"%s\n",
           rep.gate_suggestions[i].impact,
           rep.gate_suggestions[i].impact == 1 ? "" : "s",
           rep.gate_suggestions[i].has_projection ? "," : "");
    if (rep.gate_suggestions[i].has_projection)
      json_print_projected(rep.gate_suggestions[i].silences, rep.all_vbits,
                           rep.gate_suggestions[i].skip_vbits, rep.all_pbits,
                           rep.gate_suggestions[i].skip_pbits);
    printf("      }");
  }

  if (rep.suggest_lockdown) {
    if (!first_sug)
      printf(",\n");
    first_sug = 0;
    printf("      {\n");
    printf("        \"action\": \"Enable kernel lockdown (%s mode)\",\n",
           rep.lockdown_suggest_mode >= LOCKDOWN_CONFIDENTIALITY
               ? "confidentiality"
               : "integrity");
    printf("        \"surface\": \"%s\",\n", HR_SURFACE_LOCKDOWN);
    printf("        \"impact\": %d,\n", rep.lockdown_impact);
    printf("        \"detail\": \"Blocks the kernel-memory interfaces these "
           "leaks read\"%s\n",
           rep.lockdown_has_projection ? "," : "");
    if (rep.lockdown_has_projection)
      json_print_projected(rep.lockdown_silences, rep.all_vbits,
                           rep.lockdown_skip_vbits, rep.all_pbits,
                           rep.lockdown_skip_pbits);
    printf("      }");
  }

  if (rep.suggest_dmesg_fallback) {
    if (!first_sug)
      printf(",\n");
    first_sug = 0;
    printf("      {\n");
    printf("        \"action\": \"Restrict dmesg fallback files to root\",\n");
    printf("        \"surface\": \"%s\",\n", HR_SURFACE_DMESG_FALLBACK);
    printf("        \"impact\": %d,\n", rep.dmesg_fallback_count);
    printf("        \"detail\": \"%d dmesg component%s may have succeeded via "
           "log files\"%s\n",
           rep.dmesg_fallback_count, rep.dmesg_fallback_count == 1 ? "" : "s",
           rep.dmesg_fallback_has_projection ? "," : "");
    if (rep.dmesg_fallback_has_projection)
      json_print_projected(rep.dmesg_fallback_silences, rep.all_vbits,
                           rep.dmesg_fallback_skip_vbits, rep.all_pbits,
                           rep.dmesg_fallback_skip_pbits);
    printf("      }");
  }
  printf("\n    ],\n");

  /* Projected posture: current guaranteed residual entropy and the ceiling with
   * every suggestion applied. Omitted entirely when the engine is compiled out.
   */
  if (rep.has_projection) {
    printf("    \"projected_posture\": {\n");
    printf("      \"current\": { \"virt_base_entropy_bits\": %d, "
           "\"phys_base_entropy_bits\": %d },\n",
           rep.cur_vbits, rep.cur_pbits);
    printf(
        "      \"all_suggestions_applied\": { \"virt_base_entropy_bits\": %d, "
        "\"phys_base_entropy_bits\": %d, \"components_silenced\": %d }\n",
        rep.all_vbits, rep.all_pbits, rep.all_impact);
    printf("    },\n");
  }

  /* Patched vulnerabilities */
  printf("    \"patched_vulnerabilities\": {\n");
  printf("      \"total\": %d,\n", rep.vuln_total);
  printf("      \"likely_patched\": %d,\n", rep.vuln_total - rep.n_vulns);
  printf("      \"possibly_unpatched\": [\n");
  for (int i = 0; i < rep.n_vulns; i++) {
    if (i > 0)
      printf(",\n");
    printf("        {\"component\": ");
    json_print_escaped(rep.vulns[i].name);
    if (rep.vulns[i].cve) {
      printf(", \"cve\": ");
      json_print_escaped(rep.vulns[i].cve);
    }
    if (rep.vulns[i].patch) {
      printf(", \"patch\": ");
      json_print_escaped(rep.vulns[i].patch);
    }
    printf("}");
  }
  printf("\n      ]\n");
  printf("    },\n");

  /* Compile-time surface */
  printf("    \"compile_time_surface\": [\n");
  for (int i = 0; i < rep.n_surface; i++) {
    if (i > 0)
      printf(",\n");
    printf("      {\"component\": ");
    json_print_escaped(rep.surface[i].name);
    printf(", \"config\": ");
    json_print_escaped(rep.surface[i].config);
    printf(", \"discloses\": ");
    if (rep.surface[i].discloses)
      json_print_escaped(rep.surface[i].discloses);
    else
      printf("null");
    printf("}");
  }
  printf("\n    ],\n");

  /* Hardware side-channels: microarchitectural leaks (prefetch, EntryBleed,
   * etc.). succeeded marks the ones that fired on this CPU; the rest are gated
   * by an active CPU mitigation or an inapplicable attack. */
  printf("    \"hardware_side_channels\": [\n");
  for (int i = 0; i < rep.n_hw; i++) {
    if (i > 0)
      printf(",\n");
    printf("      {\"component\": ");
    json_print_escaped(rep.hw[i].name);
    printf(", \"hardware\": ");
    json_print_escaped(rep.hw[i].hardware);
    printf(", \"discloses\": ");
    if (rep.hw[i].discloses)
      json_print_escaped(rep.hw[i].discloses);
    else
      printf("null");
    printf(", \"succeeded\": %s}", rep.hw[i].succeeded ? "true" : "false");
  }
  printf("\n    ],\n");

  /* No mitigation */
  printf("    \"no_mitigation\": [\n");
  for (int i = 0; i < rep.n_nomit; i++) {
    if (i > 0)
      printf(",\n");
    printf("      {\"component\": ");
    json_print_escaped(rep.nomit[i].name);
    /* Always present, so a consumer reads the disclosure rather than inferring
     * it from a key's absence. `null` where the component disclosed nothing --
     * which OUTCOME_SUCCESS makes unreachable for this list, but the schema
     * should not depend on that holding. */
    printf(", \"discloses\": ");
    if (rep.nomit[i].discloses)
      json_print_escaped(rep.nomit[i].discloses);
    else
      printf("null");
    printf("}");
  }
  printf("\n    ]\n");

  printf("  }\n");
}

/* Markdown flavour of the hardening assessment (-H -m). Consumes the same
 * model as the text/json renderers; presents each section as a markdown
 * heading with a table or list. No ANSI colour (markdown is plain text);
 * status uses ✓ / ⚠ / ✗ glyphs as the text renderer does. */
void render_hardening_markdown(void) {
  struct hardening_report rep;
  build_hardening_report(&rep);

  printf("## Hardening Assessment\n\n");
  printf("**%d of %d** leak techniques succeeded against current defenses.\n\n",
         rep.succeeded, rep.total);

  /* Confirmed active mitigations: controls observed to defeat a leak this run
   * (mitigation dispositions). Printed only when present. */
  if (rep.n_confirmed > 0) {
    printf("### Confirmed active mitigations\n\n");
    printf("Controls observed to defeat a leak this run:\n\n");
    for (int i = 0; i < rep.n_confirmed; i++) {
      printf("- **%s** - %s", rep.confirmed[i].gate,
             rep.confirmed[i].component);
      if (rep.confirmed[i].message)
        printf(" (%s)", rep.confirmed[i].message);
      printf("\n");
    }
    printf("\n");
  }

  /* KASLR posture downgrade */
  if (rep.n_rand_detectors > 0) {
    printf("### KASLR posture\n\n");
    printf("> **KASLR randomization failed - random offset not applied at "
           "boot.** Effective slot entropy: **0 bits** (kernel at a "
           "firmware-determined position).\n\n");
    printf("Detected by:\n\n");
    for (int i = 0; i < rep.n_rand_detectors; i++)
      printf("- %s\n",
             rep.rand_detectors[i][0] ? rep.rand_detectors[i] : "(unknown)");
    printf("\n");
  }

  /* Kernel-text function ordering + symbol-resolution consequence. */
  if (rep.text_order) {
    printf("### Function layout\n\n");
    printf("- **text ordering:** %s (%s)\n", text_order_label(rep.text_order),
           text_order_source(rep.text_order_conf));
    printf("- **symbol resolution:** %s\n\n",
           symbol_resolution_label(rep.text_order));
  }

  /* Active defenses */
  printf("### Active defenses\n\n");
  printf("| Gate | Value | Status | Detail |\n");
  printf("|:-----|------:|:------:|:-------|\n");
  for (int gi = 0; gi < rep.n_gates; gi++) {
    const struct hr_gate *hg = &rep.gates[gi];
    if (hg->active) {
      int circumvented = (hg->blocked == 0 && hg->bypassed > 0);
      /* Synthetic gate (threshold 0, e.g. seccomp) has no knob value. */
      char vcol[16];
      if (hg->threshold > 0)
        snprintf(vcol, sizeof(vcol), "%d", hg->value);
      else
        snprintf(vcol, sizeof(vcol), "-");
      printf("| `%s` | %s | %s | ", hg->display, vcol,
             circumvented ? GLYPH_WARN : GLYPH_OK);
      int wrote = 0;
      if (hg->blocked > 0 && hg->blocked <= 5) {
        printf("blocked ");
        for (int n = 0; n < hg->n_blocked_names; n++)
          printf("%s%s", n ? ", " : "", hg->blocked_names[n]);
        wrote = 1;
      } else if (hg->blocked > 0) {
        printf("blocked %d of %d gated components", hg->blocked, hg->gated);
        wrote = 1;
      }
      if (hg->bypassed > 0) {
        if (wrote)
          printf("; ");
        if (hg->fallback == hg->bypassed)
          printf("%d bypassed via fallback files", hg->bypassed);
        else if (hg->fallback > 0)
          printf("%d bypassed (%d via fallback files)", hg->bypassed,
                 hg->fallback);
        else
          printf("%d bypassed", hg->bypassed);
        wrote = 1;
      }
      if (!wrote)
        printf("%d gated component%s", hg->gated, hg->gated == 1 ? "" : "s");
      printf(" |\n");
    } else if (hg->bypassed > 0) {
      printf("| `%s` | %d | %s | permissive - ", hg->display, hg->value,
             GLYPH_FAIL);
      if (hg->n_bypassed_names > 0 && hg->bypassed <= 5) {
        for (int n = 0; n < hg->n_bypassed_names; n++)
          printf("%s%s", n ? ", " : "", hg->bypassed_names[n]);
        printf(" leak%s", hg->bypassed == 1 ? "s" : "");
      } else {
        printf("%d component%s leak", hg->bypassed,
               hg->bypassed == 1 ? "" : "s");
      }
      printf(" (set >= %d) |\n", hg->threshold);
    }
  }
  const char *lockdown_str = NULL;
  switch (rep.lockdown) {
  case LOCKDOWN_INTEGRITY:
    lockdown_str = "integrity";
    break;
  case LOCKDOWN_CONFIDENTIALITY:
    lockdown_str = "confidentiality";
    break;
  default:
    break;
  }
  if (lockdown_str)
    printf("| Kernel lockdown | | %s | %s mode |\n", GLYPH_OK, lockdown_str);
  else
    printf("| Kernel lockdown | | %s | inactive |\n", GLYPH_FAIL);
  printf("\n");

  /* Available hardening */
  printf("### Available hardening\n\n");
  int exposure = rep.all_vbits > rep.cur_vbits || rep.all_pbits > rep.cur_pbits;
  if (rep.has_projection && exposure)
    printf("Base recoverable: %d bits now %s %d bits with all of the "
           "below applied.\n\n",
           rep.cur_vbits, GLYPH_ARROW, rep.all_vbits);
  else if (rep.has_projection)
    printf("Guaranteed base already at %d bits; the below silence "
           "speculative-only leaks.\n\n",
           rep.cur_vbits);
  int any_sug = 0;
  for (int i = 0; i < rep.n_gate_suggestions; i++) {
    any_sug = 1;
    printf("- Set `%s = %d` - affects %d component%s",
           rep.gate_suggestions[i].display, rep.gate_suggestions[i].threshold,
           rep.gate_suggestions[i].impact,
           rep.gate_suggestions[i].impact == 1 ? "" : "s");
    if (rep.gate_suggestions[i].has_projection)
      md_print_necessity(rep.gate_suggestions[i].silences, exposure,
                         rep.all_vbits, rep.gate_suggestions[i].skip_vbits,
                         rep.all_pbits, rep.gate_suggestions[i].skip_pbits);
    /* Enforcement surface — the lever this change lives on, so a report can
     * route it to the team that owns it (a `sysctl` differs from a
     * `file_permissions` chmod even when both close a leak). */
    if (rep.gate_suggestions[i].surface)
      printf(" [`%s`]", rep.gate_suggestions[i].surface);
    printf("\n");
  }
  if (rep.suggest_lockdown) {
    any_sug = 1;
    printf("- Enable kernel lockdown (%s mode) - blocks the kernel-memory "
           "interfaces these leaks read",
           rep.lockdown_suggest_mode >= LOCKDOWN_CONFIDENTIALITY
               ? "confidentiality"
               : "integrity");
    if (rep.lockdown_has_projection)
      md_print_necessity(rep.lockdown_silences, exposure, rep.all_vbits,
                         rep.lockdown_skip_vbits, rep.all_pbits,
                         rep.lockdown_skip_pbits);
    printf(" [`%s`]", HR_SURFACE_LOCKDOWN);
    printf("\n");
  }
  if (rep.suggest_dmesg_fallback) {
    any_sug = 1;
    printf("- Restrict dmesg fallback files to root - %d dmesg component%s may "
           "have succeeded via log files",
           rep.dmesg_fallback_count, rep.dmesg_fallback_count == 1 ? "" : "s");
    if (rep.dmesg_fallback_has_projection)
      md_print_necessity(rep.dmesg_fallback_silences, exposure, rep.all_vbits,
                         rep.dmesg_fallback_skip_vbits, rep.all_pbits,
                         rep.dmesg_fallback_skip_pbits);
    printf(" [`%s`]", HR_SURFACE_DMESG_FALLBACK);
    printf("\n");
  }
  if (!any_sug)
    printf("All available runtime hardening is active.\n");
  printf("\n");

  /* Patched vulnerabilities */
  printf("### Patched vulnerabilities\n\n");
  if (rep.vuln_total == 0) {
    printf("No vulnerability-based components in metadata.\n\n");
  } else {
    printf("%d of %d vulnerability-based components did not leak (likely "
           "patched or blocked).\n\n",
           rep.vuln_total - rep.n_vulns, rep.vuln_total);
    if (rep.n_vulns > 0) {
      printf("**%d component%s succeeded** - kernel may lack fixes for:\n\n",
             rep.n_vulns, rep.n_vulns == 1 ? "" : "s");
      for (int i = 0; i < rep.n_vulns; i++) {
        printf("- %s", rep.vulns[i].name);
        if (rep.vulns[i].cve)
          printf(" (%s", rep.vulns[i].cve);
        if (rep.vulns[i].patch)
          printf("%sfixed %s", rep.vulns[i].cve ? ", " : "(",
                 rep.vulns[i].patch);
        if (rep.vulns[i].cve || rep.vulns[i].patch)
          printf(")");
        printf("\n");
      }
      printf("\n");
    }
  }

  /* Compile-time attack surface */
  printf("### Compile-time attack surface\n\n");
  if (rep.n_surface == 0) {
    printf("No compile-time surface exposed.\n\n");
  } else {
    printf("| Component | Config | Discloses |\n");
    printf("|:---------|:-------|:----------|\n");
    for (int i = 0; i < rep.n_surface; i++)
      printf("| %s | %s | %s |\n", rep.surface[i].name, rep.surface[i].config,
             rep.surface[i].discloses ? rep.surface[i].discloses
                                      : "disclosure not stated");
    printf("\n");
  }

  /* Hardware side-channels */
  printf("### Hardware side-channels\n\n");
  if (rep.n_hw == 0) {
    printf("No hardware-mitigated components.\n\n");
  } else if (rep.hw_succeeded == 0) {
    printf("%d hardware-gated component%s did not succeed (CPU mitigations "
           "active or attack not applicable).\n\n",
           rep.n_hw, rep.n_hw == 1 ? "" : "s");
  } else {
    printf("**%d of %d** hardware-gated components succeeded:\n\n",
           rep.hw_succeeded, rep.n_hw);
    for (int i = 0; i < rep.n_hw; i++) {
      if (!rep.hw[i].succeeded)
        continue;
      printf("- %s - ", rep.hw[i].name);
      if (rep.hw[i].discloses)
        printf("discloses %s; ", rep.hw[i].discloses);
      printf("hardware: %s\n", rep.hw[i].hardware);
    }
    printf("\n");
  }

  /* No known mitigation */
  printf("### No known mitigation\n\n");
  if (rep.n_nomit == 0) {
    printf("All components have at least one mitigation key.\n\n");
  } else {
    /* A table rather than the text mode's grouped list: markdown labels a
     * column in its header, so the relationship is stated once without
     * restructuring the rows -- and it matches the tables the other markdown
     * sections already use. */
    printf("| Component | Discloses |\n");
    printf("|:----------|:----------|\n");
    for (int i = 0; i < rep.n_nomit; i++)
      printf("| %s | %s |\n", rep.nomit[i].name,
             rep.nomit[i].discloses ? rep.nomit[i].discloses : "not stated");
    printf("\n");
  }
}
