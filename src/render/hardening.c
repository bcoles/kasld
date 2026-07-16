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

/* Known sysctl gates */
struct sysctl_gate {
  const char *name;    /* meta value prefix, e.g. "dmesg_restrict" */
  const char *display; /* display string, e.g. "kernel.dmesg_restrict" */
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
    [GATE_KPTR_RESTRICT] = {"kptr_restrict", "kernel.kptr_restrict",
                            &sysctl_kptr_restrict, 1},
    [GATE_DMESG_RESTRICT] = {"dmesg_restrict", "kernel.dmesg_restrict",
                             &sysctl_dmesg_restrict, 1},
    [GATE_PERF_EVENT_PARANOID] = {"perf_event_paranoid",
                                  "kernel.perf_event_paranoid",
                                  &sysctl_perf_event_paranoid, 2},
    /* 0 = unprivileged bpf() allowed, >=1 disables it (blocks the unprivileged
     * bpf leak components), so the "value >= threshold blocks" model fits with
     * threshold 1. */
    [GATE_UNPRIVILEGED_BPF] = {"unprivileged_bpf_disabled",
                               "kernel.unprivileged_bpf_disabled",
                               &sysctl_unprivileged_bpf_disabled, 1},
    /* Not a /proc/sys knob — boot-time (no_hash_pointers) — but the same gate
     * plumbing fits: a runtime-readable mitigation that gates %pK address
     * leaks (hashed by default => low-priv readers get an id, not the addr). */
    [GATE_HASHED_POINTERS] = {"hashed_pointers", "kernel pointer hashing (%pK)",
                              &hashed_pointers, 1},
};
static const int ngates = GATE__COUNT;

static int sysctl_gate_active(const struct sysctl_gate *g) {
  /* value_ptr can be NULL if its load-time relocation was not applied; treat an
   * unreadable gate as inactive rather than dereferencing it. */
  return g->value_ptr && *g->value_ptr >= 0 && *g->value_ptr >= g->threshold;
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
  if (cl->outcome != OUTCOME_ACCESS_DENIED || seccomp <= 0 || host_paranoid < 0)
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

  /* Container confinement, for attributing perf denials to seccomp (below). */
  struct kasld_vantage vant;
  kasld_gather_vantage(&vant);
  int host_paranoid = sysctl_perf_event_paranoid;

  /* Exposure: non-detection components carrying metadata. */
  for (int i = 0; i < num_comp_logs; i++) {
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
        r->rand_detectors[r->n_rand_detectors++] = scalar_facts[i].origin;
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
    if (!gates[g].value_ptr || *gates[g].value_ptr < 0)
      continue;
    struct hr_gate hg;
    memset(&hg, 0, sizeof(hg));
    hg.display = gates[g].display;
    hg.value = *gates[g].value_ptr;
    hg.threshold = gates[g].threshold;
    hg.active = sysctl_gate_active(&gates[g]);
    for (int i = 0; i < num_comp_logs; i++) {
      if (!component_has_gate(&comp_logs[i], &gates[g]))
        continue;
      hg.gated++;
      if (hg.n_gated_names < HR_NAME_MAX)
        hg.gated_names[hg.n_gated_names++] = comp_logs[i].name;
      if (comp_logs[i].outcome == OUTCOME_ACCESS_DENIED &&
          !(g == GATE_PERF_EVENT_PARANOID &&
            seccomp_blocked_perf(&comp_logs[i], vant.seccomp, host_paranoid))) {
        /* Credit perf_event_paranoid only when it actually blocked the perf
         * component; a seccomp-blocked perf denial is credited to the seccomp
         * gate below instead of blamed on a permissive paranoid setting. */
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
  if (vant.seccomp > 0) {
    struct hr_gate sg;
    memset(&sg, 0, sizeof(sg));
    sg.display = "seccomp syscall filter";
    sg.active = 1;
    sg.value = vant.seccomp;
    for (int i = 0; i < num_comp_logs; i++) {
      if (!seccomp_blocked_perf(&comp_logs[i], vant.seccomp, host_paranoid))
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

  r->lockdown = sysctl_lockdown;

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
  const char *all[MAX_COMPONENTS];
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
      sg->threshold = r->gates[i].threshold;
      sg->impact = r->gates[i].gated;
      sg->silences = r->gates[i].n_silenced;
    }
    for (int k = 0; k < r->gates[i].n_silenced; k++)
      if (nall < MAX_COMPONENTS)
        all[nall++] = r->gates[i].silenced_names[k];
  }

  /* Lockdown suggestion. It silences only the lockdown-gated leaks that
   * succeeded with NO file fallback: lockdown blocks the klogctl() syscall, so
   * a leak that also reads a dmesg log file survives it and stays in the
   * evidence.
   */
  if (sysctl_lockdown < LOCKDOWN_INTEGRITY) {
    int lockdown_gated = 0;
    for (int i = 0; i < num_comp_logs; i++) {
      if (!meta_get(&comp_logs[i].meta, "lockdown"))
        continue;
      lockdown_gated++;
      if (comp_logs[i].outcome == OUTCOME_SUCCESS &&
          !meta_get(&comp_logs[i].meta, "fallback") && n_ld < MAX_COMPONENTS)
        ld_sil[n_ld++] = comp_logs[i].name;
    }
    if (lockdown_gated > 0) {
      r->suggest_lockdown = 1;
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
  if (sysctl_dmesg_restrict >= 1) {
    for (int i = 0; i < num_comp_logs; i++) {
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
        r->n_projecting++;
      }
    }
    if (r->suggest_lockdown) {
      struct projected_posture pp;
      project_skipping(all, nuniq, ld_sil, n_ld, &pp);
      if (pp.available) {
        r->lockdown_has_projection = 1;
        r->lockdown_skip_vbits = pp.vbits;
        r->lockdown_skip_pbits = pp.pbits;
        r->n_projecting++;
      }
    }
    if (r->suggest_dmesg_fallback) {
      struct projected_posture pp;
      project_skipping(all, nuniq, dm_sil, n_dm, &pp);
      if (pp.available) {
        r->dmesg_fallback_has_projection = 1;
        r->dmesg_fallback_skip_vbits = pp.vbits;
        r->dmesg_fallback_skip_pbits = pp.pbits;
        r->n_projecting++;
      }
    }
  }

  /* Patched vulnerabilities: total vuln-tagged components + the succeeded
   * (possibly unpatched) subset. */
  for (int i = 0; i < num_comp_logs; i++) {
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
  for (int i = 0; i < num_comp_logs; i++) {
    if (comp_logs[i].outcome != OUTCOME_SUCCESS)
      continue;
    const char *configs[4];
    int ncfg = meta_get_all(&comp_logs[i].meta, "config", configs, 4);
    if (ncfg == 0)
      continue;
    const char *addr = meta_get(&comp_logs[i].meta, "addr");
    for (int j = 0; j < ncfg && r->n_surface < HR_SURFACE_MAX; j++) {
      r->surface[r->n_surface].name = comp_logs[i].name;
      r->surface[r->n_surface].config = configs[j];
      r->surface[r->n_surface].addr = addr;
      r->n_surface++;
    }
  }

  /* Hardware side-channels: non-detection components with a hardware= key. */
  for (int i = 0; i < num_comp_logs; i++) {
    const char *hw = meta_get(&comp_logs[i].meta, "hardware");
    if (!hw)
      continue;
    const char *method = meta_get(&comp_logs[i].meta, "method");
    if (!method || strcmp(method, "detection") == 0)
      continue;
    if (r->n_hw < HR_HW_MAX) {
      r->hw[r->n_hw].name = comp_logs[i].name;
      r->hw[r->n_hw].hardware = hw;
      r->hw[r->n_hw].addr = meta_get(&comp_logs[i].meta, "addr");
      r->hw[r->n_hw].succeeded = (comp_logs[i].outcome == OUTCOME_SUCCESS);
      r->n_hw++;
      if (comp_logs[i].outcome == OUTCOME_SUCCESS)
        r->hw_succeeded++;
    }
  }

  /* No known mitigation: succeeded non-detection components with no
   * mitigation key. */
  for (int i = 0; i < num_comp_logs; i++) {
    if (comp_logs[i].outcome != OUTCOME_SUCCESS)
      continue;
    const char *method = meta_get(&comp_logs[i].meta, "method");
    if (!method || strcmp(method, "detection") == 0)
      continue;
    if (has_mitigation_keys(&comp_logs[i].meta))
      continue;
    if (r->n_nomit < HR_NOMIT_MAX) {
      r->nomit[r->n_nomit].name = comp_logs[i].name;
      r->nomit[r->n_nomit].addr = meta_get(&comp_logs[i].meta, "addr");
      r->n_nomit++;
    }
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
    printf("    no base-leak behind this — recovers nothing\n");
  } else if (fv > 0 || fp > 0) {
    if (fp > 0 && fv > 0)
      printf(
          "    load-bearing — omitting forfeits %d bits virtual, %d physical\n",
          fv, fp);
    else
      printf("    load-bearing — omitting forfeits %d %s bits\n",
             fv > 0 ? fv : fp, fv > 0 ? "virtual" : "physical");
  } else if (!exposure) {
    printf("    silences %d leak%s — speculative window only, no guaranteed "
           "bits\n",
           silences, silences == 1 ? "" : "s");
  } else {
    printf("    silences %d leak%s but 0 guaranteed bits — not required (the "
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
    printf(" — recovers nothing (no base-leak behind it)");
  else if (fv > 0 || fp > 0)
    printf("; load-bearing — omitting forfeits %d %s bits", fv > 0 ? fv : fp,
           fv > 0 ? "virtual" : "physical");
  else if (!exposure)
    printf("; speculative window only (no guaranteed bits)");
  else
    printf(
        "; 0 guaranteed bits (not required — the rest reach the same posture)");
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
    printf("  %s** KASLR randomization failed — random offset not applied "
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
           "hardware) — an operator with a previously-captured slide on "
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
             circumvented ? "\xe2\x9a\xa0" : "\xe2\x9c\x93", c(C_RESET));
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
      printf("  %-34s = %-4d %s\xe2\x9c\x97%s  permissive \xe2\x80\x94 ",
             hg->display, hg->value, c(C_YELLOW), c(C_RESET));
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
    printf("  %-34s        %s\xe2\x9c\x93%s  %s mode\n", "Kernel lockdown",
           c(C_GREEN), c(C_RESET), lockdown_str);
  } else {
    printf("  %-34s        %s\xe2\x9c\x97%s  inactive\n", "Kernel lockdown",
           c(C_DIM), c(C_RESET));
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
    printf("  %sbase recoverable: %d bits now \xe2\x86\x92 %d bits with all of "
           "the "
           "below applied%s\n",
           c(C_DIM), rep.cur_vbits, rep.all_vbits, c(C_RESET));
  else if (rep.has_projection)
    printf("  %sguaranteed base already at %d bits; the below silence "
           "speculative-only leaks%s\n",
           c(C_DIM), rep.cur_vbits, c(C_RESET));

  int any_suggestions = 0;

  for (int i = 0; i < rep.n_gate_suggestions; i++) {
    any_suggestions = 1;
    printf("  %s\xe2\x86\x92%s Set %s = %d\n", c(C_CYAN), c(C_RESET),
           rep.gate_suggestions[i].display, rep.gate_suggestions[i].threshold);
    printf("    affects %d component%s\n", rep.gate_suggestions[i].impact,
           rep.gate_suggestions[i].impact == 1 ? "" : "s");
    if (rep.gate_suggestions[i].has_projection)
      print_necessity(rep.gate_suggestions[i].silences, exposure, rep.all_vbits,
                      rep.gate_suggestions[i].skip_vbits, rep.all_pbits,
                      rep.gate_suggestions[i].skip_pbits);
  }

  if (rep.suggest_lockdown) {
    any_suggestions = 1;
    printf("  %s\xe2\x86\x92%s Enable kernel lockdown (integrity mode)\n",
           c(C_CYAN), c(C_RESET));
    printf("    blocks klogctl() even with CAP_SYSLOG\n");
    if (rep.lockdown_has_projection)
      print_necessity(rep.lockdown_silences, exposure, rep.all_vbits,
                      rep.lockdown_skip_vbits, rep.all_pbits,
                      rep.lockdown_skip_pbits);
  }

  if (rep.suggest_dmesg_fallback) {
    any_suggestions = 1;
    printf("  %s\xe2\x86\x92%s Restrict dmesg fallback files to root\n",
           c(C_CYAN), c(C_RESET));
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
      printf("  %s%d component%s succeeded%s — kernel may lack fixes for:\n",
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
    /* Group by addr type */
    int phys_count = 0, virt_count = 0;
    for (int i = 0; i < rep.n_surface; i++) {
      if (rep.surface[i].addr && strcmp(rep.surface[i].addr, "physical") == 0)
        phys_count++;
      else
        virt_count++;
    }
    if (phys_count > 0)
      printf("  %d component%s leak%s physical addresses via compiled-in "
             "features:\n",
             phys_count, phys_count == 1 ? "" : "s",
             phys_count == 1 ? "s" : "");
    for (int i = 0; i < rep.n_surface; i++) {
      if (rep.surface[i].addr && strcmp(rep.surface[i].addr, "physical") == 0)
        printf("    %-28s %s\n", rep.surface[i].name, rep.surface[i].config);
    }
    if (virt_count > 0)
      printf("  %d component%s leak%s virtual addresses via compiled-in "
             "features:\n",
             virt_count, virt_count == 1 ? "" : "s",
             virt_count == 1 ? "s" : "");
    for (int i = 0; i < rep.n_surface; i++) {
      if (!rep.surface[i].addr || strcmp(rep.surface[i].addr, "physical") != 0)
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
      printf("    %-28s %s", rep.hw[i].name, rep.hw[i].hardware);
      if (rep.hw[i].addr)
        printf(" — leaks %s address", rep.hw[i].addr);
      printf("\n");
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
    for (int i = 0; i < rep.n_nomit; i++) {
      const char *addr = rep.nomit[i].addr;
      printf("  %-28s %s%s%s\n", rep.nomit[i].name, addr ? "leaks " : "",
             addr ? addr : "no mitigation", addr ? " addresses" : "");
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
    printf("        \"action\": \"Enable kernel lockdown (integrity mode)\","
           "\n");
    printf("        \"impact\": %d,\n", rep.lockdown_impact);
    printf("        \"detail\": \"Blocks klogctl() even with CAP_SYSLOG\"%s\n",
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
    if (rep.surface[i].addr) {
      printf(", \"addr\": ");
      json_print_escaped(rep.surface[i].addr);
    }
    printf("}");
  }
  printf("\n    ],\n");

  /* No mitigation */
  printf("    \"no_mitigation\": [\n");
  for (int i = 0; i < rep.n_nomit; i++) {
    if (i > 0)
      printf(",\n");
    printf("      {\"component\": ");
    json_print_escaped(rep.nomit[i].name);
    if (rep.nomit[i].addr) {
      printf(", \"addr\": ");
      json_print_escaped(rep.nomit[i].addr);
    }
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

  /* KASLR posture downgrade */
  if (rep.n_rand_detectors > 0) {
    printf("### KASLR posture\n\n");
    printf("> **KASLR randomization failed — random offset not applied at "
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
        snprintf(vcol, sizeof(vcol), "\xe2\x80\x94"); /* em dash */
      printf("| `%s` | %s | %s | ", hg->display, vcol,
             circumvented ? "\xe2\x9a\xa0" : "\xe2\x9c\x93");
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
      printf("| `%s` | %d | \xe2\x9c\x97 | permissive — ", hg->display,
             hg->value);
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
    printf("| Kernel lockdown | | \xe2\x9c\x93 | %s mode |\n", lockdown_str);
  else
    printf("| Kernel lockdown | | \xe2\x9c\x97 | inactive |\n");
  printf("\n");

  /* Available hardening */
  printf("### Available hardening\n\n");
  int exposure = rep.all_vbits > rep.cur_vbits || rep.all_pbits > rep.cur_pbits;
  if (rep.has_projection && exposure)
    printf("Base recoverable: %d bits now \xe2\x86\x92 %d bits with all of the "
           "below applied.\n\n",
           rep.cur_vbits, rep.all_vbits);
  else if (rep.has_projection)
    printf("Guaranteed base already at %d bits; the below silence "
           "speculative-only leaks.\n\n",
           rep.cur_vbits);
  int any_sug = 0;
  for (int i = 0; i < rep.n_gate_suggestions; i++) {
    any_sug = 1;
    printf("- Set `%s = %d` — affects %d component%s",
           rep.gate_suggestions[i].display, rep.gate_suggestions[i].threshold,
           rep.gate_suggestions[i].impact,
           rep.gate_suggestions[i].impact == 1 ? "" : "s");
    if (rep.gate_suggestions[i].has_projection)
      md_print_necessity(rep.gate_suggestions[i].silences, exposure,
                         rep.all_vbits, rep.gate_suggestions[i].skip_vbits,
                         rep.all_pbits, rep.gate_suggestions[i].skip_pbits);
    printf("\n");
  }
  if (rep.suggest_lockdown) {
    any_sug = 1;
    printf("- Enable kernel lockdown (integrity mode) — blocks klogctl() even "
           "with CAP_SYSLOG");
    if (rep.lockdown_has_projection)
      md_print_necessity(rep.lockdown_silences, exposure, rep.all_vbits,
                         rep.lockdown_skip_vbits, rep.all_pbits,
                         rep.lockdown_skip_pbits);
    printf("\n");
  }
  if (rep.suggest_dmesg_fallback) {
    any_sug = 1;
    printf("- Restrict dmesg fallback files to root — %d dmesg component%s may "
           "have succeeded via log files",
           rep.dmesg_fallback_count, rep.dmesg_fallback_count == 1 ? "" : "s");
    if (rep.dmesg_fallback_has_projection)
      md_print_necessity(rep.dmesg_fallback_silences, exposure, rep.all_vbits,
                         rep.dmesg_fallback_skip_vbits, rep.all_pbits,
                         rep.dmesg_fallback_skip_pbits);
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
      printf("**%d component%s succeeded** — kernel may lack fixes for:\n\n",
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
    printf("| Component | Config | Address |\n");
    printf("|:---------|:-------|:--------|\n");
    for (int i = 0; i < rep.n_surface; i++)
      printf("| %s | %s | %s |\n", rep.surface[i].name, rep.surface[i].config,
             rep.surface[i].addr ? rep.surface[i].addr : "virtual");
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
      printf("- %s — %s", rep.hw[i].name, rep.hw[i].hardware);
      if (rep.hw[i].addr)
        printf(" (leaks %s address)", rep.hw[i].addr);
      printf("\n");
    }
    printf("\n");
  }

  /* No known mitigation */
  printf("### No known mitigation\n\n");
  if (rep.n_nomit == 0) {
    printf("All components have at least one mitigation key.\n\n");
  } else {
    for (int i = 0; i < rep.n_nomit; i++) {
      const char *addr = rep.nomit[i].addr;
      if (addr)
        printf("- %s — leaks %s addresses\n", rep.nomit[i].name, addr);
      else
        printf("- %s — no mitigation\n", rep.nomit[i].name);
    }
    printf("\n");
  }
}
