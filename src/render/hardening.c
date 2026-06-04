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
};
static const int ngates = GATE__COUNT;

static int sysctl_gate_active(const struct sysctl_gate *g) {
  return *g->value_ptr >= 0 && *g->value_ptr >= g->threshold;
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

/* Check if a component has any mitigation keys */
static int has_mitigation_keys(const struct component_meta *m) {
  static const char *mitigation_keys[] = {
      "sysctl", "config", "patch", "cve", "hardware", "lockdown", NULL};
  for (int k = 0; mitigation_keys[k]; k++) {
    if (meta_get(m, mitigation_keys[k]))
      return 1;
  }
  return 0;
}

void render_hardening_text(void) {
  printf("\n%s========================================%s\n", c(C_BOLD),
         c(C_RESET));
  printf("%s Hardening Assessment%s\n", c(C_BOLD), c(C_RESET));
  printf("%s========================================%s\n\n", c(C_BOLD),
         c(C_RESET));

  /* Count non-detection components with metadata */
  int total_meta = 0, succeeded = 0;
  for (int i = 0; i < num_comp_logs; i++) {
    const char *method = meta_get(&comp_logs[i].meta, "method");
    if (!method)
      continue;
    if (strcmp(method, "detection") == 0)
      continue;
    total_meta++;
    if (comp_logs[i].outcome == OUTCOME_SUCCESS)
      succeeded++;
  }

  printf("Hardening assessment: %s%d of %d%s leak techniques succeeded "
         "against current defenses.\n\n",
         succeeded > 0 ? c(C_YELLOW) : c(C_GREEN), succeeded, total_meta,
         c(C_RESET));

  /* ---- Section 0: KASLR posture downgrade ----
   *
   * Surfaces SF_VIRT_KASLR_RANDOMIZATION_FAILED: the kernel attempted
   * virtual KASLR at boot but could not produce a random offset (no
   * entropy seed, no PRNG, insufficient memory). The boot stub still
   * relocated the image but skipped the random component, leaving the
   * kernel at a firmware-/boot-stub-deterministic virt position.
   * Effective KASLR slot entropy is 0 bits — same address on every
   * boot of this (firmware, kernel build, hardware) tuple. The user-
   * visible "0 entropy" claim is about virt text, so we scan the virt
   * variant; a phys-only randomisation failure (SF_PHYS_KASLR_
   * RANDOMIZATION_FAILED alone) wouldn't trip this — virt KASLR via
   * the DTB seed could still have full entropy. Components that emit
   * both (every current emitter) show up via the virt scan. Distinct
   * from SF_VIRT_KASLR_DISABLED (deliberate opt-out → kernel at
   * link-time default), which is shown by the main results banner. */
  int rand_failed_origins = 0;
  for (int i = 0; i < num_scalar_facts; i++) {
    if (scalar_facts[i].fact == SF_VIRT_KASLR_RANDOMIZATION_FAILED &&
        scalar_facts[i].value != 0)
      rand_failed_origins++;
  }
  if (rand_failed_origins > 0) {
    printf("%sKASLR posture:%s\n", c(C_BOLD), c(C_RESET));
    printf("  %s** KASLR randomization failed — random offset not applied "
           "at boot **%s\n",
           c(C_YELLOW), c(C_RESET));
    printf("  Detected by:\n");
    for (int i = 0; i < num_scalar_facts; i++) {
      if (scalar_facts[i].fact == SF_VIRT_KASLR_RANDOMIZATION_FAILED &&
          scalar_facts[i].value != 0)
        printf("    %s\n", scalar_facts[i].origin[0] ? scalar_facts[i].origin
                                                     : "(unknown)");
    }
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

  /* ---- Section 1: Active Defenses ---- */
  printf("%sActive defenses:%s\n", c(C_BOLD), c(C_RESET));

  int any_active = 0;

  for (int g = 0; g < ngates; g++) {
    if (*gates[g].value_ptr < 0)
      continue; /* sysctl unavailable */

    int active = sysctl_gate_active(&gates[g]);
    int gated = 0, blocked = 0, bypassed = 0;
    const char *blocked_names[8];
    int nblocked_names = 0;

    for (int i = 0; i < num_comp_logs; i++) {
      if (!component_has_gate(&comp_logs[i], &gates[g]))
        continue;
      gated++;
      if (comp_logs[i].outcome == OUTCOME_ACCESS_DENIED) {
        blocked++;
        if (nblocked_names < 8)
          blocked_names[nblocked_names++] = comp_logs[i].name;
      } else if (comp_logs[i].outcome == OUTCOME_SUCCESS) {
        bypassed++;
      }
    }

    if (gated == 0)
      continue;

    if (active) {
      any_active = 1;
      printf("  %-34s = %-4d %s\xe2\x9c\x93%s  ", gates[g].display,
             *gates[g].value_ptr, c(C_GREEN), c(C_RESET));
      if (blocked > 0 && blocked <= 5) {
        printf("blocked ");
        for (int n = 0; n < nblocked_names; n++) {
          if (n > 0)
            printf(", ");
          printf("%s", blocked_names[n]);
        }
      } else if (blocked > 0) {
        printf("blocked %d of %d gated components", blocked, gated);
      }
      if (bypassed > 0) {
        if (blocked > 0)
          printf("; ");
        printf("%d bypassed (fallback?)", bypassed);
      }
      if (blocked == 0 && bypassed == 0)
        printf("%d gated component%s", gated, gated == 1 ? "" : "s");
      printf("\n");
    }
  }

  /* Lockdown status */
  const char *lockdown_str = NULL;
  switch (sysctl_lockdown) {
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

  int any_suggestions = 0;

  for (int g = 0; g < ngates; g++) {
    if (*gates[g].value_ptr < 0)
      continue;
    if (sysctl_gate_active(&gates[g]))
      continue; /* already active */

    int gated = 0;
    for (int i = 0; i < num_comp_logs; i++) {
      if (component_has_gate(&comp_logs[i], &gates[g]))
        gated++;
    }
    if (gated == 0)
      continue;

    any_suggestions = 1;
    printf("  %s\xe2\x86\x92%s Set %s = %d\n", c(C_CYAN), c(C_RESET),
           gates[g].display, gates[g].threshold);
    printf("    Would affect: %d component%s\n", gated, gated == 1 ? "" : "s");
  }

  /* Suggest lockdown if not active and any component has lockdown tag */
  if (sysctl_lockdown < LOCKDOWN_INTEGRITY) {
    int lockdown_gated = 0;
    for (int i = 0; i < num_comp_logs; i++) {
      if (meta_get(&comp_logs[i].meta, "lockdown"))
        lockdown_gated++;
    }
    if (lockdown_gated > 0) {
      any_suggestions = 1;
      printf("  %s\xe2\x86\x92%s Enable kernel lockdown (integrity mode)\n",
             c(C_CYAN), c(C_RESET));
      printf("    Blocks klogctl() even with CAP_SYSLOG.\n");
    }
  }

  /* Suggest restricting fallback paths if dmesg_restrict is active
     but dmesg components still succeeded */
  if (sysctl_dmesg_restrict >= 1) {
    int fallback_bypassed = 0;
    for (int i = 0; i < num_comp_logs; i++) {
      if (comp_logs[i].outcome != OUTCOME_SUCCESS)
        continue;
      if (!component_has_gate(&comp_logs[i], &gates[GATE_DMESG_RESTRICT]))
        continue;
      if (meta_get(&comp_logs[i].meta, "fallback"))
        fallback_bypassed++;
    }
    if (fallback_bypassed > 0) {
      any_suggestions = 1;
      printf("  %s\xe2\x86\x92%s Restrict dmesg fallback files to root\n",
             c(C_CYAN), c(C_RESET));
      printf("    %d dmesg component%s may have succeeded via log files\n",
             fallback_bypassed, fallback_bypassed == 1 ? "" : "s");
    }
  }

  if (!any_suggestions)
    printf("  All available runtime hardening is active.\n");

  printf("\n");

  /* ---- Section 3: Patched Vulnerabilities ---- */
  printf("%sPatched vulnerabilities:%s\n", c(C_BOLD), c(C_RESET));

  int vuln_total = 0;
  struct {
    const char *name;
    const char *cve;
    const char *patch;
  } unpatched[16];
  int nunpatched = 0;

  for (int i = 0; i < num_comp_logs; i++) {
    const char *patch = meta_get(&comp_logs[i].meta, "patch");
    const char *cve = meta_get(&comp_logs[i].meta, "cve");
    if (!patch && !cve)
      continue;
    vuln_total++;
    if (comp_logs[i].outcome == OUTCOME_SUCCESS && nunpatched < 16) {
      unpatched[nunpatched].name = comp_logs[i].name;
      unpatched[nunpatched].cve = cve;
      unpatched[nunpatched].patch = patch;
      nunpatched++;
    }
  }

  if (vuln_total == 0) {
    printf("  No vulnerability-based components in metadata.\n");
  } else {
    printf("  %d of %d vulnerability-based components did not leak "
           "(likely patched or blocked).\n",
           vuln_total - nunpatched, vuln_total);
    if (nunpatched > 0) {
      printf("  %s%d component%s succeeded%s — kernel may lack fixes for:\n",
             c(C_YELLOW), nunpatched, nunpatched == 1 ? "" : "s", c(C_RESET));
      for (int i = 0; i < nunpatched; i++) {
        printf("    %s", unpatched[i].name);
        if (unpatched[i].cve)
          printf(" (%s", unpatched[i].cve);
        if (unpatched[i].patch)
          printf("%sfixed %s", unpatched[i].cve ? ", " : "(",
                 unpatched[i].patch);
        if (unpatched[i].cve || unpatched[i].patch)
          printf(")");
        printf("\n");
      }
    }
  }

  printf("\n");

  /* ---- Section 4: Compile-Time Attack Surface ---- */
  printf("%sCompile-time attack surface:%s\n", c(C_BOLD), c(C_RESET));

  struct {
    const char *name;
    const char *config;
    const char *addr;
  } config_surface[32];
  int nconfig = 0;

  for (int i = 0; i < num_comp_logs; i++) {
    if (comp_logs[i].outcome != OUTCOME_SUCCESS)
      continue;
    const char *configs[4];
    int ncfg = meta_get_all(&comp_logs[i].meta, "config", configs, 4);
    if (ncfg == 0)
      continue;
    const char *addr = meta_get(&comp_logs[i].meta, "addr");
    for (int j = 0; j < ncfg && nconfig < 32; j++) {
      config_surface[nconfig].name = comp_logs[i].name;
      config_surface[nconfig].config = configs[j];
      config_surface[nconfig].addr = addr;
      nconfig++;
    }
  }

  if (nconfig == 0) {
    printf("  No compile-time surface exposed.\n");
  } else {
    /* Group by addr type */
    int phys_count = 0, virt_count = 0;
    for (int i = 0; i < nconfig; i++) {
      if (config_surface[i].addr &&
          strcmp(config_surface[i].addr, "physical") == 0)
        phys_count++;
      else
        virt_count++;
    }
    if (phys_count > 0)
      printf("  %d component%s leak%s physical addresses via compiled-in "
             "features:\n",
             phys_count, phys_count == 1 ? "" : "s",
             phys_count == 1 ? "s" : "");
    for (int i = 0; i < nconfig; i++) {
      if (config_surface[i].addr &&
          strcmp(config_surface[i].addr, "physical") == 0)
        printf("    %-28s %s\n", config_surface[i].name,
               config_surface[i].config);
    }
    if (virt_count > 0)
      printf("  %d component%s leak%s virtual addresses via compiled-in "
             "features:\n",
             virt_count, virt_count == 1 ? "" : "s",
             virt_count == 1 ? "s" : "");
    for (int i = 0; i < nconfig; i++) {
      if (!config_surface[i].addr ||
          strcmp(config_surface[i].addr, "physical") != 0)
        printf("    %-28s %s\n", config_surface[i].name,
               config_surface[i].config);
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

  struct {
    const char *name;
    const char *hardware;
    const char *addr;
    int outcome;
  } hw_comps[32];
  int nhw = 0, hw_succeeded = 0;

  for (int i = 0; i < num_comp_logs; i++) {
    const char *hw = meta_get(&comp_logs[i].meta, "hardware");
    if (!hw)
      continue;
    const char *method = meta_get(&comp_logs[i].meta, "method");
    if (!method || strcmp(method, "detection") == 0)
      continue;
    if (nhw < 32) {
      hw_comps[nhw].name = comp_logs[i].name;
      hw_comps[nhw].hardware = hw;
      hw_comps[nhw].addr = meta_get(&comp_logs[i].meta, "addr");
      hw_comps[nhw].outcome = comp_logs[i].outcome;
      nhw++;
      if (comp_logs[i].outcome == OUTCOME_SUCCESS)
        hw_succeeded++;
    }
  }

  if (nhw == 0) {
    printf("  No hardware-mitigated components.\n");
  } else if (hw_succeeded == 0) {
    printf("  %d hardware-gated component%s did not succeed (CPU mitigations "
           "active or attack not applicable).\n",
           nhw, nhw == 1 ? "" : "s");
  } else {
    printf("  %s%d of %d%s hardware-gated components succeeded:\n", c(C_YELLOW),
           hw_succeeded, nhw, c(C_RESET));
    for (int i = 0; i < nhw; i++) {
      if (hw_comps[i].outcome != OUTCOME_SUCCESS)
        continue;
      printf("    %-28s %s", hw_comps[i].name, hw_comps[i].hardware);
      if (hw_comps[i].addr)
        printf(" — leaks %s address", hw_comps[i].addr);
      printf("\n");
    }
    if (hw_succeeded < nhw) {
      printf("  %d of %d hardware-gated component%s did not succeed.\n",
             nhw - hw_succeeded, nhw, nhw - hw_succeeded == 1 ? "" : "s");
    }
  }

  printf("\n");

  /* ---- Section 6: No Known Mitigation ---- */
  printf("%sNo known mitigation:%s\n", c(C_BOLD), c(C_RESET));

  int any_unmit = 0;
  for (int i = 0; i < num_comp_logs; i++) {
    if (comp_logs[i].outcome != OUTCOME_SUCCESS)
      continue;
    const char *method = meta_get(&comp_logs[i].meta, "method");
    if (!method)
      continue;
    if (strcmp(method, "detection") == 0)
      continue;
    if (has_mitigation_keys(&comp_logs[i].meta))
      continue;
    any_unmit = 1;
    const char *addr = meta_get(&comp_logs[i].meta, "addr");
    printf("  %-28s %s%s%s\n", comp_logs[i].name, addr ? "leaks " : "",
           addr ? addr : "no mitigation", addr ? " addresses" : "");
  }

  if (!any_unmit)
    printf("  All components have at least one mitigation key.\n");

  printf("\n");
}

void render_hardening_json(void) {
  printf("  \"hardening\": {\n");

  /* Exposure summary */
  int total_meta = 0, succeeded_count = 0;
  for (int i = 0; i < num_comp_logs; i++) {
    const char *method = meta_get(&comp_logs[i].meta, "method");
    if (!method || strcmp(method, "detection") == 0)
      continue;
    total_meta++;
    if (comp_logs[i].outcome == OUTCOME_SUCCESS)
      succeeded_count++;
  }
  printf("    \"exposure\": {\n");
  printf("      \"succeeded\": %d,\n", succeeded_count);
  printf("      \"total\": %d,\n", total_meta);
  printf("      \"note\": \"Detection-only components excluded\"\n");
  printf("    },\n");

  /* KASLR posture: distinguishes randomization-failed from active /
   * disabled / unsupported. See render_hardening_text() Section 0 for
   * the rationale. The state field is mutually exclusive (priorities:
   * unsupported > disabled > randomization_failed > active) so JSON
   * consumers can switch on it directly. */
  int rand_failed = 0, opt_out = 0;
  int n_rand_origins = 0;
  const char *rand_origins[16];
  for (int i = 0; i < num_scalar_facts; i++) {
    if (scalar_facts[i].value == 0)
      continue;
    if (scalar_facts[i].fact == SF_VIRT_KASLR_RANDOMIZATION_FAILED) {
      /* Virt-side randomisation failure drives the user-facing
       * "randomization_failed" posture: the JSON state mirrors the text
       * banner above, both of which describe the virt KASLR slot
       * entropy. */
      rand_failed = 1;
      if (n_rand_origins < 16)
        rand_origins[n_rand_origins++] =
            scalar_facts[i].origin[0] ? scalar_facts[i].origin : "unknown";
    } else if (scalar_facts[i].fact == SF_VIRT_KASLR_DISABLED) {
      /* Virtual disable drives the user-facing "disabled" posture; a
       * phys-only disable would still leave virt randomisation active. */
      opt_out = 1;
    }
  }

  const char *state;
  int slot_entropy_zero;
  int kernel_at_default;
  if (!KASLR_SUPPORTED) {
    state = "unsupported";
    slot_entropy_zero = 1;
    kernel_at_default = 0;
  } else if (opt_out) {
    state = "disabled";
    slot_entropy_zero = 1;
    kernel_at_default = 1;
  } else if (rand_failed) {
    state = "randomization_failed";
    slot_entropy_zero = 1;
    kernel_at_default = 0;
  } else {
    state = "active";
    slot_entropy_zero = 0;
    kernel_at_default = 0;
  }

  printf("    \"kaslr_posture\": {\n");
  printf("      \"state\": \"%s\",\n", state);
  printf("      \"slot_entropy_zero\": %s,\n",
         slot_entropy_zero ? "true" : "false");
  printf("      \"kernel_at_link_time_default\": %s,\n",
         kernel_at_default ? "true" : "false");
  printf("      \"detected_by\": [");
  for (int i = 0; i < n_rand_origins; i++) {
    if (i > 0)
      printf(", ");
    json_print_escaped(rand_origins[i]);
  }
  printf("]\n");
  printf("    },\n");

  /* Active defenses */
  printf("    \"active_defenses\": [\n");
  int first_def = 1;
  for (int g = 0; g < ngates; g++) {
    if (*gates[g].value_ptr < 0)
      continue;
    int active = sysctl_gate_active(&gates[g]);

    const char *gated_names[64];
    const char *blocked_names[64];
    const char *bypassed_names[64];
    int ngated = 0, nblocked = 0, nbypassed = 0;

    for (int i = 0; i < num_comp_logs; i++) {
      if (!component_has_gate(&comp_logs[i], &gates[g]))
        continue;
      if (ngated < 64)
        gated_names[ngated] = comp_logs[i].name;
      ngated++;
      if (comp_logs[i].outcome == OUTCOME_ACCESS_DENIED && nblocked < 64)
        blocked_names[nblocked++] = comp_logs[i].name;
      else if (comp_logs[i].outcome == OUTCOME_SUCCESS && nbypassed < 64)
        bypassed_names[nbypassed++] = comp_logs[i].name;
    }

    if (ngated == 0)
      continue;

    if (!first_def)
      printf(",\n");
    first_def = 0;

    printf("      {\n");
    printf("        \"gate\": \"%s\",\n", gates[g].display);
    printf("        \"value\": %d,\n", *gates[g].value_ptr);
    printf("        \"threshold\": %d,\n", gates[g].threshold);
    printf("        \"active\": %s,\n", active ? "true" : "false");

    printf("        \"components_gated\": [");
    for (int i = 0; i < ngated && i < 64; i++) {
      if (i > 0)
        printf(", ");
      json_print_escaped(gated_names[i]);
    }
    printf("],\n");

    printf("        \"components_blocked\": [");
    for (int i = 0; i < nblocked; i++) {
      if (i > 0)
        printf(", ");
      json_print_escaped(blocked_names[i]);
    }
    printf("],\n");

    printf("        \"components_bypassed\": [");
    for (int i = 0; i < nbypassed; i++) {
      if (i > 0)
        printf(", ");
      json_print_escaped(bypassed_names[i]);
    }
    printf("]\n");
    printf("      }");
  }
  printf("\n    ],\n");

  /* Lockdown */
  const char *lockdown_str;
  switch (sysctl_lockdown) {
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
         sysctl_lockdown >= LOCKDOWN_INTEGRITY ? "true" : "false");
  printf("    },\n");

  /* Available hardening */
  printf("    \"available_hardening\": [\n");
  int first_sug = 1;
  for (int g = 0; g < ngates; g++) {
    if (*gates[g].value_ptr < 0)
      continue;
    if (sysctl_gate_active(&gates[g]))
      continue;
    int gated = 0;
    for (int i = 0; i < num_comp_logs; i++) {
      if (component_has_gate(&comp_logs[i], &gates[g]))
        gated++;
    }
    if (gated == 0)
      continue;

    if (!first_sug)
      printf(",\n");
    first_sug = 0;

    printf("      {\n");
    printf("        \"action\": \"Set %s = %d\",\n", gates[g].display,
           gates[g].threshold);
    printf("        \"impact\": %d,\n", gated);
    printf("        \"detail\": \"Blocks unprivileged access for %d "
           "component%s\"\n",
           gated, gated == 1 ? "" : "s");
    printf("      }");
  }

  if (sysctl_lockdown < LOCKDOWN_INTEGRITY) {
    int lockdown_gated = 0;
    for (int i = 0; i < num_comp_logs; i++) {
      if (meta_get(&comp_logs[i].meta, "lockdown"))
        lockdown_gated++;
    }
    if (lockdown_gated > 0) {
      if (!first_sug)
        printf(",\n");
      first_sug = 0;
      printf("      {\n");
      printf("        \"action\": \"Enable kernel lockdown (integrity mode)\","
             "\n");
      printf("        \"impact\": %d,\n", lockdown_gated);
      printf("        \"detail\": \"Blocks klogctl() even with CAP_SYSLOG\"\n");
      printf("      }");
    }
  }
  printf("\n    ],\n");

  /* Patched vulnerabilities */
  printf("    \"patched_vulnerabilities\": {\n");
  int vuln_total = 0;
  struct {
    const char *name;
    const char *cve;
    const char *patch;
  } unpatched_json[16];
  int nunpatched_json = 0;

  for (int i = 0; i < num_comp_logs; i++) {
    const char *patch = meta_get(&comp_logs[i].meta, "patch");
    const char *cve = meta_get(&comp_logs[i].meta, "cve");
    if (!patch && !cve)
      continue;
    vuln_total++;
    if (comp_logs[i].outcome == OUTCOME_SUCCESS && nunpatched_json < 16) {
      unpatched_json[nunpatched_json].name = comp_logs[i].name;
      unpatched_json[nunpatched_json].cve = cve;
      unpatched_json[nunpatched_json].patch = patch;
      nunpatched_json++;
    }
  }

  printf("      \"total\": %d,\n", vuln_total);
  printf("      \"likely_patched\": %d,\n", vuln_total - nunpatched_json);
  printf("      \"possibly_unpatched\": [\n");
  for (int i = 0; i < nunpatched_json; i++) {
    if (i > 0)
      printf(",\n");
    printf("        {\"component\": ");
    json_print_escaped(unpatched_json[i].name);
    if (unpatched_json[i].cve) {
      printf(", \"cve\": ");
      json_print_escaped(unpatched_json[i].cve);
    }
    if (unpatched_json[i].patch) {
      printf(", \"patch\": ");
      json_print_escaped(unpatched_json[i].patch);
    }
    printf("}");
  }
  printf("\n      ]\n");
  printf("    },\n");

  /* Compile-time surface */
  printf("    \"compile_time_surface\": [\n");
  int first_cfg = 1;
  for (int i = 0; i < num_comp_logs; i++) {
    if (comp_logs[i].outcome != OUTCOME_SUCCESS)
      continue;
    const char *configs[4];
    int ncfg = meta_get_all(&comp_logs[i].meta, "config", configs, 4);
    if (ncfg == 0)
      continue;
    const char *addr = meta_get(&comp_logs[i].meta, "addr");
    for (int j = 0; j < ncfg; j++) {
      if (!first_cfg)
        printf(",\n");
      first_cfg = 0;
      printf("      {\"component\": ");
      json_print_escaped(comp_logs[i].name);
      printf(", \"config\": ");
      json_print_escaped(configs[j]);
      if (addr) {
        printf(", \"addr\": ");
        json_print_escaped(addr);
      }
      printf("}");
    }
  }
  printf("\n    ],\n");

  /* No mitigation */
  printf("    \"no_mitigation\": [\n");
  int first_nomit = 1;
  for (int i = 0; i < num_comp_logs; i++) {
    if (comp_logs[i].outcome != OUTCOME_SUCCESS)
      continue;
    const char *method = meta_get(&comp_logs[i].meta, "method");
    if (!method || strcmp(method, "detection") == 0)
      continue;
    if (has_mitigation_keys(&comp_logs[i].meta))
      continue;
    if (!first_nomit)
      printf(",\n");
    first_nomit = 0;
    const char *addr = meta_get(&comp_logs[i].meta, "addr");
    printf("      {\"component\": ");
    json_print_escaped(comp_logs[i].name);
    if (addr) {
      printf(", \"addr\": ");
      json_print_escaped(addr);
    }
    printf("}");
  }
  printf("\n    ]\n");

  printf("  }\n");
}
