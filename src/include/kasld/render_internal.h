// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Render-layer cross-file glue. Used to share helpers between the
// per-output-mode files (src/render/*.c) and the dispatcher (src/render.c).
// Public consumers of the render layer use only `render_summary()` from
// kasld/internal.h — this header is internal to the renderer.
// ---
// <bcoles@gmail.com>

#ifndef KASLD_RENDER_INTERNAL_H
#define KASLD_RENDER_INTERNAL_H

#include "internal.h"

#include <stddef.h>

/* -------------------------------------------------------------------------
 * Shared formatting helpers — defined in src/render.c.
 * -------------------------------------------------------------------------
 */
const char *human_size(unsigned long bytes, char *buf, size_t bufsz);

/* Result-model helpers (mirror anchor_addr(). methods[0] is the canonical
 * single-value method; origins are iterated as r->origins[0..provenance_count]
 * at the consuming renderer). */
const char *result_method(const struct result *r);
const char *result_section(const struct result *r);
int in_bounds(const struct result *r);

/* Display heading for a (type, section) bucket. NULL for metadata-only
 * sections (e.g. "pageoffset") that have no leak-group view. */
const char *section_display_name(enum kasld_addr_type type,
                                 const char *section);

/* Number of CONF_DERIVED records currently in results[]. */
int count_derived(void);

/* Consensus over (type, section, optional region_filter). See the comment
 * on section_consensus_pick in render.c for the selection rule. */
unsigned long section_consensus(enum kasld_addr_type type, const char *section,
                                enum kasld_region region_filter);
void section_consensus_info(enum kasld_addr_type type, const char *section,
                            enum kasld_region region_filter,
                            const char **best_method, int *n_sources,
                            int *n_conflicts);

/* (type, section) extent across all in-bounds results. lo/hi = 0 when none. */
void section_range(enum kasld_addr_type type, const char *section,
                   unsigned long *out_lo, unsigned long *out_hi);

/* JSON string escaper — used by json.c and hardening.c. */
void json_print_escaped(const char *s);

/* -------------------------------------------------------------------------
 * Per-mode entry points — each is defined in one src/render/<mode>.c file.
 * render_summary() in render.c dispatches to these based on the output flags.
 * -------------------------------------------------------------------------
 */
void render_text(const struct summary *s);
void render_json(const struct summary *s);
void render_oneline(const struct summary *s);
void render_markdown(const struct summary *s);

/* -------------------------------------------------------------------------
 * Hardening assessment model.
 *
 * build_hardening_report() walks the component logs / scalar facts / sysctl
 * gates ONCE and fills this structure; the text, json, and markdown hardening
 * renderers then consume it, so the section-derivation logic lives in exactly
 * one place. Each renderer still chooses how to present (and which fields to
 * show): json omits the side-channel section and the dmesg-fallback
 * suggestion; only text annotates ✓/⚠/✗ and residual counts. Raw origin
 * strings are stored verbatim (empty allowed) so each format applies its own
 * "(unknown)" / "unknown" fallback.
 * -------------------------------------------------------------------------
 */
#define HR_NAME_MAX 64
#define HR_GATES_MAX 4
#define HR_VULNS_MAX 16
#define HR_SURFACE_MAX 64
#define HR_HW_MAX 64
#define HR_NOMIT_MAX 128
#define HR_SUGG_MAX 8

enum hr_posture {
  HR_POSTURE_ACTIVE = 0,
  HR_POSTURE_RANDOMIZATION_FAILED,
  HR_POSTURE_DISABLED,
  HR_POSTURE_UNSUPPORTED,
};

struct hr_gate {
  const char *display;
  int value, threshold, active;
  int gated, blocked, bypassed, fallback; /* full counts (names may be fewer) */
  const char *gated_names[HR_NAME_MAX];
  int n_gated_names;
  const char *blocked_names[HR_NAME_MAX];
  int n_blocked_names;
  const char *bypassed_names[HR_NAME_MAX];
  int n_bypassed_names;
};

struct hr_suggestion {
  const char *display;
  int threshold;
  int impact;
};
struct hr_vuln {
  const char *name, *cve, *patch;
};
struct hr_surface {
  const char *name, *config, *addr;
};
struct hr_hw {
  const char *name, *hardware, *addr;
  int succeeded;
};
struct hr_nomit {
  const char *name, *addr;
};

struct hardening_report {
  int succeeded, total; /* exposure: non-detection components */

  /* KASLR posture. rand_detectors[] is the raw set of randomization-failure
   * witnesses (independent of the prioritised posture state, which json uses);
   * the text banner fires whenever n_rand_detectors > 0. */
  enum hr_posture posture;
  int slot_entropy_zero, kernel_at_default;
  const char *rand_detectors[HR_NAME_MAX];
  int n_rand_detectors;

  struct hr_gate gates[HR_GATES_MAX];
  int n_gates;  /* gates with a readable value and >= 1 gated component */
  int lockdown; /* enum lockdown_state */

  struct hr_suggestion gate_suggestions[HR_SUGG_MAX];
  int n_gate_suggestions;
  int suggest_lockdown, lockdown_impact;
  int suggest_dmesg_fallback, dmesg_fallback_count; /* text-only suggestion */

  int vuln_total;
  struct hr_vuln vulns[HR_VULNS_MAX]; /* succeeded (possibly unpatched) */
  int n_vulns;

  struct hr_surface surface[HR_SURFACE_MAX];
  int n_surface;

  struct hr_hw hw[HR_HW_MAX]; /* side-channels (text-only section) */
  int n_hw, hw_succeeded;

  struct hr_nomit nomit[HR_NOMIT_MAX];
  int n_nomit;
};

/* Build the model from the global component logs / scalar facts / gates. */
void build_hardening_report(struct hardening_report *r);

/* Hardening assessment renderers — each consumes a built report. text is
 * appended to text mode under -H; json is embedded under -H -j; markdown is
 * appended to markdown mode under -H -m. Defined in src/render/hardening.c. */
void render_hardening_text(void);
void render_hardening_json(void);
void render_hardening_markdown(void);

#endif /* KASLD_RENDER_INTERNAL_H */
