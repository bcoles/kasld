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

/* Hardening assessment — appended to text mode under -H, embedded in JSON
 * mode under -H -j. Defined in src/render/hardening.c. */
void render_hardening_text(void);
void render_hardening_json(void);

#endif /* KASLD_RENDER_INTERNAL_H */
