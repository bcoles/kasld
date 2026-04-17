// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Internal header for kasld orchestrator.
// Shared types and extern declarations between orchestrator.c (core) and
// render.c.
// ---
// <bcoles@gmail.com>

#ifndef KASLD_INTERNAL_H
#define KASLD_INTERNAL_H

#include "kasld.h"

#include <stddef.h>

#ifndef VERSION
#define VERSION "unknown"
#endif

/* =========================================================================
 * Constants
 * =========================================================================
 */
#define MAX_COMPONENTS 128
#define MAX_RESULTS 512
#define LABEL_LEN 64
#define SECTION_LEN 32
#define METHOD_LEN 16
#define MAX_DERIVED 16
#define MAX_COMPONENT_LINES 64
#define MAX_LINE_LEN 512

/* =========================================================================
 * ANSI color helpers (gated by color_output flag)
 * =========================================================================
 */
#define C_RESET "\033[0m"
#define C_BOLD "\033[1m"
#define C_DIM "\033[2m"
#define C_GREEN "\033[32m"
#define C_YELLOW "\033[33m"
#define C_RED "\033[31m"
#define C_CYAN "\033[36m"
#define C_MAGENTA "\033[35m"

extern int color_output; /* forward declaration for c() */
static inline const char *c(const char *code) {
  return color_output ? code : "";
}

/* =========================================================================
 * Shared structures
 * =========================================================================
 */

/* Runtime memory layout (initialized from compile-time arch constants) */
struct kasld_layout {
  unsigned long page_offset;
  unsigned long kernel_vas_start;
  unsigned long kernel_vas_end;
  unsigned long kernel_base_min;
  unsigned long kernel_base_max;
  unsigned long modules_start;
  unsigned long modules_end;
  unsigned long kernel_align;
  unsigned long text_offset;
  unsigned long kernel_text_default;
  unsigned long kaslr_base_min;
  unsigned long kaslr_base_max;
  unsigned long kaslr_align;
};

/* Single tagged result from a component */
struct result {
  char type;
  char section[SECTION_LEN];
  unsigned long raw;
  unsigned long aligned;
  char label[LABEL_LEN];
  char method[METHOD_LEN];
  int valid;
};

/* Per-component stdout capture (for --verbose --json) */
struct component_log {
  char name[256];
  int exit_code;
  char lines[MAX_COMPONENT_LINES][MAX_LINE_LEN];
  int num_lines;
};

/* KASLR analysis results */
struct kaslr_info {
  int disabled;
  int unsupported;
  unsigned long default_addr;
  /* Virtual KASLR */
  unsigned long vtext;
  long vslide;
  unsigned long vslots;
  int vbits;
  unsigned long vslot_idx;
  int vslot_valid;
  /* Physical KASLR */
  unsigned long ptext;
  long pslide;
  unsigned long pslots;
  int pbits;
  int has_phys;
};

/* Cross-section derived address */
struct derived_addr {
  char type;
  char section[SECTION_LEN];
  unsigned long addr;
  unsigned long addr_hi; /* nonzero = range estimate */
  char label[64];
  char via[128];
};

/* Top-level analysis summary (compute-then-render pipeline) */
struct summary {
  struct kaslr_info kaslr;
  struct derived_addr derived[MAX_DERIVED];
  int num_derived;
  int decoupled_note; /* true when phys results exist but can't derive vtext */
};

/* =========================================================================
 * Shared globals (defined in orchestrator.c)
 * =========================================================================
 */
extern int verbose;
extern int json_output;
extern int oneline_output;
extern int markdown_output;
/* color_output declared above (before c()) */

extern struct kasld_layout layout;
extern struct result results[MAX_RESULTS];
extern int num_results;
extern struct component_log comp_logs[MAX_COMPONENTS];
extern int num_comp_logs;

/* =========================================================================
 * Shared functions (defined in orchestrator.c)
 * =========================================================================
 */
unsigned long group_consensus(char type, const char *section);
void group_range(char type, const char *section, unsigned long *lo,
                 unsigned long *hi);
void inject_kaslr_defaults(struct summary *s);
void compute_kaslr_info(struct summary *s);
void compute_derived_addrs(struct summary *s);

/* =========================================================================
 * Rendering functions (defined in render.c)
 * =========================================================================
 */
void print_summary(void);

#endif /* KASLD_INTERNAL_H */
