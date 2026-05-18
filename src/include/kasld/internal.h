// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Internal header for kasld orchestrator. Shared types and extern
// declarations between orchestrator.c, render.c, and the region_info table.
//
// Components don't include this — they only need kasld/api.h.
// ---
// <bcoles@gmail.com>

#ifndef KASLD_INTERNAL_H
#define KASLD_INTERNAL_H

#include "api.h"

#include <stddef.h>
#include <stdint.h>

#ifndef VERSION
#define VERSION "unknown"
#endif

/* =========================================================================
 * Constants
 * =========================================================================
 */
#define MAX_COMPONENTS 128
#define MAX_RESULTS 4096
#define NAME_LEN 48   /* specific instance: kernel symbol, ACPI ID, BDF, ... */
#define ORIGIN_LEN 64 /* component name (orchestrator-filled) */
#define METHOD_LEN 16 /* method: meta value */
#define MAX_PROVENANCE 8 /* cap on merged-record contributors */
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
 * Runtime memory layout (initialized from compile-time arch constants,
 * may be adjusted at runtime by LAYOUT_ADJUST plugins)
 * =========================================================================
 */
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
  /* Physical KASLR range (PHYS_VIRT_DECOUPLED arches only; zero otherwise). */
  unsigned long phys_kaslr_base_min;
  unsigned long phys_kaslr_base_max;
  unsigned long phys_kaslr_align;
};

/* =========================================================================
 * Result: (extent, position, confidence) over a typed region
 *
 * Optionality is via set_mask bits, never sentinel values — lo=0 and
 * hi=ULONG_MAX are both legitimate addresses. HAS_LO/HAS_HI/HAS_SAMPLE/
 * HAS_BASE_ALIGN are the only correct "is this field meaningful?" checks.
 *
 * `pos` describes what `sample` represents (BASE/TOP/INTERIOR/UNKNOWN).
 * It is NEVER a check for "do we have a known base?" — that is HAS_LO(r).
 *
 * Provenance is owned, fixed-cap arrays. The struct lives in a static
 * results[] table; pointer-to-transient-buffer fields would dangle.
 * ========================================================================= */

enum kasld_set_bits {
  LO_SET = 1u << 0,
  HI_SET = 1u << 1,
  SAMPLE_SET = 1u << 2,
  BASE_ALIGN_SET = 1u << 3,
};

struct result {
  enum kasld_addr_type type;
  enum kasld_region region;
  char name[NAME_LEN]; /* "" if no specific instance */

  unsigned long lo, hi;
  unsigned long sample;
  unsigned long base_align;
  uint32_t set_mask;

  enum kasld_position pos;
  enum kasld_confidence conf;

  /* Provenance — earliest contributor at index 0. */
  char origins[MAX_PROVENANCE][ORIGIN_LEN];
  char methods[MAX_PROVENANCE][METHOD_LEN];
  uint8_t provenance_count;
};

#define HAS_LO(r) ((r)->set_mask & LO_SET)
#define HAS_HI(r) ((r)->set_mask & HI_SET)
#define HAS_SAMPLE(r) ((r)->set_mask & SAMPLE_SET)
#define HAS_BASE_ALIGN(r) ((r)->set_mask & BASE_ALIGN_SET)

/* Zero-initialise a result. set_mask=0, provenance_count=0, all enums to
 * their _UNKNOWN values, empty strings — all the correct unset state. */
static inline void result_init(struct result *r) { memset(r, 0, sizeof(*r)); }

/* True iff the region represents physical addresses that live in DRAM —
 * i.e., addresses in physical RAM rather than MMIO or virtual-only
 * abstract spaces (PAGE_OFFSET/DIRECTMAP/VMALLOC/VMEMMAP). Includes the
 * kernel-image regions because the kernel is loaded into RAM physically.
 *
 * Inference plugins that consume "phys DRAM" addresses use this:
 * dram_bound, dram_ceiling, meminfo_phys_ceiling, phys_virt_synth,
 * directmap_page_offset_bounds, riscv64_non_efi_phys_base. */
static inline int is_phys_dram_region(enum kasld_region region) {
  switch (region) {
  case REGION_RAM:
  case REGION_DMA:
  case REGION_DMA32:
  case REGION_INITRD:
  case REGION_RESERVED_MEM:
  case REGION_SWIOTLB:
  case REGION_VMCOREINFO:
  case REGION_CRASHKERNEL:
  case REGION_PMEM:
  case REGION_ACPI_TABLE:
  case REGION_ACPI_NVS:
  case REGION_NUMA_NODE:
  case REGION_KERNEL_TEXT:
  case REGION_KERNEL_DATA:
  case REGION_KERNEL_BSS:
  case REGION_KERNEL_IMAGE:
    return 1;
  default:
    return 0;
  }
}

/* True iff the region is part of the kernel image — text, data, bss, or
 * the image-as-a-whole. The phys-text-base randomization window in the
 * physical layout box is rendered with only these regions inside;
 * unrelated leaks (MMIO, reserved memory, ...) whose address happens to
 * fall numerically in the window are excluded — they tell us nothing
 * about the text base location. */
static inline int is_kernel_image_region(enum kasld_region region) {
  switch (region) {
  case REGION_KERNEL_TEXT:
  case REGION_KERNEL_DATA:
  case REGION_KERNEL_BSS:
  case REGION_KERNEL_IMAGE:
    return 1;
  default:
    return 0;
  }
}

/* Pick the most representative address from a result. Prefers a known
 * base (when pos=BASE and lo is set), else any interior sample, else
 * any set bound, else 0. Used by inference plugins and the renderer
 * when they need a single representative address. */
static inline unsigned long anchor_addr(const struct result *r) {
  if (!r)
    return 0;
  if (r->pos == POS_BASE && HAS_LO(r))
    return r->lo;
  if (HAS_SAMPLE(r))
    return r->sample;
  if (HAS_LO(r))
    return r->lo;
  if (HAS_HI(r))
    return r->hi;
  return 0;
}

/* =========================================================================
 * Region info table
 *
 * Per-region: canonical section name (for render grouping), default base
 * alignment, and VAS-bound resolver. derive_vas != NULL means the region's
 * bounds are a function of runtime layout; otherwise static_vas applies.
 *
 * derive_vas implementations must produce valid bounds for any layout
 * state, including initial defaults — never crash, never return inverted
 * ranges. Compiled per-arch via the arch header pattern.
 * ========================================================================= */
struct region_info {
  const char *wire_name;       /* token on the wire (also kasld_region_wire) */
  const char *section_name;    /* render grouping; "" allowed */
  unsigned long default_align; /* 0 = no default */
  /* VAS resolution. derive_vas != NULL → use it; else use static_vas.
   * REGION_UNKNOWN: both zero/NULL — result_in_bounds short-circuits. */
  struct {
    unsigned long lo, hi;
  } static_vas;
  void (*derive_vas)(const struct kasld_layout *, unsigned long *lo,
                     unsigned long *hi);
};

extern const struct region_info region_info[REGION__COUNT];

/* =========================================================================
 * Runtime helpers
 * ========================================================================= */

/* True iff every set bound on `r` lies within the region's runtime VAS
 * (resolved per region_info[r->region]). Returns false for REGION_UNKNOWN
 * (forgotten-region-assignment safe). */
int result_in_bounds(const struct result *r, const struct kasld_layout *ly);

/* Trust ranking for confidences. PARSED=6, DERIVED=5, INFERRED=4,
 * HEURISTIC=3, TIMING=2, BRUTE=1, UNKNOWN=0. */
int conf_weight(enum kasld_confidence c);

/* Walk the result set; return the record best matching (type, region).
 * Preference: no-name first (canonical region anchor), then any name —
 * within each tier the highest-confidence record wins, ties broken by
 * earliest record index. Returns NULL when no match. Safe pre- or post-
 * merge. */
const struct result *select_anchor(enum kasld_addr_type type,
                                   enum kasld_region region);

/* Run the merge pass over results[]. Idempotent on its own output;
 * called between collection and the first inference phase, and at the
 * start of each subsequent convergence pass. */
void merge_results(void);

/* Adjust layout when runtime PAGE_OFFSET differs from the compile-time
 * default. Called by the layout_adjust inference plugin. */
void adjust_for_page_offset(unsigned long new_po);

/* =========================================================================
 * Component metadata, logs, outcomes — unchanged from before.
 * ========================================================================= */
#define KASLD_EXIT_UNAVAILABLE 69
#define KASLD_EXIT_NOPERM 77

enum component_outcome {
  OUTCOME_SUCCESS,
  OUTCOME_NO_RESULT,
  OUTCOME_UNAVAILABLE,
  OUTCOME_ACCESS_DENIED,
  OUTCOME_TIMEOUT,
};

#define META_MAX_ENTRIES 32
#define META_KEY_LEN 32
#define META_VALUE_LEN 256

struct meta_entry {
  char key[META_KEY_LEN];
  char value[META_VALUE_LEN];
};

struct component_meta {
  struct meta_entry entries[META_MAX_ENTRIES];
  int num_entries;
};

struct component_log {
  char name[256];
  int exit_code;
  enum component_outcome outcome;
  char lines[MAX_COMPONENT_LINES][MAX_LINE_LEN];
  int num_lines;
  char *explain;
  struct component_meta meta;
};

struct component_stats {
  int total;
  int succeeded;
  int no_result;
  int unavailable;
  int access_denied;
  int timed_out;
};

/* =========================================================================
 * KASLR analysis summary
 * ========================================================================= */
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
  /* Memory KASLR (x86_64 CONFIG_RANDOMIZE_MEMORY) */
  unsigned long page_offset_min;
  unsigned long page_offset_max;
  unsigned long vmalloc_min;
  unsigned long vmalloc_max;
  unsigned long vmemmap_min;
  unsigned long vmemmap_max;
};

struct summary {
  struct kaslr_info kaslr;
  int decoupled_note;
  struct component_stats stats;
};

/* =========================================================================
 * Shared globals (defined in orchestrator.c)
 * ========================================================================= */
extern int verbose;
extern int quiet;
extern int json_output;
extern int oneline_output;
extern int markdown_output;
extern int explain_mode;
extern int hardening_mode;
extern int sysctl_kptr_restrict;
extern int sysctl_dmesg_restrict;
extern int sysctl_perf_event_paranoid;

enum lockdown_mode {
  LOCKDOWN_UNAVAILABLE = -1,
  LOCKDOWN_NONE = 0,
  LOCKDOWN_INTEGRITY,
  LOCKDOWN_CONFIDENTIALITY,
};
extern enum lockdown_mode sysctl_lockdown;

extern struct kasld_layout layout;
extern struct result results[MAX_RESULTS];
extern int num_results;
extern struct component_log comp_logs[MAX_COMPONENTS];
extern int num_comp_logs;

/* =========================================================================
 * Shared functions (defined in orchestrator.c)
 * ========================================================================= */
const char *meta_get(const struct component_meta *m, const char *key);
int meta_get_all(const struct component_meta *m, const char *key,
                 const char **values, int max_values);
void inject_kaslr_defaults(struct summary *s);
void compute_component_stats(struct summary *s);
void compute_kaslr_info(struct summary *s);

/* =========================================================================
 * Rendering (defined in render.c)
 * ========================================================================= */
void print_summary(void);

#endif /* KASLD_INTERNAL_H */
