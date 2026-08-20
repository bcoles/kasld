// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Quantity vocabulary for the evidential inference engine.
//
// A "quantity" is an unknown the analysis solves for (the virtual text base,
// PAGE_OFFSET, ...). Each quantity has a lattice (its value domain) and a
// `top` (the widest value any configuration could produce — the honest
// maximal-uncertainty starting point). Inference narrows from top toward the
// truth by meeting constraints; because meet is monotone, narrowing is sound
// iff top contains the true value (validated per-arch; see tests).
//
// This header has no dependency on the orchestrator internals — only the
// public confidence/region enums in api.h — so the estimate core can be
// built and tested standalone.
// ---
// <bcoles@gmail.com>

#ifndef KASLD_QUANTITY_H
#define KASLD_QUANTITY_H

#include "api.h"

/* The unknowns the engine resolves. Closed enum; Q__COUNT sizes the tables. */
enum kasld_quantity {
  Q_VIRT_IMAGE_BASE =
      0,              /* kernel image base (_text), virt; _stext=+STEXT_OFFSET*/
  Q_PHYS_IMAGE_BASE,  /* kernel image base (_text), phys (decoupled arch)    */
  Q_PAGE_OFFSET,      /* direct-map base / VAS origin               */
  Q_VMALLOC_BASE,     /* x86_64 RANDOMIZE_MEMORY vmalloc base       */
  Q_VMEMMAP_BASE,     /* x86_64 RANDOMIZE_MEMORY vmemmap base       */
  Q_MODULE_BASE,      /* module region base: lowest address the      */
                      /* module allocator can hand out, virt         */
  Q_VIRT_KASLR_ALIGN, /* virtual KASLR step (alignment)             */
  Q_PHYS_KASLR_ALIGN, /* physical KASLR step                        */
  Q_VA_BITS,          /* paging level / VA width (finite set)       */
  Q__COUNT,
};

/* Q_* <-> wire token, single source of truth for both directions. Header-only
 * (like kasld_scalar_fact_wire_table in api.h) so a component's emit side and
 * the orchestrator's parse side share one mapping without linking quantities.c
 * — the tokens match the human `name` field in that table. */
static const char *const kasld_quantity_wire_table[Q__COUNT] = {
    [Q_VIRT_IMAGE_BASE] = "virt_image_base",
    [Q_PHYS_IMAGE_BASE] = "phys_image_base",
    [Q_PAGE_OFFSET] = "virt_page_offset",
    [Q_VMALLOC_BASE] = "virt_vmalloc_base",
    [Q_VMEMMAP_BASE] = "virt_vmemmap_base",
    [Q_MODULE_BASE] = "virt_module_base",
    [Q_VIRT_KASLR_ALIGN] = "virt_kaslr_align",
    [Q_PHYS_KASLR_ALIGN] = "phys_kaslr_align",
    [Q_VA_BITS] = "va_bits",
};
/* The [Q__COUNT] dimension keeps the table indexable for every Q_* (a missing
 * entry is a NULL hole, not out of bounds); it does NOT make the table
 * complete. Completeness — every Q_* has a non-NULL token, and tokens
 * round-trip — is enforced at runtime by test_wire_tables_complete
 * (tests/test_engine.c), since a sizeof check cannot see a NULL interior
 * initialiser. */

static inline const char *kasld_quantity_wire(enum kasld_quantity q) {
  if ((unsigned)q >= Q__COUNT)
    return NULL;
  return kasld_quantity_wire_table[q];
}

/* Returns Q__COUNT when the token names no known quantity. */
static inline enum kasld_quantity kasld_quantity_from_wire(const char *s) {
  for (int i = 0; i < Q__COUNT; i++)
    if (kasld_quantity_wire_table[i] &&
        strcmp(s, kasld_quantity_wire_table[i]) == 0)
      return (enum kasld_quantity)i;
  return Q__COUNT;
}

/* Lattice kind selects the meet operation and the bottom test.
 *  - LK_INTERVAL: value is [lo, hi]; meet narrows the interval; bottom = lo>hi.
 *  - LK_MAXALIGN: value is the largest known alignment (power of two); meet
 *    takes the max; never bottom (max of powers of two is a power of two).
 *  - LK_FINSET:   value is a bitmask of still-possible candidates indexed
 *    into quantity_def.candidates[]; meet intersects; bottom = empty mask. */
enum lattice_kind {
  LK_INTERVAL = 0,
  LK_MAXALIGN,
  LK_FINSET,
};

struct estimate; /* defined in estimate.h */

/* Per-quantity definition. The table `quantities[Q__COUNT]` lives in
 * quantities.c and is compiled per-arch (init_top reads arch constants). */
struct quantity_def {
  const char *name;
  enum lattice_kind lattice;
  /* Initialise an estimate to this quantity's honest top (widest value). */
  void (*init_top)(struct estimate *e);
  /* Finite-set candidates (LK_FINSET only; NULL/0 otherwise). The estimate's
   * bitmask has one bit per entry here; bit i set means candidates[i] is
   * still possible. */
  const unsigned long *candidates;
  int n_candidates;
};

/* Upper bound on n_candidates. An LK_FINSET estimate stores its live set as a
 * bitmask in a single unsigned long, so a longer list would have candidates
 * with no bit to live in — and `1ul << i` past the word width is undefined
 * rather than merely wrong. Every candidate table is checked against this at
 * compile time in quantities.c, so the meet loop can shift without a runtime
 * guard. */
#define KASLD_FINSET_MAX_CANDIDATES ((int)(sizeof(unsigned long) * 8))

extern const struct quantity_def quantities[Q__COUNT];

#endif /* KASLD_QUANTITY_H */
