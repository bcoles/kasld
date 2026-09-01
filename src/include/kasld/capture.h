// This file is part of KASLD - https://github.com/bcoles/kasld
//
// The captured evidence store: what components said, recorded verbatim.
//
// A component is a separate process that prints tagged lines. Capture reads
// those lines, validates them against the static region table, and files them
// into one of three stores -- one per wire record kind. It records what a
// component said; it does not interpret what the value means. Deciding that a
// KERNEL_TEXT base is _stext and normalising it to the image base is analysis,
// and lives with the analysis.
//
//   results[]           `V` / `P` records: a located address
//   scalar_facts[]      `S` records: a system fact with no address
//   constraint_facts[]  `C` records: a bound on a quantity a component cannot
//                       state as an address
//
// merge_results() is the store's normal form rather than a step of analysis:
// it sorts into canonical content order and collapses duplicate records, so
// what survives is a function of the record SET and not of the order components
// happened to finish. Nothing is inferred here.
//
// Included from kasld/internal.h, after struct origin_set: a result carries its
// provenance as a bitset over component discovery slots, so the two cannot be
// separated. Not for components -- they emit through the scalar-argument
// helpers in api.h and the wire is the only thing that crosses.
// ---
// <bcoles@gmail.com>

#ifndef KASLD_CAPTURE_H
#define KASLD_CAPTURE_H

/* A result carries its provenance as a bitset over component discovery slots,
 * so this header needs struct origin_set and cannot stand on its own. Say so
 * here rather than let a direct include fail on an incomplete type, which names
 * a field instead of the fix. */
#ifndef KASLD_INTERNAL_H
#error "include kasld/internal.h instead; capture.h needs struct origin_set"
#endif

#include "api.h"

#include <stdint.h>
#include <string.h>

#define MAX_RESULTS 4096

struct result {
  enum kasld_addr_type type;
  enum kasld_region region;
  char name[NAME_LEN]; /* "" if no specific instance */

  kasld_addr_t lo, hi;
  kasld_addr_t sample;
  kasld_addr_t base_align;
  uint32_t set_mask;

  enum kasld_position pos;
  enum kasld_confidence conf;

  /* The components that corroborate this record, and method_set, the union of
   * their methods. */
  struct origin_set origins;
  uint16_t method_set; /* bitmask over enum kasld_method */
};

#define HAS_LO(r) ((r)->set_mask & LO_SET)
#define HAS_HI(r) ((r)->set_mask & HI_SET)
#define HAS_SAMPLE(r) ((r)->set_mask & SAMPLE_SET)
#define HAS_BASE_ALIGN(r) ((r)->set_mask & BASE_ALIGN_SET)

/* Zero-initialise a result. set_mask=0, no contributors, all enums to their
 * _UNKNOWN values, empty strings — all the correct unset state. */
static inline void result_init(struct result *r) { memset(r, 0, sizeof(*r)); }

/* Pick the most representative address from a result. Prefers a known
 * base (when pos=BASE and lo is set), else any interior sample, else
 * any set bound, else 0. Used by the engine bridge and the renderer
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

extern struct result results[MAX_RESULTS];
extern int num_results;

/* Scalar system facts collected from components' `S` wire records, parallel to
 * results[]. The engine bridge copies these to OBS_SCALAR observations; the
 * orchestrator and renderer also read them directly (e.g.
 * SF_VIRT_KASLR_DISABLED drives s->kaslr.disabled and the "Detected by:" list).
 */
struct scalar_fact_record {
  enum kasld_scalar_fact fact;
  unsigned long value;
  enum kasld_confidence conf;
  int origin; /* discovery slot of the producing component; -1 if unattributed
               */
};
#define MAX_SCALAR_FACTS 64
extern struct scalar_fact_record scalar_facts[MAX_SCALAR_FACTS];
extern int num_scalar_facts;

/* Direct constraints collected from components' `C` wire records, parallel to
 * scalar_facts[]. The engine bridge copies these to OBS_CONSTRAINT
 * observations, which a passthrough rule folds into the meet as the named C_*
 * constraint. A component uses this channel for a bound on a known quantity it
 * cannot state as a located address (see kasld_emit_constraint). */
struct constraint_fact_record {
  enum kasld_quantity q;
  enum constraint_op op;
  unsigned long value;
  enum kasld_confidence conf;
  int origin; /* discovery slot of the producing component; -1 if unattributed
               */
};
#define MAX_CONSTRAINT_FACTS 64
extern struct constraint_fact_record constraint_facts[MAX_CONSTRAINT_FACTS];
extern int num_constraint_facts;

/* Run the merge pass over results[]. Idempotent on its own output; called
 * after each collection state to deduplicate before the engine reads them. */
void merge_results(void);
/* Capture one component wire line into the store it belongs to. `origin` is the
 * producing component's discovery slot, which becomes the record's provenance;
 * `method` names how the emitting component obtained the address.
 * Each returns non-zero when the line was filed, zero when it was rejected --
 * a rejection is reported through the discard ledger, never dropped silently.
 */
/* Is this wire-carried text safe to keep? Rejects control characters and
 * over-long fields. Exported because the component-log side parses disposition
 * records off the same pipe and holds their text to the same rule. */
int wire_text_ok(const char *s, int allow_spaces);

int capture_result(const char *line, const char *method, int origin);
int capture_scalar(const char *line, int origin);
int capture_constraint(const char *line, int origin);

#endif /* KASLD_CAPTURE_H */
