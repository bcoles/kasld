// libFuzzer harness for the report model and the renderers — the path from a
// resolved engine state to the bytes an operator reads.
//
// The six sibling harnesses stop at the parsers, which is where untrusted bytes
// enter. Nothing exercises what happens after: the model built from the
// resolved estimates, and the five formats that draw it. That code carries the
// fixed-width table cells, the column-width arithmetic sized from the run's own
// content, and the model's bounded arrays — none of it reached by a search.
//
// The input is read as a SCRIPT OF LEGAL MOVES, not as struct bytes. Each
// record becomes a constraint applied through estimate_meet(), exactly as a
// rule would apply it, so every state this reaches is one the engine can
// actually produce. Filling `struct estimate` from raw bytes would instead
// explore states the lattice forbids — an interval with lo > hi, a finite set
// whose bitmask names candidates that do not exist — and every crash found
// there would describe a configuration that cannot occur.
//
// Build with the make fuzz target:
//   make fuzz FUZZ_CC=clang
//
// Run with the seed corpus:
//   build/fuzz/fuzz_render tests/fuzz/corpus/render/ -timeout=10 -max_len=4096

#include "../../src/capture.c"
#include "../../src/orchestrator.c"
#include "../../src/region_info.c"

#include <stdint.h>
#include <string.h>

/* One scripted move: a quantity, an operation and a confidence in the first
 * three bytes, then four bytes of operand and one of scale. */
#define MOVE_LEN 8

/* Operand scale. Addresses that matter to the renderers are the architecture's
 * own — a value uniformly drawn from the full 64-bit range lands outside every
 * window and narrows nothing, so most inputs would resolve to the untouched top
 * and the search would stall. Anchoring to the quantity's own honest top keeps
 * the operands where the interesting behaviour is. */
static unsigned long scaled_operand(enum kasld_quantity q, unsigned long raw) {
  struct estimate top;
  unsigned long lo = 0, hi = 0;
  if (!quantities[q].init_top)
    return raw;
  quantities[q].init_top(&top);
  if (quantities[q].lattice == LK_FINSET)
    return raw;
  quantity_window(q, &top, &lo, &hi);
  if (hi <= lo)
    return raw;
  /* A quantity whose honest top is the whole address space -- the module base
   * is one, deliberately, so an un-narrowed one reads as unbounded -- makes the
   * span one less than it can count, and span + 1 wraps to zero. Nothing needs
   * scaling there: every value is already inside the window. */
  if (hi - lo == ULONG_MAX)
    return raw;
  return lo + (raw % ((hi - lo) + 1));
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  struct estimate est[Q__COUNT];
  struct constraint cs[64];
  struct kasld_report rep;
  struct kasld_resolution_view gv, lv;
  int n_cs = 0;
  size_t off = 0;

  /* Every quantity at its architectural top: the state before any evidence,
   * which is what the engine starts from. */
  for (int q = 0; q < Q__COUNT; q++) {
    memset(&est[q], 0, sizeof(est[q]));
    if (quantities[q].init_top)
      quantities[q].init_top(&est[q]);
  }

  while (off + MOVE_LEN <= size && n_cs < (int)(sizeof(cs) / sizeof(cs[0]))) {
    const uint8_t *m = data + off;
    struct constraint *c = &cs[n_cs];
    unsigned long raw;

    memset(c, 0, sizeof(*c));
    c->q = (enum kasld_quantity)(m[0] % Q__COUNT);
    c->op = (enum constraint_op)(m[1] % (C_STRIDE + 1));
    /* CONF_UNKNOWN is not a level a rule emits; skip it so the confidence
     * floor is exercised over the levels that can actually appear. */
    c->conf = (enum kasld_confidence)(CONF_BRUTE + (m[2] % CONF_PARSED));

    raw = ((unsigned long)m[3] << 24) | ((unsigned long)m[4] << 16) |
          ((unsigned long)m[5] << 8) | (unsigned long)m[6];
    raw <<= (m[7] % 33); /* let the fuzzer reach high addresses too */
    c->value = scaled_operand(c->q, raw);

    /* The second operand's role is op-specific, and the lattice requires it to
     * be zero where the op does not use one. */
    if (c->op == C_EXCLUDE) {
      /* value2 is the hole's inclusive top, so it must not sit below value. An
       * operand near the top of the address space would wrap it there, feeding
       * the lattice a range it can never be handed and spending the fuzzer's
       * time on a shape no rule can emit. */
      unsigned long width = raw % 0x200000ul;
      c->value2 = (c->value > ULONG_MAX - width) ? ULONG_MAX : c->value + width;
    } else if (c->op == C_STRIDE)
      c->value2 = 1ul << (m[7] % 22); /* modulus: a power of two, never zero */

    c->id = (uint32_t)n_cs + 1;
    estimate_meet(&est[c->q], &quantities[c->q], c);
    n_cs++;
    off += MOVE_LEN;
  }

  /* Both resolutions read the same estimates here. The two differ in the
   * confidence floor they are counted at, which is what the builder varies. */
  gv.est = est;
  gv.cs = cs;
  gv.n_cs = n_cs;
  gv.floor = CONF_INFERRED;
  lv = gv;
  lv.floor = CONF_BRUTE;

  kasld_report_build(gv, lv, NULL, RPOSTURE_RANDOMIZED, 0, &rep);

  /* Read every field a format reads, so a bad projection is caught even where
   * no renderer is linked into this harness. */
  for (int i = 0; i < rep.n_quantities; i++) {
    const struct kasld_report_quantity *it = &rep.quantities[i];
    volatile unsigned long sink = it->align_min + it->entropy_top;
    (void)kasld_report_likely_is_tighter(it);
    (void)kasld_report_find(&rep, it->q);
    for (int g = 0; g < 2; g++) {
      const struct kasld_report_window *w = g ? &it->likely : &it->guaranteed;
      sink += w->lo + w->hi + w->candidates + (unsigned long)w->bits;
      for (int v = 0; v < w->n_values; v++)
        sink += w->values[v];
      for (int e = 0; e < w->excluded_listed; e++)
        sink += w->excluded[e].lo + w->excluded[e].hi;
    }
    (void)sink;
  }

  return 0;
}
