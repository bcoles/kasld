// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: synthesize virt_page_offset from same-origin directmap + DRAM leaks.
//
// A component that leaks both a
// direct-map virtual address and a physical DRAM address pins the direct-map
// base: virt_page_offset = virt - phys + phys_base (the linear map's physical
// anchor — see the anchor note below). Grouping by origin and
// taking each origin's min(directmap virt) / min(phys DRAM) yields one
// candidate per origin; when all candidates agree within one KASLR alignment
// slot the result is trustworthy. On a static-direct-map arch
// (PAGE_OFFSET_FIXED
// == DIRECTMAP_STATIC: the linear-map base is a compile-time constant) the true
// base IS that single constant, so Q_PAGE_OFFSET pins to the cleanest (most
// large-page-aligned) candidate. Where the base is runtime-variable — x86_64
// (RANDOMIZE_MEMORY) and the decoupled arches whose base tracks RAM/firmware
// placement (arm64 memstart_addr, riscv64 kernel_map.page_offset, s390
// __identity_base) — the cleanest candidate is NOT guaranteed to be the base,
// so the proven [min_cand, max_cand] window is reported instead.
//
// Anchor: phys_base is the physical address the kernel maps at page_offset, and
// where to read it is the architecture's LINEAR_MAP_ANCHOR answer (api.h).
// LM_ANCHOR_PHYS_OFFSET arches supply it as the compile-time constant; on
// LM_ANCHOR_DRAM_BASE arches the kernel sets it from the base of DRAM at boot,
// so it is read from evidence as the lowest phys RAM POS_BASE and the rule
// declines when none was observed. LM_ANCHOR_UNKNOWABLE arches (arm64) get no
// derivation at all — the anchor is displaced from DRAM by an amount nothing
// unprivileged recovers, so a candidate built from the DRAM base is not merely
// imprecise but wrong by up to gigabytes, in either direction.
//
// This is the mechanism that reconstructs the EXACT randomized virt_page_offset
// on a live x86_64 (RANDOMIZE_MEMORY) host from a directmap leak — far tighter
// than the directmap_page_offset_bounds window or the VAS-floor lower bound.
// Reads the resolved Q_PAGE_OFFSET window (candidates must fall inside) and
// Q_VIRT_KASLR_ALIGN (the agreement tolerance). Inert when no paired VIRT
// directmap + PHYS RAM observation set with shared origin is present.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"
#include "include/kasld/regions.h"

#include <limits.h>
#include <string.h>

#define SYNTH_MAX_ORIGINS 16

/* PAGE_OFFSET_FIXED (from api.h, defined as DIRECTMAP_STATIC): 1 on every arch
 * whose direct-map base is a compile-time constant, 0 where it is runtime-
 * variable (x86_64 RANDOMIZE_MEMORY; arm64/riscv64/s390 RAM-/firmware-shifted).
 * On a fixed arch a within-align spread across origin candidates is pairing
 * noise, not uncertainty about a single true value, so the cleanest candidate
 * is the base; on a variable arch a mispaired candidate can be cleaner than the
 * true base, so only the spanning window is sound. */

/* Count of trailing zero bits = log2 of the largest power of two dividing v;
 * the cleanest (most large-page-aligned) candidate is the true direct-map base,
 * since a mispaired (v,p) only clears the 2 MiB PMD minimum, never the arch's
 * full PAGE_OFFSET alignment. */
/* Only the live branch uses this; on an UNKNOWABLE-anchor arch the rule
 * declines before any of it runs, and an unused static would warn. */
#if LINEAR_MAP_ANCHOR != LM_ANCHOR_UNKNOWABLE
static int trailing_zeros_ul(unsigned long v) {
  int n = 0;
  if (v == 0)
    return (int)(sizeof(v) * 8);
  while (!(v & 1ul)) {
    v >>= 1;
    n++;
  }
  return n;
}
#endif

int rule_phys_virt_synth(const struct evidence_set *ev,
                         const struct estimate *est, struct constraint *out,
                         int out_max) {
  if (out_max < 1)
    return 0;

#if LINEAR_MAP_ANCHOR == LM_ANCHOR_UNKNOWABLE
  /* The architecture places the linear map's physical anchor where no
   * unprivileged observation can find it, so the whole derivation is
   * unavailable and the rule declines. See LINEAR_MAP_ANCHOR in api.h for what
   * the anchor is and why arm64's cannot be recovered; there is no sound
   * one-sided bound to fall back on, because its displacement has no fixed
   * direction. */
  (void)ev;
  (void)est;
  (void)out;
  return 0;
#else

  struct {
    char origin[ORIGIN_LEN];
    unsigned long vmin, pmin;
  } og[SYNTH_MAX_ORIGINS];
  int n_og = 0;

  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->value_kind != OBS_ADDRESS || o->origin[0] == '\0')
      continue;
    int is_vdmap =
        (o->eff_type == KASLD_TYPE_VIRT && o->eff_region == REGION_DIRECTMAP);
    int is_pdram =
        (o->eff_type == KASLD_TYPE_PHYS && is_phys_dram_region(o->eff_region));
    if (!is_vdmap && !is_pdram)
      continue;

    int j = 0;
    for (; j < n_og; j++)
      if (strcmp(og[j].origin, o->origin) == 0)
        break;
    if (j == n_og) {
      if (n_og >= SYNTH_MAX_ORIGINS)
        continue;
      snprintf(og[n_og].origin, ORIGIN_LEN, "%s", o->origin);
      og[n_og].vmin = ULONG_MAX;
      og[n_og].pmin = ULONG_MAX;
      j = n_og++;
    }
    unsigned long a = obs_anchor(o);
    if (is_vdmap && a < og[j].vmin)
      og[j].vmin = a;
    if (is_pdram && a < og[j].pmin)
      og[j].pmin = a;
  }

  /* The anchor, from wherever this architecture keeps it (LINEAR_MAP_ANCHOR).
   */
#if LINEAR_MAP_ANCHOR == LM_ANCHOR_PHYS_OFFSET
  const unsigned long lm_base = (unsigned long)PHYS_OFFSET;
#else /* LM_ANCHOR_DRAM_BASE */
  /* The kernel set the anchor from the base of DRAM, so the lowest observed RAM
   * base names it — and the rule declines when none was observed rather than
   * guessing, since the pairing delta is then unknowable.
   *
   * Residual exposure, worth stating because it is the only one left: an
   * emitter reporting a bank the KERNEL did not take would put the anchor below
   * the real one, and low is the dangerous direction, since the pin below is
   * C_EQUALS. evidence_lowest_dram_base() reads REGION_RAM POS_BASE only —
   * the kernel's own account of its memory, not firmware's account of the
   * board — and is the same accessor dram_floor_bound trusts as a floor, so no
   * two rules can disagree about where DRAM starts. */
  unsigned long lm_base = 0;
  if (!evidence_lowest_dram_base(ev, &lm_base, NULL, NULL))
    return 0;
#endif

  const struct estimate *po = &est[Q_PAGE_OFFSET];
  unsigned long cand_lo = ULONG_MAX, cand_hi = 0;
  unsigned long best = 0; /* most-aligned candidate (the true base) */
  int best_tz = -1;
  int n_valid = 0; /* distinct origins contributing an agreeing candidate */
  for (int j = 0; j < n_og; j++) {
    unsigned long v = og[j].vmin, p = og[j].pmin;
    if (v == ULONG_MAX || p == ULONG_MAX)
      continue;
    if (p < lm_base) /* below the linear-map base: not a real directmap leak */
      continue;
    if (v < p)
      continue;
    unsigned long cand = v - p + lm_base;
    /* virt_page_offset (the direct-map base) is large-page aligned on every
     * supported arch — x86_64 RANDOMIZE_MEMORY aligns it to PUD_SIZE (1 GiB),
     * and every other arch's PAGE_OFFSET is at least PMD-aligned. A candidate
     * that isn't PMD-aligned is provably NOT the real base, which means the
     * paired (directmap virt, phys) leaks are NOT the same physical page — the
     * min/min pairing crossed two unrelated objects (e.g. a generic directmap
     * register value vs. a CR3/BSS leak). Discard it. Same soundness invariant
     * randomize_memory_page_offset enforces (PMD on Path 1, PUD on Path 2). */
    if (cand & ((2ul * 1024 * 1024) - 1))
      continue;
    if (!quantity_admits(Q_PAGE_OFFSET, po, cand))
      continue;
    n_valid++;
    if (cand < cand_lo)
      cand_lo = cand;
    if (cand > cand_hi)
      cand_hi = cand;
    int tz = trailing_zeros_ul(cand);
    if (tz > best_tz || (tz == best_tz && cand < best)) {
      best_tz = tz;
      best = cand;
    }
  }
  if (cand_lo == ULONG_MAX)
    return 0;

  unsigned long align = est[Q_VIRT_KASLR_ALIGN].lo;
  if (align < (unsigned long)KASLR_VIRT_ALIGN)
    align = (unsigned long)KASLR_VIRT_ALIGN;
  if (cand_hi - cand_lo > align) /* candidates disagree -> a bad pair */
    return 0;

  /* A single origin's min(directmap)/min(phys) is not provably the same
   * physical page, so one agreeing candidate can be a PMD-aligned mispairing.
   * Only >= 2 independent origins converging on the same value corroborate it
   * enough for the guaranteed window (CONF_DERIVED); a lone candidate is a
   * heuristic (CONF_HEURISTIC, likely-window only). */
  enum kasld_confidence synth_conf =
      (n_valid >= 2) ? CONF_DERIVED : CONF_HEURISTIC;

  int n = 0;
#if PAGE_OFFSET_FIXED
  /* Fixed-PAGE_OFFSET arch: the true direct-map base is a single architectural
   * constant, so an agreeing-within-align spread is pairing noise. Pin to the
   * cleanest (most-aligned) candidate rather than reporting a window. (When the
   * candidates are identical this is the same point the window would collapse
   * to anyway; the win is only when they differ within one slot.) */
  if (n < out_max) {
    struct constraint *c = &out[n++];
    memset(c, 0, sizeof(*c));
    c->q = Q_PAGE_OFFSET;
    c->op = C_EQUALS;
    c->value = best;
    c->conf = synth_conf;
    c->lineage_count = 0;
    snprintf(c->origin, ORIGIN_LEN, "phys_virt_synth");
  }
#else
  /* Randomized PAGE_OFFSET (x86_64): report the proven window. cand_hi ==
   * cand_lo still pins virt_page_offset exactly via lower==upper. */
  if (n < out_max) {
    struct constraint *c = &out[n++];
    memset(c, 0, sizeof(*c));
    c->q = Q_PAGE_OFFSET;
    c->op = C_LOWER_BOUND;
    c->value = cand_lo;
    c->conf = synth_conf;
    c->lineage_count = 0;
    snprintf(c->origin, ORIGIN_LEN, "phys_virt_synth");
  }
  if (n < out_max) {
    struct constraint *c = &out[n++];
    memset(c, 0, sizeof(*c));
    c->q = Q_PAGE_OFFSET;
    c->op = C_UPPER_BOUND;
    c->value = cand_hi;
    c->conf = synth_conf;
    c->lineage_count = 0;
    snprintf(c->origin, ORIGIN_LEN, "phys_virt_synth");
  }
#endif
  return n;
#endif /* anchor available */
}
