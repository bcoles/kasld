// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: synthesize virt_page_offset from same-origin directmap + DRAM leaks.
//
// A component that leaks both a
// direct-map virtual address and a physical DRAM address pins the direct-map
// base: virt_page_offset = virt - phys + PHYS_OFFSET. Grouping by origin and
// taking each origin's min(directmap virt) / min(phys DRAM) yields one
// candidate per origin; when all candidates agree within one KASLR alignment
// slot the result is trustworthy. On a fixed-PAGE_OFFSET arch (everything but
// x86_64) the true base is a single constant, so we pin Q_PAGE_OFFSET to the
// cleanest (most large-page-aligned) candidate; on x86_64 (randomized base) we
// report the proven [min_cand, max_cand] window instead.
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

/* PAGE_OFFSET_FIXED (from api.h): 1 on every arch whose direct-map base is a
 * fixed constant, 0 on x86_64 where RANDOMIZE_MEMORY slides it. On a fixed arch
 * a within-align spread across origin candidates is pairing noise, not genuine
 * uncertainty about a single true value — so we pin to the cleanest candidate
 * rather than leaving a window. */

/* Count of trailing zero bits = log2 of the largest power of two dividing v;
 * the cleanest (most large-page-aligned) candidate is the true direct-map base,
 * since a mispaired (v,p) only clears the 2 MiB PMD minimum, never the arch's
 * full PAGE_OFFSET alignment. */
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

int rule_phys_virt_synth(const struct evidence_set *ev,
                         const struct estimate *est, struct constraint *out,
                         int out_max) {
  if (out_max < 1)
    return 0;

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

  const struct estimate *po = &est[Q_PAGE_OFFSET];
  unsigned long cand_lo = ULONG_MAX, cand_hi = 0;
  unsigned long best = 0; /* most-aligned candidate (the true base) */
  int best_tz = -1;
  for (int j = 0; j < n_og; j++) {
    unsigned long v = og[j].vmin, p = og[j].pmin;
    if (v == ULONG_MAX || p == ULONG_MAX)
      continue;
#if PHYS_OFFSET
    if (p < (unsigned long)PHYS_OFFSET) /* below the DRAM base: not a leak */
      continue;
#endif
    if (v < p)
      continue;
    unsigned long cand = v - p + (unsigned long)PHYS_OFFSET;
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
    if (cand < po->lo || cand > po->hi)
      continue;
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
    c->conf = CONF_DERIVED;
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
    c->conf = CONF_DERIVED;
    c->lineage_count = 0;
    snprintf(c->origin, ORIGIN_LEN, "phys_virt_synth");
  }
  if (n < out_max) {
    struct constraint *c = &out[n++];
    memset(c, 0, sizeof(*c));
    c->q = Q_PAGE_OFFSET;
    c->op = C_UPPER_BOUND;
    c->value = cand_hi;
    c->conf = CONF_DERIVED;
    c->lineage_count = 0;
    snprintf(c->origin, ORIGIN_LEN, "phys_virt_synth");
  }
#endif
  return n;
}
