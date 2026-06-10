// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: arm64 VA_BITS discrimination from a VMEMMAP leak address.
//
// Sibling of arm64_va_bits_from_directmap.c, using the *upper* fixed
// boundary of arm64's VAS instead of the lower one. VMEMMAP_END is fixed at
// -SZ_1G = 0xffffffffc0000000 regardless of VA_BITS; VMEMMAP_START varies:
//
//   VA_BITS=48: PAGE_OFFSET = 0xffff000000000000, _PAGE_END(48) =
//               0xffff800000000000 → VMEMMAP_RANGE = 128 TiB,
//               VMEMMAP_SIZE ≈ 2 TiB (assumes the common sizeof(struct
//               page)=64), VMEMMAP_START ≈ 0xfffffdffc0000000.
//
//   VA_BITS=52: VMEMMAP_RANGE is 15.5×128 TiB and VMEMMAP_SIZE is PiB-scale,
//               so VMEMMAP_START is far below the VA_BITS=48 floor.
//
// Inference: a VIRT/VMEMMAP observation V_mm at an address strictly below
// VMEMMAP_START(VA48) cannot lie in VA_BITS=48's vmemmap region, so the kernel
// must be VA_BITS=52. Pin Q_VA_BITS=52 + the matching Q_PAGE_OFFSET ceiling at
// the VA52 floor.
//
// The opposite branch (V_mm ≥ VMEMMAP_START(VA48)) is *consistent with both*
// paging modes and so does not discriminate — the rule emits nothing for that
// case. The threshold is VMEMMAP_END - (128 TiB / 4 KiB) * sizeof(struct page);
// it is sensitive to sizeof(struct page), which SF_STRUCT_PAGE_BYTES supplies
// exactly (from BTF) when present, else the common 64-byte default
// (0xfffffdffc0000000). The resolver's confidence-priority handles a
// higher-confidence contradiction from a different source.
//
// arm64 only; inert elsewhere. Inert when no VIRT VMEMMAP observation is
// present.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"

#include <string.h>

#define ARM64_VMEMMAP_END 0xffffffffc0000000ul /* -SZ_1G; VA_BITS-invariant */
#define ARM64_VA52_PAGE_OFFSET 0xfff0000000000000ul

int rule_arm64_va_bits_from_vmemmap(const struct evidence_set *ev,
                                    const struct estimate *est,
                                    struct constraint *out, int out_max) {
  (void)est;
#if defined(__aarch64__)
  if (out_max < 1)
    return 0;

  /* Lowest VMEMMAP observation — any address below the VA48 floor is the
   * VA52-only witness we need. */
  unsigned long lowest = 0;
  enum kasld_confidence conf = CONF_UNKNOWN;
  uint32_t src = 0;
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->value_kind != OBS_ADDRESS ||
        o->eff_type != KASLD_TYPE_VIRT || o->eff_region != REGION_VMEMMAP)
      continue;
    unsigned long a = obs_anchor(o);
    if (a == 0)
      continue;
    if (src == 0 || a < lowest) {
      lowest = a;
      conf = o->conf;
      src = o->id;
    }
  }
  /* sizeof(struct page): exact from BTF (SF_STRUCT_PAGE_BYTES) when present,
   * else 64. A larger struct page lowers VMEMMAP_START(VA48) — i.e. lowers the
   * discrimination threshold — so an observation just below the 64-based line
   * is no longer mis-pinned to VA52. */
  unsigned long struct_page_bytes = 64ul;
  uint32_t sp_src = 0;
  enum kasld_confidence sp_conf = CONF_UNKNOWN;
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (o->valid && o->value_kind == OBS_SCALAR &&
        o->scalar_fact == SF_STRUCT_PAGE_BYTES && o->scalar_value >= 1 &&
        o->scalar_value <= (1ul << 20)) {
      struct_page_bytes = o->scalar_value;
      sp_src = o->id;
      sp_conf = o->conf;
      break;
    }
  }
  /* VMEMMAP_START(VA48) = VMEMMAP_END - (128 TiB / 4 KiB) * struct_page_bytes;
   * with the 64-byte default this is 0xfffffdffc0000000. */
  unsigned long va48_vmemmap_start =
      ARM64_VMEMMAP_END - (1ul << 35) * struct_page_bytes;

  if (src == 0 || lowest >= va48_vmemmap_start)
    return 0; /* no leak, or consistent with both modes (no discrimination) */

  int n = 0;
  if (n < out_max) {
    struct constraint *c = &out[n++];
    memset(c, 0, sizeof(*c));
    c->q = Q_VA_BITS;
    c->op = C_EQUALS;
    c->value = 52;
    c->conf = conf;
    c->derived_from[0] = src;
    c->lineage_count = 1;
    if (sp_src != 0) {
      c->derived_from[c->lineage_count++] = sp_src;
      if (sp_conf < c->conf)
        c->conf = sp_conf;
    }
    snprintf(c->origin, ORIGIN_LEN, "arm64_va_bits_from_vmemmap");
  }
  /* Q_PAGE_OFFSET upper bound at the VA52 floor (PAGE_OFFSET = -(1 << 52)). */
  if (n < out_max) {
    struct constraint *c = &out[n++];
    memset(c, 0, sizeof(*c));
    c->q = Q_PAGE_OFFSET;
    c->op = C_UPPER_BOUND;
    c->value = ARM64_VA52_PAGE_OFFSET;
    c->conf = conf;
    c->derived_from[0] = src;
    c->lineage_count = 1;
    if (sp_src != 0) {
      c->derived_from[c->lineage_count++] = sp_src;
      if (sp_conf < c->conf)
        c->conf = sp_conf;
    }
    snprintf(c->origin, ORIGIN_LEN, "arm64_va_bits_from_vmemmap");
  }
  return n;
#else
  (void)ev;
  (void)out;
  (void)out_max;
  return 0;
#endif
}
