// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: riscv64 text base from the FDT kaslr-seed (seed-VALUE path).
//
// On a non-EFI riscv64 boot the
// KASLR offset is derived deterministically from the FDT /chosen/kaslr-seed:
// the kernel picks slot (seed % nr_pos) of PMD_SIZE within a PUD, where
// nr_pos = (PUD_SIZE - image_size) / PMD_SIZE.
//
//   Path 1 (kernel size bracketed to one slot): image_base == KERNEL_LINK_ADDR
//                                  + (seed % nr_pos) * PMD_SIZE  (pin), fired
//                                  only when a sound [min, max] size bracket
//                                  determines nr_pos uniquely (see below)
//   Path 2 (size not bracketed):   image_base <= max over i in [1,nr_pos_max]
//   of
//                                  KERNEL_LINK_ADDR + (seed % i) * PMD_SIZE
//                                  with nr_pos_max = (PUD_SIZE - gap) /
//                                  PMD_SIZE
//
// Reads SF_FDT_KASLR_SEED (bridged binary read; 0/absent => inert — covers the
// seed-disabled/wiped case handled by virt_kaslr_disabled_pin /
// phys_kaslr_disabled_pin),
// SF_EFI_PRESENT (non-EFI only — EFI mixes in efi_kaslr_seed),
// SF_IMAGE_SIZE_MIN / SF_IMAGE_SIZE_MAX (the Path 1 nr_pos bracket), and VIRT
// text/data leaks for the Path 2 gap. riscv64 only.
// The active path requires a kernel that has not yet consumed the FDT
// kaslr-seed cell — the kernel wipes the cell to 0 once it has used it, so a
// usable seed is visible only before that point.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"
#include "include/kasld/regions.h"

#include <limits.h>
#include <stdint.h>
#include <string.h>

int rule_riscv64_fdt_kaslr_seed(const struct evidence_set *ev,
                                const struct estimate *est,
                                struct constraint *out, int out_max) {
  (void)est;
#if (defined(__riscv) || defined(__riscv__)) && __riscv_xlen == 64
  if (out_max < 1)
    return 0;

  const unsigned long pud_size = 1ul << 30; /* 1 GiB */
  const unsigned long pmd_size = 2ul * 1024 * 1024;

  uint64_t seed = 0;
  unsigned long min_text = ULONG_MAX, max_data = 0;
  int efi_present = 0;
  uint32_t src = 0;
  enum kasld_confidence seed_conf = CONF_UNKNOWN;
  enum kasld_confidence size_min_conf = CONF_UNKNOWN,
                        size_max_conf = CONF_UNKNOWN;
  uint32_t size_min_src = 0, size_max_src = 0;
  unsigned long image_size =
      evidence_image_size_min(ev, &size_min_conf, &size_min_src);
  unsigned long size_max_fp =
      evidence_image_size_max(ev, &size_max_conf, &size_max_src);
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid)
      continue;
    if (o->value_kind == OBS_SCALAR) {
      if (o->scalar_fact == SF_FDT_KASLR_SEED) {
        seed = o->scalar_value;
        src = o->id;
        seed_conf = o->conf;
      } else if (o->scalar_fact == SF_EFI_PRESENT)
        efi_present = (o->scalar_value != 0);
      continue;
    }
    if (o->eff_type == KASLD_TYPE_VIRT) {
      unsigned long a = obs_anchor(o);
      if (o->eff_region == REGION_KERNEL_TEXT ||
          o->eff_region == REGION_KERNEL_IMAGE) {
        if (a < min_text)
          min_text = a;
      } else if (o->eff_region == REGION_KERNEL_DATA ||
                 o->eff_region == REGION_KERNEL_BSS) {
        if (a > max_data)
          max_data = a;
      }
    }
  }
  if (seed == 0 || efi_present)
    return 0;

  /* Path 1: pin the exact slot the boot code chose — but only when the slot
   * index nr_pos is UNIQUELY determined by sound bounds on the kernel size.
   *
   * The boot code computes nr_pos = (PUD_SIZE - kernel_size) / PMD_SIZE with
   * kernel_size = _end - _start (exact) and selects slot (seed % nr_pos).
   * seed % nr_pos is not monotone in nr_pos, so a merely lower-bounded size
   * cannot reconstruct the slot: an over-estimated nr_pos selects a different
   * residue, giving a wrong pin. Bracket kernel_size with a sound [lo, hi] and
   * pin only when both ends land in one PMD bucket (a single nr_pos):
   *   lo = evidence_image_size_min: a footprint lower bound; every footprint
   *        origin (_start/_text/_stext) is >= _start, so lo <= _end - _start.
   *   hi = evidence_image_size_max + IMAGE_BASE_OFFSET: image_size_max upper-
   *        bounds _end - _text; IMAGE_BASE_OFFSET is the _start -> _stext
   *        .head.text gap (riscv64.h), and _text == _stext on riscv64, so
   *        adding it lifts the bound to _end - _start exactly.
   * nr_pos is monotone-decreasing in kernel_size, so the smallest size gives
   * the largest nr_pos and vice versa. With no proven upper bound the bracket
   * cannot collapse, so Path 1 stays silent and only Path 2's ceiling fires. */
  if (image_size > 0 && size_max_fp > 0) {
    unsigned long size_hi = size_max_fp + (unsigned long)IMAGE_BASE_OFFSET;
    if (size_hi >= size_max_fp /* addition did not wrap */ &&
        size_hi < pud_size && image_size <= size_hi) {
      unsigned long nr_pos_hi =
          (pud_size - image_size) / pmd_size;                    /* min size */
      unsigned long nr_pos_lo = (pud_size - size_hi) / pmd_size; /* max size */
      if (nr_pos_lo > 0 && nr_pos_lo == nr_pos_hi) {
        unsigned long nr_pos = nr_pos_lo;
        unsigned long off =
            (unsigned long)((seed % (uint64_t)nr_pos) * pmd_size);
        unsigned long candidate = (unsigned long)KERNEL_LINK_ADDR + off;
        /* No more trustworthy than the least-certain input it rests on. */
        enum kasld_confidence conf = CONF_INFERRED;
        conf = kasld_conf_min(conf, seed_conf);
        conf = kasld_conf_min(conf, size_min_conf);
        conf = kasld_conf_min(conf, size_max_conf);
        struct constraint *c = &out[0];
        memset(c, 0, sizeof(*c));
        c->q = Q_VIRT_IMAGE_BASE;
        c->op = C_EQUALS;
        c->value = candidate;
        c->conf = conf;
        c->derived_from[0] = src;
        c->derived_from[1] = size_min_src;
        c->derived_from[2] = size_max_src;
        c->lineage_count = 3;
        snprintf(c->origin, ORIGIN_LEN, "riscv64_fdt_kaslr_seed");
        return 1;
      }
    }
  }

  /* Path 2: gap fallback -> ceiling from the maximal candidate. */
  if (min_text == ULONG_MAX || max_data <= min_text)
    return 0;
  unsigned long gap = max_data - min_text;
  if (gap == 0 || gap >= pud_size)
    return 0;
  unsigned long nr_pos_max = (pud_size - gap) / pmd_size;
  if (nr_pos_max == 0)
    return 0;
  unsigned long max_cand = 0;
  for (unsigned long i = 1; i <= nr_pos_max; i++) {
    unsigned long cand = (unsigned long)KERNEL_LINK_ADDR +
                         (unsigned long)((seed % (uint64_t)i) * pmd_size);
    if (cand > max_cand)
      max_cand = cand;
  }
  if (max_cand <= (unsigned long)KERNEL_LINK_ADDR)
    return 0;
  struct constraint *c = &out[0];
  memset(c, 0, sizeof(*c));
  c->q = Q_VIRT_IMAGE_BASE;
  c->op = C_UPPER_BOUND;
  c->value = max_cand;
  c->conf = CONF_INFERRED;
  c->derived_from[0] = src;
  c->lineage_count = 1;
  snprintf(c->origin, ORIGIN_LEN, "riscv64_fdt_kaslr_seed");
  return 1;
#else
  (void)ev;
  (void)out;
  (void)out_max;
  return 0;
#endif
}
