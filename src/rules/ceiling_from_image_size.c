// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: KASLR image ceiling from kernel image size.
//
// The kernel's placement code
// never selects a base where base + image_size overflows the top of the
// randomization window, so the top [WINDOW_MAX - kernel_size, WINDOW_MAX) is
// forbidden. That yields an upper bound on the base:
//
//   base <= (WINDOW_MAX - kernel_size) rounded down to a slot boundary
//
// Aligning the ceiling down is sound because the base is itself slot-aligned;
// it is folded into the C_UPPER_BOUND value rather than tracked as a separate
// alignment quantity.
//
// Reads the SF_IMAGE_SIZE / SF_INIT_SIZE scalar observations plus the resolved
// alignment quantities. The ceiling is aligned down to the RESOLVED
// Q_VIRT_KASLR_ALIGN (resp. Q_PHYS_KASLR_ALIGN), not the compile-time
// KASLR_VIRT_ALIGN: on x86_64 boot_params_kaslr_align raises that quantity to
// the actual CONFIG_PHYSICAL_ALIGN (e.g. 16 MiB), so the ceiling snaps to that
// coarser boundary; with no boot_params the quantity is the arch
// KASLR_VIRT_ALIGN. This makes the rule cross-quantity (it reads est), so the
// fixpoint loop re-runs it after the alignment rules settle.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"

#include <string.h>

/* The kernel image size as measured (0 if none). Takes the LARGEST of the
 * available sound size facts — the /boot image-size estimate (SF_IMAGE_SIZE,
 * deliberately an under-estimate) and the exact x86 boot_params init_size
 * (SF_INIT_SIZE). Both are <= the true in-memory size, so the larger yields the
 * tightest still-sound ceiling (KASLR_VIRT_TEXT_MAX - size); when the exact
 * init_size is present it wins. */
static unsigned long image_size(const struct evidence_set *ev,
                                enum kasld_confidence *conf, uint32_t *src) {
  unsigned long best = 0;
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->value_kind != OBS_SCALAR)
      continue;
    if (o->scalar_fact != SF_IMAGE_SIZE && o->scalar_fact != SF_INIT_SIZE)
      continue;
    if (o->scalar_value > best) {
      best = o->scalar_value;
      *conf = o->conf;
      *src = o->id;
    }
  }
  return best;
}

/* Emit an aligned upper-bound ceiling for one quantity, given the window's
 * [min, max) and slot alignment. Returns the number of constraints written
 * (0 or 1). */
static int emit_ceiling(enum kasld_quantity q, unsigned long window_max,
                        unsigned long window_min, unsigned long align,
                        unsigned long kernel_size, enum kasld_confidence conf,
                        uint32_t src, struct constraint *out, int slot,
                        int out_max) {
  if (window_max <= window_min || kernel_size >= window_max - window_min)
    return 0;
  unsigned long ceiling = window_max - kernel_size;
  if (q == Q_VIRT_IMAGE_BASE)
    ceiling = kasld_floor_virt_text_bound(
        ceiling, align); /* sound on sub-offset arches */
  else if (align > 0)
    ceiling &= ~(align - 1); /* phys base carries no usable sub-offset */
  if (ceiling <= window_min || slot >= out_max)
    return 0;

  struct constraint *c = &out[slot];
  memset(c, 0, sizeof(*c));
  c->q = q;
  c->op = C_UPPER_BOUND;
  c->value = ceiling;
  c->conf = conf;
  c->derived_from[0] = src;
  c->lineage_count = 1;
  snprintf(c->origin, ORIGIN_LEN, "ceiling_from_image_size");
  return 1;
}

int rule_ceiling_from_image_size(const struct evidence_set *ev,
                                 const struct estimate *est,
                                 struct constraint *out, int out_max) {
  enum kasld_confidence conf = CONF_UNKNOWN;
  uint32_t src = 0;
  unsigned long ksize = image_size(ev, &conf, &src);
  if (ksize == 0)
    return 0;

  /* Align to the resolved alignment quantity, never below the arch default
   * (Q_VIRT_KASLR_ALIGN starts at its lattice top of 1 before any alignment
   * rule narrows it). */
  unsigned long valign = est[Q_VIRT_KASLR_ALIGN].lo;
  if (valign < (unsigned long)KASLR_VIRT_ALIGN)
    valign = (unsigned long)KASLR_VIRT_ALIGN;

  int n = 0;
  n += emit_ceiling(Q_VIRT_IMAGE_BASE, KASLR_VIRT_TEXT_MAX, KASLR_VIRT_TEXT_MIN,
                    valign, ksize, conf, src, out, n, out_max);
#if !TEXT_TRACKS_DIRECTMAP
  unsigned long palign = est[Q_PHYS_KASLR_ALIGN].lo;
  if (palign < (unsigned long)KASLR_PHYS_ALIGN)
    palign = (unsigned long)KASLR_PHYS_ALIGN;
  n += emit_ceiling(Q_PHYS_IMAGE_BASE, KASLR_PHYS_MAX, KASLR_PHYS_MIN, palign,
                    ksize, conf, src, out, n, out_max);
#endif
  return n;
}
