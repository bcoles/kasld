// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: virtual image-base FLOOR from the in-memory kernel size.
//
// Any leaked kernel-image virtual address `a` (text / image / data / bss) lies
// within [image_base, image_base + init_size], where init_size is the kernel's
// exact in-memory footprint (SF_INIT_SIZE: x86 boot_params init_size, or the
// arm64/riscv64 EFI Image header image_size; init_size >= _end - _text, so it
// bounds the offset of any in-image symbol from the base). Therefore:
//
//   image_base >= a - init_size
//
// The HIGHEST in-image observation gives the tightest sound floor. This is the
// lower-bound complement to the interior/timing oracles (which give the
// image_base <= a upper bound): a single high interior leak then brackets the
// base to a tight window even with no base-claiming source.
//
// Deliberately consumes SF_INIT_SIZE, NOT SF_IMAGE_SIZE: the latter is a /boot
// estimate that can fall back to the COMPRESSED vmlinuz file size, which is
// SMALLER than the in-memory extent. As a lower-bound subtrahend an
// under-estimate would push the floor ABOVE the true base and exclude it.
// init_size over-estimates the extent, so the floor is always sound.
//
// Self-consistency guard: the highest and lowest in-image witnesses must fit
// inside one image of size init_size (a_max - a_min <= init_size). A stray
// high outlier (a non-image pointer mis-tagged into a kernel-image region and
// not caught by coupling_validate) would otherwise yield a floor above the true
// base; the guard drops the emission in that ambiguous case rather than risk
// excluding truth.
//
// Inert when no SF_INIT_SIZE fact or no in-image virtual observation is
// present. Arch-independent; fires wherever a SF_INIT_SIZE fact exists (x86 via
// boot_params; arm64/riscv64 when a readable, uncompressed Image is present).
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"
#include "include/kasld/regions.h"

#include <limits.h>
#include <string.h>

static int is_kernel_image_obs_region(enum kasld_region r) {
  return r == REGION_KERNEL_TEXT || r == REGION_KERNEL_IMAGE ||
         r == REGION_KERNEL_DATA || r == REGION_KERNEL_BSS;
}

int rule_image_floor_from_init_size(const struct evidence_set *ev,
                                    const struct estimate *est,
                                    struct constraint *out, int out_max) {
  (void)est;
  if (out_max < 1)
    return 0;

  unsigned long init_size = 0;
  uint32_t size_src = 0;
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (o->valid && o->value_kind == OBS_SCALAR &&
        o->scalar_fact == SF_INIT_SIZE) {
      init_size = o->scalar_value;
      size_src = o->id;
      break;
    }
  }
  if (init_size == 0)
    return 0;

  /* Lowest and highest VIRT kernel-image observations: text/image/data/bss all
   * lie within [image_base, image_base + init_size]. */
  unsigned long a_min = ULONG_MAX, a_max = 0;
  uint32_t a_src = 0;
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->value_kind != OBS_ADDRESS ||
        o->eff_type != KASLD_TYPE_VIRT)
      continue;
    if (!is_kernel_image_obs_region(o->eff_region))
      continue;
    unsigned long a = obs_anchor(o);
    if (a == 0)
      continue;
    if (a < a_min)
      a_min = a;
    if (a > a_max) {
      a_max = a;
      a_src = o->id;
    }
  }
  if (a_max == 0 || a_max <= init_size)
    return 0;
  /* Both witnesses must fit one image of size init_size (overflow-safe form).
   */
  if (a_max - a_min > init_size)
    return 0;

  struct constraint *c = &out[0];
  memset(c, 0, sizeof(*c));
  c->q = Q_VIRT_IMAGE_BASE;
  c->op = C_LOWER_BOUND;
  c->value = a_max - init_size;
  c->conf = CONF_INFERRED;
  c->derived_from[0] = a_src;
  c->derived_from[1] = size_src;
  c->lineage_count = 2;
  snprintf(c->origin, ORIGIN_LEN, "image_floor_from_init_size");
  return 1;
}
