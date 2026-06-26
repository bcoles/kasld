// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: kernel-below-initrd convention → phys text upper bound.
//
// On every common boot path (GRUB on x86, U-Boot / EFI stub on arm + arm64
// + mips, OpenSBI / U-Boot on riscv64, Open Firmware on PowerPC), the
// bootloader loads the initrd at a higher physical address than the
// kernel image: kernel goes low, initrd goes above it, and the kernel's
// own relocator never picks a base whose image overlaps the initrd. So
// when a leaked initrd start is available:
//
//   phys_image_base + image_size <= initrd_start
//
// emits as a C_UPPER_BOUND on Q_PHYS_IMAGE_BASE. When SF_IMAGE_SIZE_MIN is
// known the bound is tight; otherwise a conservative KASLD_MIN_IMAGE_SIZE keeps
// the bound sound. The complementary "kernel doesn't overlap initrd"
// constraint (the exclusion hole IN [start - image_size, end - 1]) is
// already emitted by initrd_phys_exclude.c on decoupled arches; this
// rule is the strict-upper-bound version that fires on both coupling
// models — and on coupled arches the text_base_coupling_synth rule
// then projects the bound onto Q_VIRT_IMAGE_BASE.
//
// Confidence: CONF_INFERRED. Any higher-confidence evidence (kallsyms
// _stext via text_pin_from_observation, iomem Kernel code via
// kernel_image_phys_bound) overrides at the resolver. If a future
// architecture or bootloader genuinely loads the kernel ABOVE the
// initrd, this rule's heuristic value gets discarded as bottom-forcing
// against the real leak.
//
// Arch scope: gated to exclude s390. The s390 boot stub uses top-down
// physmem allocation and may legitimately place the kernel above
// firmware-supplied initrd regions; the convention this rule encodes
// does not apply there.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"
#include "include/kasld/regions.h"

#include <limits.h>
#include <string.h>

int rule_initrd_above_kernel(const struct evidence_set *ev,
                             const struct estimate *est, struct constraint *out,
                             int out_max) {
  (void)est;
#if defined(__s390__) || defined(__s390x__)
  (void)ev;
  (void)out;
  (void)out_max;
  return 0;
#else
  if (out_max < 1)
    return 0;

  unsigned long istart = ULONG_MAX;
  enum kasld_confidence kconf = CONF_UNKNOWN, iconf = CONF_PARSED;
  uint32_t ksrc = 0, isrc = 0;
  unsigned long ksize = evidence_image_size_min(ev, &kconf, &ksrc);
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid)
      continue;
    if (o->value_kind == OBS_ADDRESS && o->eff_type == KASLD_TYPE_PHYS &&
        o->eff_region == REGION_INITRD && HAS_LO(o)) {
      /* Lowest initrd-start across all sources; one observation is
       * enough, but if several emit the lowest is the binding edge. */
      if (o->lo < istart) {
        istart = o->lo;
        iconf = o->conf;
        isrc = o->id;
      }
    }
  }

  if (isrc == 0 || istart == ULONG_MAX || istart == 0)
    return 0;

  /* image_size known → tight; otherwise the conservative shared floor. */
  unsigned long subtrahend =
      ksize > 0 ? ksize : (unsigned long)KASLD_MIN_IMAGE_SIZE;
  if (istart <= subtrahend)
    return 0;
  unsigned long upper = istart - subtrahend;

  struct constraint *c = &out[0];
  memset(c, 0, sizeof(*c));
  c->q = Q_PHYS_IMAGE_BASE;
  c->op = C_UPPER_BOUND;
  c->value = upper;
  /* The bound inherits the WEAKER of the two contributing observations'
   * confidence — matches the convention in initrd_phys_exclude and the
   * other compound-evidence rules. When ksize wasn't observed (kconf =
   * UNKNOWN), defer to the initrd-start confidence; the bound is then
   * "sound but loose" via the KASLD_MIN_IMAGE_SIZE fallback. */
  if (ksrc != 0) {
    c->conf = (kconf < iconf) ? kconf : iconf;
    c->derived_from[0] = isrc;
    c->derived_from[1] = ksrc;
    c->lineage_count = 2;
  } else {
    /* Heuristic-grade upper bound from initrd alone — sound (uses
     * KASLD_MIN_IMAGE_SIZE) but loose. Any real text leak overrides. */
    c->conf = CONF_HEURISTIC;
    c->derived_from[0] = isrc;
    c->lineage_count = 1;
  }
  snprintf(c->origin, ORIGIN_LEN, "initrd_above_kernel");
  return 1;
#endif
}
