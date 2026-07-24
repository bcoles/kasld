// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: kernel-below-initrd convention → speculative phys text upper bound.
//
// On the common boot path the bootloader loads the initrd at a HIGHER physical
// address than the kernel image (kernel low, initrd above it), so a leaked
// initrd start gives
//
//   phys_image_base + image_size <= initrd_start
//
// emitted as a C_UPPER_BOUND on Q_PHYS_IMAGE_BASE. This is a CONVENTION, not an
// architectural law: physical KASLR (x86 CONFIG_RANDOMIZE_BASE) picks a random
// slot that merely AVOIDS OVERLAPPING the initrd and may land the kernel ABOVE
// it — a placement this strict "entirely below" bound would wrongly exclude. So
// the bound is CONF_HEURISTIC and shapes the speculative LIKELY window only,
// never the guaranteed one.
//
// The genuinely SOUND half of the same observation — the kernel does not
// OVERLAP the initrd — is the C_EXCLUDE hole [start - image_size + 1, end - 1]
// emitted by initrd_phys_exclude (decoupled arches), a fact kept at observation
// confidence. This rule adds the weaker "entirely below" guess on both coupling
// models; on coupled arches text_base_coupling_synth projects it (at the same
// heuristic confidence) onto Q_VIRT_IMAGE_BASE.
//
// When SF_IMAGE_SIZE_MIN is known the subtrahend is exact; otherwise the shared
// KASLD_MIN_IMAGE_SIZE keeps it conservative (never under-subtracts).
//
// Arch scope: gated to exclude s390, whose boot stub uses top-down physmem
// allocation and routinely places the kernel above firmware-supplied initrd
// regions — the convention does not hold there even as a heuristic. ppc32 is
// excluded for the same reason: BookE (e500) KASLR relocates the kernel to any
// 64 MiB-indexed slot in [0, min(RAM, 512 MiB)), so it lands above the
// fixed-position initrd on most boots — the "kernel below initrd" convention is
// systematically false there, undershooting the likely window. (BookS ppc32 has
// no text KASLR and sits at the fixed low base, so it loses nothing.)
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
#if defined(__s390__) || defined(__s390x__) ||                                 \
    (defined(__powerpc__) && !defined(__powerpc64__))
  (void)ev;
  (void)out;
  (void)out_max;
  return 0;
#else
  if (out_max < 1)
    return 0;

  unsigned long istart = ULONG_MAX;
  enum kasld_confidence kconf = CONF_UNKNOWN;
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
  /* CONF_HEURISTIC regardless of how parsed the inputs are: the "entirely
   * below" ordering is a bootloader convention, not a fact, so however certain
   * the initrd start and image size, concluding the kernel sits below the
   * initrd is a guess. Below the sound floor, it shapes the LIKELY window only.
   * (The derivation is still recorded for --verbose lineage.) */
  c->conf = CONF_HEURISTIC;
  c->derived_from[0] = isrc;
  c->lineage_count = 1;
  if (ksrc != 0)
    c->derived_from[c->lineage_count++] = ksrc;
  snprintf(c->origin, ORIGIN_LEN, "initrd_above_kernel");
  return 1;
#endif
}
