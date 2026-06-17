// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: pick the running-kernel EFI_LOADER_CODE entry from a multi-entry
// EFI memmap and pin Q_PHYS_IMAGE_BASE to its start.
//
// On an EFI stub boot the kernel's PE/COFF image occupies an
// EFI_LOADER_CODE memmap entry. Bootloader and EFI driver images still
// resident at ExitBootServices() occupy others. dmesg_efi_memmap emits
// each entry as a separate REGION_EFI_LOADER_IMAGE observation with its
// full [lo, hi] extent; the component does not distinguish entries by
// purpose (it has no knowledge of arch alignment or image size).
//
// Two filters identify the running-kernel entry:
//
//   1. ALIGNMENT — `entry.lo % EFI_KIMG_ALIGN == 0`. The EFI stub's
//      AllocatePages() call for the kernel image uses this alignment;
//      bootloader and driver images are typically loaded at 4 KiB page
//      granularity by other firmware paths. Values: arm64 = 64 KiB
//      (THREAD_ALIGN, covers 4K/16K/64K pages); riscv64 = PMD_SIZE
//      = 2 MiB; x86_64 = CONFIG_PHYSICAL_ALIGN = 2 MiB default;
//      loongarch64 = 2 MiB.
//
//   2. SIZE — `entry.size ∈ [1.0×, 2.0×] × SF_IMAGE_SIZE`. The EFI
//      allocator rounds the image size up to a page count. A 2×
//      tolerance accepts that rounding and rejects unrelated images
//      (firmware drivers are far smaller; bootloader images are
//      typically well under 1× SF_IMAGE_SIZE).
//
// Exactly one survivor → emit C_EQUALS on Q_PHYS_IMAGE_BASE at its lo at
// CONF_PARSED. The image is contiguous and the EFI stub adds no header
// gap before _text/_stext, so the entry's lo IS the phys text base.
//
// Multiple survivors:
//   • Default — emit nothing (matches the conservative behaviour of
//     the previous loader_n==1 path).
//   • SF_PHYS_KASLR_RANDOMIZATION_FAILED disambiguator — when the boot stub
//     attempted KASLR but could not produce a random offset (arm64 /
//     riscv64 "lack of seed", FDT remap failure), the EFI stub falls
//     back from efi_random_alloc() to a deterministic allocation. The
//     fallback (efi_random_alloc with seed=0, or efi_allocate_pages_
//     aligned) picks the lowest-addressed eligible slot in the EFI
//     memmap — firmware orders the memmap by physical address, so the
//     first big-enough EFI_LOADER_CODE entry is also the lowest.
//     With the signal present, emit C_EQUALS at the LOWEST survivor's
//     lo at CONF_HEURISTIC (deferred to by any CONF_PARSED leak).
//
// Zero survivors → emit nothing.
//
// Phase: POST_COLLECTION. Needs SF_IMAGE_SIZE and the per-arch
// EFI_KIMG_ALIGN constant. Gated to arches that define EFI_KIMG_ALIGN
// (arm64, riscv64, x86_64, loongarch64); inert otherwise.
//
// A pure constraint over evidence: no I/O. The underlying addresses come from
// an `efi=debug` dmesg dump parsed elsewhere.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"
#include "include/kasld/regions.h"

#include <limits.h>
#include <string.h>

#if defined(EFI_KIMG_ALIGN)

/* Size tolerance: a candidate's range size must lie in
 *   [SF_IMAGE_SIZE, ELKP_SIZE_MAX_MULT × SF_IMAGE_SIZE].
 * The EFI allocator rounds the image up to a page count; a 2× ceiling
 * catches the rounding without admitting bootloader images far larger
 * or smaller than the kernel. Floor at exactly SF_IMAGE_SIZE — the
 * range cannot legitimately be smaller than the image itself. */
#define ELKP_SIZE_MAX_MULT 2

int rule_efi_loader_kernel_pick(const struct evidence_set *ev,
                                const struct estimate *est,
                                struct constraint *out, int out_max) {
  (void)est;
  if (out_max < 1)
    return 0;

  unsigned long ksize = 0;
  uint32_t ksrc = 0;
  uint32_t rand_failed_src = 0;
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->value_kind != OBS_SCALAR)
      continue;
    if (o->scalar_fact == SF_IMAGE_SIZE && ksize == 0) {
      ksize = o->scalar_value;
      ksrc = o->id;
    } else if (o->scalar_fact == SF_PHYS_KASLR_RANDOMIZATION_FAILED &&
               o->scalar_value != 0 && rand_failed_src == 0) {
      rand_failed_src = o->id;
    }
  }
  if (ksize == 0)
    return 0; /* no SF_IMAGE_SIZE → size filter cannot apply */

  const unsigned long palign = (unsigned long)EFI_KIMG_ALIGN;
  const unsigned long size_max = ksize * (unsigned long)ELKP_SIZE_MAX_MULT;
  /* Guard against the multiply overflowing on pathological SF_IMAGE_SIZE. */
  if (size_max < ksize)
    return 0;

  /* Track BOTH the first survivor (used for the unique-survivor case) and
   * the LOWEST survivor (used as a disambiguator when SF_PHYS_KASLR_RANDOMIZA-
   * TION_FAILED is present and multiple entries pass the filters). */
  unsigned long survivor_lo = 0;
  uint32_t survivor_src = 0;
  enum kasld_confidence survivor_conf = CONF_PARSED;
  unsigned long lowest_lo = ULONG_MAX;
  uint32_t lowest_src = 0;
  enum kasld_confidence lowest_conf = CONF_PARSED;
  int survivors = 0;
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->value_kind != OBS_ADDRESS)
      continue;
    if (o->eff_type != KASLD_TYPE_PHYS ||
        o->eff_region != REGION_EFI_LOADER_IMAGE)
      continue;
    if (!HAS_LO(o) || !HAS_HI(o))
      continue;

    /* Alignment filter. */
    if (palign > 0 && (o->lo & (palign - 1)) != 0)
      continue;

    /* Size filter: range size is hi - lo + 1 (inclusive hi, matches
     * what dmesg_efi_memmap emits via kasld_result_sized). */
    if (o->hi < o->lo)
      continue;
    unsigned long range_sz = o->hi - o->lo + 1;
    if (range_sz < ksize || range_sz > size_max)
      continue;

    survivors++;
    if (survivors == 1) {
      survivor_lo = o->lo;
      survivor_src = o->id;
      /* Inherit the weaker of the two contributing observations'
       * confidence (same convention as initrd_above_kernel and the
       * compound-evidence rules generally). SF_IMAGE_SIZE and the
       * entry observation are typically both CONF_PARSED. */
      survivor_conf = (o->conf < survivor_conf) ? o->conf : survivor_conf;
    }
    if (o->lo < lowest_lo) {
      lowest_lo = o->lo;
      lowest_src = o->id;
      lowest_conf = (o->conf < lowest_conf) ? o->conf : lowest_conf;
    }
  }

  if (survivors == 0)
    return 0;

  struct constraint *c = &out[0];
  memset(c, 0, sizeof(*c));
  c->q = Q_PHYS_IMAGE_BASE;
  c->op = C_EQUALS;
  c->derived_from[1] = ksrc;
  snprintf(c->origin, ORIGIN_LEN, "efi_loader_kernel_pick");

  if (survivors == 1) {
    /* Unique survivor: alignment+size filters are tight enough to be
     * effectively a pin. CONF_PARSED. */
    c->value = survivor_lo;
    c->conf = survivor_conf;
    c->derived_from[0] = survivor_src;
    c->lineage_count = 2;
    return 1;
  }

  /* Multiple survivors: the only sound disambiguator is
   * SF_PHYS_KASLR_RANDOMIZATION_FAILED — the EFI stub fell back to a
   * deterministic alloc that prefers low addresses. Without that
   * signal, the rule cannot pick between candidates and must emit
   * nothing. */
  if (rand_failed_src == 0)
    return 0;

  /* CONF_HEURISTIC: the "firmware picks lowest" assumption is true on
   * conventional UEFI (Tianocore-derived) and ARM TF-A firmware, but
   * not contractually guaranteed across every EFI implementation. Any
   * CONF_PARSED leak (kallsyms, EFI_LOADER_CODE single-survivor case,
   * an iomem text pin) overrides this. */
  c->value = lowest_lo;
  c->conf = lowest_conf < CONF_HEURISTIC ? lowest_conf : CONF_HEURISTIC;
  c->derived_from[0] = lowest_src;
  c->derived_from[2] = rand_failed_src;
  c->lineage_count = 3;
  return 1;
}

#else /* !defined(EFI_KIMG_ALIGN) */

int rule_efi_loader_kernel_pick(const struct evidence_set *ev,
                                const struct estimate *est,
                                struct constraint *out, int out_max) {
  (void)ev;
  (void)est;
  (void)out;
  (void)out_max;
  return 0;
}

#endif
