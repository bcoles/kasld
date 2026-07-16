// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: s390 virt-phys segment-mod coupling.
//
// On s390 the kernel image is loaded at an absolute physical address aligned
// to _SEGMENT_SIZE (1 MiB) and mapped into the virtual address space at
// __kaslr_offset, which is also _SEGMENT_SIZE-aligned. Consequently the
// low 20 bits of (text_virt - PHYSICAL_START) are zero, which means
//
//     text_virt ≡ phys_anchor    (mod _SEGMENT_SIZE = 1 MiB)
//
// for any phys leak that points at a kernel-image byte at the SAME offset
// from the segment boundary as text_virt. A PHYS/KERNEL_IMAGE *base* leak (e.g.
// the kernel image base parsed from a firmware reservation) gives that
// anchor directly; the rule emits one C_STRIDE on Q_VIRT_IMAGE_BASE collapsing
// log2(_SEGMENT_SIZE / KASLR_VIRT_ALIGN) = log2(1 MiB / 16 KiB) = 6 bits of
// residual entropy.
//
// The scan, POS_BASE / grid guards, and emission are the shared
// kasld_emit_text_residue skeleton (see engine_rules.h) — the residue is well
// defined only for the image base, so only a POS_BASE kernel-image / text
// observation is used, normalised to _text, and an off-IMAGE_ALIGN-grid
// residue is skipped rather than emitted.
//
// Inert when no s390 PHYS/KERNEL_IMAGE base observation from a phys-side anchor
// (e.g. an unmasked /proc/iomem read) is present. s390 only; inert elsewhere.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"
#include "include/kasld/regions.h"

#define S390_SEGMENT_SIZE 0x100000ul /* 1 MiB */

int rule_s390_text_segment_mod(const struct evidence_set *ev,
                               const struct estimate *est,
                               struct constraint *out, int out_max) {
  (void)est;
#if defined(__s390__) || defined(__s390x__)
  /* PHYS kernel-image base → Q_VIRT_IMAGE_BASE residue (mod 1 MiB). */
  return kasld_emit_text_residue(ev, out, out_max, KASLD_TYPE_PHYS,
                                 Q_VIRT_IMAGE_BASE, S390_SEGMENT_SIZE,
                                 "s390_text_segment_mod");
#else
  (void)ev;
  (void)out;
  (void)out_max;
  return 0;
#endif
}
