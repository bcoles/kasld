// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: s390 phys-virt segment-mod coupling (reverse of s390_text_segment_mod).
//
// On s390 the kernel image is loaded at a physical address and mapped into the
// virtual address space at __kaslr_offset, which is _SEGMENT_SIZE (1 MiB)-
// aligned, so
//
//     phys_text ≡ virt_text    (mod _SEGMENT_SIZE = 1 MiB)
//
// (the same coupling s390_text_segment_mod uses in the phys → virt direction).
// A VIRT KERNEL_IMAGE / KERNEL_TEXT base leak (e.g. /proc/kallsyms _text)
// there- fore pins Q_PHYS_IMAGE_BASE's residue mod 1 MiB. The physical text
// base is THREAD_SIZE (16 KiB, IMAGE_ALIGN)-granular — finer than 1 MiB — so
// this collapses log2(1 MiB / 16 KiB) = 6 bits of the physical base's residual
// entropy.
//
// This is additive over s390_text_segment_mod (phys → virt): it helps the
// physical window when the virtual base is leaked but the physical base is not
// pinned — e.g. /proc/kallsyms is readable but /proc/iomem "Kernel code" needs
// CAP_SYS_ADMIN. On s390 text and the linear map are decoupled
// (TEXT_TRACKS_DIRECTMAP=0), so this residue is the only virt → phys
// information.
//
// Soundness:
//   * Fires only on a VIRT KERNEL_IMAGE / KERNEL_TEXT *base* observation
//     (POS_BASE): the residue is well defined only for the image base. An
//     interior sample sits at an unknown offset from _text, so it is skipped.
//   * The anchor is normalised to the image base (_text) with
//     kasld_image_base_from (a no-op on s390, STEXT_OFFSET = 0).
//   * A real virt _text is IMAGE_ALIGN-aligned, so its residue is too; a
//   residue
//     not on the IMAGE_ALIGN grid signals a bad anchor and is skipped (an
//     unaligned residue would leave no IMAGE_ALIGN-aligned base in the class
//     and force bottom). The guaranteed physical window is IMAGE_ALIGN-granular
//     (the 1 MiB Q_PHYS_KASLR_ALIGN bound is CONF_HEURISTIC / likely-only), so
//     the residue class composes without contradicting it.
//   * Confidence inherits the observation's (single source).
//
// Inert when no s390 VIRT kernel-image base observation is present. s390 only.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"
#include "include/kasld/regions.h"

#define S390_SEGMENT_SIZE 0x100000ul /* 1 MiB */

int rule_s390_phys_segment_mod(const struct evidence_set *ev,
                               const struct estimate *est,
                               struct constraint *out, int out_max) {
  (void)est;
#if defined(__s390__) || defined(__s390x__)
  /* VIRT kernel-image base → Q_PHYS_IMAGE_BASE residue (mod 1 MiB). */
  return kasld_emit_text_residue(ev, out, out_max, KASLD_TYPE_VIRT,
                                 Q_PHYS_IMAGE_BASE, S390_SEGMENT_SIZE,
                                 "s390_phys_segment_mod");
#else
  (void)ev;
  (void)out;
  (void)out_max;
  return 0;
#endif
}
