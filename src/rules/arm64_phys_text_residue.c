// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: arm64 phys-virt text residue coupling (reverse of
// arm64_text_phys_residue).
//
// On arm64 the kernel image's virtual-to-physical offset (kimage_voffset =
// virt_text - phys_text) is MIN_KIMG_ALIGN (2 MiB)-aligned: the low
// log2(MIN_KIMG_ALIGN) bits of the virtual KASLR displacement are copied from
// the physical load address so kernel text can be mapped with 2 MiB blocks
// (arch/arm64/kernel/pi/map_kernel.c; head.S on pre-v6.9). Consequently
//
//     phys_text ≡ virt_text    (mod MIN_KIMG_ALIGN = 2 MiB)
//
// (the same coupling arm64_text_phys_residue uses in the phys → virt
// direction). A VIRT KERNEL_IMAGE / KERNEL_TEXT base leak (e.g. /proc/kallsyms
// _text) therefore pins Q_PHYS_IMAGE_BASE's residue mod 2 MiB. Because the
// physical text base is only IMAGE_ALIGN (EFI_KIMG_ALIGN, 64 KiB)-granular —
// not 2 MiB-aligned — this collapses log2(2 MiB / IMAGE_ALIGN) = up to 5 bits
// of the physical base's residual entropy.
//
// This is additive over arm64_text_phys_residue (phys → virt): it helps the
// physical window when the virtual base is leaked but the physical base is not
// pinned — e.g. /proc/kallsyms is readable (kptr_restrict = 0) but /proc/iomem
// "Kernel code" needs CAP_SYS_ADMIN. On arm64 kernel text and the linear map
// are decoupled (TEXT_TRACKS_DIRECTMAP = 0), so this residue is the only virt →
// phys information; it completes the residue-coupling pair (the s390 pair
// already has both directions).
//
// Soundness:
//   * Fires only on a VIRT KERNEL_IMAGE / KERNEL_TEXT *base* observation
//     (POS_BASE): the residue is well defined only for the image base. An
//     interior sample (perf / prefetch / BPF ksym leaks) sits at an unknown
//     offset from _text, so its residue would be wrong; those are skipped.
//   * The anchor is normalised to the image base (_text) with
//     kasld_image_base_from — a KERNEL_TEXT witness is _stext and is shifted
//     down by STEXT_OFFSET (64 KiB on arm64), which the 2 MiB modulus does NOT
//     absorb.
//   * A real virt _text is IMAGE_ALIGN-aligned, so its residue is too; a
//   residue
//     not on the IMAGE_ALIGN grid signals a bad anchor and is skipped rather
//     than emitted (an unaligned residue would leave no IMAGE_ALIGN-aligned
//     base in the class and force bottom). The guaranteed physical window is
//     IMAGE_ALIGN-granular (Q_PHYS_KASLR_ALIGN is raised only to EFI_KIMG_ALIGN
//     = IMAGE_ALIGN, and any coarser 2 MiB phys bound is CONF_HEURISTIC /
//     likely-only), so the residue class composes without contradicting it.
//   * Confidence inherits the observation's (single source).
//
// Inert when no arm64 VIRT kernel-image base observation is present. arm64
// only.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"
#include "include/kasld/regions.h"

#define ARM64_KIMG_ALIGN                                                       \
  0x200000ul /* MIN_KIMG_ALIGN (2 MiB): the granule the */
             /* kernel-image virt-phys offset is aligned */
             /* to, so virt and phys _text share low bits */

int rule_arm64_phys_text_residue(const struct evidence_set *ev,
                                 const struct estimate *est,
                                 struct constraint *out, int out_max) {
  (void)est;
#if defined(__aarch64__)
  /* VIRT kernel-image base → Q_PHYS_IMAGE_BASE residue (mod 2 MiB). */
  return kasld_emit_text_residue(ev, out, out_max, KASLD_TYPE_VIRT,
                                 Q_PHYS_IMAGE_BASE, ARM64_KIMG_ALIGN,
                                 "arm64_phys_text_residue");
#else
  (void)ev;
  (void)out;
  (void)out_max;
  return 0;
#endif
}
