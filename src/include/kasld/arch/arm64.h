// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Definitions for ARM 64-bit (aarch64 / arm64)
//
// The arm64 kernel VAS layout has changed across versions.
//
// Old layout — modules and kernel image below PAGE_OFFSET:
//   MODULES_VADDR = VA_START(48) = 0xffff000000000000
//   KIMAGE_VADDR  = VA_START(48) + SZ_128M = 0xffff000008000000
//   (with BPF JIT: +SZ_128M BPF, +SZ_128M modules → KIMAGE at +SZ_256M)
//   PAGE_OFFSET   = 0xffff800000000000
//
// New layout — modules and kernel image at/above _PAGE_END:
//   _PAGE_END(48) = 0xffff800000000000
//   KIMAGE_VADDR  = _PAGE_END(48) + module_region_size
//     +SZ_128M  → 0xffff800008000000
//     +SZ_256M  → 0xffff800010000000
//     +SZ_2G    → 0xffff800080000000
//
// The key runtime discriminator is whether kernel text is above or below
// 0xffff800000000000 (_PAGE_END for 48-bit VA).
//
// KASLR support added in commit 588ab3f9afdfa1a6b1e5761c858b2c4ab6098285 in
// kernel v4.6-rc1~110 on 2016-03-17.
//
// References:
// https://github.com/torvalds/linux/commit/588ab3f9afdfa1a6b1e5761c858b2c4ab6098285
// https://lwn.net/Articles/673598/
// https://www.kernel.org/doc/Documentation/arm64/memory.txt
// https://github.com/torvalds/linux/blob/master/Documentation/arm64/booting.rst
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/Documentation/arm64/memory.rst
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/arm64/kernel/head.S
// ---
// <bcoles@gmail.com>

#ifndef KASLD_ARM64_H
#define KASLD_ARM64_H

// 52 va bits (CONFIG_ARM64_VA_BITS_52) is the default in v6.12+.
// 48 va bits (CONFIG_ARM64_VA_BITS_48) is common on older kernels.
// PAGE_OFFSET = _PAGE_OFFSET(VA_BITS) = -(1UL << VA_BITS)
//   VA_BITS=48: 0xffff000000000000
//   VA_BITS=52: 0xfff0000000000000
// https://elixir.bootlin.com/linux/v6.12/source/arch/arm64/include/asm/memory.h#L44
// We assume 52 va bits (broadest, covers all configs):
#define PAGE_OFFSET 0xfff0000000000000ul
#define PHYS_OFFSET 0ul

// VA_BITS candidates for Q_VA_BITS (finite-set lattice), smallest first. Each
// arm64 paging config has its own VA_BITS (hence its own PAGE_OFFSET /
// KIMAGE_VADDR geometry): 4K 3-level=39 (common on Android), 64K 2-level=42,
// 16K 3-level=47, 4K/16K 4-level=48, and 52-bit LVA (VA_BITS_MIN still 48).
#define VA_BITS_CANDIDATES {39ul, 42ul, 47ul, 48ul, 52ul}
// Smallest supported VA_BITS — gives the highest (widest-accepting) linear-map
// ceiling for region validation.
#define ARM64_VA_BITS_MIN_SUPPORTED 39ul

// VA_BITS-derived geometry, kept in one place so the layout math is not
// duplicated across mmap_arm64_va_bits, arm64_coupling_validate, and
// arm64_va_bits_from_directmap. arm64 PAGE_OFFSET = -(1<<VA_BITS); the linear
// map occupies [PAGE_OFFSET, _PAGE_END), _PAGE_END = -(1<<(VA_BITS-1)). Pure
// functions of VA_BITS, not randomized.
static inline unsigned long arm64_page_offset_for(unsigned long va_bits) {
  return -(1UL << va_bits);
}
static inline unsigned long arm64_page_end_for(unsigned long va_bits) {
  return -(1UL << (va_bits - 1));
}

// On arm64, PHYS_OFFSET is runtime (= memstart_addr, randomized at boot), so
// the compile-time formula is NOT a sound runtime directmap projection;
// phys_to_directmap_virt() is therefore left undefined (see gate at end of
// file). Kernel text KASLR slides independently of the linear map, so text
// does not track the directmap.
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/arm64/include/asm/memory.h#L295
#define DIRECTMAP_STATIC 0
#define TEXT_TRACKS_DIRECTMAP 0

#define KERNEL_VIRT_VAS_START PAGE_OFFSET
#define KERNEL_VIRT_VAS_END 0xfffffffffffffffful

// 48 va bits (CONFIG_ARM64_VA_BITS_48) is a common configuration;
// but an unsafe assumption since introduction of CONFIG_ARM64_VA_BITS_48_52.
// older kernels may use 0xffff000008000000ul
//
// Validation range for the modern layout (compile-time default).
// Older arm64 layouts (pre-v5.4, below _PAGE_END) fall outside this range.
#define KERNEL_VIRT_TEXT_MIN 0xffff800008000000ul
#define KERNEL_VIRT_TEXT_MAX 0xffffffffff000000ul

// Module region — VALIDATION UNION across all in-scope kernel versions.
//
//   pre-v5.4 layout:   [0xffff000000000000, 0xffff000007fffffful]  (128 MiB at
//   old VA_START(48)) v5.4 .. v6.1 :     [0xffff800000000000,
//   0xffff800007fffffful]  (128 MiB at _PAGE_END(48)) v5.0+ variant:
//   [0xffff800000000000, 0xffff80000fffffful]   (256 MiB) v6.2+:
//   [0xffff800000000000, 0xffff80007ffffffful]  (2 GiB)
//
// The two base addresses (0xffff0000... vs 0xffff8000...) belong to the old
// vs new VA layouts; both still appear in the wild. The union spans both
// bases so a real module leak from either layout is admitted by
// result_in_bounds(). Trade-off: the union includes a large addressable gap
// between the two bases where modules never actually live; addresses in
// that gap can be misclassified as REGION_MODULE_REGION by sources that
// guess region purely by address (dmesg parsers). Mitigated downstream:
// module_text_bound is inert on arm64 (MODULES_RELATIVE_TO_TEXT=0), so the
// admission does not pollute Q_VIRT_IMAGE_BASE. The runtime band rendered to
// the user comes from observed module addresses when available
// (engine_sync), not the wide validation window.
// https://elixir.bootlin.com/linux/v6.6/source/arch/arm64/include/asm/memory.h
#define MODULES_START 0xffff000000000000ul
#define MODULES_END 0xffff80007ffffffful
// Module region does not shift with KASLR on arm64.
// (Modules are loaded independently of kernel text placement.)
#define MODULES_RELATIVE_TO_TEXT 0

// MIN_KIMG_ALIGN is 2MiB (used without KASLR).
// https://elixir.bootlin.com/linux/v6.2-rc2/source/arch/arm64/include/asm/boot.h#L18
// EFI_KIMG_ALIGN is the larger of THREAD_ALIGN or SEGMENT_ALIGN:
// https://elixir.bootlin.com/linux/v6.2-rc2/source/arch/arm64/include/asm/efi.h#L102
// https://elixir.bootlin.com/linux/v6.2-rc2/source/arch/arm64/include/asm/efi.h#L72
// SEGMENT_ALIGN is hard-coded as 64KiB:
// https://elixir.bootlin.com/linux/v6.2-rc2/source/arch/arm64/include/asm/memory.h#L131
// THREAD_ALIGN = 2 * THREAD_SIZE = 2 * (1 << max(PAGE_SHIFT,
// MIN_THREAD_SHIFT=14))
// - 4K pages (PAGE_SHIFT=12): THREAD_SHIFT=14, THREAD_ALIGN=32KiB,
// EFI_KIMG_ALIGN=64KiB
// - 16K pages (PAGE_SHIFT=14): THREAD_SHIFT=14, THREAD_ALIGN=32KiB,
// EFI_KIMG_ALIGN=64KiB
// - 64K pages (PAGE_SHIFT=16): THREAD_SHIFT=16, THREAD_ALIGN=128KiB,
// EFI_KIMG_ALIGN=128KiB For 4K/16K (the common case), EFI_KIMG_ALIGN=64KiB. Use
// 64KiB (0x10000) by default. On 64K-page EFI systems this is conservative
// (128KiB actual); see arm64_phys_kaslr_align.
#define IMAGE_ALIGN 0x10000ul

// EFI_KIMG_ALIGN is the alignment the EFI stub uses when calling
// AllocatePages() for the kernel image (see arch/arm64/include/asm/efi.h).
// The arm64 stub allocates the image at this granularity, so the running
// kernel's EFI_LOADER_CODE memmap entry always starts at a multiple of
// this value — used by efi_loader_kernel_pick to filter multi-entry
// memmaps. Conservative 64 KiB matches 4K/16K-page builds (the common
// case); 64K-page builds use 128 KiB but ARE a multiple of 64 KiB, so
// the filter stays sound (just slightly less selective).
#define EFI_KIMG_ALIGN 0x10000ul

// IMAGE_BASE_OFFSET is the alignment residue (where _text sits within the KASLR
// granule); _text == KIMAGE_VADDR is 2 MiB-aligned, so it is 0. (The kernel's
// historical 0x80000 TEXT_OFFSET, dropped in v5.8, was the *physical* load
// offset from the start of RAM — a different quantity, not the _text alignment
// residue.)
// https://lore.kernel.org/all/20200428134119.GI6791@willie-the-truck/T/
#define IMAGE_BASE_OFFSET 0

// Head gap _stext - _text: arm64 places .head.text (EFI header + early vectors)
// before _stext, so _stext = _text + 0x10000. The engine solves the image base
// (_text); _stext is projected from it with STEXT_OFFSET.
#define STEXT_OFFSET 0x10000ul

// Plausible physical address range for kernel image
#define KERNEL_PHYS_MIN 0ul
#define KERNEL_PHYS_MAX (256ul * GB)

// KIMAGE_VADDR = MODULES_END on arm64. Varies by version (new layout only):
//   v5.4:  _PAGE_END(48) + SZ_128M  = 0xffff800008000000
//   v5.0:  _PAGE_END(48) + SZ_256M  = 0xffff800010000000
//   v6.2+: _PAGE_END(48) + SZ_2G    = 0xffff800080000000
// (Old pre-v5.4 layout used VA_START(48) + SZ_128M = 0xffff000008000000.)
// https://elixir.bootlin.com/linux/v6.12/source/arch/arm64/include/asm/memory.h#L46
// Use v6.2+ value (2G module region, current default).
#define KIMAGE_VADDR 0xffff800080000000ul
// Module-region size (KIMAGE_VADDR = _PAGE_END(VA_BITS_MIN) + this). v6.2+ uses
// SZ_2G; older kernels used 128M/256M. rule_arm64_text_base derives
// KIMAGE_VADDR for the resolved VA_BITS_MIN as arm64_page_end_for(VA_BITS_MIN)
// + this — for VA_BITS_MIN=48 that reproduces KIMAGE_VADDR above. The version
// spread is the pin's residual imprecision (inferred confidence; a real leak
// overrides).
#define ARM64_MODULE_REGION_SIZE (2ul * GB)

// See docs/kaslr.md "Default text base and KASLR alignment" for all
// architectures. Kernel source: arch/arm64/kernel/vmlinux.lds.S,
// arch/arm64/include/asm/memory.h
#define KERNEL_VIRT_TEXT_DEFAULT (KIMAGE_VADDR + IMAGE_BASE_OFFSET)

/* KASLR-off pin is LAYOUT-DEPENDENT on arm64: KIMAGE_VADDR varies with
 * VA_BITS_MIN (= min(VA_BITS, 48)), so the no-KASLR text base is not a single
 * compile-time constant. The generic virt_kaslr_disabled_pin (one fixed
 * default) is therefore opted OUT; rule_arm64_text_base owns the text base,
 * deriving VA_BITS_MIN from the resolved PAGE_OFFSET and narrowing/pinning to
 * KIMAGE_VADDR(VA_BITS_MIN) — correct for VA_BITS 39/42/47/48/52, not just 48.
 * Same shape as rule_riscv64_text_base. When PAGE_OFFSET is unresolved (no
 * probe result, no leak) it does not pin — the honest window stays wide
 * (sound). */
#define KASLR_DISABLED_PINS_VIRT_TEXT 0
#define KASLD_ARCH_DEFAULT_TEXT_BASE_DEFINED 1
static inline unsigned long arch_default_text_base(void) {
  return KERNEL_VIRT_TEXT_DEFAULT;
}

// KASLR randomization window (v4.6+):
// The KASLR offset from KIMAGE_VADDR is in [BIT(45), BIT(45)+BIT(46)).
// VA_BITS_MIN is always 48 (4K pages), so the offset range is constant.
// Aligned to SZ_2M (explicitly masked in v5.10; page-table granularity in
// v6.2+). Entropy: BIT(46) / SZ_2M = BIT(25) = 33554432 slots (25 bits).
//
// v6.6   kaslr_early.c: return BIT(VA_BITS_MIN-3) + (seed &
// GENMASK(VA_BITS_MIN-3,0)); v6.12  kaslr_early.c: range = (VMALLOC_END -
// KIMAGE_VADDR) / 2;
//                        return range / 2 + (((__uint128_t)range * seed) >>
//                        64);
// https://elixir.bootlin.com/linux/v6.12/source/arch/arm64/kernel/pi/kaslr_early.c
#define KASLR_VIRT_TEXT_MIN (KIMAGE_VADDR + (1ul << 45))
#define KASLR_VIRT_TEXT_MAX (KASLR_VIRT_TEXT_MIN + (1ul << 46))
#define KASLR_VIRT_ALIGN (2 * MB)

/* Honest-top floor for Q_VIRT_IMAGE_BASE — widened down to the OLD (pre-v5.4)
 * layout's image base so the engine's honest window admits every in-scope
 * arm64 text placement:
 *   (a) the pre-v5.4 layout, where the kernel image sits LOW — below _PAGE_END,
 *       at VA_START(48) + module-region (128 MiB) = 0xffff000008000000, with
 *       _text a TEXT_OFFSET above that (e.g. v4.14: 0xffff000008080000). This
 *       is the lowest text base across layouts (48-bit VA gives the lowest
 *       VA_START; sub-48 old layouts and all modern layouts sit higher);
 *   (b) the modern (v5.4+) no-KASLR case, where text sits at KIMAGE_VADDR;
 *   (c) the v6.12+ KASLR formula's lower edge at
 *       KIMAGE_VADDR + (VMALLOC_END − KIMAGE_VADDR) / 4 ≈ KIMAGE_VADDR + 31.5
 *       TiB — below the v4.6→v6.6 formula's floor at KIMAGE_VADDR + 32 TiB.
 *
 * Without this widening the honest window floors at KIMAGE_VADDR
 * (0xffff800080000000), so on a pre-v5.4 kernel with no narrowing leak
 * (the unprivileged/hardened case) Q_VIRT_IMAGE_BASE stays at a window that
 * EXCLUDES the real low text base — an unsound report. The widening only
 * widens the honest top — never narrows — so it cannot eliminate a true leak;
 * it can only stop falsely excluding one. When PAGE_OFFSET resolves,
 * rule_arm64_text_base re-narrows to the tight per-VA_BITS band.
 *
 * KASLR_VIRT_TEXT_MIN is preserved for entropy / slot reporting on KASLR-on
 * systems (the per-formula randomization window's narrower lower edge).
 * KASLR_VIRT_TEXT_MAX is unchanged — KIMAGE_VADDR + 96 TiB already covers both
 * the v6.6 upper edge (96 TiB) and the v6.12+ upper edge (~94.5 TiB). */
#define KASLR_VIRT_TEXT_MIN_WIDE 0xffff000008000000ul

/* Honest-top CEILING for Q_VIRT_IMAGE_BASE. KASLR_VIRT_TEXT_MAX is the 48-bit
 * formula's window top (kept for entropy/slot reporting); it is too low for
 * sub-48 configs, whose KIMAGE_VADDR is HIGHER (39-bit → 0xffffffc080000000).
 * Widen the honest top to the validation ceiling KERNEL_VIRT_TEXT_MAX, which
 * admits every supported VA_BITS_MIN's text base, so a sub-48 text leak is not
 * falsely excluded. Widen-only, never-narrow — same discipline as the floor. */
#define KASLR_VIRT_TEXT_MAX_WIDE KERNEL_VIRT_TEXT_MAX

#define KASLR_SUPPORTED 1

#endif /* KASLD_ARM64_H */
