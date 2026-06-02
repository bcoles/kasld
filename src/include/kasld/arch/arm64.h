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

// VA_BITS candidates for Q_VA_BITS (finite-set lattice). 48 and 52 are the two
// configurations whose PAGE_OFFSET the directmap-range rule discriminates.
#define VA_BITS_CANDIDATES {48ul, 52ul}

// On arm64, PHYS_OFFSET is runtime (= memstart_addr, randomized at boot), so
// the compile-time formula is NOT a sound runtime directmap projection;
// phys_to_directmap_virt() is therefore left undefined (see gate at end of
// file). Kernel text KASLR slides independently of the linear map, so text
// does not track the directmap.
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/arm64/include/asm/memory.h#L295
#define DIRECTMAP_STATIC 0
#define TEXT_TRACKS_DIRECTMAP 0

#define KERNEL_VAS_START PAGE_OFFSET
#define KERNEL_VAS_END 0xfffffffffffffffful

// 48 va bits (CONFIG_ARM64_VA_BITS_48) is a common configuration;
// but an unsafe assumption since introduction of CONFIG_ARM64_VA_BITS_48_52.
// older kernels may use 0xffff000008000000ul
//
// Validation range for the modern layout (compile-time default).
// Older arm64 layouts (pre-v5.4, below _PAGE_END) fall outside this range.
#define KERNEL_TEXT_MIN 0xffff800008000000ul
#define KERNEL_TEXT_MAX 0xffffffffff000000ul

// _PAGE_END(48) = 0xffff800000000000 is the runtime discriminator.
// Kernel text below this → old layout; at/above → new layout.
#define ARM64_LEGACY_LAYOUT_BOUNDARY 0xffff800000000000ul

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
// admission does not pollute Q_VIRT_TEXT_BASE. The runtime band rendered to
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
#define KERNEL_ALIGN 0x10000ul

// EFI_KIMG_ALIGN is the alignment the EFI stub uses when calling
// AllocatePages() for the kernel image (see arch/arm64/include/asm/efi.h).
// The arm64 stub allocates the image at this granularity, so the running
// kernel's EFI_LOADER_CODE memmap entry always starts at a multiple of
// this value — used by efi_loader_kernel_pick to filter multi-entry
// memmaps. Conservative 64 KiB matches 4K/16K-page builds (the common
// case); 64K-page builds use 128 KiB but ARE a multiple of 64 KiB, so
// the filter stays sound (just slightly less selective).
#define EFI_KIMG_ALIGN 0x10000ul

// TEXT_OFFSET was changed from 0x80000 to zero in 2020 from kernel v5.8 onwards
// https://elixir.bootlin.com/linux/v5.8/source/arch/arm64/Makefile
// https://lore.kernel.org/all/20200428134119.GI6791@willie-the-truck/T/
#define TEXT_OFFSET 0

// Plausible physical address range for kernel image
#define KERNEL_PHYS_MIN 0ul
#define KERNEL_PHYS_MAX (256ul * GB)

// KIMAGE_VADDR = MODULES_END on arm64. Varies by version (new layout only):
//   v5.4:  _PAGE_END(48) + SZ_128M  = 0xffff800008000000
//   v5.0:  _PAGE_END(48) + SZ_256M  = 0xffff800010000000
//   v6.2+: _PAGE_END(48) + SZ_2G    = 0xffff800080000000
// (Old layout used VA_START(48) + SZ_128M = 0xffff000008000000; see LEGACY_*)
// https://elixir.bootlin.com/linux/v6.12/source/arch/arm64/include/asm/memory.h#L46
// Use v6.2+ value (2G module region, current default).
#define KIMAGE_VADDR 0xffff800080000000ul

// See docs/kaslr.md "Default text base and KASLR alignment" for all
// architectures. Kernel source: arch/arm64/kernel/vmlinux.lds.S,
// arch/arm64/include/asm/memory.h
#define KERNEL_TEXT_DEFAULT (KIMAGE_VADDR + TEXT_OFFSET)

/* KASLR-off ⇒ pin contract: arm64 KIMAGE_VADDR is fixed at kernel build
 * time by CONFIG_ARM64_VA_BITS_MIN (universally 48 in practice). Without
 * KASLR the kernel lands at KIMAGE_VADDR + TEXT_OFFSET regardless of the
 * runtime VA_BITS (which only affects PAGE_OFFSET / the linear map). Build
 * configs with VA_BITS_MIN != 48 land at a different address; the pin rule's
 * window-containment check rejects the pin in that case. */
#define KASLR_DISABLED_PINS_TEXT 1
#define KASLD_ARCH_DEFAULT_TEXT_BASE_DEFINED 1
static inline unsigned long arch_default_text_base(void) {
  return KERNEL_TEXT_DEFAULT;
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
#define KASLR_TEXT_MIN (KIMAGE_VADDR + (1ul << 45))
#define KASLR_TEXT_MAX (KASLR_TEXT_MIN + (1ul << 46))
#define KASLR_ALIGN (2 * MB)

/* Honest-top floor for Q_VIRT_TEXT_BASE — widened down to KIMAGE_VADDR so
 * the engine's honest window admits:
 *   (a) the no-KASLR case, where text sits at KIMAGE_VADDR exactly
 *       (CONFIG_RANDOMIZE_BASE=n, or `nokaslr` cmdline);
 *   (b) the v6.12+ KASLR formula's lower edge at
 *       KIMAGE_VADDR + (VMALLOC_END − KIMAGE_VADDR) / 4 ≈ KIMAGE_VADDR + 31.5
 * TiB — below the v4.6→v6.6 formula's floor at KIMAGE_VADDR + 32 TiB.
 *
 * Without this widening, kaslr_disabled_pin's window-containment check
 * rejects the no-KASLR default (KIMAGE_VADDR) as below the v6.6-era
 * KASLR_TEXT_MIN, leaving Q_VIRT_TEXT_BASE wide and the actual text base
 * outside the window. The widening only widens the honest top — never
 * narrows — so it cannot eliminate a true leak; it can only stop falsely
 * excluding one.
 *
 * KASLR_TEXT_MIN is preserved for entropy / slot reporting on KASLR-on
 * systems (the per-formula randomization window's narrower lower edge).
 * KASLR_TEXT_MAX is unchanged — KIMAGE_VADDR + 96 TiB already covers both
 * the v6.6 upper edge (96 TiB) and the v6.12+ upper edge (~94.5 TiB). */
#define KASLR_TEXT_MIN_WIDE KIMAGE_VADDR

#define KASLR_SUPPORTED 1

// Legacy layout overrides (pre-v5.4 arm64 VAS).
// Kernel image at VA_START(48) + SZ_128M, below _PAGE_END(48).
// All values are static constants (decoupled, like the modern layout).
// The pre-v5.4 module range is covered by the unified MODULES_START/END
// validation union above.
#define LEGACY_LAYOUT_BOUNDARY ARM64_LEGACY_LAYOUT_BOUNDARY
#define LEGACY_PAGE_OFFSET 0xffff800000000000ul
#define LEGACY_KERNEL_VAS_START 0xffff000000000000ul
#define LEGACY_TEXT_OFFSET 0x80000ul
#define LEGACY_KIMAGE_VADDR 0xffff000008000000ul
#define LEGACY_KERNEL_TEXT_DEFAULT (LEGACY_KIMAGE_VADDR + LEGACY_TEXT_OFFSET)
#define LEGACY_KERNEL_TEXT_MIN LEGACY_KIMAGE_VADDR
// Old KASLR (v4.6): offset = BIT(VA_BITS-2) + (seed & mask), VA_BITS=48
// So offset ∈ [BIT(46), BIT(47)), range = BIT(46), aligned to SZ_2M.
#define LEGACY_KASLR_TEXT_MIN (LEGACY_KERNEL_TEXT_DEFAULT + (1ul << 46))
#define LEGACY_KASLR_TEXT_MAX (LEGACY_KASLR_TEXT_MIN + (1ul << 46))

#endif /* KASLD_ARM64_H */
