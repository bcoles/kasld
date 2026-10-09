// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Definitions for MIPS 32-bit (mips / mipsbe / mipsel)
//
// KASLR support added in commit 405bc8fd12f59ec865714447b2f6e1a961f49025 in
// kernel v4.7-rc1~6^2~183 on 2016-05-13.
//
// References:
// https://github.com/torvalds/linux/commit/405bc8fd12f59ec865714447b2f6e1a961f49025
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/mips/include/asm/processor.h#L39
// https://www.kernel.org/doc/Documentation/mips/booting.rst
// https://training.mips.com/basic_mips/PDF/Memory_Map.pdf
// ---
// <bcoles@gmail.com>

#ifndef KASLD_MIPS32_H
#define KASLD_MIPS32_H

// Boards:
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/mips/include/asm/mach-ar7/spaces.h#L17
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/mips/include/asm/mach-malta/spaces.h#L36
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/mips/include/asm/mach-generic/spaces.h#L91
//
// Generic, assuming kseg0: 0x80000000 - 0x9fffffff
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/mips/include/asm/mach-generic/spaces.h#L33
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/mips/include/asm/addrspace.h#L98
#define PAGE_OFFSET 0x80000000ul
// The KSEG0 segment base, which the MIPS32 ISA fixes at 0x80000000, and the
// whole of the projection constant. __va carries + PAGE_OFFSET - PHYS_OFFSET
// and PAGE_OFFSET is CAC_BASE + PHYS_OFFSET, so PHYS_OFFSET cancels and
// __va(x) is x + CAC_BASE; __pa masks with CPHYSADDR, which cannot depend on
// PHYS_OFFSET at all. virt_page_offset therefore cannot vary at runtime
// whatever PHYS_OFFSET holds -- including where it is derived at boot, since
// CONFIG_MIPS_AUTO_PFN_OFFSET makes it PFN_PHYS of the extern ARCH_PFN_OFFSET.
// arch/mips/include/asm/page.h ___pa / __va
//
// CONFIG_EVA is out of scope, and is a separate matter: under it
// mach-malta/spaces.h defines PAGE_OFFSET as 0 with PHYS_OFFSET 0x80000000
// before including the generic header, whose #ifndef PAGE_OFFSET then leaves
// that value standing. The cancellation still holds as arithmetic -- 32-bit
// CAC_BASE + PHYS_OFFSET wraps to that same 0 -- but RAM begins at physical
// 0x80000000 and __va places it at virtual 0, so the linear map begins at
// virtual 0 and its anchor is PHYS_OFFSET rather than 0. EVA is also the one
// configuration on which __pa subtracts rather than masks. The bracket below
// excludes that base.
#define PAGE_OFFSET_INVARIANT 1
// KSEG0, fixed by the MIPS ISA.
#define PAGE_OFFSET_CANDIDATES {0x80000000ul}
// Admissible kernel page sizes on this architecture. PAGE_SIZE_KNOWN_AT_BUILD
// is derived from the pair in api.h and gates pfn_to_phys(); a page-frame
// number may only be converted with a compile-time constant where the two
// edges coincide. Where they differ the runtime SF_PAGE_SIZE observation is
// the only sound multiplier.
// mips admits 4, 16 and 64 KiB pages generally
// (HAVE_PAGE_SIZE_{4,16,64}KB in arch/mips/Kconfig), and 8 or 32 KiB on Octeon.
#define PAGE_SIZE_MIN 0x1000ul
#define PAGE_SIZE_MAX 0x10000ul

#define PAGE_OFFSET_MIN 0x80000000ul
#define PAGE_OFFSET_MAX 0x80000000ul

// https://elixir.bootlin.com/linux/v6.1.1/source/arch/mips/include/asm/mach-generic/spaces.h#L28
#define PHYS_OFFSET 0ul

// CKSEG0 is hardware-fixed; PHYS_OFFSET is compile-time. The directmap
// projection is sound. Kernel text lives in CKSEG0 at a fixed offset, so
// text tracks the directmap.
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/mips/include/asm/page.h#L199
// PAGE_OFFSET is fixed by the KSEG0 hardware mapping, so the compile-time
// direct-map formula is exact (DIRECTMAP_STATIC) and text tracks the directmap.
// LINEAR_MAP_ANCHOR: the anchor is 0 on every configuration in scope, and
// stays 0 however the platform's PHYS_OFFSET is set or derived. __va(0) is
// CAC_BASE by the cancellation above, and the CPHYSADDR mask __pa applies
// returns 0 at the segment base. That covers a platform that shifts
// PHYS_OFFSET (mach-ip22 and mach-pic32 set 0x08000000) and one where it is
// a boot-time quantity (CONFIG_MIPS_AUTO_PFN_OFFSET, which
// MIPS_GENERIC_KERNEL selects, makes it PFN_PHYS of the extern
// ARCH_PFN_OFFSET).
// arch/mips/include/asm/mach-generic/spaces.h PAGE_OFFSET / PHYS_OFFSET
#define LINEAR_MAP_ANCHOR LM_ANCHOR_PHYS_OFFSET
#define DIRECTMAP_STATIC 1
#define TEXT_TRACKS_DIRECTMAP 1

#define KERNEL_VIRT_VAS_START PAGE_OFFSET
#define KERNEL_VIRT_VAS_END 0xfffffffful

#define VIRT_TEXT_PLAUSIBLE_MIN PAGE_OFFSET
// Above this, addresses fall in the module region (kseg2).
#define VIRT_TEXT_PLAUSIBLE_MAX 0xc0000000ul

// Where the module band is anchored: a fixed address range, independent of both
// the image and the linear map.
#define MODULES_ANCHOR MOD_ANCHOR_FIXED
#define MODULES_START 0xc0000000ul
#define MODULES_END 0xfffffffful

// PINNED: 32-bit MIPS has no MODULES_VADDR, so modules come from vmalloc at
// MAP_BASE (kseg2, 0xc0000000) -- this floor exactly. The floor is therefore
// the base itself, not merely a bound on it: a fixed address, not a randomized
// or runtime-derived one. The machine-specific MAP_BASE override (Loongson) is
// 64-bit only, and MODULES_END is the top of the address space, so the ceiling
// the level also asserts holds trivially.
#define MODULES_BAND_STRENGTH MOD_BAND_PINNED

// KASLR offset is shifted left 16 bits (64 KiB granularity).
// https://elixir.bootlin.com/linux/v6.12/source/arch/mips/kernel/relocate.c#L276
#define IMAGE_ALIGN 0x10000ul

// The granularity is the architecture's, not a build's: relocate.c computes
// `offset = get_random_boot() << 16`, a constant shift, and physical and
// virtual text move together here.
// https://elixir.bootlin.com/linux/latest/source/arch/mips/kernel/relocate.c
//
// The 64 KiB grid survives the wrap path for a reason the expression does not
// state. Where the drawn offset lands below the kernel image, relocate.c adds
// ALIGN(kernel_length, 0xffff) to it -- a non-power-of-two argument, so the
// mask is ~0xfffe, which clears bits 1 through 15 and leaves bit 0 alone. The
// sum stays a multiple of 64 KiB only because the image length is even. The
// grid is right; it is reached by accident of that expression, which is worth
// knowing if the expression ever changes.
#define KASLR_ALIGN_FIXED 1

// _text IS the linker load address on mips: the linker script sets
// `_text = .` at LINKER_LOAD_ADDRESS and only then emits HEAD_TEXT, so nothing
// precedes it and its residue within the 64 KiB KASLR granule is zero.
//
// The 0x400 below is the OTHER offset: head.S reserves an exception-vector
// fill between _text and _stext, so _stext = _text + 0x400. It was carried as
// IMAGE_BASE_OFFSET (the alignment residue) from the rename that split one
// conflated TEXT_OFFSET into two, which put a head gap on the residue axis.
//
//   arch/mips/kernel/vmlinux.lds.S   . = LINKER_LOAD_ADDRESS; _text = .;
//   arch/mips/kernel/head.S          __HEAD; .fill 0x400; EXPORT(_stext)
//   arch/mips/kernel/setup.c         code_resource.start = __pa_symbol(&_text)
//
// The fill is conditional -- `#ifndef CONFIG_NO_EXCEPT_FILL`, which
// MIPS_GENERIC_KERNEL and four other platforms select -- so on those kernels
// _stext == _text. STEXT_OFFSET is a fallback for _stext-only sources, and on
// mips it is always the bridge: kallsyms exports _stext and not _text, so no
// real _text leak ever overrides it. On a NO_EXCEPT_FILL kernel the image base
// derived from a leaked _stext is therefore 0x400 low. That is inherent -- the
// two configurations are indistinguishable from _stext alone -- and widening
// the derivation to cover both would cost the pin.
#define IMAGE_BASE_OFFSET 0

// https://elixir.bootlin.com/linux/v6.1.1/source/arch/mips/kernel/head.S#L67
/* head.S reserves `.fill 0x400` before EXPORT(_stext) -- a real constant,
 * but only #ifndef CONFIG_NO_EXCEPT_FILL, and MIPS_GENERIC_KERNEL,
 * BMIPS_GENERIC, BCM47XX, LANTIQ and MACH_LOONGSON64 all select it, where
 * the gap is 0. So the witness bounds the image base, it does not fix it. */
// Estimate: the .fill 0x400 head.S reserves before EXPORT(_stext), measured on
// every mips kernel booted. The floor is 0 -- CONFIG_NO_EXCEPT_FILL omits it.
#define STEXT_OFFSET 0x400ul
#define STEXT_OFFSET_MIN 0ul
#define STEXT_OFFSET_MAX 0x400ul

// Plausible physical address range for kernel image
#define PHYS_PLAUSIBLE_MIN 0ul
#define PHYS_PLAUSIBLE_MAX (512ul * MB)

// Default: 0x80100000 (kseg0 + 1 MiB standard load offset). _stext is a
// projection at +STEXT_OFFSET (0x80100400), not the image base.
// 0x100000: standard MIPS kernel load offset (load-y in arch/mips/Makefile);
// identical in mips64.h — the arch headers are standalone (no shared include),
// so the value is mirrored, not factored. Keep the two in sync.
// See docs/kaslr.md "Default text base and KASLR alignment" for all
// architectures. Kernel source: arch/mips/kernel/vmlinux.lds.S,
// arch/mips/kernel/head.S
#define KERNEL_VIRT_TEXT_DEFAULT                                               \
  (VIRT_TEXT_PLAUSIBLE_MIN + 0x100000ul + IMAGE_BASE_OFFSET)

#define KASLR_SUPPORTED 1

// Residue 0: _text IS the linker load address (see IMAGE_BASE_OFFSET above),
// and KASLR relocates by whole 64 KiB granules, so it stays on the grid.
#define IMAGE_BASE_RESIDUE_FIXED 1

#endif /* KASLD_MIPS32_H */
