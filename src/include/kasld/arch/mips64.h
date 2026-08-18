// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Definitions for MIPS 64-bit (mips64el)
//
// KASLR support added in commit 405bc8fd12f59ec865714447b2f6e1a961f49025 in
// kernel v4.7-rc1~6^2~183 on 2016-05-13.
//
// References:
// https://github.com/torvalds/linux/commit/405bc8fd12f59ec865714447b2f6e1a961f49025
// https://training.mips.com/basic_mips/PDF/Memory_Map.pdf
// ---
// <bcoles@gmail.com>

#ifndef KASLD_MIPS64_H
#define KASLD_MIPS64_H

// https://elixir.bootlin.com/linux/v6.1.1/source/arch/mips/include/asm/addrspace.h#L68
#define PAGE_OFFSET 0xffffffff80000000ul
// CKSEG0 is fixed by the MIPS ISA — virt_page_offset cannot vary at runtime.
#define PAGE_OFFSET_INVARIANT 1
// CKSEG0, fixed by the MIPS ISA. Note this sits far ABOVE
// KERNEL_VIRT_VAS_START (0x8000000000000000) -- the kernel address space
// begins well below the linear map here.
#define PAGE_OFFSET_CANDIDATES {0xffffffff80000000ul}
#define PAGE_OFFSET_MIN 0xffffffff80000000ul
#define PAGE_OFFSET_MAX 0xffffffff80000000ul

// https://elixir.bootlin.com/linux/v6.1.1/source/arch/mips/include/asm/mach-generic/spaces.h#L28
#define PHYS_OFFSET 0ul

// XKPHYS / CKSEG0 are hardware-fixed; PHYS_OFFSET is compile-time. The
// directmap projection is sound. Kernel text lives in CKSEG0/XKPHYS at a
// fixed offset, so text tracks the directmap.
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/mips/include/asm/page.h#L199
// PAGE_OFFSET is fixed by the CKSEG0 hardware mapping, so the compile-time
// direct-map formula is exact (DIRECTMAP_STATIC) and text tracks the directmap.
// LINEAR_MAP_ANCHOR: PAGE_OFFSET is CAC_BASE + PHYS_OFFSET, so the anchor
// is the compile-time PHYS_OFFSET (0), not a runtime DRAM discovery.
// arch/mips/include/asm/mach-generic/spaces.h PAGE_OFFSET / PHYS_OFFSET
#define LINEAR_MAP_ANCHOR LM_ANCHOR_PHYS_OFFSET
#define DIRECTMAP_STATIC 1
#define TEXT_TRACKS_DIRECTMAP 1

// XKPHYS base: 0x8000000000000000 (hardware-defined direct physical map).
// CKSEG0 / CKSSEG: 0xffffffff80000000+ (compatibility segments).
// Both are part of the kernel VAS.
// https://elixir.bootlin.com/linux/v6.12/source/arch/mips/include/asm/addrspace.h#L71
#define KERNEL_VIRT_VAS_START 0x8000000000000000ul
#define KERNEL_VIRT_VAS_END 0xfffffffffffffffful

#define KERNEL_VIRT_TEXT_MIN PAGE_OFFSET
// Above this, addresses fall in the module region.
#define KERNEL_VIRT_TEXT_MAX 0xffffffffc0000000ul

// Where the module band is anchored: a fixed address range, independent of both
// the image and the linear map.
#define MODULES_ANCHOR MOD_ANCHOR_FIXED
#define MODULES_START 0xffffffffc0000000ul
#define MODULES_END 0xfffffffffffffffful

// PINNED: MODULES_VADDR is CKSSEG (0xffffffffc0000000), a fixed MIPS segment
// address, so the region starts there on every 64-bit MIPS configuration --
// the floor is the base itself, not merely a bound on it. The ceiling the
// level also asserts holds: MODULES_END is FIXADDR_START - 2 pages, below the
// one declared here, and neither varies with config.
#define MODULES_BAND_STRENGTH MOD_BAND_PINNED

// KASLR offset is shifted left 16 bits (64 KiB granularity).
// https://elixir.bootlin.com/linux/v6.12/source/arch/mips/kernel/relocate.c#L276
#define IMAGE_ALIGN 0x10000ul

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
#define STEXT_OFFSET 0x400ul

// Plausible physical address range for kernel image
#define KERNEL_PHYS_MIN 0ul
#define KERNEL_PHYS_MAX (2ul * GB)

// Default: 0xffffffff80100000 (ckseg0 + 1 MiB standard load offset). _stext
// is a projection at +STEXT_OFFSET (0xffffffff80100400), not the image base.
// 0x100000: standard MIPS kernel load offset (load-y in arch/mips/Makefile);
// identical in mips32.h — the arch headers are standalone (no shared include),
// so the value is mirrored, not factored. Keep the two in sync.
// See docs/kaslr.md "Default text base and KASLR alignment" for all
// architectures. Kernel source: arch/mips/kernel/vmlinux.lds.S,
// arch/mips/kernel/head.S
#define KERNEL_VIRT_TEXT_DEFAULT                                               \
  (KERNEL_VIRT_TEXT_MIN + 0x100000ul + IMAGE_BASE_OFFSET)

#define KASLR_SUPPORTED 1

// Residue 0: _text IS the linker load address (see IMAGE_BASE_OFFSET above),
// and KASLR relocates by whole 64 KiB granules, so it stays on the grid.
#define IMAGE_BASE_RESIDUE_FIXED 1

#endif /* KASLD_MIPS64_H */
