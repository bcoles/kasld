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

// https://elixir.bootlin.com/linux/v6.1.1/source/arch/mips/include/asm/mach-generic/spaces.h#L28
#define PHYS_OFFSET 0ul

// XKPHYS / CKSEG0 are hardware-fixed; PHYS_OFFSET is compile-time. The
// directmap projection is sound. Kernel text lives in CKSEG0/XKPHYS at a
// fixed offset, so text tracks the directmap.
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/mips/include/asm/page.h#L199
// PAGE_OFFSET is fixed by the CKSEG0 hardware mapping, so the compile-time
// direct-map formula is exact (DIRECTMAP_STATIC) and text tracks the directmap.
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

#define MODULES_START 0xffffffffc0000000ul
#define MODULES_END 0xfffffffffffffffful
#define MODULES_RELATIVE_TO_TEXT 0

// KASLR offset is shifted left 16 bits (64 KiB granularity).
// https://elixir.bootlin.com/linux/v6.12/source/arch/mips/kernel/relocate.c#L276
#define IMAGE_ALIGN 0x10000ul

// https://elixir.bootlin.com/linux/v6.1.1/source/arch/mips/kernel/head.S#L67
#define IMAGE_BASE_OFFSET 0x400

// Plausible physical address range for kernel image
#define KERNEL_PHYS_MIN 0ul
#define KERNEL_PHYS_MAX (2ul * GB)

// Default: 0xffffffff80100400 (CKSEG0 + 1 MiB load offset + head.S entry).
// 0x100000: standard MIPS kernel load offset (load-y in arch/mips/Makefile);
// identical in mips32.h — the arch headers are standalone (no shared include),
// so the value is mirrored, not factored. Keep the two in sync.
// See docs/kaslr.md "Default text base and KASLR alignment" for all
// architectures. Kernel source: arch/mips/kernel/vmlinux.lds.S,
// arch/mips/kernel/head.S
#define KERNEL_VIRT_TEXT_DEFAULT                                               \
  (KERNEL_VIRT_TEXT_MIN + 0x100000ul + IMAGE_BASE_OFFSET)

#define KASLR_SUPPORTED 1

#endif /* KASLD_MIPS64_H */
