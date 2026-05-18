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

// https://elixir.bootlin.com/linux/v6.1.1/source/arch/mips/include/asm/mach-generic/spaces.h#L28
#define PHYS_OFFSET 0ul

// https://elixir.bootlin.com/linux/v6.1.1/source/arch/mips/include/asm/page.h#L199
#define PHYS_VIRT_DECOUPLED 0
#define phys_to_virt(x) ((unsigned long)((x) + PAGE_OFFSET - PHYS_OFFSET))
#define virt_to_phys(v) ((unsigned long)((v) - PAGE_OFFSET + PHYS_OFFSET))

// PAGE_OFFSET is fixed by CKSEG0 hardware mapping;
// Directmap leaks cannot reveal the KASLR slide.
#define PAGE_OFFSET_RANDOMIZED 0

// XKPHYS base: 0x8000000000000000 (hardware-defined direct physical map).
// CKSEG0 / CKSSEG: 0xffffffff80000000+ (compatibility segments).
// Both are part of the kernel VAS.
// https://elixir.bootlin.com/linux/v6.12/source/arch/mips/include/asm/addrspace.h#L71
#define KERNEL_VAS_START 0x8000000000000000ul
#define KERNEL_VAS_END 0xfffffffffffffffful

#define KERNEL_BASE_MIN PAGE_OFFSET
// Above this, addresses fall in the module region.
#define KERNEL_BASE_MAX 0xffffffffc0000000ul

#define MODULES_START 0xffffffffc0000000ul
#define MODULES_END 0xfffffffffffffffful
#define MODULES_RELATIVE_TO_TEXT 0

// KASLR offset is shifted left 16 bits (64 KiB granularity).
// https://elixir.bootlin.com/linux/v6.12/source/arch/mips/kernel/relocate.c#L276
#define KERNEL_ALIGN 0x10000ul

// https://elixir.bootlin.com/linux/v6.1.1/source/arch/mips/kernel/head.S#L67
#define TEXT_OFFSET 0x400

// Plausible physical address range for kernel image
#define KERNEL_PHYS_MIN 0ul
#define KERNEL_PHYS_MAX (2ul * GB)

// Default: 0xffffffff80100400 (CKSEG0 + 1 MiB load offset + head.S entry).
// 0x100000: standard MIPS kernel load offset (load-y in arch/mips/Makefile).
// See README.md "Default text base and KASLR alignment" for all architectures.
// Kernel source: arch/mips/kernel/vmlinux.lds.S, arch/mips/kernel/head.S
#define KERNEL_TEXT_DEFAULT (KERNEL_BASE_MIN + 0x100000ul + TEXT_OFFSET)

#define KASLR_SUPPORTED 1

#endif /* KASLD_MIPS64_H */
