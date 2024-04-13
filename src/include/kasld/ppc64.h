// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Definitions for PowerPC 64-bit (powerpc64 / ppc64 / ppc64le)
//
// Linux for PowerPC 64-bit does not support KASLR.
//
// Work in progress patches for KASLR support from 2020 appear to be abandoned:
// https://lwn.net/Articles/816271/
//
// References:
// https://www.kernel.org/doc/ols/2001/ppc64.pdf
// ---
// <bcoles@gmail.com>

// 0xc000000000000000ul is a common configuration; but an unsafe assumption.
// For Freescale E-Book readers (CONFIG_PPC_BOOK3E_64), the kernel VAS start
// and text start is 0x8000000000000000ul.
// vmalloc, I/O and Bolted sections are mapped above kernel.
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/powerpc/Kconfig#L1267
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/powerpc/Kconfig#L1264
#define PAGE_OFFSET 0xc000000000000000ul

// https://elixir.bootlin.com/linux/v6.1.1/source/arch/powerpc/include/asm/page.h#L227
#define phys_to_virt(x) ((unsigned long)((x) | PAGE_OFFSET))

#define KERNEL_VAS_START PAGE_OFFSET
#define KERNEL_VAS_END 0xfffffffffffffffful

#define KERNEL_BASE_MIN PAGE_OFFSET
#define KERNEL_BASE_MAX 0xffffffffff000000ul

#define MODULES_START 0xc000000000000000ul
#define MODULES_END 0xfffffffffffffffful

// https://elixir.bootlin.com/linux/v6.1.1/source/arch/powerpc/Kconfig#L1270
#define PHYSICAL_START 0ul

// 16KiB (0x4000) aligned
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/powerpc/Kconfig#L595
#define KERNEL_ALIGN 0x4000ul

#define TEXT_OFFSET 0

#define KERNEL_TEXT_DEFAULT (KERNEL_BASE_MIN + TEXT_OFFSET)
