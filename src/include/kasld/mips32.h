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

// Boards:
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/mips/include/asm/mach-ar7/spaces.h#L17
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/mips/include/asm/mach-malta/spaces.h#L36
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/mips/include/asm/mach-generic/spaces.h#L91
//
// We use generic and assume kseg0: 0x80000000 - 0x9fffffff
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/mips/include/asm/mach-generic/spaces.h#L33
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/mips/include/asm/addrspace.h#L98
#define PAGE_OFFSET      0x80000000ul

// https://elixir.bootlin.com/linux/v6.1.1/source/arch/mips/include/asm/mach-generic/spaces.h#L28
#define PHYS_OFFSET      0ul

// https://elixir.bootlin.com/linux/v6.1.1/source/arch/mips/include/asm/page.h#L199
#define phys_to_virt(x) ((unsigned long)((x) + PAGE_OFFSET - PHYS_OFFSET))

#define KERNEL_VAS_START PAGE_OFFSET
#define KERNEL_VAS_END   0xfffffffful

#define KERNEL_BASE_MIN  PAGE_OFFSET
#define KERNEL_BASE_MAX  0xc0000000ul

#define MODULES_START    0xc0000000ul
#define MODULES_END      0xfffffffful

// page aligned (default CONFIG_PAGE_SIZE_4KB=y)
#define KERNEL_ALIGN 0x1000ul

// https://elixir.bootlin.com/linux/v6.1.1/source/arch/mips/kernel/head.S#L67
#define TEXT_OFFSET 0x400

#define KERNEL_TEXT_DEFAULT (KERNEL_BASE_MIN + 0x100000ul + TEXT_OFFSET)
