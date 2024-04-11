// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Definitions for ARM 32-bit (arm6l / arm7l / armhf)
//
// KASLR support added in commit 588ab3f9afdfa1a6b1e5761c858b2c4ab6098285 in
// kernel v4.6-rc1~110 on 2016-03-17.
//
// References:
// https://github.com/torvalds/linux/commit/588ab3f9afdfa1a6b1e5761c858b2c4ab6098285
// https://people.kernel.org/linusw/how-the-arm32-linux-kernel-decompresses
// https://people.kernel.org/linusw/how-the-arm32-kernel-starts
// https://www.kernel.org/doc/Documentation/arm/Porting
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/arm/kernel/head.S
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/arm/include/asm/memory.h#L30
// ---
// <bcoles@gmail.com>

// 3GB vmsplit (0xc0000000) is common; but an unsafe assumption,
// especially for embedded systems
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/arm/Kconfig#L1116
#define PAGE_OFFSET      0xc0000000ul

// https://elixir.bootlin.com/linux/v6.1.1/source/arch/arm/Kconfig#L276
#define PHYS_OFFSET      0ul

// https://elixir.bootlin.com/linux/v6.1.1/source/arch/arm/include/asm/memory.h#L286
#define phys_to_virt(x) ((unsigned long)((x) - PHYS_OFFSET + PAGE_OFFSET))

#define KERNEL_VAS_START PAGE_OFFSET
#define KERNEL_VAS_END   0xfffffffful

// https://elixir.bootlin.com/linux/v6.1.1/source/arch/arm/include/asm/memory.h#L26
#define KERNEL_BASE_MIN  PAGE_OFFSET
#define KERNEL_BASE_MAX  0xf0000000ul

// Modules are located below kernel: PAGE_OFFSET - 16MiB (0x01000000)
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/arm/include/asm/memory.h#L51
#define MODULES_START    PAGE_OFFSET - 0x01000000 // 0xbf000000ul
#define MODULES_END      PAGE_OFFSET

#define KERNEL_ALIGN 2 * MB

// https://elixir.bootlin.com/linux/v6.1.1/source/arch/arm/Makefile#L145
#define TEXT_OFFSET 0x8000

#define KERNEL_TEXT_DEFAULT (KERNEL_BASE_MIN + TEXT_OFFSET)
