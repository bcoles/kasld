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

#ifndef KASLD_ARM32_H
#define KASLD_ARM32_H

// 3GB vmsplit (0xc0000000) is common; but an unsafe assumption,
// especially for embedded systems. Configurable vmsplits range from
// CONFIG_VMSPLIT_1G (0x40000000) to CONFIG_VMSPLIT_3G (0xc0000000).
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/arm/Kconfig#L1116
#define PAGE_OFFSET 0xc0000000ul

// https://elixir.bootlin.com/linux/v6.1.1/source/arch/arm/Kconfig#L276
#define PHYS_OFFSET 0ul

// https://elixir.bootlin.com/linux/v6.1.1/source/arch/arm/include/asm/memory.h#L286
#define PHYS_VIRT_DECOUPLED 0
#define phys_to_virt(x) ((unsigned long)((x) - PHYS_OFFSET + PAGE_OFFSET))

// Minimum possible kernel base across all vmsplit configurations.
// CONFIG_VMSPLIT_1G sets PAGE_OFFSET=0x40000000, the lowest possible value.
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/arm/Kconfig#L1116
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/arm/include/asm/memory.h#L26
#define KERNEL_BASE_MIN 0x40000000ul

// VAS start uses the lowest possible PAGE_OFFSET to cover all vmsplit
// configurations. The orchestrator adjusts at runtime once vmsplit is detected.
#define KERNEL_VAS_START KERNEL_BASE_MIN
#define KERNEL_VAS_END 0xfffffffful
#define KERNEL_BASE_MAX 0xf0000000ul

// Modules are located below kernel: PAGE_OFFSET - 16MiB (0x01000000)
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/arm/include/asm/memory.h#L51
#define MODULES_START (PAGE_OFFSET - 0x01000000) // 0xbf000000ul
#define MODULES_END PAGE_OFFSET
#define MODULES_RELATIVE_TO_TEXT 0

#define KERNEL_ALIGN (2 * MB)

// https://elixir.bootlin.com/linux/v6.1.1/source/arch/arm/Makefile#L145
#define TEXT_OFFSET 0x8000

// Plausible physical address range for kernel image
#define KERNEL_PHYS_MIN 0ul
#define KERNEL_PHYS_MAX (4ul * GB)

#define KERNEL_TEXT_DEFAULT (PAGE_OFFSET + TEXT_OFFSET)

#define KASLR_SUPPORTED 0

#endif /* KASLD_ARM32_H */
