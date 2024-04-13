// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Definitions for PowerPC 32-bit (powerpc / ppc)
//
// KASLR support added in commit 2b0e86cc5de6dabadc2d64cefa429fc227c8a756 in
// kernel v5.5-rc1~110^2~29^2~6 on 2019-11-13.
//
// References:
// https://github.com/torvalds/linux/commit/2b0e86cc5de6dabadc2d64cefa429fc227c8a756
// https://docs.kernel.org/6.1/powerpc/kaslr-booke32.html
// ---
// <bcoles@gmail.com>

// https://elixir.bootlin.com/linux/v6.1.1/source/arch/powerpc/Kconfig#L1203
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/powerpc/Kconfig#L1220
#define PAGE_OFFSET 0xc0000000ul

// https://elixir.bootlin.com/linux/v6.1.1/source/arch/powerpc/Kconfig#L1233
#define PHYSICAL_START 0ul

// https://elixir.bootlin.com/linux/v6.1.1/source/arch/powerpc/include/asm/page.h#L240
#define phys_to_virt(x) ((unsigned long)((x) + PAGE_OFFSET - PHYSICAL_START))

#define KERNEL_VAS_START PAGE_OFFSET
#define KERNEL_VAS_END 0xfffffffful

#define KERNEL_BASE_MIN PAGE_OFFSET
#define KERNEL_BASE_MAX 0xf0000000ul

// Modules are located below kernel: PAGE_OFFSET - 256MiB (0x10000000)
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/powerpc/include/asm/book3s/32/pgtable.h#L214
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/powerpc/include/asm/nohash/32/mmu-8xx.h#L173
#define MODULES_START PAGE_OFFSET - 0x10000000ul // 0xb0000000ul
#define MODULES_END PAGE_OFFSET

// page aligned
#define KERNEL_ALIGN 0x1000ul

#define TEXT_OFFSET 0

#define KERNEL_TEXT_DEFAULT (KERNEL_BASE_MIN + TEXT_OFFSET)
