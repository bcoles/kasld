// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Definitions for LoongArch 64-bit (loong64 / loongarch64 / la464)
//
// KASLR support added in commit e5f02b51fa0cb785e352e77271a65e96051b789b in
// kernel v6.3-rc1~42^2~15 on 2023-02-25.
//
// References:
// https://github.com/torvalds/linux/commit/e5f02b51fa0cb785e352e77271a65e96051b789b
// https://loongson.github.io/LoongArch-Documentation/LoongArch-Vol1-EN.html
// https://docs.kernel.org/arch/loongarch/introduction.html#virtual-memory
// ---
// <bcoles@gmail.com>

// https://elixir.bootlin.com/linux/v6.8.5/source/arch/loongarch/include/asm/addrspace.h#L57
// https://elixir.bootlin.com/linux/v6.8.5/source/arch/loongarch/include/asm/loongarch.h#L877
// https://elixir.bootlin.com/linux/v6.8.5/source/arch/loongarch/include/asm/addrspace.h#L39
// PAGE_OFFSET = (CSR_DMW1_VSEG << DMW_PABITS) = (0x9000 << 48)
#define PAGE_OFFSET 0x9000000000000000ul

// https://elixir.bootlin.com/linux/v6.8.5/source/arch/loongarch/include/asm/addrspace.h#L22
#define PHYS_OFFSET 0ul

// https://elixir.bootlin.com/linux/v6.8.5/source/arch/loongarch/include/asm/page.h#L81
#define phys_to_virt(x) ((unsigned long)(x) + PAGE_OFFSET - PHYS_OFFSET)

#define KERNEL_VAS_START 0x4000000000000000ul
#define KERNEL_VAS_END 0xfffffffffffffffful

// https://elixir.bootlin.com/linux/v6.8.5/source/arch/loongarch/Kconfig#L629
#define KERNEL_BASE_MIN PAGE_OFFSET
#define KERNEL_BASE_MAX 0x9000000010000000ul

// https://elixir.bootlin.com/linux/v6.8.5/source/arch/loongarch/include/asm/pgtable.h#L82
#define MODULES_START 0xffff800000000000ul
#define MODULES_END 0xffff800010000000ul

// https://elixir.bootlin.com/linux/v6.8.5/source/arch/loongarch/include/asm/efi.h#L30
#define KERNEL_ALIGN 2 * MB

// https://elixir.bootlin.com/linux/v6.8.5/source/arch/loongarch/Makefile#L99
#define TEXT_OFFSET 0x200000

#define KERNEL_TEXT_DEFAULT (KERNEL_BASE_MIN + TEXT_OFFSET)
