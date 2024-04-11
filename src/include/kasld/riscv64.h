// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Definitions for RISC-V 64-bit (riscv64)
//
// KASLR support added in commit f57805555834494e8cad729d01d86ba326d64959 in
// kernel v6.6-rc1~10^2~5 on 2023-11-08.
//
// References:
// https://github.com/torvalds/linux/commit/f57805555834494e8cad729d01d86ba326d64959
// https://www.kernel.org/doc/html/next/riscv/vm-layout.html
// https://www.kernel.org/doc/html/next/riscv/boot.html
// ---
// <bcoles@gmail.com>

// https://elixir.bootlin.com/linux/v6.1.1/source/arch/riscv/Kconfig#L171
#define PAGE_OFFSET 0xff60000000000000ul

// Assume linear mapping (not Execute-In-Place (XIP_KERNEL) kernel)
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/riscv/include/asm/page.h#L125
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/riscv/mm/init.c#L984
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/riscv/mm/init.c#L976
#define phys_to_virt(x) ((unsigned long)(x) + (PAGE_OFFSET - 0x80000000ul))

// VAS start with SV57 (5-level page tables): 0xff1bffff_fea00000
// VAS start with SV48 (4-level page tables): 0xffff8d7f_fea00000
// VAS start with SV39 (3-level page tables): 0xffffffc6_fea00000
#define KERNEL_VAS_START 0xff10000000000000ul
#define KERNEL_VAS_END 0xfffffffffffffffful

// common:
// 0xffffffe0_00000000
// 0xffffffff_80000000
#define KERNEL_BASE_MIN 0xffffffe000000000ul
#define KERNEL_BASE_MAX 0xffffffffff000000ul

// Modules are located below kernel: KERNEL_LINK_ADDR - 2GB (0x80000000)
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/riscv/include/asm/pgtable.h#L52
// 0xffffffd0_00000000 is also common
#define MODULES_START KERNEL_VAS_START - 0x80000000ul
#define MODULES_END 0xfffffffffffffffful

// https://elixir.bootlin.com/linux/v6.2-rc2/source/arch/riscv/include/asm/efi.h#L41
#define KERNEL_ALIGN 2 * MB

#define TEXT_OFFSET 0x2000

#define KERNEL_TEXT_DEFAULT (KERNEL_BASE_MIN + TEXT_OFFSET)
