// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Definitions for RISC-V 32-bit (riscv32)
//
// Linux for RISC-V 32-bit does not support KASLR.
//
// References:
// https://elixir.bootlin.com/linux/v6.8.2/source/arch/riscv/Kconfig#L819
// ---
// <bcoles@gmail.com>

#ifndef KASLD_RISCV32_H
#define KASLD_RISCV32_H

// https://elixir.bootlin.com/linux/v6.1.1/source/arch/riscv/Kconfig#L169
#define PAGE_OFFSET 0xc0000000ul

// Assume linear mapping (not Execute-In-Place (XIP_KERNEL) kernel)
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/riscv/include/asm/page.h#L125
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/riscv/mm/init.c#L984
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/riscv/mm/init.c#L976
#define PHYS_OFFSET 0ul
#define PHYS_VIRT_DECOUPLED 0
#define phys_to_virt(x) ((unsigned long)(x) + PAGE_OFFSET)

#define KERNEL_VAS_START PAGE_OFFSET
#define KERNEL_VAS_END 0xfffffffful

#define KERNEL_BASE_MIN PAGE_OFFSET
// Above this, addresses fall in the fixmap/vmalloc region.
#define KERNEL_BASE_MAX 0xf0000000ul

#define MODULES_START PAGE_OFFSET
#define MODULES_END 0xfffffffful
#define MODULES_RELATIVE_TO_TEXT 0

// https://elixir.bootlin.com/linux/v6.2-rc2/source/arch/riscv/include/asm/efi.h#L41
#define KERNEL_ALIGN (4 * MB)

// .head.text section size (8 KiB) before _stext.
#define TEXT_OFFSET 0x2000

// Plausible physical address range for kernel image
#define KERNEL_PHYS_MIN 0ul
#define KERNEL_PHYS_MAX (1ul * GB)

// Default: 0xc0002000 (PAGE_OFFSET + 8 KiB .head.text).
#define KERNEL_TEXT_DEFAULT (KERNEL_BASE_MIN + TEXT_OFFSET)

// RISC-V 32-bit does not have mainline KASLR.
#define KASLR_SUPPORTED 0

#endif /* KASLD_RISCV32_H */
