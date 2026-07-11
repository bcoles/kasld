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
// PAGE_OFFSET and PHYS_OFFSET are compile-time on riscv32; the directmap
// projection is sound. No mainline KASLR — text sits at a fixed offset
// within the linear map. The compile-time constant is the architectural
// guaranteed runtime value (no VMSPLIT/SATP/paging-mode dependency on
// riscv32), so Q_PAGE_OFFSET is pinnable without evidence — same shape
// as mips32/64 and ppc32/64. Unlocks text_base_coupling_synth.
#define DIRECTMAP_STATIC 1
#define TEXT_TRACKS_DIRECTMAP 1
#define PAGE_OFFSET_INVARIANT 1

#define KERNEL_VIRT_VAS_START PAGE_OFFSET
#define KERNEL_VIRT_VAS_END 0xfffffffful

#define KERNEL_VIRT_TEXT_MIN PAGE_OFFSET
// Above this, addresses fall in the fixmap/vmalloc region.
#define KERNEL_VIRT_TEXT_MAX 0xf0000000ul

#define MODULES_START PAGE_OFFSET
#define MODULES_END 0xfffffffful
#define MODULES_RELATIVE_TO_TEXT 0

// https://elixir.bootlin.com/linux/v6.2-rc2/source/arch/riscv/include/asm/efi.h#L41
#define IMAGE_ALIGN (4 * MB)

// .head.text section size (8 KiB) before _stext.
#define IMAGE_BASE_OFFSET 0x2000

// Plausible physical address range for the kernel image. On the standard
// RISC-V platform layout DRAM begins at 0x80000000 (firmware/MMIO occupy the
// space below) and the kernel loads at DRAM base + a firmware-sized offset
// (e.g. 0x80400000 after OpenSBI), so a real riscv32 image sits high in the
// 32-bit physical space; the ceiling spans to the top of it. riscv32 has no
// KASLR, so this is the honest validation window, not an entropy range. The
// floor is 0 (== PHYS_OFFSET, the linear-map anchor): conservative but sound,
// and consistent with the KERNEL_PHYS_MIN == PHYS_OFFSET invariant. Runtime
// iomem/DRAM bounds narrow the window to the real range.
#define KERNEL_PHYS_MIN 0ul
#define KERNEL_PHYS_MAX 0xfffff000ul

// Default: 0xc0002000 (PAGE_OFFSET + 8 KiB .head.text).
// See docs/kaslr.md "Default text base and KASLR alignment" for all
// architectures. Kernel source: arch/riscv/kernel/vmlinux.lds.S
#define KERNEL_VIRT_TEXT_DEFAULT (KERNEL_VIRT_TEXT_MIN + IMAGE_BASE_OFFSET)

// RISC-V 32-bit does not have mainline KASLR.
#define KASLR_SUPPORTED 0

#endif /* KASLD_RISCV32_H */
