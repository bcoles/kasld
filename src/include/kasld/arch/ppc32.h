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

#ifndef KASLD_PPC32_H
#define KASLD_PPC32_H

// https://elixir.bootlin.com/linux/v6.1.1/source/arch/powerpc/Kconfig#L1203
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/powerpc/Kconfig#L1220
#define PAGE_OFFSET 0xc0000000ul

// https://elixir.bootlin.com/linux/v6.1.1/source/arch/powerpc/Kconfig#L1233
#define PHYS_OFFSET 0ul

// PAGE_OFFSET and PHYS_OFFSET are compile-time on ppc32 (BookE
// CONFIG_RELOCATABLE is out of KASLD scope). Mainline ppc32 has no KASLR —
// text sits at a fixed offset within the linear map. The compile-time
// constant is the architectural guaranteed runtime value within KASLD's
// modelled scope, so Q_PAGE_OFFSET is pinnable without evidence (same
// shape as mips32/64 and ppc64). Unlocks text_base_coupling_synth.
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/powerpc/include/asm/page.h#L240
#define DIRECTMAP_STATIC 1
#define TEXT_TRACKS_DIRECTMAP 1
#define PAGE_OFFSET_INVARIANT 1

#define KERNEL_VIRT_VAS_START PAGE_OFFSET
#define KERNEL_VIRT_VAS_END 0xfffffffful

#define KERNEL_VIRT_TEXT_MIN PAGE_OFFSET
// Above this, addresses fall in the I/O or fixmap region.
#define KERNEL_VIRT_TEXT_MAX 0xf0000000ul

// ppc32 places modules in one of two entirely different regions, decided by
// the platform, and the analysing binary cannot tell which kernel it faces --
// so the band is the union of both.
//
// 8xx and BOOK3S_32 carve a dedicated window immediately below the linear map
// (task_size_32.h): MODULES_END is PAGE_OFFSET (8xx) or PAGE_OFFSET rounded
// down to 256 MiB (book3s32), with MODULES_VADDR = MODULES_END -
// CONFIG_MODULES_SIZE * 1 MiB. That Kconfig is `range 1 256`, so 256 MiB below
// PAGE_OFFSET is the lowest floor any such kernel can have.
//
// EVERY OTHER ppc32 platform -- including PPC_85xx/e500, the only one with
// CONFIG_RANDOMIZE_BASE -- leaves MODULES_VADDR undefined and allocates from
// the shared vmalloc window instead (mm/mem.c execmem_arch_setup: `#else start
// = VMALLOC_START; end = VMALLOC_END;`). On nohash/32 VMALLOC_START derives
// from runtime high_memory and so lies ABOVE PAGE_OFFSET, and VMALLOC_END is
// ioremap_bot, which moves down from IOREMAP_TOP at runtime. Neither edge is a
// compile-time constant, so the ceiling is the top of the address space.
//
// The union is therefore [PAGE_OFFSET - 256 MiB, top of VAS]. Only the floor
// is a PAGE_OFFSET relation. ppc32 is PAGE_OFFSET_INVARIANT, so the
// re-derivation the flag enables is a no-op here -- it declares the relation,
// it does not predict movement.
// https://elixir.bootlin.com/linux/v7.2/source/arch/powerpc/include/asm/task_size_32.h
// https://elixir.bootlin.com/linux/v7.2/source/arch/powerpc/mm/mem.c
#define MODULES_RELATIVE_TO_PAGE_OFFSET 1
#define MODULES_START_FOR(po) ((po) - 0x10000000ul)
#define MODULES_END_FOR(po) (KERNEL_VIRT_VAS_END)
// Instantiated at the lowest admissible split, per the union rule in api.h;
// ppc32 has only one, so this is PAGE_OFFSET spelled as the rule requires.
#define MODULES_START MODULES_START_FOR(KERNEL_VIRT_VAS_START) // 0xb0000000ul
#define MODULES_END MODULES_END_FOR(PAGE_OFFSET)
#define MODULES_RELATIVE_TO_TEXT 0

// page aligned
#define IMAGE_ALIGN 0x1000ul

// BookE (PPC_85xx) KASLR uses 16 KiB alignment within 64 MiB windows.
// https://elixir.bootlin.com/linux/v6.12/source/arch/powerpc/mm/nohash/kaslr_booke.c
#define KASLR_VIRT_ALIGN 0x4000ul

#define IMAGE_BASE_OFFSET 0

// Plausible physical address range for kernel image
#define KERNEL_PHYS_MIN 0ul
#define KERNEL_PHYS_MAX (1ul * GB)

// Default: 0xc0000000 (PAGE_OFFSET, no text offset on PPC32).
// See docs/kaslr.md "Default text base and KASLR alignment" for all
// architectures. Kernel source: arch/powerpc/kernel/vmlinux.lds.S
#define KERNEL_VIRT_TEXT_DEFAULT (KERNEL_VIRT_TEXT_MIN + IMAGE_BASE_OFFSET)

#define KASLR_SUPPORTED 1

#endif /* KASLD_PPC32_H */
