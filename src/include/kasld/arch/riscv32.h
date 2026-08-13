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
// LINEAR_MAP_ANCHOR: kernel_map.va_pa_offset = PAGE_OFFSET - phys_ram_base
// with phys_ram_base = memblock_start_of_DRAM() & PMD_MASK, so the anchor
// IS the base of DRAM (rounded down to a 2 MiB boundary — equal on every
// platform, whose DRAM base is PMD-aligned; where it is not, the candidate
// lands off a large-page boundary and the consumer's alignment check drops
// it rather than trusting it).
// arch/riscv/mm/init.c setup_bootmem()
#define LINEAR_MAP_ANCHOR LM_ANCHOR_DRAM_BASE
#define DIRECTMAP_STATIC 1
#define TEXT_TRACKS_DIRECTMAP 1
#define PAGE_OFFSET_INVARIANT 1
// Hard-coded in arch/riscv/include/asm/page.h for 32-bit MMU builds; riscv
// has no CONFIG_PAGE_OFFSET for rv32, so there is nothing to vary.
#define PAGE_OFFSET_CANDIDATES {0xc0000000ul}
#define PAGE_OFFSET_MIN 0xc0000000ul
#define PAGE_OFFSET_MAX 0xc0000000ul

#define KERNEL_VIRT_VAS_START PAGE_OFFSET
#define KERNEL_VIRT_VAS_END 0xfffffffful

#define KERNEL_VIRT_TEXT_MIN PAGE_OFFSET
// Above this, addresses fall in the fixmap/vmalloc region.
#define KERNEL_VIRT_TEXT_MAX 0xf0000000ul

// Modules share the vmalloc window, which on rv32 sits immediately BELOW the
// linear map, not above it:
//
//   MODULES_VADDR = VMALLOC_START = PAGE_OFFSET - VMALLOC_SIZE
//   MODULES_END   = VMALLOC_END   = PAGE_OFFSET
//
// VMALLOC_SIZE is KERN_VIRT_SIZE >> 1, and KERN_VIRT_SIZE is
// (PTRS_PER_PGD / 2 * PGDIR_SIZE) / 2. rv32 is sv32 only, so PGDIR_SHIFT is
// 22 (PGDIR_SIZE 4 MiB) and PTRS_PER_PGD is 4096/4 = 1024, giving
// KERN_VIRT_SIZE = 1 GiB and VMALLOC_SIZE = 512 MiB. Exact, with no
// configuration variance to take a union over.
//
// Stated as a relation to PAGE_OFFSET rather than as fixed addresses so the
// band cannot drift from the definition it instantiates. riscv32 is
// PAGE_OFFSET_INVARIANT, so the re-derivation the flag enables is a no-op
// here -- it declares the relation, it does not predict movement.
// https://elixir.bootlin.com/linux/v7.2/source/arch/riscv/include/asm/pgtable.h
#define MODULES_START_FOR(po) ((po) - 0x20000000ul)
#define MODULES_END_FOR(po) (po)
// Instantiated at the lowest admissible split, per the union rule in api.h;
// riscv32 has only one, so this is PAGE_OFFSET spelled as the rule requires.
// Where the module band is anchored: a fixed delta from PAGE_OFFSET, so a
// runtime VMSPLIT moves the band with it.
#define MODULES_ANCHOR MOD_ANCHOR_PAGE_OFFSET
#define MODULES_START MODULES_START_FOR(KERNEL_VIRT_VAS_START)
#define MODULES_END MODULES_END_FOR(PAGE_OFFSET)

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
