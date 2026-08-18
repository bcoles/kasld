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

// The linear-map base does not move at RUNTIME on ppc32 (BookE
// CONFIG_RELOCATABLE is out of KASLD scope), so the compile-time projection
// formula describes the target correctly ONCE the base is known. Text sits at
// a fixed offset within the linear map, so a physical bound propagates to the
// virtual text base.
// LINEAR_MAP_ANCHOR: MEMORY_START is memstart_addr under
// CONFIG_NONSTATIC_KERNEL, tracked as the LOWEST device-tree memory block
// (prom.c: `if (base < memstart_addr) memstart_addr = base;`), and 0 otherwise
// — which is also where DRAM starts on the platforms that build that way.
// Either way the lowest observed physical RAM base names the anchor.
// arch/powerpc/include/asm/page.h MEMORY_START; arch/powerpc/kernel/prom.c
#define LINEAR_MAP_ANCHOR LM_ANCHOR_DRAM_BASE
#define DIRECTMAP_STATIC 1
#define TEXT_TRACKS_DIRECTMAP 1

// ...but the ANALYSING BINARY does not know which base the target was built
// with. arch/powerpc/Kconfig gives ppc32 a prompt -- `config PAGE_OFFSET hex
// "Virtual address of memory base" if PAGE_OFFSET_BOOL`, inside
// `menu "Advanced setup" depends on PPC32` -- and two in-tree 85xx defconfigs
// move it (xes_mpc85xx 0x80000000, ppa8548 0xb0000000). So this is the x86_32 /
// arm32 VMSPLIT case, not the mips/ppc64 invariant case.
//
// CONFIG_PAGE_OFFSET is nonetheless build-fixed hex with no boot override --
// exactly as authoritative as arm32's and x86_32's -- so a readable
// /proc/config.gz pins the base exactly. PAGE_OFFSET_FROM_CONFIG enables that
// (page_offset_from_config), the precise path and the sound successor to the
// old PAGE_OFFSET_INVARIANT pin: that one named 0xc0000000 for EVERY ppc32,
// wrong on an 0x80000000 build, whereas the config read names the real value.
#define PAGE_OFFSET_FROM_CONFIG 1

// A BRACKET is the no-config fallback: the Kconfig symbol is a free hex field,
// not a choice, so no enumeration can be shown complete -- an incomplete one
// would exclude the truth, an over-wide bracket merely fails to narrow. With no
// Kconfig `range` the floor is a judgment call; it is kept a full GiB below the
// lowest in-tree defconfig (0x80000000) rather than raised to it, because
// raising it collapses the bracket to a single 1 GiB stride -- and a bracket
// that admits exactly its two endpoints, one of them the compile-time default,
// leaves the band no interior split to move to (see
// test_engine_sync_module_band_follows_page_offset). The live measurement
// narrows it: mmap_brute_vmsplit lands 128 KiB below the truth via
// task_size_32.h's USER_TOP = PAGE_OFFSET - SZ_128K, EXCEPT on 8xx, where
// CONFIG_TASK_SIZE defaults to 0x80000000 and wins over USER_TOP, so the probe
// reads 0x80000000 there and its likely guess is off by the split (the
// guaranteed bracket still contains the truth).
#define PAGE_OFFSET_MIN 0x40000000ul
#define PAGE_OFFSET_MAX 0xc0000000ul

// Drawn at the LOWEST admissible split (PAGE_OFFSET_MIN): a kernel built lower
// would have its text below the floor and every address it reports rejected at
// the source, so the floor tracks the bracket's low edge.
#define KERNEL_VIRT_TEXT_MIN 0x40000000ul
#define KERNEL_VIRT_VAS_START KERNEL_VIRT_TEXT_MIN
#define KERNEL_VIRT_VAS_END 0xfffffffful
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
// The union is therefore [PAGE_OFFSET - 256 MiB, top of VAS]. Only the floor is
// a PAGE_OFFSET relation, so MODULES_RELATIVE_TO_PAGE_OFFSET declares it and
// the engine re-derives MODULES_START against the resolved base. That
// re-derivation genuinely matters now that the base varies across the bracket
// -- it was inert under the old unconditional pin, not because ppc32 is
// special.
// https://elixir.bootlin.com/linux/v7.2/source/arch/powerpc/include/asm/task_size_32.h
// https://elixir.bootlin.com/linux/v7.2/source/arch/powerpc/mm/mem.c
#define MODULES_START_FOR(po) ((po) - 0x10000000ul)
#define MODULES_END_FOR(po) (KERNEL_VIRT_VAS_END)
// Instantiated at the lowest admissible split, per the union rule in api.h: the
// widest (lowest) floor any admissible base produces, MODULES_START_FOR of the
// bracket's low edge = 0x30000000. That sits BELOW KERNEL_VIRT_VAS_START, which
// is correct, not a mis-derivation: on 8xx/book3s32 the module window is carved
// immediately below the linear-map base, so the lowest module address is
// genuinely lower than the lowest linear-map base the bracket admits.
// Where the module band is anchored: a fixed delta from PAGE_OFFSET, so a
// runtime VMSPLIT moves the band with it.
#define MODULES_ANCHOR MOD_ANCHOR_PAGE_OFFSET
#define MODULES_START MODULES_START_FOR(KERNEL_VIRT_VAS_START)
#define MODULES_END MODULES_END_FOR(PAGE_OFFSET)

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
#define KERNEL_VIRT_TEXT_DEFAULT (PAGE_OFFSET + IMAGE_BASE_OFFSET)

#define KASLR_SUPPORTED 1

// Residue 0: _text is on the granule; the grid is plain alignment.
#define IMAGE_BASE_RESIDUE_FIXED 1

#endif /* KASLD_PPC32_H */
