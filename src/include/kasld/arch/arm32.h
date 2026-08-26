// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Definitions for ARM 32-bit (arm6l / arm7l / armhf)
//
// arm32 does not have mainline KASLR support. A patchset by Ard Biesheuvel
// (August 2017) wired KASLR into the EFI stub via efi_random_alloc() in
// drivers/firmware/efi/libstub/arm32-stub.c, but the series was never merged.
// https://www.openwall.com/lists/kernel-hardening/2017/08/14/31
//
// References:
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
// VMSPLIT (CONFIG_PAGE_OFFSET) is a compile-time constant, fixed at boot.
#define PAGE_OFFSET_FROM_CONFIG 1
// Every linear-map base an arm32 kernel can be built with, highest first
// (arch/arm/Kconfig: VMSPLIT_3G / 3G_OPT / 2G / 1G). arm32 has no 2G_OPT.
#define PAGE_OFFSET_CANDIDATES                                                 \
  {0xc0000000ul, 0xb0000000ul, 0x80000000ul, 0x40000000ul}
// Admissible kernel page sizes on this architecture. PAGE_SIZE_KNOWN_AT_BUILD
// is derived from the pair in api.h and gates pfn_to_phys(); a page-frame
// number may only be converted with a compile-time constant where the two
// edges coincide. Where they differ the runtime SF_PAGE_SIZE observation is
// the only sound multiplier.
// arm32 fixes the base page at 4 KiB; arch/arm selects
// HAVE_PAGE_SIZE_4KB and offers no alternative.
#define PAGE_SIZE_MIN 0x1000ul
#define PAGE_SIZE_MAX 0x1000ul

#define PAGE_OFFSET_MIN 0x40000000ul
#define PAGE_OFFSET_MAX 0xc0000000ul

// The runtime PAGE_OFFSET is one of the VMSPLIT boundaries (arch/arm/Kconfig:
// VMSPLIT_3G / 3G_OPT / 2G / 1G), listed high→low for snap-down. arm32 has no
// KASLR, so the kernel image sits at PAGE_OFFSET + IMAGE_BASE_OFFSET: any
// observed kernel virtual text address V therefore pins PAGE_OFFSET (the
// largest boundary <= V) and hence the exact image base. Consumed by the
// vmsplit_text_base engine rule. The 0xc0000000 default above is only the
// render fallback when no virtual text address is observed.
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/arm/Kconfig#L1116

// https://elixir.bootlin.com/linux/v6.1.1/source/arch/arm/Kconfig#L276
#define PHYS_OFFSET 0ul

// PAGE_OFFSET is compile-time (VMSPLIT Kconfig). PHYS_OFFSET is patched at
// boot under CONFIG_ARM_PATCH_PHYS_VIRT, but the patching reflects the
// kernel's load address rather than KASLR randomization; treat as static
// for projection purposes (matches the behaviour of every other coupled arch
// in scope). Mainline ARM has no KASLR — text sits at a fixed offset within
// the linear map.
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/arm/include/asm/memory.h#L286
// LINEAR_MAP_ANCHOR: PHYS_OFFSET is __pv_phys_pfn_offset << PAGE_SHIFT,
// patched at boot, and the kernel DISCARDS any bank below it (setup.c
// "Ignoring memory below PHYS_OFFSET"), so its own account of RAM starts
// exactly at the anchor. The lowest observed physical RAM base names it.
// arch/arm/include/asm/memory.h PHYS_OFFSET; arch/arm/kernel/setup.c
#define LINEAR_MAP_ANCHOR LM_ANCHOR_DRAM_BASE
#define DIRECTMAP_STATIC 1
#define TEXT_TRACKS_DIRECTMAP 1

// Minimum possible kernel base across all vmsplit configurations.
// CONFIG_VMSPLIT_1G sets PAGE_OFFSET=0x40000000, the lowest possible value.
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/arm/Kconfig#L1116
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/arm/include/asm/memory.h#L26
#define KERNEL_VIRT_TEXT_MIN 0x40000000ul

// VAS start uses the lowest possible PAGE_OFFSET to cover all vmsplit
// configurations. The orchestrator adjusts at runtime once vmsplit is detected.
#define KERNEL_VIRT_VAS_START KERNEL_VIRT_TEXT_MIN
#define KERNEL_VIRT_VAS_END 0xfffffffful
// Above this, addresses fall in the vectors/fixmap region.
#define KERNEL_VIRT_TEXT_MAX 0xf0000000ul

// arm32 gives modules a dedicated window immediately below the linear map:
// MODULES_VADDR is PAGE_OFFSET - 16 MiB (8 MiB on a Thumb-2 kernel, whose
// relocations reach less far, so the 16 MiB floor covers both), and
// MODULES_END is PAGE_OFFSET, or one PMD below it under CONFIG_HIGHMEM.
//
// That window is not the whole story. CONFIG_ARM_MODULE_PLTS -- `default y`,
// so this is the ordinary case rather than an exotic one -- gives the
// allocator a fallback of [VMALLOC_START, VMALLOC_END] for modules that no
// longer fit, reached via PLT veneers (arch/arm/mm/init.c execmem_arch_setup).
// VMALLOC_START derives from runtime high_memory and therefore lies ABOVE
// PAGE_OFFSET, so a band that stops at PAGE_OFFSET describes only the first
// window and rejects every module that spilled into the second. VMALLOC_END is
// 0xff800000, but a band is the union over what a kernel MIGHT do, and
// CONFIG_XIP_KERNEL re-points MODULES_VADDR at the execute-in-place ROM
// entirely -- so the ceiling is the top of the address space.
//
// The floor is the only PAGE_OFFSET relation of the two, and it is
// instantiated at the lowest admissible split rather than this binary's:
// VMSPLIT is a build choice of the kernel under analysis, and
// kasld_addr_is_module_band() runs inside components, before the engine has
// resolved which split that kernel used.
// https://elixir.bootlin.com/linux/v7.2/source/arch/arm/include/asm/memory.h
// https://elixir.bootlin.com/linux/v7.2/source/arch/arm/mm/init.c
#define MODULES_START_FOR(po) ((po) - 0x01000000ul)
#define MODULES_END_FOR(po) (KERNEL_VIRT_VAS_END)
// Where the module band is anchored: a fixed delta from PAGE_OFFSET, so a
// runtime VMSPLIT moves the band with it.
#define MODULES_ANCHOR MOD_ANCHOR_PAGE_OFFSET
#define MODULES_START MODULES_START_FOR(KERNEL_VIRT_VAS_START) // 0x3f000000ul
#define MODULES_END MODULES_END_FOR(PAGE_OFFSET)
// Module region is fixed below PAGE_OFFSET; does not shift with KASLR.

// https://elixir.bootlin.com/linux/v6.1.1/source/arch/arm/include/asm/efi.h
#define IMAGE_ALIGN (2 * MB)

// https://elixir.bootlin.com/linux/v6.1.1/source/arch/arm/Makefile#L145
#define IMAGE_BASE_OFFSET 0x8000

// Plausible physical address range for kernel image. KERNEL_PHYS_MAX is
// the highest 32-bit-addressable byte (~4 GiB - 1) rather than `4 * GB`
// — the latter expression evaluates to 0x100000000 which OVERFLOWS the
// 32-bit `unsigned long` on this arch and silently produces 0, collapsing
// the honest top of Q_PHYS_IMAGE_BASE to a bottom interval. LPAE permits
// up to 40-bit phys addresses, but the kernel image's early-boot MMU
// setup requires the image be in the lower 32-bit-addressable window,
// so 0xFFFFFFFF is a sound ceiling.
#define KERNEL_PHYS_MIN 0ul
#define KERNEL_PHYS_MAX 0xFFFFFFFFul

// Default: 0xc0008000 (PAGE_OFFSET + 32 KiB IMAGE_BASE_OFFSET).
// See docs/kaslr.md "Default text base and KASLR alignment" for all
// architectures. Kernel source: arch/arm/kernel/vmlinux.lds.S,
// arch/arm/Makefile
#define KERNEL_VIRT_TEXT_DEFAULT (PAGE_OFFSET + IMAGE_BASE_OFFSET)

// The head gap is a RANGE, not a constant. _stext is _text padded up to ARM's
// section-mapping boundary (vmlinux.lds.S: ALIGN(1<<SECTION_SHIFT) after
// .head.text under CONFIG_STRICT_KERNEL_RWX), so it depends on where _text
// lands inside the granule and on the config: 1 MiB with 2-level paging, 2 MiB
// under LPAE (pgtable-3level.h SECTION_SHIFT 21), different again with
// CONFIG_ARM_MPU or another TEXT_OFFSET. Measured 0xf8000 on a 6.12 and a 7.0
// build alike -- the ALIGN, not a constant either could carry.
//
// The gap is reached. Not every ARM kernel exports _text: a stock Debian 13
// armhf kernel and mainline 7.0 both publish _stext alone, so a _stext witness
// is all there is and the projection runs. Modelled as exact it pinned the
// guaranteed window to _stext, 0xf8000 above the real _text, putting the true
// base outside the window -- on both endiannesses, the byte order being
// irrelevant to it. STEXT_OFFSET_MAX makes the witness bound the image base
// instead. arm64 differs only in degree -- its gap is one of two segment
// alignments -- while loongarch64's has a floor but no ceiling at all.
//
// The ceiling needs one more link than the ALIGN itself. The gap is
// ALIGN(_text + sizeof(.head.text), G) - _text, which is G - (_text mod G) only
// while the head fits in that remainder; a head larger than it rounds up a
// second granule and the gap reaches 2G. So 0x200000 rests on the head being
// small against the granule, not on SECTION_SHIFT <= 21 alone. It is: the head
// runs from _text to __fixup_pv_table, under 1 KiB, against 0xf8000 of
// remainder on a 1 MiB granule -- everything above it is ALIGN padding. That is
// the assumption loongarch64 cannot make, its head exceeding its own 64 KiB
// granule, which is why it states a floor and no ceiling.

// Estimate: ALIGN over the 1 MiB section boundary less the 0x8000 the image
// base sits inside it -- 0xf8000, measured on every arm32 kernel booted, both
// endiannesses and both load offsets (0x8000 and 0x208000 share the residue).
// The floor is 0: the ALIGN is absent without CONFIG_STRICT_KERNEL_RWX.
#define STEXT_OFFSET 0xf8000ul
#define STEXT_OFFSET_MIN 0ul
#define STEXT_OFFSET_MAX 0x200000ul

#define KASLR_SUPPORTED 0

// _text's offset within the 2 MiB KASLR_VIRT_ALIGN grid is NOT an architectural
// constant: ARM's TEXT_OFFSET is config-dependent (0x8000 default, 0x208000 and
// larger on other platforms/configs) and _stext is padded up to the 1 MiB
// section boundary, so the residue varies by kernel (a multi_v7 build links
// _stext at PAGE_OFFSET + 0x300000, residue 0x100000, not 0x8000). Disable
// image_base_grid_align's grid-snap, which would otherwise floor an
// interior-sample ceiling below the true base on such a kernel.
#define IMAGE_BASE_RESIDUE_FIXED 0

#endif /* KASLD_ARM32_H */
