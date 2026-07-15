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

// The runtime PAGE_OFFSET is one of the VMSPLIT boundaries (arch/arm/Kconfig:
// VMSPLIT_3G / 3G_OPT / 2G / 1G), listed high→low for snap-down. arm32 has no
// KASLR, so the kernel image sits at PAGE_OFFSET + IMAGE_BASE_OFFSET: any
// observed kernel virtual text address V therefore pins PAGE_OFFSET (the
// largest boundary <= V) and hence the exact image base. Consumed by the
// vmsplit_text_base engine rule. The 0xc0000000 default above is only the
// render fallback when no virtual text address is observed.
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/arm/Kconfig#L1116
#define HAVE_VMSPLIT_PAGE_OFFSET 1
#define VMSPLIT_PAGE_OFFSETS                                                   \
  {0xc0000000ul, 0xb0000000ul, 0x80000000ul, 0x40000000ul}

// https://elixir.bootlin.com/linux/v6.1.1/source/arch/arm/Kconfig#L276
#define PHYS_OFFSET 0ul

// PAGE_OFFSET is compile-time (VMSPLIT Kconfig). PHYS_OFFSET is patched at
// boot under CONFIG_ARM_PATCH_PHYS_VIRT, but the patching reflects the
// kernel's load address rather than KASLR randomization; treat as static
// for projection purposes (matches the behaviour of every other coupled arch
// in scope). Mainline ARM has no KASLR — text sits at a fixed offset within
// the linear map.
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/arm/include/asm/memory.h#L286
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

// Modules are located below kernel: PAGE_OFFSET - 16MiB (0x01000000)
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/arm/include/asm/memory.h#L51
#define MODULES_START (PAGE_OFFSET - 0x01000000) // 0xbf000000ul
#define MODULES_END PAGE_OFFSET
// Module region is fixed below PAGE_OFFSET; does not shift with KASLR.
#define MODULES_RELATIVE_TO_TEXT 0

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

// STEXT_OFFSET is deliberately left at its 0 default (so _stext is modelled as
// _text) even though _stext sits ~1 MiB above _text on ARM (e.g. _text
// 0x80008000, _stext 0x80100000). That gap is _text padded up to ARM's 1 MiB
// section-mapping boundary, not a fixed architectural constant a single
// STEXT_OFFSET could carry across configs. It is also unused here: ARM has no
// text KASLR (the base is the compile-time default), and where kallsyms is
// readable it yields _text and _stext directly — so the _stext -> _text
// projection via STEXT_OFFSET is never taken. Contrast arm64/loongarch64,
// which do model a fixed head gap.

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
