// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Definitions for ARM 64-bit (aarch64 / arm64)
//
// The arm64 kernel VAS layout has changed across versions.
//
// Old layout — modules and kernel image below PAGE_OFFSET:
//   MODULES_VADDR = VA_START(48) = 0xffff000000000000
//   KIMAGE_VADDR  = VA_START(48) + SZ_128M = 0xffff000008000000
//   (with BPF JIT: +SZ_128M BPF, +SZ_128M modules → KIMAGE at +SZ_256M)
//   PAGE_OFFSET   = 0xffff800000000000
//
// New layout — modules and kernel image at/above _PAGE_END:
//   _PAGE_END(48) = 0xffff800000000000
//   KIMAGE_VADDR  = _PAGE_END(48) + module_region_size
//     +SZ_128M  → 0xffff800008000000
//     +SZ_256M  → 0xffff800010000000
//     +SZ_2G    → 0xffff800080000000
//
// The key runtime discriminator is whether kernel text is above or below
// 0xffff800000000000 (_PAGE_END for 48-bit VA).
//
// KASLR support added in commit 588ab3f9afdfa1a6b1e5761c858b2c4ab6098285 in
// kernel v4.6-rc1~110 on 2016-03-17.
//
// References:
// https://github.com/torvalds/linux/commit/588ab3f9afdfa1a6b1e5761c858b2c4ab6098285
// https://lwn.net/Articles/673598/
// https://www.kernel.org/doc/Documentation/arm64/memory.txt
// https://github.com/torvalds/linux/blob/master/Documentation/arm64/booting.rst
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/Documentation/arm64/memory.rst
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/arm64/kernel/head.S
// ---
// <bcoles@gmail.com>

#ifndef KASLD_ARM64_H
#define KASLD_ARM64_H

// 52 va bits (CONFIG_ARM64_VA_BITS_52) is the default in v6.12+.
// 48 va bits (CONFIG_ARM64_VA_BITS_48) is common on older kernels.
// PAGE_OFFSET = _PAGE_OFFSET(VA_BITS) = -(1UL << VA_BITS)
//   VA_BITS=48: 0xffff000000000000
//   VA_BITS=52: 0xfff0000000000000
// https://elixir.bootlin.com/linux/v6.12/source/arch/arm64/include/asm/memory.h#L44
// We assume 52 va bits (broadest, covers all configs):
#define PAGE_OFFSET 0xfff0000000000000ul
#define PHYS_OFFSET 0ul

// Physical and virtual KASLR are decoupled on arm64.
// phys_to_virt() yields a direct-map virtual address, NOT a kernel text
// address.
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/arm64/include/asm/memory.h#L295
#define PHYS_VIRT_DECOUPLED 1
#define phys_to_virt(x) ((unsigned long)((x) - PHYS_OFFSET) | PAGE_OFFSET)

#define KERNEL_VAS_START PAGE_OFFSET
#define KERNEL_VAS_END 0xfffffffffffffffful

// 48 va bits (CONFIG_ARM64_VA_BITS_48) is a common configuration;
// but an unsafe assumption since introduction of CONFIG_ARM64_VA_BITS_48_52.
// older kernels may use 0xffff000008000000ul
//
// Validation range for the modern layout (compile-time default).
// Legacy addresses (below _PAGE_END) are initially invalid; the runtime
// legacy detection in orchestrator.c adjusts kernel_base_min when triggered.
#define KERNEL_BASE_MIN 0xffff800008000000ul
#define KERNEL_BASE_MAX 0xffffffffff000000ul

// _PAGE_END(48) = 0xffff800000000000 is the runtime discriminator.
// Kernel text below this → old layout; at/above → new layout.
#define ARM64_LEGACY_LAYOUT_BOUNDARY 0xffff800000000000ul

// Module region: ranges from 128M (v4.6) to 2G (v6.2+).
// Use 2G for widest validation coverage.
// https://elixir.bootlin.com/linux/v6.6/source/arch/arm64/include/asm/memory.h
#define MODULES_START 0xffff800000000000ul
#define MODULES_END 0xffff80007ffffffful
// Module region does not shift with KASLR on arm64.
// (Modules are loaded independently of kernel text placement.)
#define MODULES_RELATIVE_TO_TEXT 0

// MIN_KIMG_ALIGN is 2MiB (used without KASLR).
// https://elixir.bootlin.com/linux/v6.2-rc2/source/arch/arm64/include/asm/boot.h#L18
// EFI_KIMG_ALIGN is the larger of THREAD_ALIGN or SEGMENT_ALIGN:
// https://elixir.bootlin.com/linux/v6.2-rc2/source/arch/arm64/include/asm/efi.h#L102
// https://elixir.bootlin.com/linux/v6.2-rc2/source/arch/arm64/include/asm/efi.h#L72
// SEGMENT_ALIGN is hard-coded as 64KiB:
// https://elixir.bootlin.com/linux/v6.2-rc2/source/arch/arm64/include/asm/memory.h#L131
// The largest possible THREAD_ALIGN is also 64KiB.
// THREAD_ALIGN = THREAD_SIZE = (1 << THREAD_SHIFT)
// default CONFIG_ARM64_PAGE_SHIFT is 12. largest is 16.
// https://elixir.bootlin.com/linux/v6.2-rc2/source/arch/arm64/Kconfig#L262
// Use 64KiB (0x10000) by default
#define KERNEL_ALIGN 0x10000ul

// TEXT_OFFSET was changed from 0x80000 to zero in 2020 from kernel v5.8 onwards
// https://elixir.bootlin.com/linux/v5.8/source/arch/arm64/Makefile
// https://lore.kernel.org/all/20200428134119.GI6791@willie-the-truck/T/
#define TEXT_OFFSET 0

// Plausible physical address range for kernel image
#define KERNEL_PHYS_MIN 0ul
#define KERNEL_PHYS_MAX (256ul * GB)

// KIMAGE_VADDR = MODULES_END on arm64. Varies by version (new layout only):
//   v5.4:  _PAGE_END(48) + SZ_128M  = 0xffff800008000000
//   v5.0:  _PAGE_END(48) + SZ_256M  = 0xffff800010000000
//   v6.2+: _PAGE_END(48) + SZ_2G    = 0xffff800080000000
// (Old layout used VA_START(48) + SZ_128M = 0xffff000008000000; see LEGACY_*)
// https://elixir.bootlin.com/linux/v6.12/source/arch/arm64/include/asm/memory.h#L46
// Use v6.2+ value (2G module region, current default).
#define KIMAGE_VADDR 0xffff800080000000ul

#define KERNEL_TEXT_DEFAULT (KIMAGE_VADDR + TEXT_OFFSET)

// KASLR randomization window (v4.6+):
// The KASLR offset from KIMAGE_VADDR is in [BIT(45), BIT(45)+BIT(46)).
// VA_BITS_MIN is always 48 (4K pages), so the offset range is constant.
// Aligned to SZ_2M (explicitly masked in v5.10; page-table granularity in
// v6.2+). Entropy: BIT(46) / SZ_2M = BIT(25) = 33554432 slots (25 bits).
//
// v6.6   kaslr_early.c: return BIT(VA_BITS_MIN-3) + (seed &
// GENMASK(VA_BITS_MIN-3,0)); v6.12  kaslr_early.c: range = (VMALLOC_END -
// KIMAGE_VADDR) / 2;
//                        return range / 2 + (((__uint128_t)range * seed) >>
//                        64);
// https://elixir.bootlin.com/linux/v6.12/source/arch/arm64/kernel/pi/kaslr_early.c
#define KASLR_BASE_MIN (KIMAGE_VADDR + (1ul << 45))
#define KASLR_BASE_MAX (KASLR_BASE_MIN + (1ul << 46))
#define KASLR_ALIGN (2 * MB)

#define KASLR_SUPPORTED 1

// Legacy layout overrides (old arm64 VAS, pre-v5.4).
// Kernel image at VA_START(48) + SZ_128M, below _PAGE_END(48).
// All values are static constants (decoupled, like the modern layout).
#define LEGACY_LAYOUT_BOUNDARY ARM64_LEGACY_LAYOUT_BOUNDARY
#define LEGACY_PAGE_OFFSET 0xffff800000000000ul
#define LEGACY_KERNEL_VAS_START 0xffff000000000000ul
#define LEGACY_MODULES_START 0xffff000000000000ul
#define LEGACY_MODULES_END 0xffff000007fffffful
#define LEGACY_TEXT_OFFSET 0x80000ul
#define LEGACY_KIMAGE_VADDR 0xffff000008000000ul
#define LEGACY_KERNEL_TEXT_DEFAULT (LEGACY_KIMAGE_VADDR + LEGACY_TEXT_OFFSET)
#define LEGACY_KERNEL_BASE_MIN LEGACY_KIMAGE_VADDR
// Old KASLR (v4.6): offset = BIT(VA_BITS-2) + (seed & mask), VA_BITS=48
// So offset ∈ [BIT(46), BIT(47)), range = BIT(46), aligned to SZ_2M.
#define LEGACY_KASLR_BASE_MIN (LEGACY_KERNEL_TEXT_DEFAULT + (1ul << 46))
#define LEGACY_KASLR_BASE_MAX (LEGACY_KASLR_BASE_MIN + (1ul << 46))

#endif /* KASLD_ARM64_H */
