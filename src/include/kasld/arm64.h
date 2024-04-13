// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Definitions for ARM 64-bit (aarch64 / arm64)
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

// 52 va bits (CONFIG_ARM64_VA_BITS_48_52) is largest.
// 48 va bits (CONFIG_ARM64_VA_BITS_48) is more common.
// page_offset = (0xffffffffffffffffUL) << (va_bits - 1)
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/arm64/include/asm/memory.h#L45
// We assume 52 va bits:
#define PAGE_OFFSET 0xfff8000000000000ul
#define PHYS_OFFSET 0ul

// https://elixir.bootlin.com/linux/v6.1.1/source/arch/arm64/include/asm/memory.h#L295
#define phys_to_virt(x) ((unsigned long)((x)-PHYS_OFFSET) | PAGE_OFFSET)

#define KERNEL_VAS_START PAGE_OFFSET
#define KERNEL_VAS_END 0xfffffffffffffffful

// 48 va bits (CONFIG_ARM64_VA_BITS_48) is a common configuration;
// but an unsafe assumption since introduction of CONFIG_ARM64_VA_BITS_48_52.
// older kernels may use 0xffff000008000000ul
#define KERNEL_BASE_MIN 0xffff800008000000ul
#define KERNEL_BASE_MAX 0xffffffffff000000ul

#define MODULES_START 0xffff800000000000ul
#define MODULES_END 0xffff800007fffffful

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

#define KERNEL_TEXT_DEFAULT (KERNEL_BASE_MIN + TEXT_OFFSET)
