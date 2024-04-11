// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Definitions for x86_32 (i386 / i686)
//
// KASLR support added in commit 8ab3820fd5b2896d66da7bb2a906bc382e63e7bc in
// kernel v3.14-rc1~156^2~11 on 2013-10-13.
//
// KASLR was not compatible with hibernation (CONFIG_HIBERNATION) until commit
// 65fe935dd2387a4faf15314c73f5e6d31ef0217e in v4.8-rc1~179^2~20 on 2016-06-26.
//
// Enabled by default in commit 16b76293c5c81e6345323d7aef41b26e8390f62d in
// kernel v4.12-rc1~150 on 2017-05-01.
//
// References:
// https://github.com/torvalds/linux/commit/8ab3820fd5b2896d66da7bb2a906bc382e63e7bc
// https://github.com/torvalds/linux/commit/16b76293c5c81e6345323d7aef41b26e8390f62d
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/x86/Kconfig
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/x86/kernel/head_32.S
// ---
// <bcoles@gmail.com>

// 3GB vmsplit (0xc0000000) is a common configuration
// for distro kernels for non-embedded systems
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/x86/Kconfig#L1474
#define PAGE_OFFSET      0xc0000000ul

// https://elixir.bootlin.com/linux/v6.1.1/source/arch/x86/include/asm/page.h#L59
#define phys_to_virt(x)  ((unsigned long)(x + PAGE_OFFSET))

#define KERNEL_VAS_START PAGE_OFFSET
#define KERNEL_VAS_END   0xfffffffful

// Old <= 4.4 era kernels used the RANDOMIZE_BASE_MAX_OFFSET config option
// which limited the maximum offset to 512 MiB (0x2000_0000), yielding 256
// possible base addresses (between 0xc0000000 and 0xe0000000).
// The RANDOMIZE_BASE_MAX_OFFSET option was later removed.
// We use a larger range with a max of 0xf0000000.
#define KERNEL_BASE_MIN  PAGE_OFFSET
#define KERNEL_BASE_MAX  0xf0000000ul

#define MODULES_START    0xf0000000ul
#define MODULES_END      0xfffffffful

// For x86_32, possible max alignment is 0x100_0000 (16MiB) with default of
// 0x20_0000 (2MiB) in increments of 0x2000 (8KiB).
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/x86/boot/compressed/kaslr.c#L850
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/x86/Kconfig#L2182
#define KERNEL_ALIGN 2 * MB

#define TEXT_OFFSET 0

#define KERNEL_TEXT_DEFAULT (KERNEL_BASE_MIN + TEXT_OFFSET)
