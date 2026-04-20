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

#ifndef KASLD_X86_32_H
#define KASLD_X86_32_H

// 3GB vmsplit (0xc0000000) is a common configuration
// for distro kernels for non-embedded systems. Configurable vmsplits range
// from CONFIG_VMSPLIT_1G (0x40000000) to CONFIG_VMSPLIT_3G (0xc0000000).
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/x86/Kconfig#L1474
#define PAGE_OFFSET 0xc0000000ul

// https://elixir.bootlin.com/linux/v6.1.1/source/arch/x86/include/asm/page.h#L59
#define PHYS_OFFSET 0ul
#define PHYS_VIRT_DECOUPLED 0
#define phys_to_virt(x) ((unsigned long)(x + PAGE_OFFSET))

// Minimum possible kernel base across all vmsplit configurations.
// CONFIG_VMSPLIT_1G sets PAGE_OFFSET=0x40000000, the lowest possible value.
// We use this as KERNEL_BASE_MIN to accept kernel addresses from all vmsplits.
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/x86/Kconfig#L1474
#define KERNEL_BASE_MIN 0x40000000ul

// VAS start uses the lowest possible PAGE_OFFSET to cover all vmsplit
// configurations. The orchestrator adjusts at runtime once vmsplit is detected.
#define KERNEL_VAS_START KERNEL_BASE_MIN
#define KERNEL_VAS_END 0xfffffffful
// Above this, addresses fall in the module/fixmap region.
#define KERNEL_BASE_MAX 0xf0000000ul

// Modules placed in high memory above kernel text.
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/x86/kernel/module.c
#define MODULES_START 0xf0000000ul
#define MODULES_END 0xfffffffful
// Module region is fixed; does not shift with KASLR.
#define MODULES_RELATIVE_TO_TEXT 0

// For x86_32, possible max alignment is 0x100_0000 (16MiB) with default of
// 0x20_0000 (2MiB) in increments of 0x2000 (8KiB).
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/x86/boot/compressed/kaslr.c#L850
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/x86/Kconfig#L2182
#define KERNEL_ALIGN (2 * MB)

#define TEXT_OFFSET 0

// Plausible physical address range for kernel image
#define KERNEL_PHYS_MIN 0ul
#define KERNEL_PHYS_MAX (1ul * GB)

// Default: 0xc0000000 (PAGE_OFFSET with 3GB vmsplit, no offset).
// See README.md "Default text base and KASLR alignment" for all architectures.
// Kernel source: arch/x86/kernel/vmlinux.lds.S
#define KERNEL_TEXT_DEFAULT (PAGE_OFFSET + TEXT_OFFSET)

#define KASLR_SUPPORTED 1

#endif /* KASLD_X86_32_H */
