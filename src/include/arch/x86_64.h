// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Definitions for x86_64 (amd64)
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
// https://www.kernel.org/doc/Documentation/x86/x86_64/mm.txt
// ---
// <bcoles@gmail.com>

#ifndef KASLD_X86_64_H
#define KASLD_X86_64_H

// VAS start with 5-level page tables: 0xff000000_00000000
// VAS start with 4-level page tables: 0xffff8000_00000000
// 5-level paging is always compiled in since v6.17 (CONFIG_X86_5LEVEL removed);
// runtime detection via pgtable_l5_enabled().
// https://www.kernel.org/doc/html/latest/x86/x86_64/mm.html
// https://elixir.bootlin.com/linux/v6.12/source/arch/x86/include/asm/page_64_types.h#L34
#define PAGE_OFFSET 0xff00000000000000ul
#define PHYS_OFFSET 0ul

// Physical and virtual KASLR are decoupled on x86_64 since v4.8.
// phys_to_virt() yields a direct-map virtual address, NOT a kernel text
// address.
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/x86/include/asm/page.h#L59
#define PHYS_VIRT_DECOUPLED 1
#define phys_to_virt(x) ((unsigned long)(x + PAGE_OFFSET))

#define KERNEL_VAS_START PAGE_OFFSET
#define KERNEL_VAS_END 0xfffffffffffffffful

// Old <= 4.4 era kernels used the RANDOMIZE_BASE_MAX_OFFSET config option
// which limited the maximum offset to 1 GiB (0x4000_0000), yielding 512
// possible base addresses (between 0xffffffff_80000000 and
// 0xffffffff_c0000000). The RANDOMIZE_BASE_MAX_OFFSET option was later removed.
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/x86/include/asm/page_64_types.h#L50
#define KERNEL_BASE_MIN 0xffffffff80000000ul
#define KERNEL_BASE_MAX 0xffffffffc0000000ul

// MODULES_VADDR = __START_KERNEL_map + KERNEL_IMAGE_SIZE = 0xffffffffc0000000
// MODULES_END   = 0xffffffffff000000 (or 0xfffffffffe000000 with
// DEBUG_KMAP_LOCAL_FORCE_MAP)
// https://elixir.bootlin.com/linux/v6.12/source/arch/x86/include/asm/pgtable_64_types.h
#define MODULES_START 0xffffffffc0000000ul
#define MODULES_END 0xffffffffff000000ul
// Module region is fixed at MODULES_VADDR; does not shift with KASLR.
#define MODULES_RELATIVE_TO_TEXT 0

// For x86_64, possible max alignment is 0x100_0000 (16MiB) with default of
// 0x20_0000 (2MiB) in increments of 0x20_0000 (2MiB).
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/x86/boot/compressed/kaslr.c#L850
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/x86/Kconfig#L2182
#define KERNEL_ALIGN (2 * MB)

// https://elixir.bootlin.com/linux/v6.1.1/source/arch/x86/Kconfig#L2084
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/x86/boot/compressed/kaslr.c#L869
#define PHYSICAL_START 0x1000000ul

// Plausible physical address range for kernel image
#define KERNEL_PHYS_MIN PHYSICAL_START
#define KERNEL_PHYS_MAX (16ul * GB)

// x86_64 kernel text starts at the base address (no offset from _stext).
#define TEXT_OFFSET 0

// Default: 0xffffffff81000000 (base + 16 MiB PHYSICAL_START).
// See README.md "Default text base and KASLR alignment" for all architectures.
// Kernel source: arch/x86/kernel/vmlinux.lds.S,
// arch/x86/include/asm/page_64_types.h
#define KERNEL_TEXT_DEFAULT (KERNEL_BASE_MIN + PHYSICAL_START + TEXT_OFFSET)

#define KASLR_SUPPORTED 1

// Virtual KASLR range: __START_KERNEL_map + LOAD_PHYSICAL_ADDR to
// __START_KERNEL_map + KERNEL_IMAGE_SIZE.
// https://elixir.bootlin.com/linux/v6.12/source/arch/x86/boot/compressed/kaslr.c
#define KASLR_BASE_MIN (KERNEL_BASE_MIN + PHYSICAL_START)

#endif /* KASLD_X86_64_H */
