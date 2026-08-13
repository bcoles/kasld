// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Definitions for PowerPC 64-bit (powerpc64 / ppc64 / ppc64le)
//
// Linux for PowerPC 64-bit does not support KASLR.
//
// Work in progress patches for KASLR support from 2020 appear to be abandoned:
// https://lwn.net/Articles/816271/
//
// References:
// https://www.kernel.org/doc/ols/2001/ppc64.pdf
// ---
// <bcoles@gmail.com>

#ifndef KASLD_PPC64_H
#define KASLD_PPC64_H

// 0xc000000000000000ul is a common configuration; but an unsafe assumption.
// For Freescale E-Book readers (CONFIG_PPC_BOOK3E_64), the kernel VAS start
// and text start is 0x8000000000000000ul.
// vmalloc, I/O and Bolted sections are mapped above kernel.
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/powerpc/Kconfig#L1267
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/powerpc/Kconfig#L1264
#define PAGE_OFFSET 0xc000000000000000ul
// book3s64 linear-mapping base is architecturally fixed (not
// user-configurable).
#define PAGE_OFFSET_INVARIANT 1
// book3s64 linear-mapping base. arch/powerpc/Kconfig declares it under
// `if PPC64` as a hex with no prompt, so it cannot be configured.
#define PAGE_OFFSET_CANDIDATES {0xc000000000000000ul}
#define PAGE_OFFSET_MIN 0xc000000000000000ul
#define PAGE_OFFSET_MAX 0xc000000000000000ul

// https://elixir.bootlin.com/linux/v6.1.1/source/arch/powerpc/include/asm/page.h#L227
#define PHYS_OFFSET 0ul
// PAGE_OFFSET and PHYS_OFFSET (= 0) are compile-time on ppc64; the directmap
// projection is sound. Mainline ppc64 has no KASLR — text sits at a fixed
// offset within the linear map.
// (The bitwise OR form of phys_to_virt used in kernel headers — equivalent to
// addition when the bit ranges don't overlap — is subsumed by the canonical
// (p - PHYS_OFFSET + PAGE_OFFSET) form in api.h.)
// LINEAR_MAP_ANCHOR: MEMORY_START is 0UL unconditionally on PPC64, so
// physical 0 maps to the linear-map base and the compile-time PHYS_OFFSET
// is the anchor.
// arch/powerpc/include/asm/page.h (#ifdef CONFIG_PPC64: MEMORY_START 0UL)
#define LINEAR_MAP_ANCHOR LM_ANCHOR_PHYS_OFFSET
#define DIRECTMAP_STATIC 1
#define TEXT_TRACKS_DIRECTMAP 1

#define KERNEL_VIRT_VAS_START PAGE_OFFSET
#define KERNEL_VIRT_VAS_END 0xfffffffffffffffful

#define KERNEL_VIRT_TEXT_MIN PAGE_OFFSET
#define KERNEL_VIRT_TEXT_MAX 0xffffffffff000000ul

// 64-bit PowerPC defines no MODULES_VADDR, so modules come from the vmalloc
// region -- whose base differs by MMU and page size, across a 32 TiB spread:
//
//   radix     RADIX_KERN_VIRT_START = 0xc008000000000000  (+ 1<<49)
//   hash-64k  H_KERN_VIRT_START     = 0xc008000000000000
//   hash-4k   H_KERN_VIRT_START     = 0xc0003d0000000000
//   Book3E    KERN_VIRT_START       = 0xc000100000000000  (+ 0x100000000000)
//
// The floor is the lowest of those (Book3E), not the Book3S one: a floor at
// 0xc008000000000000 admits radix and 64k-page hash but rejects every module
// address on a 4K-page hash kernel or a Book3E part (e5500/e6500), which is a
// silent drop -- proc_modules reports "no kernel address found", the same as
// an empty file. The ceiling is the radix vmalloc end, the highest of the four.
// https://elixir.bootlin.com/linux/v7.2/source/arch/powerpc/include/asm/book3s/64/radix.h
// https://elixir.bootlin.com/linux/v7.2/source/arch/powerpc/include/asm/nohash/64/pgtable.h
// Where the module band is anchored: a fixed address range, independent of both
// the image and the linear map.
#define MODULES_ANCHOR MOD_ANCHOR_FIXED
#define MODULES_START 0xc000100000000000ul
#define MODULES_END 0xc009fffffffffffful

// Usable as a BOUND: the floor is the lowest vmalloc base of any 64-bit
// PowerPC MMU configuration, and the ceiling the highest vmalloc end.
#define MODULES_BAND_EXACT 1

// The live vmalloc base -- and so the module region's base -- is decided by the
// translation mode and, for hash, the page size. All three values are
// compile-time constants in the kernel; only the SELECTION is runtime, and both
// selectors are observable unprivileged (SF_PPC64_MMU_MODE from /proc/cpuinfo,
// SF_PAGE_SIZE from sysconf). module_base_ppc64_vmalloc turns the pair into a
// pin.
//
// Book3E (KERN_VIRT_START = 0xc000100000000000) is deliberately absent: it is
// identified only by the ABSENCE of the MMU line, which a restricted /proc
// mimics exactly, so it stays unpinned rather than inferred from a missing
// signal. The band floor above still covers it.
// https://elixir.bootlin.com/linux/v7.2/source/arch/powerpc/include/asm/book3s/64/radix.h
// https://elixir.bootlin.com/linux/v7.2/source/arch/powerpc/include/asm/book3s/64/hash-64k.h
// https://elixir.bootlin.com/linux/v7.2/source/arch/powerpc/include/asm/book3s/64/hash-4k.h
#define MODULES_BASE_PPC64_RADIX 0xc008000000000000ul
#define MODULES_BASE_PPC64_HASH_64K 0xc008000000000000ul
#define MODULES_BASE_PPC64_HASH_4K 0xc0003d0000000000ul

// Plausible physical address range for kernel image
#define KERNEL_PHYS_MIN 0ul
#define KERNEL_PHYS_MAX (64ul * GB)

// 16KiB (0x4000) aligned
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/powerpc/Kconfig#L595
#define IMAGE_ALIGN 0x4000ul

#define IMAGE_BASE_OFFSET 0

// Default: 0xc000000000000000 (PAGE_OFFSET, no text offset on PPC64).
// See docs/kaslr.md "Default text base and KASLR alignment" for all
// architectures. Kernel source: arch/powerpc/kernel/vmlinux.lds.S
#define KERNEL_VIRT_TEXT_DEFAULT (KERNEL_VIRT_TEXT_MIN + IMAGE_BASE_OFFSET)

// PPC64 does not have mainline KASLR.
#define KASLR_SUPPORTED 0

#endif /* KASLD_PPC64_H */
