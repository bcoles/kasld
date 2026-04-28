// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Definitions for S390 64-bit (s390x / z/Architecture)
//
// s390x support is limited. The s390 virtual memory layout differs
// significantly from other architectures (no kernel/user split, separate
// ASCEs, identity mapping as directmap). Many KASLD components will
// produce no useful results on s390x.
//
// KASLR support added in commit b2d24b97b2a9691351920e700bfda4368c177232 in
// kernel v5.2-rc1~186^2~14 on 2019-02-03.
//
// s390x memory layout (arch/s390/mm documentation):
//   - Identity mapping at __identity_base: virt = phys + __identity_base
//     (__identity_base = 0 by default; randomized with RANDOMIZE_IDENTITY_BASE)
//   - Kernel text mapped separately at __kaslr_offset (virtual) with physical
//     load at __kaslr_offset_phys. The two are independently randomized.
//   - Modules: 2 GiB region (MODULES_LEN) placed just below kernel text.
//   - ASCE limit: 4 TiB (3-level) or 8 PiB (4-level).
//   - TEXT_OFFSET = 0x100000 (1 MiB): .text starts 1 MiB into image.
//   - Physical alignment: _SEGMENT_SIZE (1 MiB).
//   - Virtual alignment: THREAD_SIZE (typically 16 KiB).
//
// Note: The above layout describes v6.8+ kernels with CONFIG_KERNEL_IMAGE_BASE
// (introduced ~v6.8). Pre-v6.8 kernels ran identity-mapped: virtual = physical,
// with _stext at TEXT_OFFSET (0x100000) and physical-only KASLR randomization
// (THREAD_SIZE alignment within the identity map).
//
// Note: s390 does NOT have a traditional kernel/user address space split.
// Kernel and user addresses occupy separate ASCEs (address space control
// elements), not separate halves of the virtual range. The entire virtual
// range [0, ASCE_LIMIT) is available to both kernel and user (in their
// respective ASCEs).
//
// References:
// https://github.com/torvalds/linux/commit/b2d24b97b2a9691351920e700bfda4368c177232
// https://www.kernel.org/doc/html/latest/arch/s390/mm.html
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/s390/include/asm/page.h
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/s390/include/asm/pgtable.h
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/s390/boot/startup.c
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/s390/boot/kaslr.c
// ---
// <bcoles@gmail.com>

#ifndef KASLD_S390_H
#define KASLD_S390_H

// Identity mapping base (__identity_base): 0 without RANDOMIZE_IDENTITY_BASE.
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/s390/include/asm/page.h
// #define PAGE_OFFSET __identity_base
#define PAGE_OFFSET 0ul

// Physical memory starts at address 0.
#define PHYS_OFFSET 0ul

// Physical and virtual KASLR are decoupled (v6.8+). __kaslr_offset (virtual)
// and __kaslr_offset_phys (physical) are randomized independently.
// phys_to_virt() yields an identity-mapping address, NOT a kernel text
// address. Relationship: phys == (kvirt - __kaslr_offset) +
// __kaslr_offset_phys. Note: pre-v6.8 kernels used identity mapping (virtual =
// physical); KASLR was physical-only in that era.
#define PHYS_VIRT_DECOUPLED 1
#define phys_to_virt(x) ((unsigned long)(x) + PAGE_OFFSET - PHYS_OFFSET)
#define virt_to_phys(v) ((unsigned long)(v) - PAGE_OFFSET + PHYS_OFFSET)

// Identity mapping base is NOT randomized by default.
// CONFIG_RANDOMIZE_IDENTITY_BASE depends on RANDOMIZE_BASE and defaults to
// DEBUG_VM (typically off in production).
#define PAGE_OFFSET_RANDOMIZED 0

// Kernel VAS: entire address space up to the ASCE limit.
// 3-level paging: _REGION2_SIZE = 1 << 42 = 0x40000000000   (4 TiB)
// 4-level paging: _REGION1_SIZE = 1 << 53 = 0x20000000000000 (8 PiB)
// Use the 4-level limit for broadest coverage.
#define KERNEL_VAS_START 0ul
#define KERNEL_VAS_END 0x20000000000000ul

// Kernel text virtual address range.
// CONFIG_KERNEL_IMAGE_BASE:
//   range  0x100000 .. 0x1FFFFFE0000000 (without KASAN)
//   default 0x3FFE0000000  (= _REGION2_SIZE - KERNEL_IMAGE_SIZE = 4 TiB - 512
//   MiB)
// With KASLR, the kernel is placed near the top of the ASCE limit within a
// 2 GiB window (KASLR_LEN = 1 << 31).
#define KERNEL_BASE_MIN 0x100000ul
#define KERNEL_BASE_MAX 0x20000000000000ul

// Modules: 2 GiB (MODULES_LEN = 1 << 31) placed just below kernel text.
// MODULES_END = round_down(__kaslr_offset, _SEGMENT_SIZE).
// Runtime-determined; use wide bounds for validation.
#define MODULES_START 0ul
#define MODULES_END 0x20000000000000ul
#define MODULES_RELATIVE_TO_TEXT 0

// Virtual KASLR granularity: THREAD_SIZE (16 KiB on s390, PAGE_SIZE << 2).
// Physical placement uses _SEGMENT_SIZE (1 MiB), but virtual text addresses
// are only THREAD_SIZE-aligned. Confirmed on real hardware: _stext on a
// v6.18 system was 0x4000-aligned but not 1 MiB aligned.
#define KERNEL_ALIGN 0x4000ul

// Physical KASLR uses _SEGMENT_SIZE (1 MiB) alignment (v6.8+).
// Pre-v6.8 physical KASLR used THREAD_SIZE alignment.
#define KASLR_PHYS_ALIGN 0x100000ul

// TEXT_OFFSET: .text begins 1 MiB (0x100000) into the kernel image.
// arch/s390/include/asm/page.h: #define TEXT_OFFSET 0x100000
#define TEXT_OFFSET 0x100000ul

// Plausible physical address range for kernel image base (__kaslr_offset_phys).
// Physical text address = __kaslr_offset_phys + TEXT_OFFSET >= TEXT_OFFSET.
// CONFIG_MAX_PHYSMEM_BITS default is 46 (64 TiB).
#define KERNEL_PHYS_MIN 0ul
#define KERNEL_PHYS_MAX (64ul * GB)

// Virtual KASLR randomization window (v6.8+ upstream defaults):
// Image base picked from [CONFIG_KERNEL_IMAGE_BASE, KIB + KASLR_LEN).
// KASLR_LEN = 1 << 31 = 2 GiB. _stext = image_base + TEXT_OFFSET.
#define KASLR_BASE_MIN (0x3FFE0000000ul + TEXT_OFFSET)
#define KASLR_BASE_MAX (0x3FFE0000000ul + (1ul << 31) + TEXT_OFFSET)

// Default kernel text virtual address without KASLR.
// CONFIG_KERNEL_IMAGE_BASE (introduced ~v6.8) default = 0x3FFE0000000
// (+ TEXT_OFFSET for _stext). Pre-v6.8 kernels used identity mapping with
// _stext at TEXT_OFFSET (0x100000). Distros may override.
// See README.md "Default text base and KASLR alignment" for all architectures.
// Kernel source: arch/s390/kernel/vmlinux.lds.S, arch/s390/boot/startup.c
#define KERNEL_TEXT_DEFAULT 0x3FFE0100000ul

#define KASLR_SUPPORTED 1

#endif /* KASLD_S390_H */
