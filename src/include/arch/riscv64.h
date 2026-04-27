// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Definitions for RISC-V 64-bit (riscv64)
//
// The riscv64 virtual address layout changed significantly in ~v5.10-v5.13:
//
// Legacy layout (pre-v5.10):
//   - SV39 only, PAGE_OFFSET is compile-time (Kconfig)
//   - KERNEL_LINK_ADDR = PAGE_OFFSET (text in linear mapping)
//   - PAGE_OFFSET = 0xffffffe000000000 (MAXPHYSMEM_128GB)
//   - phys_to_virt yields kernel text address (coupled)
//   - No KASLR
//
// Modern layout (v5.10+):
//   - SV39/SV48/SV57 with runtime detection (set_satp_mode)
//   - KERNEL_LINK_ADDR = ADDRESS_SPACE_END - SZ_2G + 1 = 0xffffffff80000000
//   - PAGE_OFFSET varies by mode (runtime):
//       SV39: 0xffffffd800000000 (PAGE_OFFSET_L3)
//       SV48: 0xffffaf8000000000 (PAGE_OFFSET_L4)
//       SV57: 0xff60000000000000 (PAGE_OFFSET_L5)
//   - Kernel text and linear map have separate VA-PA mappings (decoupled)
//   - KASLR added in v6.6 (within 1 PUD / 1 GiB, at 2 MiB granularity)
//
// KASLR support added in commit f57805555834494e8cad729d01d86ba326d64959 in
// kernel v6.6-rc1~10^2~5 on 2023-11-08.
//
// References:
// https://github.com/torvalds/linux/commit/f57805555834494e8cad729d01d86ba326d64959
// https://www.kernel.org/doc/html/next/riscv/vm-layout.html
// https://www.kernel.org/doc/html/next/riscv/boot.html
// ---
// <bcoles@gmail.com>

#ifndef KASLD_RISCV64_H
#define KASLD_RISCV64_H

// PAGE_OFFSET is runtime-determined on v5.10+. Use the SV57 value
// (PAGE_OFFSET_L5, broadest), matching the approach used for x86_64 5-level
// paging. CONFIG_PAGE_OFFSET Kconfig entry removed in v6.17; the value is
// now hardcoded as PAGE_OFFSET_L5 in arch/riscv/include/asm/page.h.
// https://elixir.bootlin.com/linux/v6.12/source/arch/riscv/include/asm/page.h
#define PAGE_OFFSET 0xff60000000000000ul

// Physical RAM base (platform-dependent; 0x80000000 for QEMU virt, SiFive,
// etc.)
#define PHYS_OFFSET 0x80000000ul

// On v5.10+, kernel text lives at KERNEL_LINK_ADDR (top 2 GiB) while the
// linear mapping starts at PAGE_OFFSET. These have separate VA-PA offsets
// (va_kernel_pa_offset vs va_pa_offset), so phys_to_virt yields a directmap
// alias, NOT the kernel text address. Same situation as x86_64.
//
// On legacy kernels (pre-v5.10), text WAS in the linear map (coupled), but
// those kernels had no KASLR so the loss of coupled derivation is acceptable.
#define PHYS_VIRT_DECOUPLED 1
#define phys_to_virt(x) ((unsigned long)(x) + (PAGE_OFFSET - PHYS_OFFSET))
#define virt_to_phys(v) ((unsigned long)(v) - (PAGE_OFFSET - PHYS_OFFSET))

// VAS start with SV57 (5-level page tables): ~0xff1bffff_fea00000
// VAS start with SV48 (4-level page tables): ~0xffff8d7f_fea00000
// VAS start with SV39 (3-level page tables): ~0xffffffc6_fea00000
#define KERNEL_VAS_START 0xff10000000000000ul
#define KERNEL_VAS_END 0xfffffffffffffffful

// Kernel text region. Covers both modern and legacy layouts for validation:
//   Legacy: _stext ≈ 0xffffffe000200000 (>= KERNEL_BASE_MIN)
//   Modern: _stext ≈ 0xffffffff80200000 (>= KERNEL_BASE_MIN, < KERNEL_BASE_MAX)
// KASLR (v6.6+) randomizes within 1 PUD (1 GiB) from KERNEL_LINK_ADDR.
// https://elixir.bootlin.com/linux/v6.6/source/arch/riscv/include/asm/pgtable.h#L63
#define KERNEL_BASE_MIN 0xffffffe000000000ul
#define KERNEL_BASE_MAX 0xffffffffc0000000ul

// Modern (v5.10+): KERNEL_LINK_ADDR = 0xffffffff80000000;
// module region = [PFN_ALIGN(&_end) - 2G, PFN_ALIGN(&_start)], always below
// kernel text and shifting with KASLR.
// https://elixir.bootlin.com/linux/v6.6/source/arch/riscv/include/asm/pgtable.h#L69
//
// Legacy: modules also below kernel, anchored to _end.
// Use a wide range covering both layouts for validation.
#define MODULES_START 0xffffffde00000000ul
#define MODULES_END 0xffffffffc0000000ul

// Module region is anchored to kernel _end (shifts with KASLR)
#define MODULES_RELATIVE_TO_TEXT 1
#define MODULES_END_TO_TEXT_OFFSET 0x80000000ul /* 2 GiB */

// https://elixir.bootlin.com/linux/v6.6/source/arch/riscv/include/asm/efi.h#L41
#define KERNEL_ALIGN (2 * MB)

// OpenSBI loads the kernel at DRAM_BASE + 2MiB by default.
// The kernel requires PMD-aligned (2MiB) placement.
#define TEXT_OFFSET (2 * MB)

// Plausible physical address range for kernel image
#define KERNEL_PHYS_MIN PHYS_OFFSET
#define KERNEL_PHYS_MAX (PHYS_OFFSET + 4ul * GB)

// Modern (v5.10+) default: KERNEL_LINK_ADDR is the kernel image virtual base.
// KASLR only exists on v6.6+ which always uses the modern layout.
// On legacy kernels, default is PAGE_OFFSET (text in linear map, no KASLR).
//
// NOTE: TEXT_OFFSET (2 MiB) is the *physical* offset from DRAM base where
// OpenSBI loads the kernel. It does NOT apply to the virtual address:
// the kernel maps its image starting at KERNEL_LINK_ADDR, with _stext
// at KERNEL_LINK_ADDR + 0x2000 (.head.text section). Aligned to
// KERNEL_ALIGN (2 MiB), _stext rounds down to KERNEL_LINK_ADDR.
#define KERNEL_LINK_ADDR 0xffffffff80000000ul
// See README.md "Default text base and KASLR alignment" for all architectures.
// Kernel source: arch/riscv/kernel/vmlinux.lds.S,
// arch/riscv/include/asm/pgtable.h
#define KERNEL_TEXT_DEFAULT KERNEL_LINK_ADDR

// KASLR randomization window. KERNEL_BASE_MIN is intentionally wide to
// accept legacy (pre-v5.10) addresses for validation, but the actual KASLR
// range (v6.6+) is [KERNEL_LINK_ADDR, KERNEL_LINK_ADDR + 1 PUD) = 1 GiB.
#define KASLR_BASE_MIN KERNEL_LINK_ADDR

// No physical KASLR on RISC-V. The kernel always loads at a fixed offset
// (TEXT_OFFSET) from the DRAM base provided by firmware. Only the virtual
// mapping is randomized (v6.6+).
#define KASLR_PHYS_MAX (KERNEL_PHYS_MIN + TEXT_OFFSET)

#define KASLR_SUPPORTED 1

// Legacy layout detection (pre-v5.10 SV39).
// Text in the linear map below KERNEL_LINK_ADDR → coupled layout where
// PAGE_OFFSET is derived from the observed text address.
#define LEGACY_LAYOUT_BOUNDARY KERNEL_LINK_ADDR
#define LEGACY_COUPLED 1
#define LEGACY_PAGE_OFFSET_MASK (~(2ul * GB - 1))
#define LEGACY_TEXT_OFFSET 0

#endif /* KASLD_RISCV64_H */
