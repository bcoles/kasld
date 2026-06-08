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
//   - phys_to_directmap_virt yields kernel text address (coupled)
//   - No KASLR
//
// Modern layout (v5.10+):
//   - SV39/SV48/SV57 with runtime detection (set_satp_mode)
//   - KERNEL_LINK_ADDR = ADDRESS_SPACE_END - SZ_2G + 1 = 0xffffffff80000000
//   - PAGE_OFFSET varies by mode (runtime):
//       SV39: 0xffffffd600000000 (PAGE_OFFSET_L3, v6.12+)
//             0xffffffd800000000 (PAGE_OFFSET_L3, v5.10 - v6.10)
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

// On v5.10+, PAGE_OFFSET (= kernel_map.virt_page_offset) and va_pa_offset are
// runtime-resolved; kernel text lives at KERNEL_LINK_ADDR with its OWN
// independent va_kernel_pa_offset. The compile-time formula is NOT a sound
// runtime directmap projection; phys_to_directmap_virt() is therefore left
// undefined (see gate at end of file). Text moves independently of the
// linear map, so text does not track the directmap.
//
// On legacy kernels (pre-v5.10) text WAS in the linear map, but those
// kernels had no KASLR so the lost coupled-derivation is acceptable.
#define DIRECTMAP_STATIC 0
#define TEXT_TRACKS_DIRECTMAP 0

/* Q_VA_BITS candidate set: SV39, SV48, SV57 (pgtable_l4_enabled /
 * pgtable_l5_enabled at boot select one). proc_cpuinfo emits
 * SF_VIRT_ADDR_BITS from /proc/cpuinfo "mmu" line; riscv64_va_bits_pin
 * narrows Q_VA_BITS to the single selected value. */
#define VA_BITS_CANDIDATES {39ul, 48ul, 57ul}

// VAS start with SV57 (5-level page tables): ~0xff1bffff_fea00000
// VAS start with SV48 (4-level page tables): ~0xffff8d7f_fea00000
// VAS start with SV39 (3-level page tables): ~0xffffffc6_fea00000
#define KERNEL_VIRT_VAS_START 0xff10000000000000ul
#define KERNEL_VIRT_VAS_END 0xfffffffffffffffful

// Kernel text region. Covers both modern and legacy layouts for validation:
//   Legacy: _stext ≈ 0xffffffe000200000 (>= KERNEL_VIRT_TEXT_MIN)
//   Modern: _stext ≈ 0xffffffff80200000 (>= KERNEL_VIRT_TEXT_MIN, <
//   KERNEL_VIRT_TEXT_MAX)
// KASLR (v6.6+) randomizes within 1 PUD (1 GiB) from KERNEL_LINK_ADDR.
// https://elixir.bootlin.com/linux/v6.6/source/arch/riscv/include/asm/pgtable.h#L63
#define KERNEL_VIRT_TEXT_MIN 0xffffffe000000000ul
#define KERNEL_VIRT_TEXT_MAX 0xffffffffc0000000ul

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
// MODULES_BELOW_TEXT_START selects the s390-style "Case B" placement
// (module band sits below the image). riscv64 puts modules ABOVE the
// image's _end, so explicitly 0 — needed (not just implicit-zero) so
// -Wundef does not fire at the `#if MODULES_BELOW_TEXT_START` sites in
// orchestrator.c + rules/module_text_bound.c (those sites are gated on
// MODULES_RELATIVE_TO_TEXT so they're only reachable on riscv64 + s390).
#define MODULES_BELOW_TEXT_START 0
#define MODULES_END_TO_TEXT_OFFSET 0x80000000ul /* 2 GiB */

// https://elixir.bootlin.com/linux/v6.6/source/arch/riscv/include/asm/efi.h#L41
#define IMAGE_ALIGN (2 * MB)

// EFI_KIMG_ALIGN is the alignment the EFI stub uses when calling
// AllocatePages() for the kernel image. On riscv64 this is PMD_SIZE
// (2 MiB) — see arch/riscv/include/asm/efi.h. Used by efi_loader_kernel_pick
// to filter multi-entry EFI_LOADER_CODE memmaps.
#define EFI_KIMG_ALIGN (2 * MB)

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
// the kernel maps its image starting at KERNEL_LINK_ADDR (== _start /
// _text), with _stext at KERNEL_LINK_ADDR + RISCV64_HEAD_TEXT_OFFSET
// (the .head.text section). Aligned to IMAGE_ALIGN (2 MiB), _stext
// rounds down to KERNEL_LINK_ADDR.
#define KERNEL_LINK_ADDR 0xffffffff80000000ul
// .head.text section length on riscv64 — the offset from the image base
// (_start) to _stext. Stable across v5.10+ kernels: the head holds the EFI
// PE/COFF header + SBI entry stub + paging-mode handoff, sized to a 0x2000
// page boundary. arch/riscv/kernel/head.S + arch/riscv/kernel/vmlinux.lds.S.
// See `_stext - _start` in kallsyms on any default-config riscv64 boot.
#define RISCV64_HEAD_TEXT_OFFSET 0x2000ul
// See docs/kaslr.md "Default text base and KASLR alignment" for all
// architectures. Kernel source: arch/riscv/kernel/vmlinux.lds.S,
// arch/riscv/include/asm/pgtable.h
//
// KERNEL_VIRT_TEXT_DEFAULT names the default _stext virtual address (per the
// api.h convention "Default _stext virtual address (no KASLR)"). On
// riscv64 that is KERNEL_LINK_ADDR + the head-text offset — NOT
// KERNEL_LINK_ADDR itself, which is _start (image base). Pinning to
// KERNEL_LINK_ADDR alone is unsound: the engine's virt_/phys_kaslr_disabled_pin
// rule would emit a value 0x2000 below the actual _stext, excluding
// truth from the resolved window.
#define KERNEL_VIRT_TEXT_DEFAULT (KERNEL_LINK_ADDR + RISCV64_HEAD_TEXT_OFFSET)

/* Build-time check: KERNEL_VIRT_TEXT_DEFAULT must include the .head.text
 * offset so it names _stext (per the api.h convention "Default _stext
 * virtual address"), not _start. Defining KERNEL_VIRT_TEXT_DEFAULT as
 * KERNEL_LINK_ADDR alone would pin Q_VIRT_TEXT_BASE 0x2000 below the
 * actual _stext via the engine's virt_/phys_kaslr_disabled_pin rule, excluding
 * the true text base from the resolved window. __extension__ silences
 * -Wpedantic on -std=c99. */
__extension__ _Static_assert(
    (KERNEL_VIRT_TEXT_DEFAULT - KERNEL_LINK_ADDR) == RISCV64_HEAD_TEXT_OFFSET,
    "riscv64 KERNEL_VIRT_TEXT_DEFAULT must equal KERNEL_LINK_ADDR + "
    "RISCV64_HEAD_TEXT_OFFSET (it names _stext, not _start / image base)");

/* KASLR-off ⇒ pin contract: modern riscv64 (v5.10+, which is where KASLR
 * exists) puts the kernel image at KERNEL_LINK_ADDR — the top 2 GiB of VA,
 * fixed regardless of SATP mode (SV39/SV48/SV57). The mode-dependent address
 * is PAGE_OFFSET (the linear map base), NOT the kernel image VA, so the default
 * does not depend on any runtime-resolved quantity here. Pre-v5.10 kernels
 * placed text in the linear map at PAGE_OFFSET; those have no KASLR support so
 * the disabled marker is moot, and the rule's window-containment check catches
 * the legacy case if the marker fires anyway. */
#define KASLR_DISABLED_PINS_VIRT_TEXT 1
#define KASLD_ARCH_DEFAULT_TEXT_BASE_DEFINED 1
static inline unsigned long arch_default_text_base(void) {
  return KERNEL_VIRT_TEXT_DEFAULT;
}

// KASLR randomization window. KERNEL_VIRT_TEXT_MIN is intentionally wide to
// accept legacy (pre-v5.10) addresses for validation, but the actual KASLR
// range (v6.6+) is [KERNEL_LINK_ADDR, KERNEL_LINK_ADDR + 1 PUD) = 1 GiB.
#define KASLR_VIRT_TEXT_MIN KERNEL_LINK_ADDR

// No physical KASLR on RISC-V. The kernel always loads at a fixed offset
// (TEXT_OFFSET) from the DRAM base provided by firmware. Only the virtual
// mapping is randomized (v6.6+).
//
// TEXT_OFFSET = 2 MiB is the OpenSBI convention: OpenSBI occupies the first
// 2 MiB of DRAM (trap vectors, fw_jump payload, etc.) and the kernel image
// follows immediately. This gives a deterministic physical base on non-EFI
// boots. On EFI-booted systems the EFI stub allocates memory from the EFI
// memory map — anywhere in the physical address space — bypassing this
// convention entirely. Additionally, the DRAM base itself varies by platform
// (0x80000000 on QEMU virt/SiFive, 0x40000000 on StarFive VisionFive 2, etc.),
// so the physical kernel base is not fixed across hardware. KASLR_PHYS_MAX is
// therefore set to KERNEL_PHYS_MAX rather than the hardware default.
#define KASLR_PHYS_MAX KERNEL_PHYS_MAX

#define KASLR_SUPPORTED 1

// Legacy layout detection (pre-v5.10 SV39).
// Text in the linear map below KERNEL_LINK_ADDR → coupled layout where
// PAGE_OFFSET is derived from the observed text address.
#define LEGACY_LAYOUT_BOUNDARY KERNEL_LINK_ADDR
#define LEGACY_COUPLED 1
#define LEGACY_PAGE_OFFSET_MASK (~(2ul * GB - 1))
#define LEGACY_TEXT_OFFSET 0

#endif /* KASLD_RISCV64_H */
