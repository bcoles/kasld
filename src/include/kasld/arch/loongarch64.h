// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Definitions for LoongArch 64-bit (loong64 / loongarch64 / la464)
//
// KASLR support added in commit e5f02b51fa0cb785e352e77271a65e96051b789b in
// kernel v6.3-rc1~42^2~15 on 2023-02-25.
//
// References:
// https://github.com/torvalds/linux/commit/e5f02b51fa0cb785e352e77271a65e96051b789b
// https://loongson.github.io/LoongArch-Documentation/LoongArch-Vol1-EN.html
// https://docs.kernel.org/arch/loongarch/introduction.html#virtual-memory
// ---
// <bcoles@gmail.com>

#ifndef KASLD_LOONGARCH64_H
#define KASLD_LOONGARCH64_H

// https://elixir.bootlin.com/linux/v6.8.5/source/arch/loongarch/include/asm/addrspace.h#L57
// https://elixir.bootlin.com/linux/v6.8.5/source/arch/loongarch/include/asm/loongarch.h#L877
// https://elixir.bootlin.com/linux/v6.8.5/source/arch/loongarch/include/asm/addrspace.h#L39
// PAGE_OFFSET = (CSR_DMW1_VSEG << DMW_PABITS) = (0x9000 << 48)
#define PAGE_OFFSET 0x9000000000000000ul

// https://elixir.bootlin.com/linux/v6.8.5/source/arch/loongarch/include/asm/addrspace.h#L22
#define PHYS_OFFSET 0ul

// DMW hardware fixes PAGE_OFFSET; PHYS_OFFSET is compile-time. The directmap
// projection is sound. Kernel text lives in XKPRANGE at a fixed offset, so
// text tracks the directmap.
// https://elixir.bootlin.com/linux/v6.8.5/source/arch/loongarch/include/asm/page.h#L81
// PAGE_OFFSET is fixed by DMW hardware (CSR_DMW1_VSEG << DMW_PABITS) — KASLR
// randomizes only the physical load address — so the compile-time direct-map
// formula is exact (DIRECTMAP_STATIC) and text tracks the directmap.
// LINEAR_MAP_ANCHOR: __va(x) = x + PAGE_OFFSET - PHYS_OFFSET with
// PHYS_OFFSET a compile-time 0, so the anchor is that constant.
// arch/loongarch/include/asm/page.h __va(); asm/addrspace.h PHYS_OFFSET
#define LINEAR_MAP_ANCHOR LM_ANCHOR_PHYS_OFFSET
#define DIRECTMAP_STATIC 1
#define TEXT_TRACKS_DIRECTMAP 1

// The compile-time PAGE_OFFSET is the architectural guaranteed runtime
// value: the kernel writes _ULCAST_(0x9) to the DMW1 CSR unconditionally
// at boot, so Q_PAGE_OFFSET can be pinned without evidence — same
// "architectural certainty" shape as MIPS CKSEG0 and ppc64 book3s.
// Unlocks text_base_coupling_synth (it needs Q_PAGE_OFFSET pinned to
// propagate Q_VIRT_IMAGE_BASE ↔ Q_PHYS_IMAGE_BASE).
#define PAGE_OFFSET_INVARIANT 1
// The DMW1 direct-mapped window base, fixed by the architecture. Above
// KERNEL_VIRT_VAS_START (0x8000000000000000), as on mips64.
#define PAGE_OFFSET_CANDIDATES {0x9000000000000000ul}
#define PAGE_OFFSET_MIN 0x9000000000000000ul
#define PAGE_OFFSET_MAX 0x9000000000000000ul

// XKPRANGE starts at 0x8000000000000000 (hardware direct map windows DMW0/1/2).
// XKVRANGE starts at 0xc000000000000000 (vmalloc, modules, vmemmap).
// XSPRANGE (0x4000000000000000) is hardware-accessible at PLV0 but unused by
// Linux. We use XKPRANGE as the floor since no kernel address is below it.
// https://elixir.bootlin.com/linux/v6.12/source/arch/loongarch/include/asm/addrspace.h#L107
#define KERNEL_VIRT_VAS_START 0x8000000000000000ul
#define KERNEL_VIRT_VAS_END 0xfffffffffffffffful

// https://elixir.bootlin.com/linux/v6.8.5/source/arch/loongarch/Kconfig#L629
#define KERNEL_VIRT_TEXT_MIN PAGE_OFFSET
// KASLR offset: get_random_u16() << 16, max ~4 GiB. Use 8 GiB headroom.
// https://elixir.bootlin.com/linux/v6.12/source/arch/loongarch/kernel/relocate.c
#define KERNEL_VIRT_TEXT_MAX 0x9000000200000000ul

// Modules are in XKVRANGE at vm_map_base + PCI_IOSIZE + 2*PAGE_SIZE.
// vm_map_base = 0 - (1 << vabits); for 48-bit VA: 0xffff000000000000.
// Module region size: SZ_256M.
// Use conservative floor (48-bit VA) and wide ceiling to cover all VA configs.
// https://elixir.bootlin.com/linux/v6.12/source/arch/loongarch/include/asm/pgtable.h#L82
// The floor covers any VALEN the kernel can describe, not just today's parts.
// vm_map_base = 0 - (1 << cpu_vabits), read from CPUCFG1 at boot, so a wider
// VA moves the module region DOWN. Shipping parts report 39 (Loongson-2K) and
// 48 (LA464/LA664) -- both land above 0xffff000000000000 -- but the kernel's
// own page tables reach VA_BITS = PGDIR_SHIFT + (PAGE_SHIFT - PTRLOG) = 58 at
// 4 levels with 16K pages, so a future VALEN in 49..58 would sit below it.
// Anchor on that geometric bound (0 - (1 << 58)) rather than on the widest
// part that happens to exist: the failure mode of guessing is a silently
// dropped module address, and the cost of the wider band is only
// classify-by-range, which the REGION_MODULE provenance split already made
// non-load-bearing.
// Where the module band is anchored: a fixed address range, independent of both
// the image and the linear map.
#define MODULES_ANCHOR MOD_ANCHOR_FIXED
#define MODULES_START 0xfc00000000000000ul // 0 - (1 << 58)
#define MODULES_END 0xffffffffffff0000ul

// Usable as a BOUND, not only as an admission filter: the floor above is
// derived from the widest VA the kernel's page tables can describe, so it sits
// at or below vm_map_base for every VALEN a running kernel could report.
#define MODULES_BAND_STRENGTH MOD_BAND_BOUNDS

// The module region's placement is a pure function of the hardware VA width:
//   vm_map_base   = 0 - (1 << cpu_vabits)
//   MODULES_VADDR = vm_map_base + PCI_IOSIZE + 2 * PAGE_SIZE   (PCI_IOSIZE=32M)
// Nothing randomizes it, so a resolved width pins the quantity exactly rather
// than bounding it. Declared as an addend so the rule needs no loongarch
// literals of its own; the width comes from SF_VIRT_ADDR_BITS.
// https://elixir.bootlin.com/linux/v7.2/source/arch/loongarch/include/asm/pgtable.h#L98
// https://elixir.bootlin.com/linux/v7.2/source/arch/loongarch/include/asm/addrspace.h#L141
#define MODULES_BASE_FROM_VA_BITS_ADDEND (0x2000000ul + 2ul * PAGE_SIZE)

// EFI_KIMG_ALIGN is SZ_2M, but KASLR offset uses << 16 = 64 KiB granularity.
// https://elixir.bootlin.com/linux/v6.12/source/arch/loongarch/kernel/relocate.c
// https://elixir.bootlin.com/linux/v6.12/source/arch/loongarch/include/asm/efi.h#L30
#define IMAGE_ALIGN 0x10000ul

// EFI_KIMG_ALIGN is the alignment the EFI stub uses when calling
// AllocatePages() for the kernel image — SZ_2M on LoongArch per the
// kernel header linked above. Distinct from IMAGE_ALIGN (the KASLR
// offset granularity, 64 KiB) which is used by KASLR_PHYS_ALIGN paths
// elsewhere. Used by efi_loader_kernel_pick to filter multi-entry
// EFI_LOADER_CODE memmaps.
#define EFI_KIMG_ALIGN (2 * MB)

// IMAGE_BASE_OFFSET here is the load offset of _text from the DMW1 base (the
// kernel's VMLINUX_LOAD_ADDRESS offset), i.e. the alignment residue.
// https://elixir.bootlin.com/linux/v6.8.5/source/arch/loongarch/Makefile#L99
#define IMAGE_BASE_OFFSET 0x200000

// Head gap _stext - _text: loongarch64 places a header before _stext, so
// _stext = _text + 0x20000 (observed on the v6.18 lts kernel). The engine
// solves the image base (_text); _stext is projected from it with STEXT_OFFSET
// (a fallback — the real _text symbol is used at runtime when kallsyms is
// readable).
#define STEXT_OFFSET 0x20000ul

// Plausible physical address range for kernel image
#define KERNEL_PHYS_MIN 0ul
#define KERNEL_PHYS_MAX (64ul * GB)

// See docs/kaslr.md "Default text base and KASLR alignment" for all
// architectures. Kernel source: arch/loongarch/kernel/vmlinux.lds.S,
// arch/loongarch/Makefile
#define KERNEL_VIRT_TEXT_DEFAULT (KERNEL_VIRT_TEXT_MIN + IMAGE_BASE_OFFSET)

/* KASLR-off ⇒ pin contract: arch/loongarch/kernel/relocate.c kaslr_disabled()
 * short-circuits the relocate path and the kernel stays at the link address
 * VMLINUX_LOAD_ADDRESS = PAGE_OFFSET + IMAGE_BASE_OFFSET =
 * KERNEL_VIRT_TEXT_DEFAULT here. Triggered by the "kexec_file" cmdline token
 * (loongarch_kexec_file_nokaslr), the resume= hibernation path
 * (hibernation_nokaslr), nokaslr cmdline (proc_cmdline), or RANDOMIZE_BASE=n
 * (proc_config / boot_config). The pin rule's window-containment check is the
 * backstop for a distro-overridden VMLINUX_LOAD_ADDRESS. */
#define KASLR_DISABLED_PINS_VIRT_TEXT 1
#define KASLD_ARCH_DEFAULT_TEXT_BASE_DEFINED 1
static inline unsigned long arch_default_text_base(void) {
  return KERNEL_VIRT_TEXT_DEFAULT;
}

/* KASLR-off ⇒ phys pin contract: loongarch64's relocate.c skips
 * relocation when kaslr_disabled(), so the kernel stays at its build-time
 * physical load address VMLINUX_LOAD_ADDRESS = PAGE_OFFSET + IMAGE_BASE_OFFSET
 * in the virtual mapping; the physical equivalent is IMAGE_BASE_OFFSET above
 * the RAM base. With PHYS_OFFSET=0 that collapses to IMAGE_BASE_OFFSET. */
#define KASLR_DISABLED_PINS_PHYS 1
#define KASLD_ARCH_DEFAULT_PHYS_TEXT_BASE_DEFINED 1
static inline unsigned long arch_default_phys_text_base(void) {
  return (unsigned long)IMAGE_BASE_OFFSET;
}

// KASLR randomization: offset = get_random_u16() << 16, range [0, 0xFFFF0000].
// Virtual text = PAGE_OFFSET + IMAGE_BASE_OFFSET + offset.
#define KASLR_VIRT_TEXT_MIN (PAGE_OFFSET + IMAGE_BASE_OFFSET)
#define KASLR_VIRT_TEXT_MAX (PAGE_OFFSET + IMAGE_BASE_OFFSET + 0x100000000ul)

#define KASLR_SUPPORTED 1

#endif /* KASLD_LOONGARCH64_H */
