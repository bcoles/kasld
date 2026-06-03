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
#define DIRECTMAP_STATIC 1
#define TEXT_TRACKS_DIRECTMAP 1

// PAGE_OFFSET is fixed by DMW hardware (CSR_DMW1_VSEG << DMW_PABITS);
// KASLR randomizes only the physical load address.
// Directmap leaks cannot reveal the KASLR slide.
#define PAGE_OFFSET_RANDOMIZED 0

// XKPRANGE starts at 0x8000000000000000 (hardware direct map windows DMW0/1/2).
// XKVRANGE starts at 0xc000000000000000 (vmalloc, modules, vmemmap).
// XSPRANGE (0x4000000000000000) is hardware-accessible at PLV0 but unused by
// Linux. We use XKPRANGE as the floor since no kernel address is below it.
// https://elixir.bootlin.com/linux/v6.12/source/arch/loongarch/include/asm/addrspace.h#L107
#define KERNEL_VAS_START 0x8000000000000000ul
#define KERNEL_VAS_END 0xfffffffffffffffful

// https://elixir.bootlin.com/linux/v6.8.5/source/arch/loongarch/Kconfig#L629
#define KERNEL_TEXT_MIN PAGE_OFFSET
// KASLR offset: get_random_u16() << 16, max ~4 GiB. Use 8 GiB headroom.
// https://elixir.bootlin.com/linux/v6.12/source/arch/loongarch/kernel/relocate.c
#define KERNEL_TEXT_MAX 0x9000000200000000ul

// Modules are in XKVRANGE at vm_map_base + PCI_IOSIZE + 2*PAGE_SIZE.
// vm_map_base = 0 - (1 << vabits); for 48-bit VA: 0xffff000000000000.
// Module region size: SZ_256M.
// Use conservative floor (48-bit VA) and wide ceiling to cover all VA configs.
// https://elixir.bootlin.com/linux/v6.12/source/arch/loongarch/include/asm/pgtable.h#L82
#define MODULES_START 0xffff000000000000ul
#define MODULES_END 0xffffffffffff0000ul
#define MODULES_RELATIVE_TO_TEXT 0

// EFI_KIMG_ALIGN is SZ_2M, but KASLR offset uses << 16 = 64 KiB granularity.
// https://elixir.bootlin.com/linux/v6.12/source/arch/loongarch/kernel/relocate.c
// https://elixir.bootlin.com/linux/v6.12/source/arch/loongarch/include/asm/efi.h#L30
#define KERNEL_ALIGN 0x10000ul

// EFI_KIMG_ALIGN is the alignment the EFI stub uses when calling
// AllocatePages() for the kernel image — SZ_2M on LoongArch per the
// kernel header linked above. Distinct from KERNEL_ALIGN (the KASLR
// offset granularity, 64 KiB) which is used by KASLR_PHYS_ALIGN paths
// elsewhere. Used by efi_loader_kernel_pick to filter multi-entry
// EFI_LOADER_CODE memmaps.
#define EFI_KIMG_ALIGN (2 * MB)

// https://elixir.bootlin.com/linux/v6.8.5/source/arch/loongarch/Makefile#L99
#define TEXT_OFFSET 0x200000

// Plausible physical address range for kernel image
#define KERNEL_PHYS_MIN 0ul
#define KERNEL_PHYS_MAX (64ul * GB)

// See docs/kaslr.md "Default text base and KASLR alignment" for all
// architectures. Kernel source: arch/loongarch/kernel/vmlinux.lds.S,
// arch/loongarch/Makefile
#define KERNEL_TEXT_DEFAULT (KERNEL_TEXT_MIN + TEXT_OFFSET)

/* KASLR-off ⇒ pin contract: arch/loongarch/kernel/relocate.c kaslr_disabled()
 * short-circuits the relocate path and the kernel stays at the link address
 * VMLINUX_LOAD_ADDRESS = PAGE_OFFSET + TEXT_OFFSET = KERNEL_TEXT_DEFAULT here.
 * Triggered by the "kexec_file" cmdline token (loongarch_kexec_file_nokaslr),
 * the resume= hibernation path (hibernation_nokaslr), nokaslr cmdline
 * (proc_cmdline), or RANDOMIZE_BASE=n (proc_config / boot_config). The pin
 * rule's window-containment check is the backstop for a distro-overridden
 * VMLINUX_LOAD_ADDRESS. */
#define KASLR_DISABLED_PINS_TEXT 1
#define KASLD_ARCH_DEFAULT_TEXT_BASE_DEFINED 1
static inline unsigned long arch_default_text_base(void) {
  return KERNEL_TEXT_DEFAULT;
}

/* KASLR-off ⇒ phys pin contract: loongarch64's relocate.c skips
 * relocation when kaslr_disabled(), so the kernel stays at its build-time
 * physical load address VMLINUX_LOAD_ADDRESS = PAGE_OFFSET + TEXT_OFFSET in
 * the virtual mapping; the physical equivalent is TEXT_OFFSET above the RAM
 * base. With PHYS_OFFSET=0 that collapses to TEXT_OFFSET. */
#define KASLR_DISABLED_PINS_PHYS 1
#define KASLD_ARCH_DEFAULT_PHYS_TEXT_BASE_DEFINED 1
static inline unsigned long arch_default_phys_text_base(void) {
  return (unsigned long)TEXT_OFFSET;
}

// KASLR randomization: offset = get_random_u16() << 16, range [0, 0xFFFF0000].
// Virtual text = PAGE_OFFSET + TEXT_OFFSET + offset.
#define KASLR_TEXT_MIN (PAGE_OFFSET + TEXT_OFFSET)
#define KASLR_TEXT_MAX (PAGE_OFFSET + TEXT_OFFSET + 0x100000000ul)

#define KASLR_SUPPORTED 1

#endif /* KASLD_LOONGARCH64_H */
