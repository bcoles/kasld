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

// On x86_64, CONFIG_RANDOMIZE_MEMORY makes the runtime PAGE_OFFSET differ
// from the compile-time constant (= virt_page_offset_base, randomized each
// boot), so the compile-time (p + PAGE_OFFSET) formula is NOT a sound runtime
// directmap projection. phys_to_directmap_virt() is therefore left
// undefined (see gate at end of file). Kernel text KASLR (RANDOMIZE_BASE)
// is independent of RANDOMIZE_MEMORY, so text does not track the directmap.
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/x86/include/asm/page.h#L59
#define DIRECTMAP_STATIC 0
#define TEXT_TRACKS_DIRECTMAP 0

// CONFIG_RANDOMIZE_MEMORY places the direct-map / vmalloc / vmemmap region
// bases on PUD_SIZE (1 GiB) boundaries, so a bounded region base has
// (window / 1 GiB) candidate positions of residual entropy.
#define RANDOMIZE_MEMORY_ALIGN (1ul << 30)

// RANDOMIZE_MEMORY slides PAGE_OFFSET (the direct-map base) per boot — unlike
// every other supported arch, where PAGE_OFFSET is a fixed constant. Rules that
// reconstruct virt_page_offset report a window here rather than pinning a
// value.
#define PAGE_OFFSET_RANDOMIZED 1

#define KERNEL_VIRT_VAS_START PAGE_OFFSET
#define KERNEL_VIRT_VAS_END 0xfffffffffffffffful

// Old <= 4.4 era kernels used the RANDOMIZE_BASE_MAX_OFFSET config option
// which limited the maximum offset to 1 GiB (0x4000_0000), yielding 512
// possible base addresses (between 0xffffffff_80000000 and
// 0xffffffff_c0000000). The RANDOMIZE_BASE_MAX_OFFSET option was later removed.
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/x86/include/asm/page_64_types.h#L50
#define KERNEL_VIRT_TEXT_MIN 0xffffffff80000000ul
#define KERNEL_VIRT_TEXT_MAX 0xffffffffc0000000ul

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
#define IMAGE_ALIGN (2 * MB)

// EFI_KIMG_ALIGN: the alignment the EFI stub uses when allocating pages
// for the kernel image. On x86_64 this is CONFIG_PHYSICAL_ALIGN, whose
// distro default is 2 MiB (the practical minimum enforced by
// _SEGMENT_SIZE alignment — see PHYSICAL_START_MIN_PRACTICAL below).
// Used by efi_loader_kernel_pick to filter multi-entry EFI_LOADER_CODE
// memmaps. A non-default CONFIG_PHYSICAL_ALIGN > 2 MiB stays a multiple
// of this value, so the filter remains sound.
#define EFI_KIMG_ALIGN (2 * MB)

// https://elixir.bootlin.com/linux/v6.1.1/source/arch/x86/Kconfig#L2084
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/x86/boot/compressed/kaslr.c#L869
//
// CONFIG_PHYSICAL_START is configurable per kernel build (Kconfig default
// 16 MiB, minimum 2 MiB enforced by _SEGMENT_SIZE alignment). The hardcoded
// default below is the common case; distro-customised kernels may differ.
// The honest-top floors below (KASLR_*_BASE_MIN_CONSERVATIVE) widen to the
// 2 MiB practical minimum so a non-default build's text base is admitted;
// the physical_start_lower_bound rule restores the tight floor via either a
// learned SF_PHYSICAL_START (CONF_PARSED) or this compile-time default
// (CONF_HEURISTIC, overridable by any real evidence).
#define PHYSICAL_START 0x1000000ul
#define PHYSICAL_START_MIN_PRACTICAL 0x200000ul /* _SEGMENT_SIZE = 2 MiB */

// Plausible physical address range for kernel image.
// NOTE: KERNEL_PHYS_MAX is a *heuristic* ceiling (the kernel is usually
// loaded low in RAM), NOT an architectural limit — a large machine's phys
// KASLR base can legitimately exceed it. The inference engine treats it as
// a HEURISTIC-confidence constraint, not as the honest top. The honest top
// for the physical text base is PHYS_ADDR_TOP below.
#define KERNEL_PHYS_MIN PHYSICAL_START
#define KERNEL_PHYS_MAX (16ul * GB)

// Honest architectural tops for the inference engine (widest realisable
// value any configuration could produce). Typical-case ceilings are
// expressed as defeasible constraints, never as tops — the engine must
// never exclude a valid kernel placement, only narrow toward it.
//
// PHYS_ADDR_TOP: 2^MAXPHYADDR. x86_64 architectural max physical-address
// width is 52 bits; CPUID leaf 0x80000008 reports the implemented width at
// runtime (a narrowing constraint), but 52 bits is the honest ceiling.
#define PHYS_ADDR_TOP (1ul << 52)

// VA_BITS candidate set (paging levels): 4-level (48-bit) and 5-level
// (57-bit). The finite-set lattice narrows to the actual level as evidence
// arrives. Must list every level the kernel can run.
#define VA_BITS_CANDIDATES {48ul, 57ul}
#define VA_BITS_DEFAULT 48ul

// x86_64 kernel text starts at the base address (no offset from _stext).
#define TEXT_OFFSET 0

// Default: 0xffffffff81000000 (base + 16 MiB PHYSICAL_START).
// See docs/kaslr.md "Default text base and KASLR alignment" for all
// architectures. Kernel source: arch/x86/kernel/vmlinux.lds.S,
// arch/x86/include/asm/page_64_types.h
#define KERNEL_VIRT_TEXT_DEFAULT                                               \
  (KERNEL_VIRT_TEXT_MIN + PHYSICAL_START + TEXT_OFFSET)

/* KASLR-off ⇒ pin contract: x86_64 with nokaslr loads the kernel at
 * __START_KERNEL_map + LOAD_PHYSICAL_ADDR exactly, regardless of LA48/LA57.
 * Depends only on compile-time constants (PHYSICAL_START is
 * CONFIG_PHYSICAL_START, almost universally 0x1000000). The pin rule's
 * window-containment check is the backstop for a non-default
 * CONFIG_PHYSICAL_START build. */
#define KASLR_DISABLED_PINS_VIRT_TEXT 1
#define KASLD_ARCH_DEFAULT_TEXT_BASE_DEFINED 1
static inline unsigned long arch_default_text_base(void) {
  return KERNEL_VIRT_TEXT_DEFAULT;
}

/* KASLR-off ⇒ phys pin contract: x86_64's choose_random_location() returns
 * early when nokaslr / CONFIG_RANDOMIZE_BASE=n is in effect, so the kernel
 * stays at CONFIG_PHYSICAL_START (= PHYSICAL_START here, the compile-time
 * default). The physical_start_lower_bound rule already overrides this with
 * a learned SF_PHYSICAL_START at higher confidence when /boot/config or
 * /sys/kernel/boot_params/data is readable, so the heuristic here is the
 * lowest layer and yields cleanly to truth. */
#define KASLR_DISABLED_PINS_PHYS 1
#define KASLD_ARCH_DEFAULT_PHYS_TEXT_BASE_DEFINED 1
static inline unsigned long arch_default_phys_text_base(void) {
  return PHYSICAL_START;
}

#define KASLR_SUPPORTED 1

// Virtual KASLR range: __START_KERNEL_map + LOAD_PHYSICAL_ADDR to
// __START_KERNEL_map + KERNEL_IMAGE_SIZE.
// https://elixir.bootlin.com/linux/v6.12/source/arch/x86/boot/compressed/kaslr.c
#define KASLR_VIRT_TEXT_MIN (KERNEL_VIRT_TEXT_MIN + PHYSICAL_START)

/* Conservative lower edges of Q_VIRT_TEXT_BASE / Q_PHYS_TEXT_BASE windows
 * on x86_64. KASLR_VIRT_TEXT_MIN / KASLR_PHYS_MIN above bake in
 * CONFIG_PHYSICAL_START at its compile-time default (0x1000000). A kernel
 * built with a smaller CONFIG_PHYSICAL_START legitimately places text
 * below that floor, and a leak then becomes unsatisfiable against the
 * engine's window — the leak gets filed as a conflict and the engine's
 * resolved window EXCLUDES truth.
 *
 * The wider variant uses PHYSICAL_START_MIN_PRACTICAL (2 MiB, the
 * Kconfig-enforced minimum _SEGMENT_SIZE alignment) instead of the
 * default. Real kernels built with smaller CONFIG_PHYSICAL_START are now
 * admitted. The physical_start_lower_bound rule pushes the floor back up
 * at the right confidence (CONF_PARSED when learned, CONF_HEURISTIC
 * otherwise) — so default-config kernels still see a tight window. */
#define KASLR_VIRT_TEXT_MIN_WIDE                                               \
  (KERNEL_VIRT_TEXT_MIN + PHYSICAL_START_MIN_PRACTICAL)
#define KASLR_PHYS_MIN_WIDE PHYSICAL_START_MIN_PRACTICAL

#endif /* KASLD_X86_64_H */
