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

// Continuous: CONFIG_RANDOMIZE_MEMORY randomizes the linear-map base within
// its region, so there is no set to enumerate -- only the window.
//
// The upper edge is __START_KERNEL_map, where the kernel IMAGE mapping begins.
// The linear map lies below it by construction, so the bound holds irrespective
// of KASLR, of config, and of paging level (the constant is the same at four
// and five levels); a kernel with memory randomization off keeps
// __PAGE_OFFSET_BASE_L4/_L5, far below.
//
// It is deliberately NOT the tighter CPU_ENTRY_AREA_BASE (0xfffffe0000000000),
// which is where kernel_randomize_memory() actually stops today. That value is
// only correct from v4.15: arch/x86/mm/kaslr.c chose vaddr_end by config before
// commit 1dddd2512511 ("x86/kaslr: Fix the vaddr_end mess"), taking
// ESPFIX_BASE_ADDR, EFI_VA_END or __START_KERNEL_map. Those three commits are
// the whole history of the value, and __START_KERNEL_map is the highest of
// them, so it is the tightest bound that is sound on every kernel this may run
// against -- and version-gating to get the rest is not available.
// Spelled as the literal because KERNEL_VIRT_TEXT_MIN is defined below; the
// assertion beneath that definition keeps the two from drifting apart.
// Admissible kernel page sizes on this architecture. PAGE_SIZE_KNOWN_AT_BUILD
// is derived from the pair in api.h and gates pfn_to_phys(); a page-frame
// number may only be converted with a compile-time constant where the two
// edges coincide. Where they differ the runtime SF_PAGE_SIZE observation is
// the only sound multiplier.
// x86 fixes the base page at 4 KiB; arch/x86 selects
// HAVE_PAGE_SIZE_4KB and offers no alternative.
#define PAGE_SIZE_MIN 0x1000ul
#define PAGE_SIZE_MAX 0x1000ul

#define PAGE_OFFSET_MIN KERNEL_VIRT_VAS_START
#define PAGE_OFFSET_MAX 0xffffffff80000000ul
#define PHYS_OFFSET 0ul

// On x86_64, CONFIG_RANDOMIZE_MEMORY makes the runtime PAGE_OFFSET differ
// from the compile-time constant (= virt_page_offset_base, randomized each
// boot), so the compile-time (p + PAGE_OFFSET) formula is NOT a sound runtime
// directmap projection. phys_to_directmap_virt() is therefore left
// undefined (see gate at end of file). Kernel text KASLR (RANDOMIZE_BASE)
// is independent of RANDOMIZE_MEMORY, so text does not track the directmap.
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/x86/include/asm/page.h#L59
// LINEAR_MAP_ANCHOR: __va(x) = x + page_offset_base, so physical 0 maps to
// the linear-map base and the anchor is the compile-time PHYS_OFFSET (0).
// RANDOMIZE_MEMORY slides the VIRTUAL base, never the physical anchor.
// arch/x86/include/asm/page_64.h __va()
#define LINEAR_MAP_ANCHOR LM_ANCHOR_PHYS_OFFSET
#define DIRECTMAP_STATIC 0
#define TEXT_TRACKS_DIRECTMAP 0
// PHYS_OFFSET is unconditionally 0 on x86_64 (__pa(x) = x - PAGE_OFFSET, no
// physical-base randomization), so directmap_va - __pa(directmap_va) recovers
// page_offset_base exactly even though the directmap VA base itself randomizes.
#define PHYS_OFFSET_EXACT 1

// CONFIG_RANDOMIZE_MEMORY places the direct-map / vmalloc / vmemmap region
// bases on PUD_SIZE (1 GiB) boundaries, so a bounded region base has
// (window / 1 GiB) candidate positions of residual entropy.
#define RANDOMIZE_MEMORY_ALIGN (1ul << 30)

// Compile-time default region bases — the values page_offset_base /
// vmalloc_base / vmemmap_base are initialised to (head64.c) and KEEP whenever
// kernel_randomize_memory() returns early, i.e. when KASLR is off OR
// CONFIG_KASAN=y (kaslr_memory_enabled() = kaslr_enabled() && !KASAN). On
// x86_64 __PAGE_OFFSET / VMALLOC_START / VMEMMAP_START are unconditionally
// these variables (page_64_types.h, pgtable_64_types.h), so under the disabled
// gate the runtime base IS the constant. Selected by paging level: L4 = 4-level
// (VA 48), L5 = 5-level (VA 57). Consumed by directmap_kaslr_disabled_pin.
#define PAGE_OFFSET_BASE_L4 0xffff888000000000ul
#define PAGE_OFFSET_BASE_L5 0xff11000000000000ul
#define VMALLOC_BASE_L4 0xffffc90000000000ul
#define VMALLOC_BASE_L5 0xffa0000000000000ul
#define VMEMMAP_BASE_L4 0xffffea0000000000ul
#define VMEMMAP_BASE_L5 0xffd4000000000000ul

#define KERNEL_VIRT_VAS_START PAGE_OFFSET
#define KERNEL_VIRT_VAS_END 0xfffffffffffffffful

// Old <= 4.4 era kernels used the RANDOMIZE_BASE_MAX_OFFSET config option
// which limited the maximum offset to 1 GiB (0x4000_0000), yielding 512
// possible base addresses (between 0xffffffff_80000000 and
// 0xffffffff_c0000000). The RANDOMIZE_BASE_MAX_OFFSET option was later removed.
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/x86/include/asm/page_64_types.h#L50
#define KERNEL_VIRT_TEXT_MIN 0xffffffff80000000ul
// PAGE_OFFSET_MAX above is this same boundary (__START_KERNEL_map), written as
// a literal because it is defined before this line. Tied together here so
// moving one cannot silently leave the other behind.
__extension__ _Static_assert(PAGE_OFFSET_MAX == KERNEL_VIRT_TEXT_MIN,
                             "PAGE_OFFSET_MAX must be __START_KERNEL_map, the "
                             "boundary KERNEL_VIRT_TEXT_MIN also names");
#define KERNEL_VIRT_TEXT_MAX 0xffffffffc0000000ul

// The text window holds the kernel image and the module region and nothing
// else: the linear map is 64 TiB lower, and vmalloc/vmemmap lower still.
// Ruling out the module band therefore leaves the image, so a bare address
// here can be attributed by value. See TEXT_WINDOW_EXCLUSIVE in api.h.
#define TEXT_WINDOW_EXCLUSIVE 1

// MODULES_VADDR = __START_KERNEL_map + KERNEL_IMAGE_SIZE, and KERNEL_IMAGE_SIZE
// is NOT constant:
//
//   CONFIG_RANDOMIZE_BASE=y   1 GiB   -> MODULES_VADDR = 0xffffffffc0000000
//   CONFIG_RANDOMIZE_BASE=n   512 MiB -> MODULES_VADDR = 0xffffffffa0000000
//
// (page_64_types.h: "If KASLR is disabled we can shrink it to 0.5 GiB and
// increase the size of the modules area to 1.5 GiB".) The floor is therefore
// the non-randomized value: a floor at 0xffffffffc0000000 rejects every module
// address on a kernel BUILT without RANDOMIZE_BASE -- a build-time condition,
// so booting `nokaslr` does not reproduce it and the nokaslr VM cells never
// caught it.
//
// MODULES_END is 0xffffffffff000000, or 0xfffffffffe000000 with
// DEBUG_KMAP_LOCAL_FORCE_MAP; the wider value is kept, since a ceiling that is
// too high only admits, never rejects.
//
// Cost: the band now overlaps the text window [0xffffffff80000000,
// 0xffffffffc0000000] by 512 MiB, so classify-by-range cannot separate text
// from modules there. That is contained by the REGION_MODULE provenance split
// -- module_text_bound and module_text_bracket are both inert on x86_64, and
// module_base_bounds reads REGION_MODULE only -- so a mis-tag is
// presentational.
// https://elixir.bootlin.com/linux/v7.2/source/arch/x86/include/asm/page_64_types.h
// https://elixir.bootlin.com/linux/v7.2/source/arch/x86/include/asm/pgtable_64_types.h
// Where the module band is anchored: a fixed address range, independent of both
// the image and the linear map.
#define MODULES_ANCHOR MOD_ANCHOR_FIXED
#define MODULES_START 0xffffffffa0000000ul
#define MODULES_END 0xffffffffff000000ul

// BOUNDS: the floor is the lower of the two KERNEL_IMAGE_SIZE placements, so it
// holds whether or not the kernel was built with KASLR.
#define MODULES_BAND_STRENGTH MOD_BAND_BOUNDS

// execmem_arch_setup() places the module range's start at
//   start = MODULES_VADDR + offset
//   offset = kaslr_enabled() ? get_random_u32_inclusive(1, 1024) * PAGE_SIZE :
//   0
// so the base is confined to a 1024-page window above MODULES_VADDR -- ~10 bits
// drawn independently of the text slide.
//
// MODULES_VADDR below is the CONFIG_RANDOMIZE_BASE=y placement
// (__START_KERNEL_map + 1 GiB). Naming it separately from MODULES_START, which
// is the =n placement, is what lets a rule use it: the two differ, and only
// evidence that the image MOVED proves which one is live (a relocated image
// implies RANDOMIZE_BASE=y implies KERNEL_IMAGE_SIZE = 1 GiB). Offset 0 stays
// in the window because kaslr_enabled() is RANDOMIZE_MEMORY && KASLR_FLAG, and
// RANDOMIZE_MEMORY depends on RANDOMIZE_BASE -- so a =y kernel with
// RANDOMIZE_MEMORY=n randomizes text but leaves the module base at
// MODULES_VADDR exactly.
// https://elixir.bootlin.com/linux/v7.2/source/arch/x86/mm/init.c#L1066
#define MODULES_BASE_RANDOMIZED 0xffffffffc0000000ul
// execmem_arch_setup() places the module range at MODULES_VADDR + a whole
// number of PAGE_SIZE, drawn from get_random_u32_inclusive(1, 1024) -- and 0
// where kaslr_enabled() is false, which needs CONFIG_RANDOMIZE_MEMORY and not
// merely RANDOMIZE_BASE, so an image that moved does not rule the zero out. The
// span therefore spans 1025 positions, not 1024. The STEP is x86_64's
// PAGE_SIZE, which is 4 KiB unconditionally, so it is the pitch itself and not
// a floor under one.
// https://elixir.bootlin.com/linux/latest/source/arch/x86/mm/init.c
#define MODULES_BASE_RANDOM_STEP 0x1000ul
#define MODULES_BASE_RANDOM_SPAN (1024ul * MODULES_BASE_RANDOM_STEP)
// Module region is fixed at MODULES_VADDR; does not shift with KASLR.

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

// x86_64 kernel text starts at the base address (no offset from _stext).
#define IMAGE_BASE_OFFSET 0

// Default: 0xffffffff81000000 (base + 16 MiB PHYSICAL_START).
// See docs/kaslr.md "Default text base and KASLR alignment" for all
// architectures. Kernel source: arch/x86/kernel/vmlinux.lds.S,
// arch/x86/include/asm/page_64_types.h
#define KERNEL_VIRT_TEXT_DEFAULT                                               \
  (KERNEL_VIRT_TEXT_MIN + PHYSICAL_START + IMAGE_BASE_OFFSET)

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

// Residue 0: the image base is 2 MiB-aligned by construction, so the grid is
// plain alignment and there is no sub-offset to get wrong.
#define IMAGE_BASE_RESIDUE_FIXED 1

// Virtual KASLR range: __START_KERNEL_map + LOAD_PHYSICAL_ADDR to
// __START_KERNEL_map + KERNEL_IMAGE_SIZE.
// https://elixir.bootlin.com/linux/v6.12/source/arch/x86/boot/compressed/kaslr.c
#define KASLR_VIRT_TEXT_MIN (KERNEL_VIRT_TEXT_MIN + PHYSICAL_START)

/* Conservative lower edges of Q_VIRT_IMAGE_BASE / Q_PHYS_IMAGE_BASE windows
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
