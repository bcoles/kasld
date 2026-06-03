// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Expected kernel address space values for supported architectures, plus the
// shared component API: result emission helpers, region enum, KASLD_EXPLAIN,
// KASLD_META.
//
// Each architecture header (arch/*.h) defines kernel address-space constants
// used throughout kasld; see any arch/*.h for the set, and the #error guards
// below for the symbols every arch must supply.
// ---
// <bcoles@gmail.com>

#ifndef KASLD_API_H
#define KASLD_API_H

#define PAGE_SIZE 0x1000ul
#define KB 0x400ul
#define MB 0x100000ul
#define GB 0x40000000ul
#define TB 0x10000000000ul

#if defined(__x86_64__) || defined(__amd64__)
#include "arch/x86_64.h"
#elif defined(__i386__)
#include "arch/x86_32.h"
#elif defined(__aarch64__)
#include "arch/arm64.h"
#elif defined(__arm__) || defined(__ARM_ARCH_6__) ||                           \
    defined(__ARM_ARCH_6J__) || defined(__ARM_ARCH_6K__) ||                    \
    defined(__ARM_ARCH_6Z__) || defined(__ARM_ARCH_6ZK__) ||                   \
    defined(__ARM_ARCH_6T2__) || defined(__ARM_ARCH_7__) ||                    \
    defined(__ARM_ARCH_7A__) || defined(__ARM_ARCH_7R__) ||                    \
    defined(__ARM_ARCH_7M__) || defined(__ARM_ARCH_7S__)
#include "arch/arm32.h"
#elif defined(__mips64) || defined(__mips64__)
#include "arch/mips64.h"
#elif defined(__mips__)
#include "arch/mips32.h"
#elif defined(__powerpc64__) || defined(__POWERPC64__) ||                      \
    defined(__ppc64__) || defined(__PPC64__)
#include "arch/ppc64.h"
#elif defined(__powerpc__) || defined(__POWERPC__) || defined(__ppc__) ||      \
    defined(__PPC__)
#include "arch/ppc32.h"
#elif (defined(__riscv) || defined(__riscv__)) && __riscv_xlen == 64
#include "arch/riscv64.h"
#elif (defined(__riscv) || defined(__riscv__)) && __riscv_xlen == 32
#include "arch/riscv32.h"
#elif defined(__loongarch__) && __loongarch_grlen == 64
#include "arch/loongarch64.h"
#elif defined(__s390x__) || defined(__zarch__)
#include "arch/s390.h" /* experimental */
#elif defined(__sparc__)
#include "arch/sparc.h"
#else
#error "Unrecognised architecture!"
#endif

/* Sanity-check arch-supplied values. */
#if KERNEL_VAS_START > KERNEL_VAS_END
#error "Defined KERNEL_VAS_START is larger than KERNEL_VAS_END"
#endif
#if KERNEL_VAS_START > KERNEL_TEXT_MIN
#error "Defined KERNEL_VAS_START is larger than KERNEL_TEXT_MIN"
#endif
#if KERNEL_TEXT_MAX > KERNEL_VAS_END
#error "Defined KERNEL_TEXT_MAX is larger than KERNEL_VAS_END"
#endif
#if KERNEL_TEXT_DEFAULT > KERNEL_TEXT_MAX
#error "Generated KERNEL_TEXT_DEFAULT is larger than KERNEL_TEXT_MAX"
#endif
#if KERNEL_TEXT_DEFAULT < KERNEL_TEXT_MIN
#error "Generated KERNEL_TEXT_DEFAULT is smaller than KERNEL_TEXT_MIN"
#endif
#ifdef KERNEL_PHYS_MIN
#if KERNEL_PHYS_MIN > KERNEL_PHYS_MAX
#error "Defined KERNEL_PHYS_MIN is larger than KERNEL_PHYS_MAX"
#endif
#endif

/* DIRECTMAP_STATIC and TEXT_TRACKS_DIRECTMAP must be declared by every arch
 * header — no defaults. Forcing each arch author to make the decision
 * explicitly is the whole point. See kasld.h banner for semantics. */
#ifndef DIRECTMAP_STATIC
#error "arch header must define DIRECTMAP_STATIC (0 or 1)"
#endif
#ifndef TEXT_TRACKS_DIRECTMAP
#error "arch header must define TEXT_TRACKS_DIRECTMAP (0 or 1)"
#endif

/* Canonical directmap projections (both directions). Defined once here, gated
 * by the same predicate on every arch. Callers must use `#ifdef
 * phys_to_directmap_virt` or `#ifdef directmap_virt_to_phys` — unsound arches
 * don't get the macro, so forgetting the guard fails to compile rather than
 * silently emitting a wrong observation. Both macros are bijective on a
 * static linear map and share the same gate. */
#if DIRECTMAP_STATIC
#define phys_to_directmap_virt(p)                                              \
  ((unsigned long)((p) - PHYS_OFFSET + PAGE_OFFSET))
#define directmap_virt_to_phys(v)                                              \
  ((unsigned long)((v) - PAGE_OFFSET + PHYS_OFFSET))
#endif

/* Conservative lower edges of Q_VIRT_TEXT_BASE / Q_PHYS_TEXT_BASE windows.
 *
 * KASLR_TEXT_MIN / KASLR_PHYS_MIN can bake in configurable Kconfig values
 * (currently x86_64 with CONFIG_PHYSICAL_START) at their *default*. Real
 * kernels built with a smaller value place text below that floor, and the
 * engine's window then excludes truth. KASLR_TEXT_MIN_WIDE /
 * KASLR_PHYS_MIN_WIDE are the *wider* variants — the smallest practical
 * value across all reasonable Kconfig choices on the arch — used by
 * quantities.c as the honest-top floor.
 *
 * Arches without configurable floors default these to KASLR_*_MIN
 * (no widening). The physical_start_lower_bound rule restores the tight
 * floor via a learned SF_PHYSICAL_START (CONF_PARSED) or the compile-time
 * default (CONF_HEURISTIC), overridable by any real evidence. */
#ifndef KASLR_TEXT_MIN_WIDE
#define KASLR_TEXT_MIN_WIDE KASLR_TEXT_MIN
#endif
#if defined(KASLR_PHYS_MIN) && !defined(KASLR_PHYS_MIN_WIDE)
#define KASLR_PHYS_MIN_WIDE KASLR_PHYS_MIN
#endif

/* KASLR randomization window defaults (override per-arch when narrower) */
#ifndef KASLR_TEXT_MIN
#define KASLR_TEXT_MIN KERNEL_TEXT_MIN
#endif
#ifndef KASLR_TEXT_MAX
#define KASLR_TEXT_MAX KERNEL_TEXT_MAX
#endif
#ifndef KASLR_ALIGN
#define KASLR_ALIGN KERNEL_ALIGN
#endif

#if defined(KERNEL_PHYS_MIN) && !defined(KERNEL_PHYS_DEFAULT)
#define KERNEL_PHYS_DEFAULT (KERNEL_PHYS_MIN + TEXT_OFFSET)
#endif
#if !defined(KASLR_PHYS_MIN) && defined(KERNEL_PHYS_DEFAULT)
#define KASLR_PHYS_MIN KERNEL_PHYS_DEFAULT
#endif
#if !defined(KASLR_PHYS_MAX) && defined(KERNEL_PHYS_MAX)
#define KASLR_PHYS_MAX KERNEL_PHYS_MAX
#endif
#ifndef KASLR_PHYS_ALIGN
#define KASLR_PHYS_ALIGN KERNEL_ALIGN
#endif

#ifndef PAGE_OFFSET_RANDOMIZED
#define PAGE_OFFSET_RANDOMIZED 0
#endif

/* PAGE_OFFSET is a fixed architectural constant (per VA-bits) unless KASLR
 * slides it — only x86_64 RANDOMIZE_MEMORY does. page_offset-reconstructing
 * rules pin to a single value on fixed arches, report a window on randomized.
 */
#ifndef PAGE_OFFSET_FIXED
#define PAGE_OFFSET_FIXED (!PAGE_OFFSET_RANDOMIZED)
#endif

/* Alignment granularity the kernel randomizes the CONFIG_RANDOMIZE_MEMORY
 * region bases (direct map / vmalloc / vmemmap) to — kernel_randomize_memory()
 * places each on a PUD_SIZE boundary on x86_64. Used only to report the
 * residual positional entropy of a bounded region base (window / align =
 * candidate positions). 0 = the arch does not randomize these regions, so no
 * entropy is reported. */
#ifndef RANDOMIZE_MEMORY_ALIGN
#define RANDOMIZE_MEMORY_ALIGN 0
#endif

/* 1 iff the compile-time PAGE_OFFSET is the GUARANTEED runtime value on this
 * arch — i.e. page_offset cannot vary by config (VMSPLIT/CONFIG_PAGE_OFFSET),
 * paging mode (arm64 VA_BITS, riscv SATP), or randomisation (x86_64
 * RANDOMIZE_MEMORY, s390). Only then is pinning Q_PAGE_OFFSET to PAGE_OFFSET
 * sound with no evidence. Set per-arch (mips CKSEG0, ppc64 book3s linear base);
 * defaults to 0 (the honest window is kept until a landmark/probe resolves it).
 */
#ifndef PAGE_OFFSET_INVARIANT
#define PAGE_OFFSET_INVARIANT 0
#endif

/* 1 iff CONFIG_PAGE_OFFSET is the AUTHORITATIVE runtime page_offset on this
 * arch — i.e. page_offset is a pure compile-time constant set by the
 * config/VMSPLIT and cannot be overridden at boot. True on x86_32/arm32
 * (user/kernel split is fixed at build). NOT true on riscv64
 * (CONFIG_PAGE_OFFSET reflects the built SATP mode but the kernel may boot a
 * narrower mode) or arm64 (VA_BITS), so those must use the runtime probe, not
 * the config. Defaults to 0. */
#ifndef PAGE_OFFSET_FROM_CONFIG
#define PAGE_OFFSET_FROM_CONFIG 0
#endif

/* "KASLR-off ⇒ engine pins virt text base to the arch default" contract.
 *
 * On arches where this is 1, the absence of KASLR (nokaslr cmdline, kernel
 * compiled without CONFIG_RANDOMIZE_BASE, or an arch-specific equivalent) means
 * the kernel sits at the address returned by `arch_default_text_base()` below.
 * The kaslr_disabled_pin rule pins Q_VIRT_TEXT_BASE to that value when a
 * KASLR-off signal (SF_KASLR_DISABLED) is present, with a window-containment
 * backstop that refuses to pin if the computed default falls outside the honest
 * window (a misconfig the arch_default_text_base() formula does not model).
 *
 * MUST stay 0 (default) on arches where the bootloader can place the kernel
 * elsewhere even without KASLR (CONFIG_RELOCATABLE in practice): x86_32,
 * arm32, ppc, mips, loongarch, s390 — pinning would be unsound there. */
#ifndef KASLR_DISABLED_PINS_TEXT
#define KASLR_DISABLED_PINS_TEXT 0
#endif

/* Per-arch derivation of the no-KASLR text base. Default stub never used (the
 * rule is gated on KASLR_DISABLED_PINS_TEXT, which is 0 here). Arch headers
 * override with the actual constant. If a future arch needs to derive this from
 * engine-resolved quantities (PAGE_OFFSET, VA_BITS, CONFIG_PHYSICAL_START …),
 * extend the signature and add dependency gating to the rule then. */
#ifndef KASLD_ARCH_DEFAULT_TEXT_BASE_DEFINED
static inline unsigned long arch_default_text_base(void) { return 0; }
#endif

/* Pin contract for the *physical* text base under KASLR-off. Parallel axis to
 * KASLR_DISABLED_PINS_TEXT and orthogonal to it: virt and phys KASLR offsets
 * are not always linked, so per-arch reality decides per-quantity.
 *
 * 1 (locked) on arches where SF_KASLR_DISABLED proves the kernel sits at the
 * compile-time physical default — i.e. the kernel's own decompressor/
 * relocator respects nokaslr for BOTH virt and phys:
 *   x86_64 (choose_random_location returns early; image stays at
 *           CONFIG_PHYSICAL_START)
 *   loongarch64 (kaslr_disabled() short-circuits relocate.c; image stays at
 *           VMLINUX_LOAD_ADDRESS = PAGE_OFFSET + TEXT_OFFSET)
 *
 * MUST stay 0 (default) where the phys load is bootloader / platform /
 * memstart-determined and not a fixed compile-time value, even under
 * KASLR-off:
 *   arm64 (memstart_addr from DT/EFI; no compile-time default)
 *   riscv64 (DRAM_BASE varies by platform — QEMU virt 0x80000000,
 *            StarFive 0x40000000, ...)
 *   s390 (independent __kaslr_offset_phys randomization; SF_KASLR_DISABLED
 *         is about the virt side only) */
#ifndef KASLR_DISABLED_PINS_PHYS
#define KASLR_DISABLED_PINS_PHYS 0
#endif

/* Per-arch derivation of the no-KASLR physical text base. Parallel to
 * arch_default_text_base(). Default stub never used (the rule is gated on
 * KASLR_DISABLED_PINS_PHYS, which is 0 here). Arch headers override only when
 * KASLR_DISABLED_PINS_PHYS=1. */
#ifndef KASLD_ARCH_DEFAULT_PHYS_TEXT_BASE_DEFINED
static inline unsigned long arch_default_phys_text_base(void) { return 0; }
#endif

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Filesystem-fact reads route through the KASLD_SYSROOT redirection layer so
 * captured filesystem trees replay offline. api.h is kasld's universal
 * include root, so pulling it here makes the wrappers visible in every
 * translation unit. */
#include "sysroot.h"

/* Generic [lo, hi] half-open or inclusive range; semantics decided by the
 * caller. Used by component-side region accumulators (dmesg_* parsers,
 * sysfs walkers) that aggregate per-line spans before emitting a result. */
struct addr_range {
  unsigned long lo;
  unsigned long hi;
};

/* MIPS64 XKPHYS: a 64-bit virtual address with bits [63:62] == 0b10 is a
 * hardware direct physical mapping. Bits [61:59] are the Cache Coherency
 * Attribute; bits [58:0] are the physical address (up to 2^59). A leaked
 * XKPHYS address looks like an ordinary kernel pointer but is really PHYS — the
 * observation boundary decodes it so it is never mistaken for a directmap VIRT
 * leak (which would let page_offset synthesis derive a bogus PAGE_OFFSET). Pure
 * bit math; the WHEN (mips64 only) is the caller's gate.
 * Ref: arch/mips/include/asm/addrspace.h; MIPS64 PRA Vol. III §4.3. */
static inline int kasld_addr_is_xkphys(unsigned long va) {
  /* Shift via a 64-bit type: on 32-bit arches `unsigned long` is 32 bits, where
   * XKPHYS cannot exist (a 32-bit address has no bit 63) and `va >> 62` would
   * be a shift-count-overflow. The zero-extended value yields 0 there,
   * correctly. */
  return ((unsigned long long)va >> 62) == 2ull;
}
static inline unsigned long kasld_xkphys_to_phys(unsigned long va) {
  return (unsigned long)((unsigned long long)va &
                         0x07ffffffffffffffull); /* strip
                                                    marker[63:62]+CCA[61:59] */
}

/* Predicate: is `va` plausibly inside the kernel module region on this arch?
 *
 * Wraps the MODULES_START/END validation union (see CONTRACT in kasld.h).
 * Used by components that classify leaked addresses as module-region
 * (proc_modules, sysfs_module_sections, dmesg-parsers). Centralising the
 * check here means the per-arch widening / future per-version handling
 * lives in one place rather than four. Pure arithmetic; safe in any TU. */
static inline int kasld_addr_is_module_region(unsigned long va) {
  return va >= (unsigned long)MODULES_START && va <= (unsigned long)MODULES_END;
}

/* =========================================================================
 * Result model: (extent, position, confidence) over a typed region
 * =========================================================================
 *
 * Tagged wire format:
 *   <type> <region>[:<name>] pos=<pos> conf=<conf> \
 *       [lo=<hex>] [hi=<hex>|sz=<hex>] [sample=<hex>] [base_align=<hex>]
 *
 *   type:    P (physical), V (virtual). Scalar system facts use the parallel
 *            `S <fact> conf=<c> value=<hex>` record (see kasld_emit_scalar).
 *   region:  closed vocabulary; see enum kasld_region
 *   name:    specific instance, when known (kernel symbol, module name,
 *            ACPI OEM ID, PCI BDF). Region:name splits on the FIRST `:`
 *            only — names may legitimately contain `:` (e.g. PCI BDF
 *            "0000:00:14.0").
 *   pos:     base | top | interior | unknown (what `sample` represents)
 *   conf:    parsed | derived | inferred | heuristic | timing | brute
 *
 * Components emit results via the kasld_result_* helpers. Each helper
 * picks one combination of bounds + sample + position. Components author
 * the helper that matches what they actually know — there is no path to
 * accidentally over-claim. There is no `_exact` helper — "exact" was a
 * precision conflation; precision lives in trust (`conf`) + bounds width.
 * ========================================================================= */

/* Address type. */
enum kasld_addr_type {
  KASLD_TYPE_UNKNOWN = 0,
  KASLD_TYPE_PHYS,
  KASLD_TYPE_VIRT,
};

/* Position: what does `sample` represent within the region's extent?
 * (Bounds-set-ness is carried independently in the HAS_LO/HAS_HI flags
 * — never derive "lo is known" from pos.) */
enum kasld_position {
  POS_UNKNOWN = 0,
  POS_BASE,
  POS_TOP,
  POS_INTERIOR,
};

/* Confidence: how reliable is the source of this claim?
 * Strictly a *trust* ordering, not a precision ordering — precision lives
 * in the width of [lo, hi]. PARSED > DERIVED > INFERRED > HEURISTIC >
 * TIMING > BRUTE. CONF_UNKNOWN = 0 is the memset-default; every wire
 * emission must declare a real confidence (UNKNOWN is rejected on the
 * wire and at the helper boundary). */
enum kasld_confidence {
  CONF_UNKNOWN = 0,
  CONF_BRUTE,
  CONF_TIMING,
  CONF_HEURISTIC,
  CONF_INFERRED,
  CONF_DERIVED,
  CONF_PARSED,
};

/* Region table — single source of truth for the closed enum vocabulary.
 *
 * One row per region, expanded into the enum (kasld_region), the
 * wire-name lookup (kasld_region_wire_table[]), and the per-region
 * descriptor (region_info[] in src/region_info.c) via X-macros.
 *
 * Row format: X(enum_id, wire_name, section_name, vas_kind)
 *
 *   enum_id      Full enum identifier (REGION_RAM, ...). Spelled in full so
 *                grep "REGION_RAM" lands on the definition.
 *   wire_name    Lowercase snake_case token used on the IPC line.
 *   section_name Render grouping ("dram" / "mmio" / "text" / ...).
 *                "" for the unknown sentinel; never appears in render.
 *   vas_kind     One of K_OPEN, K_VIRT, K_PAGEOFFSET, K_MODULE — selects
 *                the {static_vas, derive_vas} pair via VAS_<kind>_STATIC
 *                / VAS_<kind>_DERIVE in region_info.c. The K_ prefix is
 *                deliberate: arch headers define names like PAGE_OFFSET
 *                and would collide on the `kind` argument before
 *                token-pasting if we used the bare names.
 *                  K_OPEN       — {0, ULONG_MAX}, NULL (any phys address)
 *                  K_VIRT       — {KERNEL_VAS_START, KERNEL_VAS_END}, NULL
 *                                 (kernel-VAS-bounded virtual-only regions)
 *                  K_PAGEOFFSET — {0, 0}, derive_vas_page_offset
 *                                 (PAGE_OFFSET itself; layout-derived)
 *                  K_MODULE     — coupled vs decoupled handled in
 *                                 region_info.c via #if !TEXT_TRACKS_DIRECTMAP
 *
 * Adding a region: add one row here. The enum value, the wire-name entry,
 * and the region_info[] entry all get generated. REGION__COUNT auto-sizes
 * the arrays — compile fails if anything is out of sync.
 *
 * REGION_UNKNOWN = 0 is the memset-default and is intentionally NOT in
 * the X-list: it's the sentinel, hardcoded with empty section and
 * {0, 0}/NULL VAS so result_in_bounds() short-circuits. */
#define KASLD_REGION_LIST(X)                                                   \
  /* ---- Physical landmarks (DRAM-resident and MMIO) -------------------- */  \
  X(REGION_RAM, "ram", "dram", K_OPEN)                                         \
  X(REGION_DMA, "dma", "dram", K_OPEN)                                         \
  X(REGION_DMA32, "dma32", "dram", K_OPEN)                                     \
  X(REGION_INITRD, "initrd", "dram", K_OPEN)                                   \
  X(REGION_CMDLINE, "cmdline", "dram", K_OPEN)                                 \
  X(REGION_CMDLINE_MEMMAP, "cmdline_memmap", "dram", K_OPEN)                   \
  X(REGION_RESERVED_MEM, "reserved_mem", "dram", K_OPEN)                       \
  X(REGION_SWIOTLB, "swiotlb", "dram", K_OPEN)                                 \
  X(REGION_VMCOREINFO, "vmcoreinfo", "dram", K_OPEN)                           \
  X(REGION_CRASHKERNEL, "crashkernel", "dram", K_OPEN)                         \
  X(REGION_PMEM, "pmem", "dram", K_OPEN)                                       \
  X(REGION_ACPI_TABLE, "acpi_table", "dram", K_OPEN)                           \
  X(REGION_ACPI_NVS, "acpi_nvs", "dram", K_OPEN)                               \
  X(REGION_EFI_MEMMAP, "efi_memmap", "dram", K_OPEN)                           \
  /* One PHYS extent per EFI_LOADER_CODE memmap entry — the EFI stub's */      \
  /* PE/COFF image regions resident at ExitBootServices(). The running */      \
  /* kernel is exactly one of these on an EFI stub boot; bootloader / driver   \
   */                                                                          \
  /* images claim the others. efi_loader_kernel_pick filters by alignment + */ \
  /* SF_IMAGE_SIZE size match to identify the running-kernel entry. */         \
  X(REGION_EFI_LOADER_IMAGE, "efi_loader_image", "dram", K_OPEN)               \
  X(REGION_NUMA_NODE, "numa_node", "dram", K_OPEN)                             \
  X(REGION_MMIO, "mmio", "mmio", K_OPEN)                                       \
  X(REGION_PCI_MMIO, "pci_mmio", "mmio", K_OPEN)                               \
  /* ---- Kernel image (legitimately exists in both phys and virt) ------- */  \
  /* K_OPEN keeps PHYS leaks visible alongside VIRT — per-type narrowing   */  \
  /* lives in the parser / inference layer, not the region table.          */  \
  X(REGION_KERNEL_TEXT, "kernel_text", "text", K_OPEN)                         \
  X(REGION_KERNEL_DATA, "kernel_data", "data", K_OPEN)                         \
  X(REGION_KERNEL_BSS, "kernel_bss", "bss", K_OPEN)                            \
  X(REGION_KERNEL_IMAGE, "kernel_image", "text", K_OPEN)                       \
  X(REGION_MODULE, "module", "module", K_MODULE)                               \
  X(REGION_MODULE_REGION, "module_region", "module", K_MODULE)                 \
  /* ---- Direct-map / virtual landmarks --------------------------------- */  \
  X(REGION_DIRECTMAP, "directmap", "directmap", K_VIRT)                        \
  X(REGION_PAGE_OFFSET, "page_offset", "pageoffset", K_PAGEOFFSET)             \
  X(REGION_VMALLOC, "vmalloc", "directmap", K_VIRT)                            \
  X(REGION_VMEMMAP, "vmemmap", "directmap", K_VIRT)

/* Closed-enum vocabulary of kernel memory areas. */
enum kasld_region {
  REGION_UNKNOWN = 0,
#define X(name, wire, sec, kind) name,
  KASLD_REGION_LIST(X)
#undef X
  /* Sentinel. Must be last so we can iterate 0..REGION__COUNT-1. */
  REGION__COUNT,
};

/* Wire-token mappings. Generated from KASLD_REGION_LIST; do not edit
 * directly. Convention: lowercase snake_case of the enum suffix
 * (REGION_KERNEL_IMAGE -> "kernel_image"). */
static const char *const kasld_region_wire_table[REGION__COUNT] = {
    [REGION_UNKNOWN] = "unknown",
#define X(name, wire, sec, kind) [name] = wire,
    KASLD_REGION_LIST(X)
#undef X
};

static inline const char *kasld_region_wire(enum kasld_region r) {
  if ((unsigned)r >= REGION__COUNT)
    return "unknown";
  const char *s = kasld_region_wire_table[r];
  return s ? s : "unknown";
}

static inline char kasld_type_wire(enum kasld_addr_type t) {
  switch (t) {
  case KASLD_TYPE_PHYS:
    return 'P';
  case KASLD_TYPE_VIRT:
    return 'V';
  default:
    return '?';
  }
}

static inline const char *kasld_pos_wire(enum kasld_position p) {
  switch (p) {
  case POS_BASE:
    return "base";
  case POS_TOP:
    return "top";
  case POS_INTERIOR:
    return "interior";
  default:
    return "unknown";
  }
}

static inline const char *kasld_conf_wire(enum kasld_confidence c) {
  switch (c) {
  case CONF_PARSED:
    return "parsed";
  case CONF_DERIVED:
    return "derived";
  case CONF_INFERRED:
    return "inferred";
  case CONF_HEURISTIC:
    return "heuristic";
  case CONF_TIMING:
    return "timing";
  case CONF_BRUTE:
    return "brute";
  default:
    return "unknown";
  }
}

/* =========================================================================
 * Scalar system facts (non-address). A component emits these as `S` wire
 * records via kasld_emit_scalar(); the engine consumes them as OBS_SCALAR.
 * Closed vocabulary — add an entry, a wire token below, and a rule.
 * ========================================================================= */
enum kasld_scalar_fact {
  SF_NONE = 0,
  SF_MEMTOTAL,         /* total RAM bytes (/proc/meminfo)                  */
  SF_PHYS_ADDR_BITS,   /* CPU physical-address width (/proc/cpuinfo)       */
  SF_IMAGE_SIZE,       /* kernel image size bytes (/boot; estimate)        */
  SF_VA_BITS,          /* virtual-address width / paging level             */
  SF_INIT_SIZE,        /* exact in-memory kernel init_size (x86 boot_params)*/
  SF_LOWMEM,           /* 32-bit lowmem bytes (/proc/meminfo LowTotal)     */
  SF_FW_RESERVED_BASE, /* ppc64 firmware reserved region base (OPAL/RTAS)  */
  SF_MAX_PFN,          /* highest spanned PFN (/proc/zoneinfo)             */
  SF_KERNEL_ALIGN,     /* CONFIG_PHYSICAL_ALIGN slot granularity (x86)     */
  SF_PAGE_SIZE,        /* host page size in bytes                          */
  SF_RANDOMIZE_MAX_OFFSET, /* CONFIG_RANDOMIZE_BASE_MAX_OFFSET
                              (MIPS/LoongArch)*/
  SF_CONFIG_PAGE_OFFSET, /* CONFIG_PAGE_OFFSET (VMSPLIT; authoritative arches)*/
  SF_EFI_PRESENT,        /* 1 if /sys/firmware/efi exists (EFI boot)         */
  SF_FDT_KASLR_SEED,     /* FDT /chosen/kaslr-seed (riscv64)                 */
  SF_KASLR_DISABLED,     /* 1 if a detector saw KASLR-off (nokaslr / no       */
                         /* CONFIG_RANDOMIZE_BASE / riscv64 no FDT seed).     */
                         /* Implies kernel sits at the link-time default text */
                         /* base on arches where KASLR_DISABLED_PINS_TEXT/PHYS*/
                         /* hold; consumed by the kaslr_disabled_pin rule.    */
  SF_KASLR_RANDOMIZATION_FAILED, /* 1 if the boot stub attempted KASLR but */
  /* could not produce a random offset (arm64/riscv64  */
  /* "lack of seed", arm64 "FDT remapping failure",    */
  /* s390 "CPU has no PRNG" / "not enough memory").    */
  /* Kernel was still relocated to a firmware- or      */
  /* boot-stub-determined position — NOT the link-time */
  /* default — so this signal does NOT pin a value via */
  /* kaslr_disabled_pin. Consumed by: the hardening    */
  /* report posture section (entropy downgrade);       */
  /* efi_loader_kernel_pick (lowest-survivor pick from */
  /* multiple EFI_LOADER_CODE entries when the stub    */
  /* fell back to deterministic allocation); s390_text */
  /* _no_random (low-memory upper bound on s390 phys   */
  /* text from the boot stub's nokaslr_text_lma path). */
  SF_CMDLINE_MEM,       /* `mem=N` cmdline cap on usable RAM (bytes; x86)   */
  SF_CMDLINE_HUGEPAGES, /* 1 if `hugepages=` on cmdline (x86 EFI)      */
  SF_CMDLINE_MEMMAP_COUNT, /* count of `memmap=size{@,$,!,#}start` with offset
                            */
  SF_PHYSICAL_START, /* CONFIG_PHYSICAL_START (kernel's LOAD_PHYSICAL_ADDR  */
                     /* / pref_address; x86). Used to raise the Q_*_TEXT   */
                     /* honest-top floors above their conservative default.*/
  SF__COUNT,
};

/* SF_* <-> wire token, single source of truth for both directions. */
static const char *const kasld_scalar_fact_wire_table[SF__COUNT] = {
    [SF_NONE] = "none",
    [SF_MEMTOTAL] = "memtotal",
    [SF_PHYS_ADDR_BITS] = "phys_addr_bits",
    [SF_IMAGE_SIZE] = "image_size",
    [SF_VA_BITS] = "va_bits",
    [SF_INIT_SIZE] = "init_size",
    [SF_LOWMEM] = "lowmem",
    [SF_FW_RESERVED_BASE] = "fw_reserved_base",
    [SF_MAX_PFN] = "max_pfn",
    [SF_KERNEL_ALIGN] = "kernel_align",
    [SF_PAGE_SIZE] = "page_size",
    [SF_RANDOMIZE_MAX_OFFSET] = "randomize_max_offset",
    [SF_CONFIG_PAGE_OFFSET] = "config_page_offset",
    [SF_EFI_PRESENT] = "efi_present",
    [SF_FDT_KASLR_SEED] = "fdt_kaslr_seed",
    [SF_KASLR_DISABLED] = "kaslr_disabled",
    [SF_KASLR_RANDOMIZATION_FAILED] = "kaslr_randomization_failed",
    [SF_CMDLINE_MEM] = "cmdline_mem",
    [SF_CMDLINE_HUGEPAGES] = "cmdline_hugepages",
    [SF_CMDLINE_MEMMAP_COUNT] = "cmdline_memmap_count",
    [SF_PHYSICAL_START] = "physical_start",
};
/* Adding an SF_* without a wire token shrinks this below SF__COUNT -> error. */
typedef char kasld_sf_wire_table_complete
    [(sizeof(kasld_scalar_fact_wire_table) / sizeof(char *)) == SF__COUNT ? 1
                                                                          : -1];

static inline const char *kasld_scalar_fact_wire(enum kasld_scalar_fact f) {
  if ((unsigned)f >= SF__COUNT)
    return NULL;
  return kasld_scalar_fact_wire_table[f];
}

static inline enum kasld_scalar_fact
kasld_scalar_fact_from_wire(const char *s) {
  for (int i = SF_NONE + 1; i < SF__COUNT; i++)
    if (kasld_scalar_fact_wire_table[i] &&
        strcmp(s, kasld_scalar_fact_wire_table[i]) == 0)
      return (enum kasld_scalar_fact)i;
  return SF_NONE;
}

/* =========================================================================
 * Emitter helpers
 *
 * All helpers return 1 on emit, 0 on rejection (with a stderr warning).
 * Rejection happens for: CONF_UNKNOWN, invalid type, invalid region,
 * helper-specific preconditions (e.g. _sized overflow).
 * `name = NULL` or `""` means no specific instance (the wire form omits
 * the `:name` suffix). Names with leading/trailing whitespace or unsupported
 * chars are NOT validated here — the parser at ingest is the gatekeeper.
 * ========================================================================= */

static inline int kasld__emit_check(enum kasld_addr_type t, enum kasld_region r,
                                    enum kasld_confidence c, const char *who) {
  if (t == KASLD_TYPE_UNKNOWN) {
    fprintf(stderr, "%s: KASLD_TYPE_UNKNOWN rejected; no result emitted\n",
            who);
    return 0;
  }
  if ((unsigned)r >= REGION__COUNT || r == REGION_UNKNOWN) {
    fprintf(stderr, "%s: invalid region %u rejected; no result emitted\n", who,
            (unsigned)r);
    return 0;
  }
  if (c == CONF_UNKNOWN) {
    fprintf(stderr, "%s: CONF_UNKNOWN rejected; no result emitted\n", who);
    return 0;
  }
  return 1;
}

static inline void kasld__emit_prefix(enum kasld_addr_type t,
                                      enum kasld_region r, const char *name) {
  if (name && *name)
    printf("%c %s:%s", kasld_type_wire(t), kasld_region_wire(r), name);
  else
    printf("%c %s", kasld_type_wire(t), kasld_region_wire(r));
}

/* `lo`+`hi` known (extent fully bounded). pos=base, addr=lo. */
static inline int kasld_result_range(enum kasld_addr_type t,
                                     enum kasld_region r, unsigned long lo,
                                     unsigned long hi, const char *name,
                                     enum kasld_confidence c) {
  if (!kasld__emit_check(t, r, c, "kasld_result_range"))
    return 0;
  if (lo > hi) {
    fprintf(stderr,
            "kasld_result_range: lo=0x%lx > hi=0x%lx; no result emitted\n", lo,
            hi);
    return 0;
  }
  kasld__emit_prefix(t, r, name);
  printf(" pos=base conf=%s lo=0x%lx hi=0x%lx\n", kasld_conf_wire(c), lo, hi);
  return 1;
}

/* `lo`+`size` known. Normalises to inclusive hi = lo + sz - 1. */
static inline int kasld_result_sized(enum kasld_addr_type t,
                                     enum kasld_region r, unsigned long lo,
                                     unsigned long sz, const char *name,
                                     enum kasld_confidence c) {
  if (!kasld__emit_check(t, r, c, "kasld_result_sized"))
    return 0;
  if (sz == 0 || sz - 1 > ULONG_MAX - lo) {
    fprintf(stderr,
            "kasld_result_sized: invalid sz=0x%lx lo=0x%lx "
            "(would overflow lo+sz-1); no result emitted\n",
            sz, lo);
    return 0;
  }
  unsigned long hi = lo + sz - 1;
  kasld__emit_prefix(t, r, name);
  printf(" pos=base conf=%s lo=0x%lx hi=0x%lx\n", kasld_conf_wire(c), lo, hi);
  return 1;
}

/* Base only — `lo` known, `hi` unknown. pos=base, addr=lo. */
static inline int kasld_result_base(enum kasld_addr_type t, enum kasld_region r,
                                    unsigned long lo, const char *name,
                                    enum kasld_confidence c) {
  if (!kasld__emit_check(t, r, c, "kasld_result_base"))
    return 0;
  kasld__emit_prefix(t, r, name);
  printf(" pos=base conf=%s lo=0x%lx\n", kasld_conf_wire(c), lo);
  return 1;
}

/* Top only — `hi` known, `lo` unknown. pos=top, addr=hi. */
static inline int kasld_result_top(enum kasld_addr_type t, enum kasld_region r,
                                   unsigned long hi, const char *name,
                                   enum kasld_confidence c) {
  if (!kasld__emit_check(t, r, c, "kasld_result_top"))
    return 0;
  kasld__emit_prefix(t, r, name);
  printf(" pos=top conf=%s hi=0x%lx\n", kasld_conf_wire(c), hi);
  return 1;
}

/* Interior sample — address known, position within extent unknown. */
static inline int kasld_result_sample(enum kasld_addr_type t,
                                      enum kasld_region r, unsigned long addr,
                                      const char *name,
                                      enum kasld_confidence c) {
  if (!kasld__emit_check(t, r, c, "kasld_result_sample"))
    return 0;
  kasld__emit_prefix(t, r, name);
  printf(" pos=interior conf=%s sample=0x%lx\n", kasld_conf_wire(c), addr);
  return 1;
}

/* Emit one scalar system fact: `S <fact> conf=<c> value=0x<hex>`. */
static inline int kasld_emit_scalar(enum kasld_scalar_fact f,
                                    unsigned long value,
                                    enum kasld_confidence c) {
  const char *w = kasld_scalar_fact_wire(f);
  if (f == SF_NONE || !w) {
    fprintf(stderr, "kasld_emit_scalar: invalid fact %d; nothing emitted\n",
            (int)f);
    return 0;
  }
  if (c == CONF_UNKNOWN) {
    fprintf(stderr, "kasld_emit_scalar: CONF_UNKNOWN for %s; nothing emitted\n",
            w);
    return 0;
  }
  printf("S %s conf=%s value=0x%lx\n", w, kasld_conf_wire(c), value);
  return 1;
}

/* Component exit codes — the component-side ABI for signalling status to
 * the orchestrator. A non-zero exit with one of these values lets the
 * orchestrator distinguish "component ran but found nothing" (exit 0, no
 * tagged lines) from "data source unavailable" or "access denied". The
 * orchestrator maps these to OUTCOME_UNAVAILABLE / OUTCOME_ACCESS_DENIED
 * for the hardening report. */
#define KASLD_EXIT_UNAVAILABLE                                                 \
  69                         /* feature/hardware not present (EX_UNAVAILABLE) */
#define KASLD_EXIT_NOPERM 77 /* access denied (EX_NOPERM) */

/* When stdout is a pipe (as when the orchestrator captures output), glibc
 * switches to fully-buffered mode. stderr remains unbuffered. Both pipes
 * merge, so stderr lines can arrive before stdout lines that were logically
 * printed first. Force stdout to line-buffered so output order matches the
 * printf call order in each component. */
__attribute__((constructor)) static void kasld_init_buffering(void) {
  setvbuf(stdout, NULL, _IOLBF, 0);
}

/* Suppress -Wpedantic "ISO C forbids an empty translation unit". */
typedef int make_iso_compilers_happy;

/* Plain-text technique explanation, placed in a dedicated ELF section.
 * The orchestrator reads it (without executing the binary) for --explain. */
#define KASLD_EXPLAIN(text)                                                    \
  __attribute__((                                                              \
      used, section(".kasld_explain"))) static const char kasld_explain[] =    \
      text

/* Machine-readable metadata in a dedicated ELF section. Newline-delimited
 * key:value pairs. Recognised keys:
 *   method:  Technique description for the hardening report.
 *            Common values: parsed, timing, heuristic, brute-force.
 *   phase:   "inference" (default) or "probing".
 *   addr:    "virtual" or "physical".
 *   status:  "experimental" — opt-in via -x.
 *   sysctl:  Mitigating sysctl.
 *   bypass:  Capability that bypasses the mitigation.
 *   patch:   Kernel version that closed the bug.
 *   cve:     Associated CVE.
 *   hardware: Hardware requirement.
 */
#define KASLD_META(text)                                                       \
  __attribute__((                                                              \
      used, section(".kasld_meta"))) static const char kasld_meta[] = text

#endif /* KASLD_API_H */
