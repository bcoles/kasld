// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Expected kernel address space values for supported architectures.
//
// Each architecture header (arch/*.h) defines the following constants:
//
// Virtual address space layout:
// - PAGE_OFFSET:              Start of the kernel direct-mapping (linear map).
// - KERNEL_VAS_START:         Lowest plausible kernel virtual address (floor).
//                             Often equals PAGE_OFFSET, but may be lower on
//                             architectures with configurable vmsplit to cover
//                             all configs (eg. 0x40000000 on 32-bit x86/arm).
// - KERNEL_VAS_END:           End of kernel virtual address space.
// - KERNEL_BASE_MIN:          Minimum plausible kernel text virtual address.
// - KERNEL_BASE_MAX:          Maximum plausible kernel text virtual address.
// - MODULES_START:            Start of kernel module virtual address range.
// - MODULES_END:              End of kernel module virtual address range.
// - MODULES_RELATIVE_TO_TEXT: 1 if the module region shifts with KASLR text.
// - KERNEL_ALIGN:             Kernel text address alignment.
// - TEXT_OFFSET:              Offset from base address to _stext.
// - KERNEL_TEXT_DEFAULT:      Default _stext virtual address (no KASLR).
//                             Defined per-architecture.
//
// Physical addresses:
// - PHYS_OFFSET:              Physical RAM base address.
// - KERNEL_PHYS_MIN:          Minimum plausible kernel physical load address.
// - KERNEL_PHYS_MAX:          Maximum plausible kernel physical load address.
//
// KASLR and address derivation:
// - KASLR_SUPPORTED:          1 if the architecture has mainline KASLR.
// - PHYS_VIRT_DECOUPLED:      1 if physical and virtual KASLR are independent
//                             (phys_to_virt yields directmap, not text addr).
// - phys_to_virt():           Macro to convert physical to virtual address.
// - virt_to_phys():           Macro to convert directmap virtual to physical
//                             address.
//
// The default values should work on most systems, but may need
// to be tweaked for the target system - especially old kernels,
// embedded devices (ie, armv7), or systems with a non-default
// memory layout.
// ---
// <bcoles@gmail.com>

#ifndef KASLD_H
#define KASLD_H

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

/* -----------------------------------------------------------------------------
 * Sanity check configured values
 * -----------------------------------------------------------------------------
 */
#if KERNEL_VAS_START > KERNEL_VAS_END
#error "Defined KERNEL_VAS_START is larger than KERNEL_VAS_END"
#endif

#if KERNEL_VAS_START > KERNEL_BASE_MIN
#error "Defined KERNEL_VAS_START is larger than KERNEL_BASE_MIN"
#endif

#if KERNEL_BASE_MAX > KERNEL_VAS_END
#error "Defined KERNEL_BASE_MAX is larger than KERNEL_VAS_END"
#endif

#if KERNEL_TEXT_DEFAULT > KERNEL_BASE_MAX
#error "Generated KERNEL_TEXT_DEFAULT is larger than KERNEL_BASE_MAX"
#endif

#if KERNEL_TEXT_DEFAULT < KERNEL_BASE_MIN
#error "Generated KERNEL_TEXT_DEFAULT is smaller than KERNEL_BASE_MIN"
#endif

#ifdef KERNEL_PHYS_MIN
#if KERNEL_PHYS_MIN > KERNEL_PHYS_MAX
#error "Defined KERNEL_PHYS_MIN is larger than KERNEL_PHYS_MAX"
#endif
#endif

/* -----------------------------------------------------------------------------
 * KASLR randomization window (KASLR_BASE_MIN/MAX, KASLR_ALIGN)
 *
 * Two tiers of address ranges are used:
 *
 *   KERNEL_BASE_MIN/MAX  — the **validation range**. Any leaked virtual text
 *                          address in [MIN, MAX] is considered plausible on
 *                          this architecture. Wide enough to cover all vmsplit
 *                          configurations, non-KASLR defaults, and old kernels.
 *                          Used by validate_for_section() to accept or reject
 *                          a result.
 *
 *   KASLR_BASE_MIN/MAX   — the **randomization window**. The narrower range
 *                          that the KASLR mechanism actually selects from at
 *                          boot. Used to compute the number of possible KASLR
 *                          slots and entropy bits.
 *
 *   KASLR_ALIGN           — the KASLR slot granularity.
 *
 * On most architectures the two ranges are identical and KASLR_ALIGN equals
 * KERNEL_ALIGN, so the defaults below simply alias them. Architecture headers
 * override when the ranges differ:
 *
 *   x86_64:  KERNEL_BASE = [0xffffffff80000000, 0xffffffffc0000000]  (1 GiB)
 *            KASLR_BASE  = [KERNEL_BASE_MIN + 16 MiB, ...]
 *            KASLR_ALIGN = KERNEL_ALIGN (2 MiB)
 *
 *   arm64:   KERNEL_BASE = [0xffff800008000000, 0xffffffffff000000]  (~128 TiB)
 *            KASLR_BASE  = [KIMAGE_VADDR + 2^45, + 2^45 + 2^46]     (~64 TiB)
 *            KASLR_ALIGN = 2 MiB (vs KERNEL_ALIGN = 64 KiB)
 * -----------------------------------------------------------------------------
 */
#ifndef KASLR_BASE_MIN
#define KASLR_BASE_MIN KERNEL_BASE_MIN
#endif

#ifndef KASLR_BASE_MAX
#define KASLR_BASE_MAX KERNEL_BASE_MAX
#endif

#ifndef KASLR_ALIGN
#define KASLR_ALIGN KERNEL_ALIGN
#endif

/* Default physical kernel text address (load address without randomization).
 * Architectures that define KERNEL_PHYS_MIN inherit KERNEL_PHYS_MIN +
 * TEXT_OFFSET unless they override KERNEL_PHYS_DEFAULT explicitly. */
#if defined(KERNEL_PHYS_MIN) && !defined(KERNEL_PHYS_DEFAULT)
#define KERNEL_PHYS_DEFAULT (KERNEL_PHYS_MIN + TEXT_OFFSET)
#endif

/* Physical KASLR randomization window. Defaults mirror the full validation
 * range KERNEL_PHYS_MIN..KERNEL_PHYS_MAX. Architectures without physical
 * KASLR (e.g. riscv64) or with a narrower window should override these. */
#if !defined(KASLR_PHYS_MIN) && defined(KERNEL_PHYS_DEFAULT)
#define KASLR_PHYS_MIN KERNEL_PHYS_DEFAULT
#endif

#if !defined(KASLR_PHYS_MAX) && defined(KERNEL_PHYS_MAX)
#define KASLR_PHYS_MAX KERNEL_PHYS_MAX
#endif

#ifndef KASLR_PHYS_ALIGN
#define KASLR_PHYS_ALIGN KERNEL_ALIGN
#endif

/* PAGE_OFFSET_RANDOMIZED: whether KASLR randomizes PAGE_OFFSET.
 * On architectures with hardware-fixed direct-map windows (e.g. LoongArch
 * DMW, MIPS KSEG0/CKSEG0), PAGE_OFFSET is constant regardless of KASLR.
 * Directmap leaks on such architectures cannot reveal the KASLR slide,
 * so the vdmap->vtext derivation must be skipped.
 * Default: 0 (conservative). Override to 1 if PAGE_OFFSET shifts with KASLR. */
#ifndef PAGE_OFFSET_RANDOMIZED
#define PAGE_OFFSET_RANDOMIZED 0
#endif

/* -----------------------------------------------------------------------------
 * Machine-parseable tagged address output
 *
 * Format: "<type> <section> <addr> <region>"          — name unknown / generic
 *      or "<type> <section> <addr> <region>:<name>"   — specific instance known
 *
 *   type:    V = virtual, P = physical, D = default/KASLR-disabled
 *   section: which address space the leak lives in
 *              text, module, directmap, data, dram, mmio, pageoffset, -
 *   addr:    raw leaked address (post-processor handles alignment)
 *   region:  what kind of thing is at the address — see KASLD_REGION_*.
 *              The compact table column.
 *   name:    which specific instance, when known — e.g. a kernel symbol
 *              ("hypercall_page"), an ACPI OEM table ID ("Cpu0Ist"), a
 *              module name ("nf_conntrack"), a PCI BDF ("0000:00:14.0").
 *              Optional. The orchestrator displays it after the region in
 *              the compact column when present.
 *
 * The Region / Name / Section / Origin model:
 *   Region  answers "what kind of thing is at the address?"
 *   Name    answers "which specific instance, when known?"
 *   Section answers "which address space does this address live in?"
 *   Origin  answers "how did we find out?" (component name).
 *
 * Origin is NOT on the wire. The orchestrator already knows which
 * subprocess produced each line and fills `r->origin` from the
 * component's binary name. Components that need their own name for
 * stderr/log messages should use argv[0].
 *
 * Adding a new component should normally require zero new region
 * constants. Subsystem-specific reservations (CBMEM, RMTFS, ION, ...)
 * collapse to a standard kernel concept (RESERVED_MEM, PMEM, ...).
 * Specific identities go in the optional `name` field via
 * kasld_result().
 * -----------------------------------------------------------------------------
 */
#include <stdio.h>

#define KASLD_ADDR_PHYS 'P'
#define KASLD_ADDR_VIRT 'V'
#define KASLD_ADDR_DEFAULT 'D'

/* Section: which address space the leak lives in. */
#define KASLD_SECTION_TEXT "text"
#define KASLD_SECTION_MODULE "module"
#define KASLD_SECTION_DIRECTMAP "directmap"
#define KASLD_SECTION_DATA "data"
#define KASLD_SECTION_DRAM "dram"
#define KASLD_SECTION_MMIO "mmio"
#define KASLD_SECTION_PAGEOFFSET "pageoffset"
#define KASLD_SECTION_NONE "-"

/* -----------------------------------------------------------------------------
 * Region: what kind of kernel memory is at the address.
 *
 * String constants (not an enum) for grep-ability and forward
 * compatibility with out-of-tree components. Components are expected to
 * use one of the constants below; the orchestrator does not enforce.
 *
 * The vocabulary is closed by *kernel concepts*, not by *the existing
 * component set*: each entry is defined whether or not a leak currently
 * exists for it. Adding a new component should normally require zero
 * new constants.
 *
 * The single sanctioned free-form region is `module:<name>` — module
 * identity is part of the answer. No other free-form regions.
 * -----------------------------------------------------------------------------
 */

/* Physical RAM boundaries (single addresses on a region edge). */
#define KASLD_REGION_RAM_BASE "ram_base"   /* bottom of usable RAM */
#define KASLD_REGION_RAM_TOP "ram_top"     /* top of usable RAM */
#define KASLD_REGION_DMA_TOP "dma_top"     /* DMA zone ceiling */
#define KASLD_REGION_DMA32_TOP "dma32_top" /* DMA32 zone ceiling */

/* Physical memory regions (semantic kernel memory areas). */
#define KASLD_REGION_KERNEL_IMAGE                                              \
  "kernel_image"                     /* vmlinux text/rodata/data/init (phys) */
#define KASLD_REGION_INITRD "initrd" /* initramfs / initrd */
#define KASLD_REGION_RESERVED_MEM                                              \
  "reserved_mem" /* firmware/DT-reserved (CMA, CBMEM, RMTFS, ION, ...) */
#define KASLD_REGION_SWIOTLB "swiotlb"       /* software IOTLB bounce buffers */
#define KASLD_REGION_VMCOREINFO "vmcoreinfo" /* vmcoreinfo ELF notes */
#define KASLD_REGION_CRASHKERNEL "crashkernel" /* crashkernel reservation */
#define KASLD_REGION_PMEM "pmem" /* persistent memory (PMEM/CXL/NVDIMM) */
#define KASLD_REGION_ACPI_TABLE                                                \
  "acpi_table" /* ACPI table (static or dynamic) */
#define KASLD_REGION_ACPI_NVS                                                  \
  "acpi_nvs" /* ACPI Non-Volatile Sleeping memory                              \
              */
#define KASLD_REGION_EFI_MEMMAP "efi_memmap" /* EFI memory map descriptors */
#define KASLD_REGION_NUMA_NODE "numa_node"   /* NUMA node descriptor (pgdat) */
#define KASLD_REGION_MMIO "mmio"             /* generic device MMIO */
#define KASLD_REGION_PCI_MMIO "pci_mmio"     /* PCI MMIO BAR */

/* Kernel virtual memory regions. */
#define KASLD_REGION_KERNEL_TEXT "kernel_text" /* kernel .text */
#define KASLD_REGION_KERNEL_DATA "kernel_data" /* .data / .rodata / .bss */
#define KASLD_REGION_MODULE                                                    \
  "module" /* loaded LKM (instance: "module:<name>") */
#define KASLD_REGION_MODULE_REGION                                             \
  "module_region" /* bounds of the modules region */

/* Address-space landmarks (fallback when contents unknown). */
#define KASLD_REGION_DIRECTMAP "directmap" /* arbitrary point in direct-map */
#define KASLD_REGION_PAGE_OFFSET "page_offset" /* start of direct-map */
#define KASLD_REGION_VMALLOC "vmalloc"         /* somewhere in vmalloc */
#define KASLD_REGION_VMEMMAP "vmemmap"         /* somewhere in vmemmap */

/* Sentinel — used by the orchestrator's synthetic "default" / "no-leak"
 * results, never by components. */
#define KASLD_REGION_NONE "-"

/* Emit a tagged result.
 *
 *   region: what kind of thing — KASLD_REGION_* constant.
 *   name:   the specific instance, when known — e.g. kernel symbol
 *           ("hypercall_page"), ACPI table OEM ID ("Cpu0Ist"), module
 *           name ("nf_conntrack"), PCI BDF ("0000:00:14.0").
 *           Pass NULL or "" when no specific instance is known.
 *
 * The compact table shows "<region>" or "<region>:<name>" when a name
 * is given. The JSON output gets separate "region" and "name" keys.
 * The name may itself contain colons — the orchestrator splits on the
 * first `:` only. The orchestrator fills `origin` (the component name)
 * automatically from the subprocess identity. */
static inline void kasld_result(char type, const char *section,
                                unsigned long addr, const char *region,
                                const char *name) {
  if (!region)
    region = "";
  if (name && *name)
    printf("%c %s 0x%016lx %s:%s\n", type, section, addr, region, name);
  else
    printf("%c %s 0x%016lx %s\n", type, section, addr, region);
}

/* When stdout is a pipe (as when the orchestrator captures output), glibc
 * switches to fully-buffered mode.  stderr remains unbuffered.  Since both
 * are merged into the same pipe, stderr lines can arrive before stdout lines
 * that were logically printed first — producing out-of-order output in the
 * verbose JSON log.  Force stdout to line-buffered so output order matches
 * the printf call order in each component. */
__attribute__((constructor)) static void kasld_init_buffering(void) {
  setvbuf(stdout, NULL, _IOLBF, 0);
}

// Suppress GCC compiler warning when compiled with -pedantic:
// warning: ISO C forbids an empty translation unit [-Wpedantic]
typedef int make_iso_compilers_happy;

/* Place a plain-text explanation string in a dedicated ELF section.
 * The orchestrator reads this section from the binary (without executing it)
 * and prints it when --explain is active.  Usage:
 *
 *   KASLD_EXPLAIN("One-paragraph explanation of the technique.");
 */
#define KASLD_EXPLAIN(text)                                                    \
  __attribute__((                                                              \
      used, section(".kasld_explain"))) static const char kasld_explain[] =    \
      text

/* Place machine-readable metadata in a dedicated ELF section.
 * The orchestrator reads this section to determine the component's leak
 * primitive type, address type, and applicable mitigations.  Format is
 * newline-delimited key:value pairs.  Usage:
 *
 *   KASLD_META(
 *       "method:parsed\n"
 *       "addr:physical\n"
 *       "sysctl:dmesg_restrict>=1\n"
 *   )
 */
#define KASLD_META(text)                                                       \
  __attribute__((                                                              \
      used, section(".kasld_meta"))) static const char kasld_meta[] = text

#endif /* KASLD_H */
