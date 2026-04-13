// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Expected kernel address space values for supported architectures.
//
// - KERNEL_VAS_START:    Expected virtual address for start of the kernel
//                        virtual address space (VAS).
//                        (eg. 0xc0000000 for 32-bit systems with 3GB vmsplit)
//
// - KERNEL_VAS_END:      Expected end of kernel virtual address space.
//                        (including modules, I/O, guard regions, ...)
//
// - KERNEL_BASE_MIN:     Expected minimum possible kernel base virtual address.
//
// - KERNEL_BASE_MAX:     Expected maximum possible kernel base virtual address.
//
// - MODULES_START:       Expected start virtual address for kernel modules.
//
// - MODULES_END:         Expected end virtual address for kernel modules.
//
// - KERNEL_ALIGN:        Expected kernel address alignment.
//                        (usually 2MiB on modern systems)
//
// - KERNEL_TEXT_DEFAULT: Default kernel base virtual address when KASLR is
//                        disabled (including text offset). This value is
//                        calculated automatically based on above values.
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
 *   arm64:   KERNEL_BASE = [KIMAGE_VADDR, KIMAGE_VADDR + 128 TiB]   (full VA)
 *            KASLR_BASE  = [KIMAGE_VADDR + 2^45, + 2^46]            (narrower)
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
 * Format: "<type> <section> <addr> <label>"
 *   type:    V = virtual, P = physical, D = default/KASLR-disabled
 *   section: text, module, directmap, data, dram, or - (default)
 *   addr:    raw leaked address (post-processor handles alignment)
 *   label:   human-readable source identifier
 * -----------------------------------------------------------------------------
 */
#include <stdio.h>

#define KASLD_ADDR_PHYS 'P'
#define KASLD_ADDR_VIRT 'V'
#define KASLD_ADDR_DEFAULT 'D'

#define KASLD_SECTION_TEXT "text"
#define KASLD_SECTION_MODULE "module"
#define KASLD_SECTION_DIRECTMAP "directmap"
#define KASLD_SECTION_DATA "data"
#define KASLD_SECTION_DRAM "dram"
#define KASLD_SECTION_MMIO "mmio"
#define KASLD_SECTION_PAGEOFFSET "pageoffset"
#define KASLD_SECTION_NONE "-"

static inline void kasld_result(char type, const char *section,
                                unsigned long addr, const char *label) {
  printf("%c %s 0x%016lx %s\n", type, section, addr, label);
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

#endif /* KASLD_H */
