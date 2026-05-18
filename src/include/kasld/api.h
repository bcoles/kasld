// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Expected kernel address space values for supported architectures, plus the
// shared component API: result emission helpers, region enum, KASLD_EXPLAIN,
// KASLD_META.
//
// Each architecture header (arch/*.h) defines the constants documented at the
// top of arch/x86_64.h.
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

/* KASLR randomization window defaults (override per-arch when narrower) */
#ifndef KASLR_BASE_MIN
#define KASLR_BASE_MIN KERNEL_BASE_MIN
#endif
#ifndef KASLR_BASE_MAX
#define KASLR_BASE_MAX KERNEL_BASE_MAX
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

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Generic [lo, hi] half-open or inclusive range; semantics decided by the
 * caller. Used by component-side region accumulators (dmesg_* parsers,
 * sysfs walkers) that aggregate per-line spans before emitting a result. */
struct addr_range {
  unsigned long lo;
  unsigned long hi;
};

/* =========================================================================
 * Result model: (extent, position, confidence) over a typed region
 * =========================================================================
 *
 * Tagged wire format:
 *   <type> <region>[:<name>] pos=<pos> conf=<conf> \
 *       [lo=<hex>] [hi=<hex>|sz=<hex>] [sample=<hex>] [base_align=<hex>]
 *
 *   type:    P (physical), V (virtual), D (default / KASLR-disabled)
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
  KASLD_TYPE_DEFAULT_VIRT,
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

/* Region: closed vocabulary of kernel memory areas.
 * REGION_UNKNOWN = 0 is the memset-default; result_in_bounds() returns
 * false for it (forgotten-region assignment → silently skipped, not UB). */
enum kasld_region {
  REGION_UNKNOWN = 0,

  /* Physical landmarks. */
  REGION_RAM,
  REGION_DMA,
  REGION_DMA32,
  REGION_INITRD,
  REGION_RESERVED_MEM,
  REGION_SWIOTLB,
  REGION_VMCOREINFO,
  REGION_CRASHKERNEL,
  REGION_PMEM,
  REGION_ACPI_TABLE,
  REGION_ACPI_NVS,
  REGION_EFI_MEMMAP,
  REGION_NUMA_NODE,
  REGION_MMIO,
  REGION_PCI_MMIO,

  /* Kernel image — text, data, bss, image-as-a-whole, modules. */
  REGION_KERNEL_TEXT,
  REGION_KERNEL_DATA,
  REGION_KERNEL_BSS,
  REGION_KERNEL_IMAGE,
  REGION_MODULE,
  REGION_MODULE_REGION,

  /* Direct-map / virtual landmarks. */
  REGION_DIRECTMAP,
  REGION_PAGE_OFFSET,
  REGION_VMALLOC,
  REGION_VMEMMAP,

  /* Sentinel. Must be last so we can iterate 0..REGION__COUNT-1. */
  REGION__COUNT,
};

/* Wire-token mappings. The region table here is the source of truth
 * for region wire names; region_info[] in region_info.c references the
 * same strings.
 *
 * Convention: lowercase snake_case of the enum suffix
 * (REGION_KERNEL_IMAGE -> "kernel_image"). */
static const char *const kasld_region_wire_table[REGION__COUNT] = {
    [REGION_UNKNOWN] = "unknown",
    [REGION_RAM] = "ram",
    [REGION_DMA] = "dma",
    [REGION_DMA32] = "dma32",
    [REGION_INITRD] = "initrd",
    [REGION_RESERVED_MEM] = "reserved_mem",
    [REGION_SWIOTLB] = "swiotlb",
    [REGION_VMCOREINFO] = "vmcoreinfo",
    [REGION_CRASHKERNEL] = "crashkernel",
    [REGION_PMEM] = "pmem",
    [REGION_ACPI_TABLE] = "acpi_table",
    [REGION_ACPI_NVS] = "acpi_nvs",
    [REGION_EFI_MEMMAP] = "efi_memmap",
    [REGION_NUMA_NODE] = "numa_node",
    [REGION_MMIO] = "mmio",
    [REGION_PCI_MMIO] = "pci_mmio",
    [REGION_KERNEL_TEXT] = "kernel_text",
    [REGION_KERNEL_DATA] = "kernel_data",
    [REGION_KERNEL_BSS] = "kernel_bss",
    [REGION_KERNEL_IMAGE] = "kernel_image",
    [REGION_MODULE] = "module",
    [REGION_MODULE_REGION] = "module_region",
    [REGION_DIRECTMAP] = "directmap",
    [REGION_PAGE_OFFSET] = "page_offset",
    [REGION_VMALLOC] = "vmalloc",
    [REGION_VMEMMAP] = "vmemmap",
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
  case KASLD_TYPE_DEFAULT_VIRT:
    return 'D';
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
 *            (`exact` is no longer used — per-result confidence replaces it.)
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
