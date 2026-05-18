// This file is part of KASLD - https://github.com/bcoles/kasld
//
// region_info[] — per-region wire name, render section, default alignment,
// and VAS-bound resolver. Compiled per-arch (derive_vas entries reference
// arch-conditional helpers).
//
// ---
// <bcoles@gmail.com>

#include "include/kasld/internal.h"

/* =========================================================================
 * derive_vas implementations for layout-derived regions
 *
 * Contract: produce valid (lo <= hi) bounds for ANY layout state,
 * including the initial compile-time-defaults state. Never crash.
 * Conservative bounds are fine when layout fields haven't been set yet.
 * ========================================================================= */

static void derive_vas_page_offset(const struct kasld_layout *ly,
                                   unsigned long *lo, unsigned long *hi) {
  /* PAGE_OFFSET is itself a layout field. Validate page_offset records
   * against the ARCH-default kernel VAS window (compile-time constants),
   * NOT the runtime layout.kernel_vas_start — the latter gets tightened
   * by inference plugins (phys_virt_synth, directmap_page_offset_bounds)
   * which themselves derive their tightenings from page_offset records.
   * Using the runtime layout would create a circular dependency where
   * a page_offset record gets rejected because earlier inference (based
   * on different records) tightened the bound above it.
   *
   * The compile-time KERNEL_VAS_START/END from the arch header is the
   * widest plausible PAGE_OFFSET range; that's the right validation
   * window. */
  (void)ly;
  *lo = (unsigned long)KERNEL_VAS_START;
  *hi = (unsigned long)KERNEL_VAS_END;
}

#if !PHYS_VIRT_DECOUPLED
static void derive_vas_module_region_coupled(const struct kasld_layout *ly,
                                             unsigned long *lo,
                                             unsigned long *hi) {
  *lo = ly->modules_start;
  *hi = ly->modules_end;
}
#endif

/* =========================================================================
 * The table
 * ========================================================================= */

#define WIRE(R) kasld_region_wire_table[R]

const struct region_info region_info[REGION__COUNT] = {
    /* REGION_UNKNOWN — result_in_bounds short-circuits before reading. */
    [REGION_UNKNOWN] =
        {
            .wire_name = "unknown",
            .section_name = "",
            .default_align = 0,
            .static_vas = {0, 0},
            .derive_vas = NULL,
        },

    /* ---- Physical landmarks --------------------------------------- */
    [REGION_RAM] =
        {
            .wire_name = "ram",
            .section_name = "dram",
            .default_align = 0,
            .static_vas = {0, ULONG_MAX},
            .derive_vas = NULL,
        },
    [REGION_DMA] =
        {
            .wire_name = "dma",
            .section_name = "dram",
            .default_align = 0,
            .static_vas = {0, ULONG_MAX},
            .derive_vas = NULL,
        },
    [REGION_DMA32] =
        {
            .wire_name = "dma32",
            .section_name = "dram",
            .default_align = 0,
            .static_vas = {0, ULONG_MAX},
            .derive_vas = NULL,
        },
    [REGION_INITRD] =
        {
            .wire_name = "initrd",
            .section_name = "dram",
            .default_align = 0,
            .static_vas = {0, ULONG_MAX},
            .derive_vas = NULL,
        },
    [REGION_RESERVED_MEM] =
        {
            .wire_name = "reserved_mem",
            .section_name = "dram",
            .default_align = 0,
            .static_vas = {0, ULONG_MAX},
            .derive_vas = NULL,
        },
    [REGION_SWIOTLB] =
        {
            .wire_name = "swiotlb",
            .section_name = "dram",
            .default_align = 0,
            .static_vas = {0, ULONG_MAX},
            .derive_vas = NULL,
        },
    [REGION_VMCOREINFO] =
        {
            .wire_name = "vmcoreinfo",
            .section_name = "dram",
            .default_align = 0,
            .static_vas = {0, ULONG_MAX},
            .derive_vas = NULL,
        },
    [REGION_CRASHKERNEL] =
        {
            .wire_name = "crashkernel",
            .section_name = "dram",
            .default_align = 0,
            .static_vas = {0, ULONG_MAX},
            .derive_vas = NULL,
        },
    [REGION_PMEM] =
        {
            .wire_name = "pmem",
            .section_name = "dram",
            .default_align = 0,
            .static_vas = {0, ULONG_MAX},
            .derive_vas = NULL,
        },
    [REGION_ACPI_TABLE] =
        {
            .wire_name = "acpi_table",
            .section_name = "dram",
            .default_align = 0,
            .static_vas = {0, ULONG_MAX},
            .derive_vas = NULL,
        },
    [REGION_ACPI_NVS] =
        {
            .wire_name = "acpi_nvs",
            .section_name = "dram",
            .default_align = 0,
            .static_vas = {0, ULONG_MAX},
            .derive_vas = NULL,
        },
    [REGION_EFI_MEMMAP] =
        {
            .wire_name = "efi_memmap",
            .section_name = "dram",
            .default_align = 0,
            .static_vas = {0, ULONG_MAX},
            .derive_vas = NULL,
        },
    [REGION_NUMA_NODE] =
        {
            .wire_name = "numa_node",
            .section_name = "dram",
            .default_align = 0,
            .static_vas = {0, ULONG_MAX},
            .derive_vas = NULL,
        },
    [REGION_MMIO] =
        {
            .wire_name = "mmio",
            .section_name = "mmio",
            .default_align = 0,
            .static_vas = {0, ULONG_MAX},
            .derive_vas = NULL,
        },
    [REGION_PCI_MMIO] =
        {
            .wire_name = "pci_mmio",
            .section_name = "mmio",
            .default_align = 0,
            .static_vas = {0, ULONG_MAX},
            .derive_vas = NULL,
        },

    /* ---- Kernel image --------------------------------------------- */
    /* Kernel image regions (TEXT/DATA/BSS/IMAGE) legitimately exist in BOTH
     * virtual space (kernel VAS) and physical space (kernel load address).
     * The static_vas must accept either — narrowing to the virtual VAS would
     * reject every PHYS leak of the kernel image. Per-type validation can be
     * added later if needed; for now open VAS keeps both kinds of leaks
     * visible. */
    [REGION_KERNEL_TEXT] =
        {
            .wire_name = "kernel_text",
            .section_name = "text",
            .default_align = 0,
            .static_vas = {0, ULONG_MAX},
            .derive_vas = NULL,
        },
    [REGION_KERNEL_DATA] =
        {
            .wire_name = "kernel_data",
            .section_name = "data",
            .default_align = 0,
            .static_vas = {0, ULONG_MAX},
            .derive_vas = NULL,
        },
    [REGION_KERNEL_BSS] =
        {
            .wire_name = "kernel_bss",
            .section_name = "bss",
            .default_align = 0,
            .static_vas = {0, ULONG_MAX},
            .derive_vas = NULL,
        },
    /* REGION_KERNEL_IMAGE: vmlinux as a whole. Phys context: full phys
     * range. Virt context: validate against kernel image VAS. The wire
     * type disambiguates — both phys and virt contexts share this entry
     * by accepting the union (full phys range OR full kernel image
     * range). result_in_bounds() can't see type-vs-VAS distinction
     * cleanly here; we keep static_vas wide and rely on the parser's
     * per-type sanity. */
    [REGION_KERNEL_IMAGE] =
        {
            .wire_name = "kernel_image",
            .section_name = "text",
            .default_align = 0,
            .static_vas = {0, ULONG_MAX},
            .derive_vas = NULL,
        },
    [REGION_MODULE] =
        {
            .wire_name = "module",
            .section_name = "module",
            .default_align = 0,
#if !PHYS_VIRT_DECOUPLED
            .static_vas = {0, 0},
            .derive_vas = derive_vas_module_region_coupled,
#else
            .static_vas = {MODULES_START, MODULES_END},
            .derive_vas = NULL,
#endif
        },
    [REGION_MODULE_REGION] =
        {
            .wire_name = "module_region",
            .section_name = "module",
            .default_align = 0,
#if !PHYS_VIRT_DECOUPLED
            .static_vas = {0, 0},
            .derive_vas = derive_vas_module_region_coupled,
#else
            .static_vas = {MODULES_START, MODULES_END},
            .derive_vas = NULL,
#endif
        },

    /* ---- Direct-map / virtual landmarks ---------------------------- */
    [REGION_DIRECTMAP] =
        {
            .wire_name = "directmap",
            .section_name = "directmap",
            .default_align = 0,
            .static_vas = {KERNEL_VAS_START, KERNEL_VAS_END},
            .derive_vas = NULL,
        },
    [REGION_PAGE_OFFSET] =
        {
            .wire_name = "page_offset",
            .section_name = "pageoffset",
            .default_align = 0,
            .static_vas = {0, 0},
            .derive_vas = derive_vas_page_offset,
        },
    [REGION_VMALLOC] =
        {
            .wire_name = "vmalloc",
            .section_name = "directmap",
            .default_align = 0,
            .static_vas = {KERNEL_VAS_START, KERNEL_VAS_END},
            .derive_vas = NULL,
        },
    [REGION_VMEMMAP] =
        {
            .wire_name = "vmemmap",
            .section_name = "directmap",
            .default_align = 0,
            .static_vas = {KERNEL_VAS_START, KERNEL_VAS_END},
            .derive_vas = NULL,
        },
};
