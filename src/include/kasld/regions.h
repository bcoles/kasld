// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Region-class predicates shared by the rules. Depends only on the region enum
// in api.h. #ifndef-guarded against redefinition by internal.h.
// ---
// <bcoles@gmail.com>

#ifndef KASLD_REGIONS_H
#define KASLD_REGIONS_H

#include "api.h"

#ifndef KASLD_REGION_PREDICATES
#define KASLD_REGION_PREDICATES 1

/* Part of the kernel image: text, data, bss, or the image as a whole. */
static inline int is_kernel_image_region(enum kasld_region r) {
  switch (r) {
  case REGION_KERNEL_TEXT:
  case REGION_KERNEL_DATA:
  case REGION_KERNEL_BSS:
  case REGION_KERNEL_IMAGE:
    return 1;
  default:
    return 0;
  }
}

/* Physical addresses that live in DRAM (not MMIO or virtual-only spaces).
 * Includes kernel-image regions (the kernel loads into physical RAM).
 *
 * Descriptor-style regions whose tagged address is structurally NOT bound
 * to DRAM are deliberately excluded even though they share the "dram"
 * display section in the X-macro:
 *   - REGION_EFI_MEMMAP    — a UEFI memory-map descriptor entry can
 *                            classify any address (MMIO, reserved, ACPI,
 *                            conventional RAM, ...).
 *   - REGION_CMDLINE_MEMMAP — `memmap=N$X` on the cmdline can mark any
 *                            physical range as reserved, including MMIO. */
static inline int is_phys_dram_region(enum kasld_region r) {
  switch (r) {
  case REGION_RAM:
  case REGION_DMA:
  case REGION_DMA32:
  case REGION_INITRD:
  case REGION_CMDLINE:
  case REGION_RESERVED_MEM:
  case REGION_SWIOTLB:
  case REGION_VMCOREINFO:
  case REGION_CRASHKERNEL:
  case REGION_PMEM:
  case REGION_ACPI_TABLE:
  case REGION_ACPI_NVS:
  case REGION_EFI_LOADER_IMAGE: /* the kernel image at EFI boot */
  case REGION_NUMA_NODE:
  case REGION_KERNEL_TEXT:
  case REGION_KERNEL_DATA:
  case REGION_KERNEL_BSS:
  case REGION_KERNEL_IMAGE:
    return 1;
  default:
    return 0;
  }
}

/* Memory-mapped I/O windows (definitely NOT where kernel text loads). */
static inline int is_mmio_region(enum kasld_region r) {
  return r == REGION_MMIO || r == REGION_PCI_MMIO;
}

/* Physical regions the kernel image provably cannot occupy, so a leaked extent
 * of one forbids the physical base from the band whose image would overlap it
 * (sound to C_EXCLUDE). Two disjointness sources, both checked against the
 * kernel source:
 *   - never System RAM: MMIO/PCI windows, persistent memory, ACPI tables/NVS
 *     are not E820_TYPE_RAM, and the compressed-boot KASLR places the image
 *     ONLY in RAM (arch/x86/boot/compressed/kaslr.c process_e820_entries:
 *     `if (entry->type != E820_TYPE_RAM) continue`), fitting it wholly in one
 *     region (`if (region.size < image_size) ...`);
 *   - reserved from FREE RAM after the image is already placed: crashkernel,
 *     SWIOTLB, and reserved-memory pools come from memblock_phys_alloc_range
 *     over free memblock (the image's pages are already reserved), so they
 *     cannot overlap it.
 * Deliberately NOT here: RAM / DMA / DMA32 / NUMA (the image CAN live there);
 * the kernel-image / EFI-loader-image regions (that IS the image); VMCOREINFO
 * (kernel data, may overlap the image); and INITRD / CMDLINE / *_MEMMAP (each
 * carved by its own dedicated exclude rule). */
static inline int is_phys_kernel_forbidden_region(enum kasld_region r) {
  switch (r) {
  case REGION_MMIO:
  case REGION_PCI_MMIO:
  case REGION_RESERVED_MEM:
  case REGION_CRASHKERNEL:
  case REGION_SWIOTLB:
  case REGION_PMEM:
  case REGION_ACPI_TABLE:
  case REGION_ACPI_NVS:
    return 1;
  default:
    return 0;
  }
}

/* Physical regions that locate the kernel image (a leaked address here pins
 * the kernel's physical base, modulo the section's offset). */
static inline int is_kernel_locating_region(enum kasld_region r) {
  return r == REGION_KERNEL_IMAGE || r == REGION_KERNEL_TEXT ||
         r == REGION_KERNEL_DATA || r == REGION_KERNEL_BSS;
}

#endif /* KASLD_REGION_PREDICATES */
#endif /* KASLD_REGIONS_H */
