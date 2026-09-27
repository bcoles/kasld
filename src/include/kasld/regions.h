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

/* Part of the kernel image: text, data, bss, or the image as a whole.
 *
 * REGION_KERNEL_TEXT_BAND is deliberately ABSENT. It names an address that fell
 * inside the admissible text window without any evidence it is in the image, so
 * admitting it here would let every image-base rule bound the guaranteed window
 * from a range guess — the failure this split exists to prevent. A rule that
 * wants band samples names the region itself and caps what it derives; see
 * range_from_interior, currently the only one. */
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
  case REGION_DRAM_CARVEOUT:
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

/* RAM *coverage* regions: contiguous spans of usable System RAM, whose ABSENCE
 * therefore establishes a non-RAM gap. Deliberately narrower than
 * is_phys_dram_region(): that predicate answers "is this address inside DRAM?"
 * and so also admits interior reservations (initrd, crashkernel, reserved-mem,
 * ACPI, ...) and the kernel image — ranges that sit WITHIN RAM but do not
 * define its boundaries. A hole test must use coverage regions only: an
 * interior reservation is not a RAM boundary, so the gaps between reservations
 * are real RAM, and treating them as non-RAM would wrongly cap a bound below a
 * true base sitting there. PMEM and the kernel-image regions are excluded for
 * the same reason (not usable-DRAM coverage / interior). */
static inline int is_phys_ram_coverage_region(enum kasld_region r) {
  switch (r) {
  case REGION_RAM:
  case REGION_DMA:
  case REGION_DMA32:
  case REGION_NUMA_NODE:
    return 1;
  default:
    return 0;
  }
}

/* Memory-mapped I/O windows (definitely NOT where kernel text loads). */
static inline int is_mmio_region(enum kasld_region r) {
  return r == REGION_MMIO || r == REGION_PCI_MMIO;
}

/* Why the kernel image provably cannot occupy a physical region.
 *
 * One axis rather than a set of booleans, because the two reasons below are
 * alternatives and they are NOT interchangeable downstream: they make opposite
 * predictions about whether the region's address is System RAM. A rule that
 * treated the pair as one flag would either never be able to check a
 * never-RAM claim against a RAM map, or would check a reserved-from-RAM claim
 * against it and invalidate every correct observation. A region added later
 * has to name its reason, and a typo in the value does not compile.
 *
 * Both reasons are verified against the kernel source and both license the
 * same C_EXCLUDE: a leaked extent forbids the physical base from the band
 * whose image would overlap it. */
enum kasld_forbidden_reason {
  /* Not forbidden — the image can be here. */
  FORBIDDEN_NO = 0,
  /* Never System RAM: MMIO/PCI windows, persistent memory, ACPI tables/NVS
   * are not E820_TYPE_RAM, and the compressed-boot KASLR places the image
   * ONLY in RAM (arch/x86/boot/compressed/kaslr.c process_e820_entries:
   * `if (entry->type != E820_TYPE_RAM) continue`), fitting it wholly in one
   * region (`if (region.size < image_size) ...`).
   *
   * Because the claim IS "this address is not System RAM", a RAM map that
   * says otherwise contradicts the observation outright — see
   * ram_map_nonram_conflict. */
  FORBIDDEN_NEVER_RAM,
  /* Reserved from FREE RAM after the image is already placed: crashkernel,
   * SWIOTLB, and the memblock reserved-memory pools come from
   * memblock_phys_alloc_range over free memblock (the image's pages are
   * already reserved), so they cannot overlap it.
   *
   * "Allocated over free memblock" is the whole of the argument, and it is a
   * property of HOW the region came to be, not of when or of who reported it.
   * Two things fail it. A reservation at a FIXED address -- a device-tree
   * /reserved-memory node carrying a `reg`, a firmware carve-out, an IOMMU
   * window -- was not allocated at all: something names an address,
   * memblock_reserve() merges it silently if it overlaps the image, and
   * nothing reports the collision. And an allocation made LATE, after
   * free_initmem() has returned the image's __init pages to the page
   * allocator, can land inside the image's original footprint, which is the
   * span the exclusion subtracts. Neither belongs here; both are
   * REGION_DRAM_CARVEOUT.
   *
   * What survives the test does so because the allocator itself refuses an
   * overlap: crashkernel reaches memblock_phys_alloc_range() even for
   * crashkernel=size@offset, SWIOTLB is a plain memblock allocation, and CMA's
   * cma_fixed_reserve() returns -EBUSY on memblock_is_region_reserved(). The
   * question to ask of a new producer is which of those two it is, and the
   * reporting channel does not answer it -- one dmesg line can carry both.
   *
   * These addresses are EXPECTED to be inside System RAM. A RAM-membership
   * test says nothing about them and must not be applied. */
  FORBIDDEN_RESERVED_FROM_RAM,
};

/* The reason a leaked extent of this region forbids the physical base.
 *
 * Deliberately FORBIDDEN_NO: RAM / DMA / DMA32 / NUMA (the image CAN live
 * there); the kernel-image / EFI-loader-image regions (that IS the image);
 * VMCOREINFO (kernel data, may overlap the image); INITRD / CMDLINE /
 * *_MEMMAP (each carved by its own dedicated exclude rule); and
 * DRAM_CARVEOUT -- DRAM set aside at an address the blob or a driver chose,
 * where nothing establishes the image avoided it. The last is a landmark
 * saying "DRAM reaches here" and nothing more; reading it as a reservation
 * the image cannot occupy is what carves the true base out of the window. */
static inline enum kasld_forbidden_reason
phys_kernel_forbidden_reason(enum kasld_region r) {
  switch (r) {
  case REGION_MMIO:
  case REGION_PCI_MMIO:
  case REGION_PMEM:
  case REGION_ACPI_TABLE:
  case REGION_ACPI_NVS:
    return FORBIDDEN_NEVER_RAM;
  case REGION_RESERVED_MEM:
  case REGION_CRASHKERNEL:
  case REGION_SWIOTLB:
    return FORBIDDEN_RESERVED_FROM_RAM;
  default:
    return FORBIDDEN_NO;
  }
}

/* Physical regions the kernel image provably cannot occupy, for either
 * reason, so a leaked extent forbids the base from the overlapping band
 * (sound to C_EXCLUDE). Derived from the axis above — the reason is what a
 * caller that needs to distinguish the two asks for. */
static inline int is_phys_kernel_forbidden_region(enum kasld_region r) {
  return phys_kernel_forbidden_reason(r) != FORBIDDEN_NO;
}

/* Physical regions that locate the kernel image (a leaked address here pins
 * the kernel's physical base, modulo the section's offset). */
static inline int is_kernel_locating_region(enum kasld_region r) {
  return r == REGION_KERNEL_IMAGE || r == REGION_KERNEL_TEXT ||
         r == REGION_KERNEL_DATA || r == REGION_KERNEL_BSS;
}

/* Regions whose address describes the MACHINE rather than where the kernel was
 * put: the board's memory map and its firmware tables, all fixed before a
 * kernel is loaded and identical across boots of the same hardware.
 *
 * It separates evidence that narrows where the kernel COULD have been placed
 * from evidence of where it actually IS -- the distinction the leak-free
 * resolution rests on, since a window narrowed by a leak is no longer the set
 * the leak reduced.
 *
 * A whitelist, not an exclusion list: a region added later is machine-
 * describing only once someone says so here. The failure direction of an
 * omission is a wider window, which understates a reduction; the failure
 * direction of a wrong inclusion is a window narrowed by the very leak it is
 * meant to be measured against, which overstates one.
 *
 * Deliberately NOT here, though each is physical and none is a kernel section:
 * INITRD, CMDLINE, VMCOREINFO, CRASHKERNEL, RESERVED_MEM, SWIOTLB and
 * EFI_LOADER_IMAGE. Every one is placed during boot by the loader or the
 * kernel, so its address moves with the kernel's -- initrd_above_kernel derives
 * a kernel bound from the first of them precisely because it does. MMIO, PCI,
 * PMEM and the ACPI regions stay in: they are hardware, and the holes they
 * carve are slots the kernel never had. */
static inline int is_machine_describing_region(enum kasld_region r) {
  switch (r) {
  case REGION_RAM:
  case REGION_DMA:
  case REGION_DMA32:
  case REGION_NUMA_NODE:
  case REGION_MMIO:
  case REGION_PCI_MMIO:
  case REGION_PMEM:
  case REGION_ACPI_TABLE:
  case REGION_ACPI_NVS:
  case REGION_EFI_MEMMAP:
  case REGION_CMDLINE_MEMMAP:
    return 1;
  default:
    return 0;
  }
}

#endif /* KASLD_REGION_PREDICATES */
#endif /* KASLD_REGIONS_H */
