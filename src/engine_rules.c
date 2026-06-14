// This file is part of KASLD - https://github.com/bcoles/kasld
//
// The engine rule registry (see engine_rules.h). Single source of truth for
// the constraint-rule and verdict-rule lists the engine consumes.
//
// Rules are grouped by family. Order within the registry is irrelevant (the
// engine fixpoint re-runs all rules to convergence); the grouping exists
// purely to make adding a new rule and spot-auditing the set easier.
//
// To register a new rule:
//   1. Add the prototype to its family's section in
//   include/kasld/engine_rules.h.
//   2. Add the function pointer to k_rules[] (or k_vrules[]) below, under the
//      same family.
// ---
// <bcoles@gmail.com>

/* Rule prototypes (R(...) / V(...) declarations) and the rule_fn /
 * verdict_fn typedefs live in this header — the single source of truth shared
 * with each rule .c file. */
#include "include/kasld/engine_rules.h"

/* ── Constraint rule registry ───────────────────────────────────────────── */

static const rule_fn k_rules[] = {
    /* Image-size ceilings */
    rule_ceiling_from_image_size,
    rule_phys_ceiling_from_memtotal,
    rule_virt_ceiling_from_memtotal,
    rule_phys_bits_ceiling,
    rule_image_size_text_data_gap,
    rule_min_offset_from_image_size,
    rule_vmsplit_text_base,
    rule_range_from_interior,

    /* DRAM bounds */
    rule_dram_floor_bound,
    rule_dram_ceiling,
    rule_mmio_floor_phys_ceiling,
    rule_phys_hole_filter,
    rule_kernel_image_phys_bound,
    rule_highmem_32bit_bound,

    /* virt_page_offset rules */
    rule_page_offset_from_landmark,
    rule_page_offset_invariant_pin,
    rule_page_offset_from_config,
    rule_directmap_page_offset_bounds,
    rule_randomize_memory_page_offset,

    /* Cmdline rules */
    rule_initrd_phys_exclude,
    rule_phys_reservation_exclude,
    rule_ram_map_phys_exclude,
    rule_initrd_above_kernel,
    rule_cmdline_phys_exclude,
    rule_cmdline_mem_phys_ceiling,
    rule_cmdline_mem_virt_ceiling,
    rule_cmdline_memmap_phys_exclude,
    rule_cmdline_memmap_too_large_phys_pin,
    rule_x86_64_efi_phys_seed_zero,

    /* KASLR alignment */
    rule_kaslr_align_arch_default,
    rule_boot_params_kaslr_align,
    rule_arm64_efi_kimg_align,
    rule_config_max_offset_ceiling,
    rule_base_align_cross_validate,

    /* KASLR-off pin */
    rule_virt_kaslr_disabled_pin,
    rule_directmap_kaslr_disabled_pin,
    rule_phys_kaslr_disabled_pin,
    rule_physical_start_lower_bound,

    /* Module-relative text bounds */
    rule_module_text_bound,

    /* Multi-entry EFI_LOADER_CODE → Q_PHYS_IMAGE_BASE pin */
    rule_efi_loader_kernel_pick,

    /* Text-base pin from POS_BASE kernel-image observation */
    rule_text_pin_from_observation,

    /* Symmetric phys↔virt text-base coupling synthesizer */
    rule_text_base_coupling_synth,

    /* phys_virt_synth */
    rule_phys_virt_synth,

    /* arm64-specific */
    rule_arm64_memstart_align,
    rule_arm64_va_bits_from_directmap,
    rule_arm64_va_bits_from_vmemmap,

    /* riscv64-specific */
    rule_riscv64_non_efi_phys_base,
    rule_riscv64_fdt_kaslr_seed,
    rule_riscv64_page_offset_from_vmalloc_vmemmap,
    rule_riscv64_va_bits_pin,

    /* s390-specific */
    rule_s390_paging_level,
    rule_s390_text_from_belows,
    rule_s390_text_segment_mod,
    rule_s390_text_no_random,

    /* ppc-specific */
    rule_ppc32_phys_ceiling,
    rule_ppc64_firmware_ceiling,

    /* x86_32-specific */
    rule_x86_32_vmsplit_ceiling,

    /* x86_64-specific */
    rule_x86_64_vmalloc_base_bound,
    rule_x86_64_vmemmap_base_bound,
    rule_x86_64_la57_from_directmap,
    rule_x86_64_page_offset_from_vmalloc_vmemmap,
};

/* ── Verdict rule registry ──────────────────────────────────────────────── */

static const verdict_fn k_vrules[] = {
    rule_coupling_validate,
    rule_text_cluster_filter,
    rule_firmware_memmap_holes,
    rule_x86_64_vmalloc_vmemmap_invariant,
    rule_arm64_coupling_validate,
    rule_riscv64_coupling_validate,
    rule_loongarch64_coupling_validate,
};

const rule_fn *engine_rules(int *n) {
  *n = (int)(sizeof(k_rules) / sizeof(k_rules[0]));
  return k_rules;
}

const verdict_fn *engine_verdict_rules(int *n) {
  *n = (int)(sizeof(k_vrules) / sizeof(k_vrules[0]));
  return k_vrules;
}
