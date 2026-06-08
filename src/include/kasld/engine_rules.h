// This file is part of KASLD - https://github.com/bcoles/kasld
//
// The engine's complete rule registry — the single source of truth for which
// constraint rules and curation (verdict) rules run, shared by the orchestrator
// (engine_resolve) and the integration tests so the two cannot drift.
//
// Each rule's prototype is also declared here so the rule .c file can include
// this header at its definition site and satisfy -Wmissing-prototypes; the
// registry in engine_rules.c then references the same names. Adding a new
// rule means: prototype here + entry in engine_rules.c's k_rules / k_vrules.
// ---
// <bcoles@gmail.com>

#ifndef KASLD_ENGINE_RULES_H
#define KASLD_ENGINE_RULES_H

#include "engine.h"

/* Constraint rules, in registry order. *n is set to the count. */
const rule_fn *engine_rules(int *n);

/* Curation (verdict) rules, in registry order. *n is set to the count. */
const verdict_fn *engine_verdict_rules(int *n);

/* ─────────────────────────────────────────────────────────────────────────
 * Rule prototypes — grouped by family to mirror the registry layout in
 * engine_rules.c. The R(...) / V(...) macros expand to the long
 * rule_fn / verdict_fn signatures from engine.h.
 * ─────────────────────────────────────────────────────────────────────── */

#define R(name)                                                                \
  int rule_##name(const struct evidence_set *, const struct estimate *,        \
                  struct constraint *, int)
#define V(name)                                                                \
  int rule_##name(const struct evidence_set *, struct verdict *, int)

/* Image-size ceilings (CONFIG_KERNEL_IMAGE_SIZE / SF_IMAGE_SIZE etc.) */
R(ceiling_from_image_size);
R(phys_ceiling_from_memtotal);
R(virt_ceiling_from_memtotal);
R(phys_bits_ceiling);
R(image_size_text_data_gap);
R(min_offset_from_image_size);
R(range_from_interior);

/* DRAM bounds (MMIO ceilings, holes, kernel-image phys gap, firmware) */
R(dram_floor_bound);
R(dram_ceiling);
R(mmio_floor_phys_ceiling);
R(phys_hole_filter);
R(kernel_image_phys_bound);
R(highmem_32bit_bound);

/* virt_page_offset rules */
R(page_offset_from_landmark);
R(page_offset_invariant_pin);
R(page_offset_from_config);
R(directmap_page_offset_bounds);
R(randomize_memory_page_offset);

/* Cmdline rules (mem= / memmap= / initrd / efi-seed) */
R(initrd_phys_exclude);
R(phys_reservation_exclude);
R(firmware_memmap_phys_exclude);
R(initrd_above_kernel);
R(cmdline_phys_exclude);
R(cmdline_mem_phys_ceiling);
R(cmdline_mem_virt_ceiling);
R(cmdline_memmap_phys_exclude);
R(cmdline_memmap_too_large_phys_pin);
R(x86_64_efi_phys_seed_zero);

/* KASLR alignment */
R(kaslr_align_arch_default);
R(boot_params_kaslr_align);
R(arm64_efi_kimg_align);
R(config_max_offset_ceiling);
R(base_align_cross_validate);

/* KASLR-off pin + learned floor */
R(virt_kaslr_disabled_pin);
R(phys_kaslr_disabled_pin);
R(physical_start_lower_bound);

/* Module-relative text bounds */
R(module_text_bound);

/* Multi-entry EFI_LOADER_CODE → Q_PHYS_TEXT_BASE pin (arm64/riscv64/x86_64) */
R(efi_loader_kernel_pick);

/* Text-base pin from POS_BASE kernel-image observation */
R(text_pin_from_observation);

/* Symmetric phys↔virt text-base coupling synthesizer */
R(text_base_coupling_synth);

/* phys_virt_synth */
R(phys_virt_synth);

/* arm64-specific rules */
R(arm64_memstart_align);
R(arm64_va_bits_from_directmap);
R(arm64_va_bits_from_vmemmap);

/* riscv64-specific rules */
R(riscv64_non_efi_phys_base);
R(riscv64_fdt_kaslr_seed);
R(riscv64_page_offset_from_vmalloc_vmemmap);
R(riscv64_va_bits_pin);

/* s390-specific rules */
R(s390_paging_level);
R(s390_text_from_vmalloc);
R(s390_text_from_vmemmap);
R(s390_text_segment_mod);
R(s390_text_no_random);

/* ppc-specific rules */
R(ppc32_phys_ceiling);
R(ppc64_firmware_ceiling);

/* x86_32-specific rules */
R(x86_32_vmsplit_ceiling);

/* x86_64-specific rules */
R(x86_64_vmalloc_base_bound);
R(x86_64_vmemmap_base_bound);
R(x86_64_la57_from_directmap);
R(x86_64_page_offset_from_vmalloc_vmemmap);

/* Verdict rules */
V(coupling_validate);
V(text_cluster_filter);
V(firmware_memmap_holes);
V(x86_64_vmalloc_vmemmap_invariant);
V(arm64_coupling_validate);
V(riscv64_coupling_validate);
V(loongarch64_coupling_validate);

#undef R
#undef V

#endif /* KASLD_ENGINE_RULES_H */
