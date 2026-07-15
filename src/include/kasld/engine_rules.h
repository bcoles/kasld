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

#include <stdio.h>
#include <string.h>

/* Constraint rules, in registry order. *n is set to the count. */
const rule_fn *engine_rules(int *n);

/* Curation (verdict) rules, in registry order. *n is set to the count. */
const verdict_fn *engine_verdict_rules(int *n);

/* Confidence propagation for cross-quantity derived constraints. A bound
 * derived from another quantity's resolved edge is no more trustworthy than
 * that edge: a rule caps its emitted conf at kasld_conf_min(own_grade,
 * edge_conf). kasld_edge_conf normalizes a zero-initialized estimate (lo_conf/
 * hi_conf == CONF_UNKNOWN, e.g. a hand-built test estimate) to the axiom
 * default CONF_PARSED, matching the honest top set by init_top. */
static inline enum kasld_confidence kasld_conf_min(enum kasld_confidence a,
                                                   enum kasld_confidence b) {
  return (int)a < (int)b ? a : b;
}
static inline enum kasld_confidence
kasld_edge_conf(enum kasld_confidence edge) {
  return edge == CONF_UNKNOWN ? CONF_PARSED : edge;
}

/* Shared skeleton for the per-arch `*_coupling_validate` verdict rules. Each
 * such rule emits V_INVALID for every VIRT address observation whose anchor
 * falls outside its region's fixed VA band — the band layout is the only
 * arch-specific part, supplied as `is_bad(region, anchor)`. This folds the
 * identical scan + verdict-emission boilerplate the four rules used to repeat.
 * An anchor of 0 (no usable address) is never flagged. */
typedef int (*kasld_va_band_check)(enum kasld_region region,
                                   unsigned long anchor);

static inline int kasld_emit_va_band_verdicts(const struct evidence_set *ev,
                                              struct verdict *out, int out_max,
                                              kasld_va_band_check is_bad,
                                              const char *origin) {
  int n = 0;
  for (int i = 0; i < ev->n_obs && n < out_max; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->value_kind != OBS_ADDRESS ||
        o->eff_type != KASLD_TYPE_VIRT)
      continue;
    unsigned long a = obs_anchor(o);
    if (a == 0)
      continue;
    if (!is_bad(o->eff_region, a))
      continue;
    struct verdict *v = &out[n++];
    memset(v, 0, sizeof(*v));
    v->observation_id = o->id;
    v->kind = V_INVALID;
    v->conf = o->conf;
    v->derived_from[0] = o->id;
    v->lineage_count = 1;
    snprintf(v->origin, ORIGIN_LEN, "%s", origin);
  }
  return n;
}

/* Shared skeleton for the virt/phys KASLR-disabled text pins. On a positive
 * `signal` scalar, pin quantity `q` to the arch default `dflt` — an assumed
 * standard-config value, not a parsed fact, so emitted at <= CONF_INFERRED
 * (capped to the signal's own confidence) and only when `dflt` lies inside the
 * quantity's current honest window (so a leak that already narrowed past it
 * wins). Returns 1 if a pin was emitted, 0 otherwise. */
static inline int kasld_emit_kaslr_disabled_pin(
    const struct evidence_set *ev, const struct estimate *est,
    struct constraint *out, int out_max, enum kasld_scalar_fact signal,
    enum kasld_quantity q, unsigned long dflt, const char *origin) {
  if (out_max < 1)
    return 0;

  uint32_t sig_id = 0;
  enum kasld_confidence sig_conf = CONF_UNKNOWN;
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->value_kind != OBS_SCALAR)
      continue;
    if (o->scalar_fact == signal && o->scalar_value != 0) {
      sig_id = o->id;
      sig_conf = o->conf;
      break;
    }
  }
  if (sig_id == 0)
    return 0;

  const struct estimate *e = &est[q];
  if (dflt == 0 || dflt < e->lo || dflt > e->hi)
    return 0;

  struct constraint *c = &out[0];
  memset(c, 0, sizeof(*c));
  c->q = q;
  c->op = C_EQUALS;
  c->value = dflt;
  c->conf = sig_conf < CONF_INFERRED ? sig_conf : CONF_INFERRED;
  c->derived_from[0] = sig_id;
  c->lineage_count = 1;
  snprintf(c->origin, ORIGIN_LEN, "%s", origin);
  return 1;
}

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

/* Image-size ceilings (CONFIG_KERNEL_IMAGE_SIZE / SF_IMAGE_SIZE_MIN etc.) */
R(ceiling_from_image_size);
R(phys_ceiling_from_memtotal);
R(virt_ceiling_from_memtotal);
R(phys_bits_ceiling);
R(image_size_text_data_gap);
R(min_offset_from_image_size);
R(image_floor_from_init_size);
R(vmsplit_text_base);
R(range_from_interior);
R(image_base_grid_align);
R(image_base_resolved_grid_align);

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
R(ram_map_phys_exclude);
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
R(directmap_kaslr_disabled_pin);
R(phys_kaslr_disabled_pin);
R(physical_start_lower_bound);

/* Module-relative text bounds */
R(module_text_bound);

/* Multi-entry EFI_LOADER_CODE → Q_PHYS_IMAGE_BASE pin (arm64/riscv64/x86_64) */
R(efi_loader_kernel_pick);

/* Text-base pin from POS_BASE kernel-image observation */
R(text_pin_from_observation);

/* Symmetric phys↔virt text-base coupling synthesizer */
R(text_base_coupling_synth);

/* phys_virt_synth */
R(phys_virt_synth);

/* arm64-specific rules */
R(arm64_text_base);
R(arm64_memstart_align);
R(arm64_va_bits_from_directmap);
R(arm64_va_bits_from_vmemmap);
R(arm64_text_phys_residue);
R(arm64_phys_text_residue);

/* riscv64-specific rules */
R(riscv64_text_base);
R(riscv64_non_efi_phys_base);
R(riscv64_fdt_kaslr_seed);
R(riscv64_page_offset_from_vmalloc_vmemmap);
R(riscv64_va_bits_pin);

/* s390-specific rules */
R(s390_paging_level);
R(s390_text_from_belows);
R(s390_text_segment_mod);
R(s390_phys_segment_mod);
R(s390_text_no_random);
R(s390_image_base_from_config);

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
