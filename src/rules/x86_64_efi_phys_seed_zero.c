// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: x86_64 EFI stub forces physical KASLR seed to 0 when a memory-
// rewriting cmdline token is present.
//
// drivers/firmware/efi/libstub/x86-stub.c parse_options() sets
// cmdline_memmap_override on detecting `mem=`, `memmap=`, or `hugepages=` on
// the cmdline with kernel-identical word-boundary semantics. When the
// override is set, the random-allocation path forces `seed[0] = 0` and calls
// efi_random_alloc(); with target_slot = (total_slots * 0) >> 32 = 0 the
// kernel image is placed at the LOWEST qualifying slot in the EFI memory
// map ≥ LOAD_PHYSICAL_ADDR (= PHYSICAL_START, 16 MiB) that fits image_size.
//
// Two cases handled here:
//
//   1. STRONG (PHYS REGION_KERNEL_IMAGE observation present): dmesg_efi_memmap
//      emits a kernel_image bound when EFI_LOADER_CODE has exactly one entry
//      — that entry IS the kernel's physical extent. With the seed-zero
//      trigger confirmed, the placement is no longer "≤ loader.lo" (an upper
//      bound) but exactly loader.lo (a bilateral pin): emit C_EQUALS on
//      Q_PHYS_TEXT_BASE at the lowest PHYS kernel_image lo.
//
//   2. FALLBACK (no kernel_image observation): the EFI memory map is not
//      readable from userspace (dmesg restricted or memmap not emitted). The
//      kernel lands "near" LOAD_PHYSICAL_ADDR, but the exact slot depends on
//      individual EFI descriptor sizes. Skip: a heuristic ceiling here would
//      be unsound (an earlier non-RAM descriptor could push the actual slot
//      arbitrarily higher). Live-host validation may revisit.
//
// Only the *physical* placement seed is zeroed; `virt_addr` uses seed[1],
// unaffected. The constraint is strictly on Q_PHYS_TEXT_BASE.
//
// References:
// https://elixir.bootlin.com/linux/v6.12/source/drivers/firmware/efi/libstub/x86-stub.c#L815
// https://elixir.bootlin.com/linux/v6.12/source/drivers/firmware/efi/libstub/randomalloc.c#L102
// ---
// <bcoles@gmail.com>

#include "../include/kasld/engine_rules.h"

#include <string.h>

int rule_x86_64_efi_phys_seed_zero(const struct evidence_set *ev,
                                   const struct estimate *est,
                                   struct constraint *out, int out_max) {
  (void)est;
#if !defined(__x86_64__)
  (void)ev;
  (void)out;
  (void)out_max;
  return 0;
#else
  if (out_max < 1)
    return 0;

  /* Trigger collection: EFI present + any of mem=/memmap=/hugepages=. The
   * three legs are independent — emitted by different components and
   * different shapes (scalar value / observations / scalar presence). */
  int efi_present = 0, has_mem = 0, has_memmap = 0, has_hugepages = 0;
  uint32_t lineage[MAX_LINEAGE];
  int n_lineage = 0;
  enum kasld_confidence trigger_conf = CONF_PARSED;

  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid)
      continue;
    if (o->value_kind == OBS_SCALAR) {
      if (o->scalar_fact == SF_EFI_PRESENT && o->scalar_value != 0) {
        efi_present = 1;
        if (n_lineage < MAX_LINEAGE)
          lineage[n_lineage++] = o->id;
        if (o->conf < trigger_conf)
          trigger_conf = o->conf;
      } else if (o->scalar_fact == SF_PHYS_CMDLINE_MEM &&
                 o->scalar_value != 0) {
        has_mem = 1;
        if (n_lineage < MAX_LINEAGE)
          lineage[n_lineage++] = o->id;
        if (o->conf < trigger_conf)
          trigger_conf = o->conf;
      } else if (o->scalar_fact == SF_CMDLINE_HUGEPAGES &&
                 o->scalar_value != 0) {
        has_hugepages = 1;
        if (n_lineage < MAX_LINEAGE)
          lineage[n_lineage++] = o->id;
        if (o->conf < trigger_conf)
          trigger_conf = o->conf;
      }
    } else if (o->value_kind == OBS_ADDRESS && o->eff_type == KASLD_TYPE_PHYS &&
               o->eff_region == REGION_CMDLINE_MEMMAP) {
      has_memmap = 1;
      if (n_lineage < MAX_LINEAGE)
        lineage[n_lineage++] = o->id;
      if (o->conf < trigger_conf)
        trigger_conf = o->conf;
    }
  }

  if (!efi_present || !(has_mem || has_memmap || has_hugepages))
    return 0;

  /* Strong case: find the lowest PHYS REGION_KERNEL_IMAGE anchor. The
   * dmesg_efi_memmap single-Loader-Code path emits this as samples; we read
   * either an extent lo or the lowest sample, whichever is present. */
  unsigned long pin = ULONG_MAX;
  uint32_t pin_src = 0;
  enum kasld_confidence pin_conf = CONF_PARSED;
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->value_kind != OBS_ADDRESS ||
        o->eff_type != KASLD_TYPE_PHYS || o->eff_region != REGION_KERNEL_IMAGE)
      continue;
    unsigned long a = HAS_LO(o) ? o->lo : (HAS_SAMPLE(o) ? o->sample : 0);
    if (a == 0)
      continue;
    if (a < pin) {
      pin = a;
      pin_src = o->id;
      pin_conf = o->conf;
    }
  }
  if (pin == ULONG_MAX)
    return 0; /* fallback case deferred (see file header) */

  /* Sanity guard: pin must be a plausible kernel phys base. */
  if (pin < (unsigned long)KASLR_PHYS_MIN)
    return 0;
  unsigned long palign = est[Q_PHYS_KASLR_ALIGN].lo;
  if (palign < (unsigned long)KASLR_PHYS_ALIGN)
    palign = (unsigned long)KASLR_PHYS_ALIGN;
  if (palign > 0 && (pin & (palign - 1)))
    return 0; /* unaligned: the kernel_image observation is not the kernel base
               */

  struct constraint *c = &out[0];
  memset(c, 0, sizeof(*c));
  c->q = Q_PHYS_TEXT_BASE;
  c->op = C_EQUALS;
  c->value = pin;
  /* Confidence: weaker of (kernel_image observation) and (the trigger set).
   * The pin is corroborated by efi_present + at least one cmdline trigger
   * plus the kernel_image observation; the resolver tiebreaker promotes by
   * lineage_count when multiple equally-confident sources agree. */
  c->conf = (pin_conf < trigger_conf) ? pin_conf : trigger_conf;

  /* Lineage: kernel_image observation + every trigger that contributed. */
  c->derived_from[0] = pin_src;
  c->lineage_count = 1;
  for (int i = 0; i < n_lineage && c->lineage_count < MAX_LINEAGE; i++)
    c->derived_from[c->lineage_count++] = lineage[i];

  snprintf(c->origin, ORIGIN_LEN, "x86_64_efi_phys_seed_zero");
  return 1;
#endif
}
