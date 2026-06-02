// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: x86 `memmap=` over-count → physical KASLR aborted, pin to image base.
//
// arch/x86/boot/compressed/kaslr.c parse_memmap() stores at most
// MAX_MEMMAP_REGIONS (= 4) with-offset memmap= reservations; a 5th sets
// memmap_too_large = true, which makes find_random_phys_addr() bail
// (returns 0). choose_random_location() then leaves *output unchanged, so
// the kernel image stays at the bootloader's pre-relocation physical
// address — the same end-state as the EFI seed[0]=0 / lowest-EFI-slot path
// (see x86_64_efi_phys_seed_zero) but reached via a different code path.
// Crucially: this path triggers on both legacy BIOS and EFI boots, so it
// complements the EFI-only seed-zero rule.
//
// When a PHYS REGION_KERNEL_IMAGE observation is present (dmesg_efi_memmap's
// single-Loader-Code-entry path), pin Q_PHYS_TEXT_BASE to that address.
// Alignment + min-bound sanity checks are the same as the seed-zero rule.
//
// x86_64 only (x86_32 has no phys KASLR window to collapse — its
// Q_PHYS_TEXT_BASE quantity is inert). Dormant until a cmdline carries 5+
// memmap=offset tokens; cheap when absent.
//
// References:
// https://elixir.bootlin.com/linux/v6.12/source/arch/x86/boot/compressed/kaslr.c#L194
// https://elixir.bootlin.com/linux/v6.12/source/arch/x86/boot/compressed/kaslr.c#L815
// ---
// <bcoles@gmail.com>

#include "../include/kasld/engine_rules.h"

#include <limits.h>
#include <string.h>

#define X86_KASLR_MAX_MEMMAP_REGIONS 4ul

int rule_cmdline_memmap_too_large_phys_pin(const struct evidence_set *ev,
                                           const struct estimate *est,
                                           struct constraint *out,
                                           int out_max) {
  (void)est;
#if !defined(__x86_64__)
  (void)ev;
  (void)out;
  (void)out_max;
  return 0;
#else
  if (out_max < 1)
    return 0;

  /* Trigger: count > MAX_MEMMAP_REGIONS. */
  unsigned long count = 0;
  uint32_t count_src = 0;
  enum kasld_confidence trig_conf = CONF_PARSED;
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->value_kind != OBS_SCALAR ||
        o->scalar_fact != SF_CMDLINE_MEMMAP_COUNT)
      continue;
    count = o->scalar_value;
    count_src = o->id;
    trig_conf = o->conf;
    break;
  }
  if (count <= X86_KASLR_MAX_MEMMAP_REGIONS)
    return 0;

  /* Lowest PHYS kernel-image anchor (same shape as the EFI seed-zero rule).
   * Without one we
   * cannot derive a specific phys base — the proposal's conservative
   * fallback (≤ LOAD_PHYSICAL_ADDR + small) is unsound when intervening
   * reservations push the actual placement higher; defer. */
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
    return 0;

  if (pin < (unsigned long)KASLR_PHYS_MIN)
    return 0;
  unsigned long palign = est[Q_PHYS_KASLR_ALIGN].lo;
  if (palign < (unsigned long)KASLR_PHYS_ALIGN)
    palign = (unsigned long)KASLR_PHYS_ALIGN;
  if (palign > 0 && (pin & (palign - 1)))
    return 0;

  struct constraint *c = &out[0];
  memset(c, 0, sizeof(*c));
  c->q = Q_PHYS_TEXT_BASE;
  c->op = C_EQUALS;
  c->value = pin;
  c->conf = (pin_conf < trig_conf) ? pin_conf : trig_conf;
  c->derived_from[0] = pin_src;
  c->derived_from[1] = count_src;
  c->lineage_count = 2;
  snprintf(c->origin, ORIGIN_LEN, "cmdline_memmap_too_large_phys_pin");
  return 1;
#endif
}
