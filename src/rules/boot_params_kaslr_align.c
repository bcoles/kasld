// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: KASLR slot granularity from x86 CONFIG_PHYSICAL_ALIGN.
//
// CONFIG_PHYSICAL_ALIGN is the actual physical KASLR slot granularity —
// default 2 MiB, Kconfig range [2 MiB, 16 MiB]. When it exceeds the arch
// default the slot count is proportionally smaller, so raise both
// Q_KASLR_ALIGN and Q_PHYS_KASLR_ALIGN (physical and virtual offsets are
// locked on x86-64).
//
// Reads SF_KERNEL_ALIGN, emitted by either source:
//   - boot_params_facts.c — /sys/kernel/boot_params/data hdr.kernel_alignment
//     (the kernel's runtime echo of CONFIG_PHYSICAL_ALIGN; canonical).
//   - boot_config.c / proc_config.c — CONFIG_PHYSICAL_ALIGN= line from
//     /boot/config-$REL or /proc/config.gz (fallback when boot_params is
//     unreadable, e.g. minimal containers).
// Both sources emit CONF_PARSED; the engine's strongest-wins resolver
// dedupes when both fire.
//
// C_AT_LEAST_ALIGN narrows the max-align lattice upward; a value below the
// arch baseline is simply dominated by the axiomatic kaslr_align_arch_default
// constraint. A sanity check (power of two, [4 KiB, 1 GiB]) gates emission.
//
// x86 only (boot_params is x86-specific; CONFIG_PHYSICAL_ALIGN is an x86
// Kconfig knob); inert elsewhere.
// ---
// <bcoles@gmail.com>

#include "../include/kasld/engine_rules.h"

#include <string.h>

int rule_boot_params_kaslr_align(const struct evidence_set *ev,
                                 const struct estimate *est,
                                 struct constraint *out, int out_max) {
  (void)est;
#if defined(__x86_64__) || defined(__i386__)
  unsigned long align = 0;
  uint32_t src = 0;
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (o->valid && o->value_kind == OBS_SCALAR &&
        o->scalar_fact == SF_KERNEL_ALIGN) {
      align = o->scalar_value;
      src = o->id;
      break;
    }
  }

  /* Sanity: non-zero power of two in [4 KiB, 1 GiB]. */
  if (align == 0 || (align & (align - 1)) != 0 || align < 4096ul ||
      align > (1024ul * 1024 * 1024))
    return 0;

  int n = 0;
  const enum kasld_quantity qs[] = {Q_KASLR_ALIGN, Q_PHYS_KASLR_ALIGN};
  for (size_t i = 0; i < sizeof(qs) / sizeof(qs[0]) && n < out_max; i++) {
    struct constraint *c = &out[n++];
    memset(c, 0, sizeof(*c));
    c->q = qs[i];
    c->op = C_AT_LEAST_ALIGN;
    c->value = align;
    c->conf = CONF_PARSED;
    c->derived_from[0] = src;
    c->lineage_count = src ? 1 : 0;
    snprintf(c->origin, ORIGIN_LEN, "boot_params_kaslr_align");
  }
  return n;
#else
  (void)ev;
  (void)out;
  (void)out_max;
  return 0;
#endif
}
