// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: x86_64 direct-map KASLR-disabled pin (page_offset / vmalloc / vmemmap).
//
// arch/x86/mm/kaslr.c:kernel_randomize_memory() returns BEFORE touching any
// base when !kaslr_memory_enabled(), and
//
//   kaslr_memory_enabled() = kaslr_enabled() && !IS_ENABLED(CONFIG_KASAN)
//
// (identical in linux-6.6 … 7.0 and mainline). So page_offset_base /
// vmalloc_base / vmemmap_base keep their compile-time defaults whenever KASLR
// is off (SF_VIRT_KASLR_DISABLED) OR CONFIG_KASAN=y (SF_KASAN_ENABLED) — and on
// x86_64 __PAGE_OFFSET / VMALLOC_START / VMEMMAP_START ARE those variables
// unconditionally (page_64_types.h, pgtable_64_types.h), so the runtime base
// equals the constant. The non-obvious case is KASAN with
// CONFIG_RANDOMIZE_MEMORY=y: the config advertises a randomized direct map but
// KASAN overrides it at runtime — common on syzkaller / CTF / debug kernels.
//
// On a positive disable signal, pin all three bases to the paging-level default
// (L4 = VA 48, L5 = VA 57). The level comes from SF_VIRT_ADDR_BITS
// (proc_cpuinfo's "bits virtual", which tracks the active level — leak-free, so
// the pin can fire without any direct-map leak), falling back to a resolved
// Q_VA_BITS (e.g. x86_64_la57_from_directmap, from a directmap leak's top bits)
// when cpuinfo is unavailable. CONFIG_RANDOMIZE_BASE is independent of the
// memory randomization, so kernel TEXT stays randomized; this pins only the
// direct-map side.
//
// Soundness:
//   * Fires only on a positive disable signal AND a resolved VA width.
//   * The pinned values are exact, non-config-tunable kernel constants for the
//     resolved level — no window-containment read is needed, and an
//     out-of-window C_EQUALS is dropped by the engine's meet as a conflict.
//   * The only estimate read is est[Q_VA_BITS] (the level): cross-quantity, not
//     a self-edge on the bases written here, and acyclic — Q_VA_BITS derives
//     from the directmap observation, never from est[Q_PAGE_OFFSET].
//   * A higher-confidence real direct-map leak still wins via the resolver's
//     conflict handling.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"

#include <string.h>

int rule_directmap_kaslr_disabled_pin(const struct evidence_set *ev,
                                      const struct estimate *est,
                                      struct constraint *out, int out_max) {
#if defined(__x86_64__) || defined(__amd64__)
  uint32_t sig_id = 0, va_id = 0;
  enum kasld_confidence sig_conf = CONF_UNKNOWN, va_conf = CONF_UNKNOWN;
  unsigned long va_bits = 0;
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->value_kind != OBS_SCALAR)
      continue;
    if ((o->scalar_fact == SF_KASAN_ENABLED ||
         o->scalar_fact == SF_VIRT_KASLR_DISABLED) &&
        o->scalar_value != 0) {
      if (sig_id == 0) {
        sig_id = o->id;
        sig_conf = o->conf;
      }
    } else if (o->scalar_fact == SF_VIRT_ADDR_BITS && o->scalar_value != 0) {
      va_bits = o->scalar_value;
      va_id = o->id;
      va_conf = o->conf;
    }
  }
  if (sig_id == 0)
    return 0;

  /* Paging level (L4 = VA 48 / L5 = VA 57): prefer the leak-free cpuinfo scalar
   * (SF_VIRT_ADDR_BITS); fall back to a resolved Q_VA_BITS — e.g.
   * x86_64_la57_from_directmap pins it from a directmap leak's top bits when
   * cpuinfo is unavailable. Reading est[Q_VA_BITS] is cross-quantity (not a
   * self-edge on the bases this rule writes) and acyclic — Q_VA_BITS derives
   * from the directmap observation, never from est[Q_PAGE_OFFSET]. */
  if (va_bits == 0)
    estimate_finset_value(&quantities[Q_VA_BITS], &est[Q_VA_BITS], &va_bits);
  if (va_bits == 0)
    return 0;

  /* Active paging level: 48-bit VA -> 4-level (L4), 57-bit -> 5-level (L5). */
  int l5;
  if (va_bits <= 48)
    l5 = 0;
  else if (va_bits <= 57)
    l5 = 1;
  else
    return 0; /* unexpected width — don't pin. */

  struct {
    enum kasld_quantity q;
    unsigned long value;
  } pins[3] = {
      {Q_PAGE_OFFSET, l5 ? PAGE_OFFSET_BASE_L5 : PAGE_OFFSET_BASE_L4},
      {Q_VMALLOC_BASE, l5 ? VMALLOC_BASE_L5 : VMALLOC_BASE_L4},
      {Q_VMEMMAP_BASE, l5 ? VMEMMAP_BASE_L5 : VMEMMAP_BASE_L4},
  };

  /* When the level came from the cpuinfo scalar, corroborate with its
   * confidence + id; when it came from the already-resolved estimate there is
   * no observation to cite, so the pin rests on the disable signal alone. */
  enum kasld_confidence conf =
      va_id ? ((sig_conf < va_conf) ? sig_conf : va_conf) : sig_conf;
  int n = 0;
  for (int k = 0; k < 3 && n < out_max; k++) {
    struct constraint *c = &out[n++];
    memset(c, 0, sizeof(*c));
    c->q = pins[k].q;
    c->op = C_EQUALS;
    c->value = pins[k].value;
    c->conf = conf;
    c->derived_from[0] = sig_id;
    c->derived_from[1] = va_id;
    c->lineage_count = va_id ? 2 : 1;
    snprintf(c->origin, ORIGIN_LEN, "directmap_kaslr_disabled_pin");
  }
  return n;
#else
  (void)ev;
  (void)est;
  (void)out;
  (void)out_max;
  return 0;
#endif
}
