// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: riscv64 no-KASLR kernel text base, layout-aware.
//
// riscv64 has TWO kernel-text layouts. Which one is running is determined by
// the resolved PAGE_OFFSET — NOT by the kernel version, which KASLD does not
// trust. The split is the v5.13 commit "riscv: Move kernel mapping outside of
// linear mapping":
//
//   Legacy (pre-v5.13): text lives in the LINEAR map at PAGE_OFFSET +
//     load_offset, where PAGE_OFFSET is the compile-time CONFIG_PAGE_OFFSET.
//     arch/riscv/Kconfig had two 64-bit values (see kernel git history):
//       0xffffffe000000000  (MAXPHYSMEM_128GB, CMODEL_MEDANY — needs modules)
//       0xffffffff80000000  (MAXPHYSMEM_2GB,   CMODEL_MEDLOW — no modules)
//     No KASLR existed in this era.
//   Modern (v5.13+): text has its OWN mapping at KERNEL_LINK_ADDR (the top
//     2 GiB), independent of PAGE_OFFSET, which became a runtime value strictly
//     below the legacy floor (PAGE_OFFSET_L3/L4/L5: 0xffffffd6.../0xffffaf8.../
//     0xff60... — all < RISCV_LEGACY_PAGE_OFFSET).
//
// So PAGE_OFFSET >= RISCV_LEGACY_PAGE_OFFSET (0xffffffe000000000, the LOWEST
// legacy value) is the version-free "text is in the linear map" signal, and
// PAGE_OFFSET below it means modern.
//
// A single compile-time default is wrong for one of the two layouts, so the
// generic virt_kaslr_disabled_pin is opted out for riscv64
// (KASLR_DISABLED_PINS_VIRT_TEXT 0) and this rule owns the no-KASLR text base:
//
//   * Legacy (PAGE_OFFSET resolved >= RISCV_LEGACY_PAGE_OFFSET): text is in the
//     linear map, so _stext >= PAGE_OFFSET + IMAGE_BASE_OFFSET (it cannot
//     precede the image's own .head.text). The load offset is build/firmware-
//     specific, so emit that SOUND lower bound (from the RESOLVED PAGE_OFFSET,
//     covering both legacy values) rather than a C_EQUALS pin that would
//     exclude the truth; module_text_bound supplies the upper bound from a
//     leaked module address. Fires regardless of the disabled marker — a legacy
//     PAGE_OFFSET already implies no KASLR.
//   * Modern (PAGE_OFFSET resolved < RISCV_LEGACY_PAGE_OFFSET): pin
//     Q_VIRT_IMAGE_BASE to KERNEL_VIRT_TEXT_DEFAULT when KASLR is reported
//     disabled — the contract the generic pin provided, scoped to the layout
//     where the constant is correct.
//
// riscv64 only; inert elsewhere.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"

#include <string.h>

#if defined(__riscv) && __riscv_xlen == 64

int rule_riscv64_text_base(const struct evidence_set *ev,
                           const struct estimate *est, struct constraint *out,
                           int out_max) {
  if (out_max < 1)
    return 0;

  const struct estimate *po = &est[Q_PAGE_OFFSET];

  /* Legacy layout: PAGE_OFFSET resolved at or above the legacy floor means text
   * is in the linear map (both MAXPHYSMEM values land here; every modern
   * PAGE_OFFSET is strictly below). Match on the resolved LOWER bound — a
   * CONFIG_PAGE_OFFSET `pos=base` landmark resolves Q_PAGE_OFFSET with lo at
   * the legacy value. Emit a SOUND lower bound from the resolved PAGE_OFFSET
   * (not a constant — it must track whichever legacy value is live), not a
   * C_EQUALS pin (the load offset varies). module_text_bound carries the
   * ceiling. */
  if (po->kind == LK_INTERVAL &&
      po->lo >= (unsigned long)RISCV_LEGACY_PAGE_OFFSET) {
    struct constraint *c = &out[0];
    memset(c, 0, sizeof(*c));
    c->q = Q_VIRT_IMAGE_BASE;
    c->op = C_LOWER_BOUND;
    c->value = po->lo + (unsigned long)IMAGE_BASE_OFFSET;
    c->conf = CONF_INFERRED;
    c->derived_from[0] = po->lo_binding;
    c->lineage_count = po->lo_binding ? 1 : 0;
    snprintf(c->origin, ORIGIN_LEN, "riscv64_text_base");
    return 1;
  }

  /* Modern layout: text at KERNEL_LINK_ADDR. Pin to the compile-time default
   * when KASLR is reported off (mirrors the generic virt_kaslr_disabled_pin,
   * scoped to riscv64-modern).
   *
   * CRITICAL ordering guard: only act once PAGE_OFFSET is RESOLVED strictly
   * below the legacy value (every modern PAGE_OFFSET is). Q_PAGE_OFFSET starts
   * at its top [sv57, legacy], where the legacy branch above can't yet tell the
   * layout — and the engine fixpoint ACCUMULATES constraints across passes, so
   * emitting the modern pin now (before PAGE_OFFSET resolves to legacy) would
   * leave a stale C_EQUALS that outranks the later legacy lower bound. Waiting
   * for po->hi < legacy means we never pin modern on a kernel that turns out
   * legacy. */
  if (!(po->kind == LK_INTERVAL &&
        po->hi < (unsigned long)RISCV_LEGACY_PAGE_OFFSET))
    return 0;

  uint32_t sig_id = 0;
  enum kasld_confidence sig_conf = CONF_UNKNOWN;
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->value_kind != OBS_SCALAR)
      continue;
    if (o->scalar_fact == SF_VIRT_KASLR_DISABLED && o->scalar_value != 0) {
      sig_id = o->id;
      sig_conf = o->conf;
      break;
    }
  }
  if (sig_id == 0)
    return 0;

  unsigned long v = arch_default_text_base();
  const struct estimate *vt = &est[Q_VIRT_IMAGE_BASE];
  if (v == 0 || v < vt->lo || v > vt->hi)
    return 0; /* default doesn't model this build; keep the wider window. */

  struct constraint *c = &out[0];
  memset(c, 0, sizeof(*c));
  c->q = Q_VIRT_IMAGE_BASE;
  c->op = C_EQUALS;
  c->value = v;
  /* Same as virt_kaslr_disabled_pin: the modern default is an assumed
   * standard-config value, so cap at inferred (never above the signal) and let
   * a real text leak outrank it by confidence. */
  c->conf = sig_conf < CONF_INFERRED ? sig_conf : CONF_INFERRED;
  c->derived_from[0] = sig_id;
  c->lineage_count = 1;
  snprintf(c->origin, ORIGIN_LEN, "riscv64_text_base");
  return 1;
}

#else

int rule_riscv64_text_base(const struct evidence_set *ev,
                           const struct estimate *est, struct constraint *out,
                           int out_max) {
  (void)ev;
  (void)est;
  (void)out;
  (void)out_max;
  return 0;
}

#endif
