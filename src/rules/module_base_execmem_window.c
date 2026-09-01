// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: confine Q_MODULE_BASE to the allocator's own randomization window on
// arches that draw a module-base offset independently of the text slide.
//
// Where MODULES_BASE_RANDOMIZED / MODULES_BASE_RANDOM_SPAN are declared, the
// module range starts at a fixed base plus an offset the allocator picks at
// boot, bounded by the span:
//
//   base ∈ [MODULES_BASE_RANDOMIZED, MODULES_BASE_RANDOMIZED + SPAN]
//
// On x86_64 that is execmem_arch_setup()'s `MODULES_VADDR + rand(1,1024) *
// PAGE_SIZE` — about 10 bits, versus the ~17 the whole band spans.
//
// GATE: the named base is the CONFIG_RANDOMIZE_BASE=y placement of
// MODULES_VADDR, which is only where the module region lives if that option
// was set. Two things establish it, and either will do:
//
//   SF_KASLR_RANDOMIZED — the boot stub's own record that it randomized the
//     kernel. The code that sets it is compiled in only under
//     CONFIG_RANDOMIZE_BASE, so the flag IS that option, observed rather than
//     inferred. It answers on a run that has resolved no base at all, which is
//     exactly the confined vantage this window is worth most to.
//   the IMAGE MOVED — a resolved Q_VIRT_IMAGE_BASE that excludes the
//     compile-time default. A relocated image proves the KASLR machinery ran,
//     which proves RANDOMIZE_BASE=y, which fixes KERNEL_IMAGE_SIZE and hence
//     MODULES_VADDR.
//
// Without either the base could sit at the =n placement instead, and the window
// would be in the wrong place entirely; the rule stays silent rather than
// guess.
//
// Inert where the arch declares no such window, and inert until the image base
// is resolved enough to rule the default out.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"
#include "include/kasld/regions.h"

#include <string.h>

int rule_module_base_execmem_window(const struct evidence_set *ev,
                                    const struct estimate *est,
                                    struct constraint *out, int out_max) {
#if defined(MODULES_BASE_RANDOMIZED) && defined(MODULES_BASE_RANDOM_SPAN)
  if (out_max < 2)
    return 0;

  /* Did the image move? The same test default_base_remark applies: the default
   * is ruled out exactly when a KNOWN edge lies on the wrong side of it. An
   * unknown edge rules nothing out, so an unresolved base leaves this inert. */
  const unsigned long def = (unsigned long)KERNEL_VIRT_TEXT_DEFAULT;
  const struct estimate *vt = &est[Q_VIRT_IMAGE_BASE];
  struct estimate top;
  quantities[Q_VIRT_IMAGE_BASE].init_top(&top);
  int lo_known = vt->lo > top.lo, hi_known = vt->hi < top.hi;
  int moved = (lo_known && vt->lo > def) || (hi_known && vt->hi < def);
  int randomized = 0;
  for (int i = 0; i < ev->n_obs && !randomized; i++) {
    const struct observation *o = &ev->obs[i];
    randomized = o->valid && o->value_kind == OBS_SCALAR &&
                 o->scalar_fact == SF_KASLR_RANDOMIZED && o->scalar_value;
  }
  if (!moved && !randomized)
    return 0;

  int n = 0;
  struct constraint *c = &out[n++];
  memset(c, 0, sizeof(*c));
  c->q = Q_MODULE_BASE;
  c->op = C_LOWER_BOUND;
  c->value = (unsigned long)MODULES_BASE_RANDOMIZED;
  c->conf = CONF_INFERRED;
  snprintf(c->origin, ORIGIN_LEN, "module_base_execmem_window");

  c = &out[n++];
  memset(c, 0, sizeof(*c));
  c->q = Q_MODULE_BASE;
  c->op = C_UPPER_BOUND;
  c->value = (unsigned long)MODULES_BASE_RANDOMIZED +
             (unsigned long)MODULES_BASE_RANDOM_SPAN;
  c->conf = CONF_INFERRED;
  snprintf(c->origin, ORIGIN_LEN, "module_base_execmem_window");

  return n;
#else
  (void)ev;
  (void)est;
  (void)out;
  (void)out_max;
  return 0;
#endif
}
