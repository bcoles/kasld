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
// was set. Three things speak to it, and they are NOT equally strong, so the
// window is emitted at the confidence of whichever spoke:
//
//   SF_KASLR_COMPILED_IN — the kernel config read directly. The option itself,
//     which is what the window rests on, so this is the licence the rule most
//     wants. It carries the confidence of the config that supplied it: an
//     unkeyed /boot/config is not bound to the running kernel and arrives
//     below the sound floor, which is exactly right here.
//   SF_KASLR_RANDOMIZED — the boot stub's own record that it randomized the
//     kernel this boot. The randomizer lives in code compiled only under
//     CONFIG_RANDOMIZE_BASE, so a set flag implies the option. Proof, but a
//     narrower one: it is silent on a =y kernel booted with `nokaslr`, where
//     the compile-time layout is unchanged and this window still holds.
//   the IMAGE MOVED — a resolved Q_VIRT_IMAGE_BASE that excludes the
//     compile-time default. Strong evidence that the KASLR machinery ran, but
//     not proof: the default is where a DEFAULT build puts the image, and the
//     knob that moves it is independent of RANDOMIZE_BASE. On x86_64 the image
//     is linked at __START_KERNEL_map + ALIGN(CONFIG_PHYSICAL_START,
//     CONFIG_PHYSICAL_ALIGN), so a kernel built with a non-default
//     PHYSICAL_START — the crash-dump case, where the option is offered
//     precisely so the image can be linked at the reservation — sits away from
//     the default with KASLR off. This test then reads "moved" for an image
//     that never moved, and the =n module region is 512 MiB lower, since
//     KERNEL_IMAGE_SIZE is 512 MiB rather than 1 GiB without RANDOMIZE_BASE.
//     A guaranteed window there would exclude the true base, so this path
//     emits below the sound floor and shapes the likely window only.
//
// Without any of them the base could sit at the =n placement instead, and the
// window would be in the wrong place entirely; the rule stays silent rather
// than guess.
//
// Inert where the arch declares no such window, and inert until something
// establishes the option or the image base is resolved enough to rule the
// default out.
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

  /* The strongest licence on offer, and who said it. Either observed fact
   * establishes the option outright, so each licenses the window at its own
   * confidence -- capped at the sound floor, because the window is inferred
   * from the option rather than read. A displaced image is not proof (see the
   * GATE note) and licenses nothing above CONF_HEURISTIC. */
  enum kasld_confidence conf = moved ? CONF_HEURISTIC : CONF_UNKNOWN;
  uint32_t src = 0;
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->value_kind != OBS_SCALAR || !o->scalar_value)
      continue;
    if (o->scalar_fact != SF_KASLR_COMPILED_IN &&
        o->scalar_fact != SF_KASLR_RANDOMIZED)
      continue;
    enum kasld_confidence c = kasld_conf_min(o->conf, CONF_INFERRED);
    if ((int)c > (int)conf) {
      conf = c;
      src = o->id;
    }
  }
  if (conf == CONF_UNKNOWN)
    return 0;

  int n = 0;
  struct constraint *c = &out[n++];
  memset(c, 0, sizeof(*c));
  c->q = Q_MODULE_BASE;
  c->op = C_LOWER_BOUND;
  c->value = (unsigned long)MODULES_BASE_RANDOMIZED;
  c->conf = conf;
  if (src) {
    c->derived_from[0] = src;
    c->lineage_count = 1;
  }
  snprintf(c->origin, ORIGIN_LEN, "module_base_execmem_window");

  c = &out[n++];
  memset(c, 0, sizeof(*c));
  c->q = Q_MODULE_BASE;
  c->op = C_UPPER_BOUND;
  c->value = (unsigned long)MODULES_BASE_RANDOMIZED +
             (unsigned long)MODULES_BASE_RANDOM_SPAN;
  c->conf = conf;
  if (src) {
    c->derived_from[0] = src;
    c->lineage_count = 1;
  }
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
