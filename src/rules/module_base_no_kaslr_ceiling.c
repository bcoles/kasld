// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: cap the module base where the allocator drew no random offset.
//
// execmem_arch_setup() offsets the module range from MODULES_VADDR only when
// kaslr_enabled(); otherwise the offset is zero and the range starts at
// MODULES_VADDR exactly. So a run that knows KASLR did not randomize this
// kernel knows the module base IS that constant.
//
// Which constant is the part that is not known. MODULES_VADDR is
// __START_KERNEL_map + KERNEL_IMAGE_SIZE, and KERNEL_IMAGE_SIZE is 1 GiB under
// CONFIG_RANDOMIZE_BASE and 512 MiB without it -- two placements, and a
// KASLR-off run has not established which. Both are named by the architecture:
// the =n one is where the module band starts, and the =y one is
// MODULES_BASE_RANDOMIZED. The base is therefore one of exactly two values, and
// the coarser of them is a CEILING on it.
//
// A ceiling is all this states. Naming the pair as a set would say more, but a
// base quantity is an interval here and an upper bound is the part of that pair
// an interval can carry -- while still cutting the window to the span between
// the two placements, from the whole architectural band.
//
// The value is a compile-time virtual constant, so the bound holds however the
// kernel was placed physically: a kexec-loaded kernel running somewhere else
// entirely still has its module region begin at MODULES_VADDR.
//
// Reads SF_VIRT_KASLR_DISABLED, which every off-signal converges on -- a clear
// KASLR flag in boot_params, `nokaslr` on the command line,
// CONFIG_RANDOMIZE_BASE unset, a kernel built without CONFIG_RELOCATABLE. Each
// of them means kaslr_enabled() was false, which is the condition the allocator
// tested. Capped at the confidence of the signal it rests on, so an unkeyed
// config cannot reach the guaranteed window.
//
// Inert where the architecture declares no randomized module placement.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"

#include <string.h>

int rule_module_base_no_kaslr_ceiling(const struct evidence_set *ev,
                                      const struct estimate *est,
                                      struct constraint *out, int out_max) {
#if defined(MODULES_BASE_RANDOMIZED)
  (void)est;
  if (out_max < 1)
    return 0;

  enum kasld_confidence conf = CONF_UNKNOWN;
  uint32_t src = 0;
  int off = 0;
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->value_kind != OBS_SCALAR)
      continue;
    if (o->scalar_fact != SF_VIRT_KASLR_DISABLED || !o->scalar_value)
      continue;
    /* Strongest signal wins, matching how every other consumer of this fact
     * treats a set of them. */
    if (!off || o->conf > conf) {
      conf = o->conf;
      src = o->id;
      off = 1;
    }
  }
  if (!off)
    return 0;

  struct constraint *c = &out[0];
  memset(c, 0, sizeof(*c));
  c->q = Q_MODULE_BASE;
  c->op = C_UPPER_BOUND;
  c->value = (unsigned long)MODULES_BASE_RANDOMIZED;
  c->conf = conf;
  c->derived_from[0] = src;
  c->lineage_count = src ? 1 : 0;
  snprintf(c->origin, ORIGIN_LEN, "module_base_no_kaslr_ceiling");
  return 1;
#else
  (void)ev;
  (void)est;
  (void)out;
  (void)out_max;
  return 0;
#endif
}
