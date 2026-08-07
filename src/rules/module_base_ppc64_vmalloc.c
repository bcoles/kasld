// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: pin Q_MODULE_BASE on 64-bit PowerPC from the live translation mode and
// the page size.
//
// ppc64 defines no MODULES_VADDR, so modules are allocated from vmalloc, and
// VMALLOC_START is a runtime variable set to one of three compile-time
// constants depending on how the kernel booted:
//
//   Radix              RADIX_VMALLOC_START  = 0xc008000000000000
//   Hash, 64K pages    H_VMALLOC_START      = 0xc008000000000000
//   Hash, 4K pages     H_VMALLOC_START      = 0xc0003d0000000000
//
// Both selectors are observable without privilege: the mode from
// /proc/cpuinfo's "MMU" line (SF_PPC64_MMU_MODE), the page size from sysconf
// (SF_PAGE_SIZE). Knowing both fixes the base exactly, collapsing a band that
// otherwise spans 32 TiB.
//
// POSITIVE EVIDENCE ONLY. Every branch requires a fact to be present and to
// match a value this rule understands; nothing is concluded from a fact being
// absent. That matters most for Book3E, whose base (0xc000100000000000) is NOT
// listed above: Book3E is distinguished only by printing no "MMU" line, and a
// restricted or unreadable /proc/cpuinfo is indistinguishable from that. An
// unfamiliar page size is treated the same way — no pin, rather than a guess.
// The band bound from module_base_bounds remains in either case.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"
#include "include/kasld/regions.h"

#include <string.h>

int rule_module_base_ppc64_vmalloc(const struct evidence_set *ev,
                                   const struct estimate *est,
                                   struct constraint *out, int out_max) {
#if defined(MODULES_BASE_PPC64_RADIX)
  (void)est;
  if (out_max < 1)
    return 0;

  enum kasld_confidence mconf = CONF_UNKNOWN;
  uint32_t msrc = 0;
  unsigned long mode =
      kasld_scalar_fact_value(ev, SF_PPC64_MMU_MODE, &mconf, &msrc);
  if (!mode)
    return 0;

  unsigned long base;
  enum kasld_confidence conf = mconf;
  uint32_t src = msrc;

  if (mode == KASLD_PPC64_MMU_RADIX) {
    /* Radix places vmalloc at one address whatever the page size. */
    base = (unsigned long)MODULES_BASE_PPC64_RADIX;
  } else if (mode == KASLD_PPC64_MMU_HASH) {
    enum kasld_confidence pconf = CONF_UNKNOWN;
    uint32_t psrc = 0;
    unsigned long pagesz =
        kasld_scalar_fact_value(ev, SF_PAGE_SIZE, &pconf, &psrc);
    if (pagesz == 65536ul) {
      base = (unsigned long)MODULES_BASE_PPC64_HASH_64K;
    } else if (pagesz == 4096ul) {
      base = (unsigned long)MODULES_BASE_PPC64_HASH_4K;
    } else {
      return 0; /* no page size, or one this rule does not model */
    }
    /* Two facts, so the pin is only as good as the weaker of them. */
    conf = kasld_conf_min(mconf, pconf);
    src = psrc ? psrc : msrc;
  } else {
    return 0; /* a mode this rule does not model */
  }

  struct constraint *c = &out[0];
  memset(c, 0, sizeof(*c));
  c->q = Q_MODULE_BASE;
  c->op = C_EQUALS;
  c->value = base;
  c->conf = conf;
  if (src) {
    c->derived_from[0] = src;
    c->lineage_count = 1;
  }
  snprintf(c->origin, ORIGIN_LEN, "module_base_ppc64_vmalloc");
  return 1;
#else
  (void)ev;
  (void)est;
  (void)out;
  (void)out_max;
  return 0;
#endif
}
