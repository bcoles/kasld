// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: pin Q_MODULE_BASE from a resolved virtual-address width, on arches
// whose module region is placed by arithmetic on that width alone.
//
// Where MODULES_BASE_FROM_VA_BITS_ADDEND is declared, the kernel computes
//
//   vm_map_base   = 0 - (1 << va_bits)
//   MODULES_VADDR = vm_map_base + <addend>
//
// with nothing randomized in between, so a known width fixes the base
// exactly -- an equality, not a window.
//
// The width must be the HARDWARE one (loongarch cpu_vabits, published by
// proc_cpuinfo from "Address Sizes ... bits virtual"). An mmap boundary probe
// measures TASK_SIZE = 1 << min(cpu_vabits, VA_BITS), clamped to the kernel's
// page-table width, and feeding that here would place the region too high --
// by a factor of two per clamped bit. SF_VIRT_ADDR_BITS is the contract that
// says "the active virtual width", which is what this needs.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"
#include "include/kasld/regions.h"

#include <string.h>

int rule_module_base_from_va_bits(const struct evidence_set *ev,
                                  const struct estimate *est,
                                  struct constraint *out, int out_max) {
#if defined(MODULES_BASE_FROM_VA_BITS_ADDEND)
  (void)est;
  if (out_max < 1)
    return 0;

  enum kasld_confidence conf = CONF_UNKNOWN;
  uint32_t src = 0;
  unsigned long bits =
      kasld_scalar_fact_value(ev, SF_VIRT_ADDR_BITS, &conf, &src);
  /* A width outside the addressable range would shift by an undefined amount;
   * treat it as no evidence rather than compute on it. */
  if (!bits || bits >= (sizeof(unsigned long) * 8))
    return 0;

  unsigned long base =
      (0ul - (1ul << bits)) + (unsigned long)MODULES_BASE_FROM_VA_BITS_ADDEND;

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
  snprintf(c->origin, ORIGIN_LEN, "module_base_from_va_bits");
  return 1;
#else
  (void)ev;
  (void)est;
  (void)out;
  (void)out_max;
  return 0;
#endif
}
