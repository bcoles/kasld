// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: pin Q_MODULE_BASE on loongarch64 from the reported VA width and page
// size.
//
// The module region is placed by arithmetic on the hardware VA width, with
// nothing randomized in between, so knowing the width and the page size fixes
// the base exactly -- an equality, not a window:
//
//   vm_map_base   = 0 - (1 << cpu_vabits)
//   MODULES_VADDR = vm_map_base + PCI_IOSIZE + 2 * PAGE_SIZE
//
// Two things about that arithmetic are easy to get wrong, and both cost a wrong
// pin rather than a wide one.
//
// THE SHIFT IS NOT THE REPORTED WIDTH. cpu_vabits is the raw CPUCFG1.VALEN
// field, which is the width minus one, and /proc/cpuinfo prints VALEN + 1.
// SF_VIRT_ADDR_BITS carries the printed width, so the shift is one bit less --
// shifting by the reported width lands a whole granule of address space low.
//
// THE PAGE SIZE IS A FACT, NOT A CONSTANT. loongarch admits 4 KiB, 16 KiB and
// 64 KiB pages and the two-page term differs under each, so SF_PAGE_SIZE is a
// second required input; the analysing build's PAGE_SIZE describes only itself.
// Absent that fact the rule declines rather than assuming its own.
//
// The width must also be the HARDWARE one. An mmap boundary probe measures
// TASK_SIZE = 1 << min(cpu_vabits, VA_BITS), clamped to the kernel's page-table
// width, and feeding that here would place the region too high by a factor of
// two per clamped bit. SF_VIRT_ADDR_BITS is the contract that says "the active
// virtual width", which is what this needs.
//
// loongarch64 only; inert elsewhere.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"
#include "include/kasld/regions.h"

#include <string.h>

int rule_loongarch64_module_base(const struct evidence_set *ev,
                                 const struct estimate *est,
                                 struct constraint *out, int out_max) {
#if defined(MODULES_BASE_LOONGARCH64_PCI_IOSIZE)
  (void)est;
  if (out_max < 1)
    return 0;

  enum kasld_confidence conf = CONF_UNKNOWN;
  uint32_t src = 0;
  unsigned long bits =
      kasld_scalar_fact_value(ev, SF_VIRT_ADDR_BITS, &conf, &src);
  /* The shift is the reported width less one (VALEN vs the printed value). A
   * width of 1 or less would shift by a negative amount, and one at or above
   * the word size by an undefined one; treat either as no evidence rather than
   * compute on it. */
  if (bits <= 1ul || bits >= (sizeof(unsigned long) * 8))
    return 0;
  unsigned long shift = bits - 1ul;

  enum kasld_confidence pconf = CONF_UNKNOWN;
  uint32_t psrc = 0;
  unsigned long page_bytes = kasld_page_size_observed(ev, &pconf, &psrc);
  if (!page_bytes)
    return 0;
  /* Two facts, so the pin is only as good as the weaker of them. */
  conf = kasld_conf_min(conf, pconf);

  unsigned long base = (0ul - (1ul << shift)) +
                       (unsigned long)MODULES_BASE_LOONGARCH64_PCI_IOSIZE +
                       2ul * page_bytes;

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
  if (psrc && c->lineage_count < MAX_LINEAGE)
    c->derived_from[c->lineage_count++] = psrc;
  snprintf(c->origin, ORIGIN_LEN, "loongarch64_module_base");
  return 1;
#else
  (void)ev;
  (void)est;
  (void)out;
  (void)out_max;
  return 0;
#endif
}
