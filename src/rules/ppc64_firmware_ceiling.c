// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: ppc64 firmware reserved-region ceiling.
//
// OPAL (PowerNV)
// and RTAS (pseries) occupy physically contiguous firmware regions in the
// first few GiB; the kernel image must fit below them. On ppc64 PHYS_OFFSET =
// TEXT_OFFSET = 0 and the base is PAGE_OFFSET (no mainline KASLR), so
// phys_to_directmap_virt(x) = PAGE_OFFSET + x = KASLR_VIRT_TEXT_MIN + x,
// giving:
//
//   virt_ceiling = KASLR_VIRT_TEXT_MIN + fw_base - MIN_IMAGE_SIZE
//
// The kernel must fit below BOTH firmware regions, so the bridge supplies the
// lower of the OPAL/RTAS bases (SF_PHYS_FW_RESERVED_BASE); the merged ceiling
// equals the tighter of the two bounds. C_UPPER_BOUND on Q_VIRT_TEXT_BASE.
// ppc64 only; emits nothing when no firmware base is present.
// ---
// <bcoles@gmail.com>

#include "../include/kasld/engine_rules.h"

#include <string.h>

/* Conservative lower bound on the kernel image size; keeps the ceiling sound.
 */
#define MIN_IMAGE_SIZE (16UL * 1024 * 1024)

int rule_ppc64_firmware_ceiling(const struct evidence_set *ev,
                                const struct estimate *est,
                                struct constraint *out, int out_max) {
  (void)est;
#if !defined(__powerpc64__)
  (void)ev;
  (void)out;
  (void)out_max;
  return 0;
#else
  if (out_max < 1)
    return 0;

  unsigned long fw_base = 0;
  enum kasld_confidence conf = CONF_UNKNOWN;
  uint32_t src = 0;
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (o->valid && o->value_kind == OBS_SCALAR &&
        o->scalar_fact == SF_PHYS_FW_RESERVED_BASE) {
      fw_base = o->scalar_value;
      conf = o->conf;
      src = o->id;
      break;
    }
  }
  if (fw_base <= MIN_IMAGE_SIZE)
    return 0;

  unsigned long ceiling = KASLR_VIRT_TEXT_MIN + fw_base - MIN_IMAGE_SIZE;
  if (KASLR_VIRT_ALIGN > 0)
    ceiling &= ~(KASLR_VIRT_ALIGN - 1);
  if (ceiling <= KASLR_VIRT_TEXT_MIN)
    return 0;

  struct constraint *c = &out[0];
  memset(c, 0, sizeof(*c));
  c->q = Q_VIRT_TEXT_BASE;
  c->op = C_UPPER_BOUND;
  c->value = ceiling;
  c->conf = conf;
  c->derived_from[0] = src;
  c->lineage_count = 1;
  snprintf(c->origin, ORIGIN_LEN, "ppc64_firmware_ceiling");
  return 1;
#endif
}
