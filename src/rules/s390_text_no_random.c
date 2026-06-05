// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: s390 phys-text upper bound when KASLR randomization failed.
//
// When the s390 boot stub's randomization fails (no PRNG, not enough
// memory), the kernel lands at a low, deterministic physical address
// rather than the KASLR-selected slot. The exact value depends on the
// kernel version:
//
//   Pre-v6.8 (identity-mapped layout):
//     phys_text = TEXT_OFFSET = 0x100000 (1 MiB exactly).
//     KASLR-off keeps the IPL-loaded image at the link-time LMA.
//
//   v6.8 → v6.10 (arch/s390/boot/startup.c uses nokaslr_offset_phys):
//     nokaslr_offset_phys = ALIGN(mem_safe_offset(), _SEGMENT_SIZE)
//     phys_text = nokaslr_offset_phys + TEXT_OFFSET (effectively
//     ALIGN(decompressor_heap_end, 1 MiB)).
//
//   v6.12+ (nokaslr_text_lma renamed, same algorithm):
//     text_lma = nokaslr_text_lma = ALIGN(mem_safe_offset(), _SEGMENT_SIZE)
//     __kaslr_offset_phys = text_lma − TEXT_OFFSET
//     phys_text base = text_lma (with kaslr_large_page_offset OR'd in,
//     which is 0 when kaslr is off).
//
// In every case the kernel sits in the LOW portion of physical memory:
// either at TEXT_OFFSET (pre-v6.8) or immediately above the decompressor
// heap (v6.8+). Worst-case decompressor heap is bounded by the compressor
// choice:
//   gzip:  ~64 KiB
//   xz:    typically 32 MiB dictionary
//   zstd:  ~128 MiB worst case
//
// S390_NO_RAND_PHYS_TEXT_MAX = 256 MiB is a conservative upper bound
// that admits every configuration the algorithm can produce, with a
// safety margin:
//   • Pre-v6.8 case (kernel at TEXT_OFFSET = 1 MiB)
//   • Typical compressed kernels (decompressor heap end ~10 MiB
//     after init)
//   • Worst-case zstd-compressed (~128 MiB peak heap)
//   • Uncompressed (_compressed_start) — implementation-dependent but
//     still in low memory
//
// CONF_HEURISTIC: the bound is sound by construction for known
// algorithms, but any CONF_PARSED leak (kallsyms, an iomem text pin,
// dmesg backtrace) overrides this. The rule's purpose is to narrow the
// otherwise-vast Q_PHYS_TEXT_BASE window (KERNEL_PHYS_MIN .. 64 GiB)
// down to the low-memory portion when only the dmesg signal is
// available — typical for low-priv s390 leak scenarios.
//
// Phase: POST_COLLECTION. Gated on s390 build + SF_PHYS_KASLR_RANDOMIZATION_
// FAILED scalar. Inert otherwise.
//
// References:
// arch/s390/boot/startup.c (nokaslr_text_lma / nokaslr_offset_phys)
// arch/s390/boot/decompressor.c (mem_safe_offset)
// arch/s390/boot/kaslr.c (get_random / check_prng failure paths)
// ---
// <bcoles@gmail.com>

#include "../include/kasld/engine_rules.h"

#include <string.h>

#if defined(__s390__) || defined(__s390x__)

/* Upper bound on phys_text_base when randomization failed. 256 MiB
 * covers every algorithm variant (pre-v6.8 fixed at 1 MiB; v6.8+
 * bounded by decompressor heap end aligned to 1 MiB). */
#define S390_NO_RAND_PHYS_TEXT_MAX (256ul * 1024ul * 1024ul)

int rule_s390_text_no_random(const struct evidence_set *ev,
                             const struct estimate *est, struct constraint *out,
                             int out_max) {
  (void)est;
  if (out_max < 1)
    return 0;

  uint32_t sig_id = 0;
  enum kasld_confidence sig_conf = CONF_UNKNOWN;
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->value_kind != OBS_SCALAR)
      continue;
    if (o->scalar_fact == SF_PHYS_KASLR_RANDOMIZATION_FAILED &&
        o->scalar_value != 0) {
      sig_id = o->id;
      sig_conf = o->conf;
      break;
    }
  }
  if (sig_id == 0)
    return 0;

  struct constraint *c = &out[0];
  memset(c, 0, sizeof(*c));
  c->q = Q_PHYS_TEXT_BASE;
  c->op = C_UPPER_BOUND;
  c->value = S390_NO_RAND_PHYS_TEXT_MAX;
  /* CONF_HEURISTIC: deferred to by any CONF_PARSED leak. Take the
   * weaker of CONF_HEURISTIC and the signal's confidence (so a
   * lower-confidence signal source doesn't get artificially upgraded). */
  c->conf = sig_conf < CONF_HEURISTIC ? sig_conf : CONF_HEURISTIC;
  c->derived_from[0] = sig_id;
  c->lineage_count = 1;
  snprintf(c->origin, ORIGIN_LEN, "s390_text_no_random");
  return 1;
}

#else /* !s390 */

int rule_s390_text_no_random(const struct evidence_set *ev,
                             const struct estimate *est, struct constraint *out,
                             int out_max) {
  (void)ev;
  (void)est;
  (void)out;
  (void)out_max;
  return 0;
}

#endif
