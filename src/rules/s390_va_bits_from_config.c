// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: s390 paging level, computed the way the kernel computes it.
//
// s390 does not expose its ASCE limit, and it cannot be measured: an mmap
// boundary probe reads the USER address space, which is per-mm, starts at
// _REGION2_SIZE for every process and grows on demand, so it reports the
// 4-level width whatever the kernel chose. See the note beside
// VA_BITS_CANDIDATES in s390.h.
//
// The level is not measured here either. It is DERIVED, by reproducing the
// decision the boot code makes. arch/s390/boot/startup.c
// setup_kernel_memory_layout() takes the 4-level limit when
//
//     IS_ENABLED(CONFIG_KASAN)
//     || __NO_KASLR_END_KERNEL > _REGION2_SIZE
//     || (vsize > _REGION2_SIZE && kaslr_enabled())
//
// and the 3-level limit otherwise, where __NO_KASLR_END_KERNEL is
// CONFIG_KERNEL_IMAGE_BASE + KERNEL_IMAGE_SIZE (asm/page.h).
//
// The first two disjuncts are parsed facts already in evidence:
// SF_KASAN_ENABLED and SF_VIRT_KERNEL_IMAGE_BASE, both from a readable kernel
// config. Either one being true PROVES the 4-level limit.
//
// BOTH DIRECTIONS, but they are not symmetric and the asymmetry shapes the
// code. Proving 4-level needs any SINGLE disjunct, and the first two are
// parsed outright. Proving 3-level needs ALL THREE false, so it additionally
// has to bound the vmem estimate from above.
//
// The estimate is get_vmem_size(), called with _REGION3_SIZE as its rounding
// granularity:
//
//     max_mappable = max(identity_size, MAX_DCSS_ADDR)
//     vsize = round_up(SZ_2G + max_mappable, rte)
//           + round_up(vmemmap_size, rte)
//           + FIXMAP_SIZE + MODULES_LEN + KASLR_LEN
//           + (CONFIG_KMSAN ? MODULES_LEN * 2 : 0)
//           + vmalloc_size
//
// Every term here is bounded from ABOVE, which is what makes the direction
// safe: overestimating vsize makes `vsize <= _REGION2_SIZE` HARDER to satisfy,
// so an error inflates the estimate and the rule declines. It cannot inflate
// its way into asserting 3-level. Terms whose exact value is not worth
// recovering are therefore given generous constants rather than modelled:
// FIXMAP_SIZE measures a few MiB against a 4 TiB threshold, and the KMSAN
// term is added unconditionally rather than read from a fact.
//
// THE ONE TERM THAT IS AN ASSUMPTION, AND IT IS DELIBERATE. identity_size
// comes from SF_PHYS_MAX_PFN, which is the highest ONLINE spanned frame from
// /proc/zoneinfo. The kernel's ident_map_size derives from max_physmem_end --
// memory DETECTED, not memory online. A machine holding memory above the last
// online zone therefore has a larger ident_map_size than this rule can see,
// and the rule would under-count vsize. Three things bound that risk, and none
// of them is a proof:
//   * max_mappable is max(identity_size, MAX_DCSS_ADDR = 512 GiB), so
//     identity_size does not enter the estimate at all until it passes 512
//     GiB. Below that the term is a constant and the reading cannot be wrong.
//   * Reaching the 4 TiB threshold needs roughly 3 TiB of memory unseen by
//     zoneinfo, against a computed estimate near 1 TiB on an ordinary guest.
//   * s390_image_base_from_config already treats SF_PHYS_MAX_PFN as the
//     principled top of RAM at CONF_PARSED, so the same reading is load
//     bearing elsewhere in the engine; this rule does not introduce it.
// What would falsify it: an s390 guest with present-but-offline memory above
// the last online zone, enough of it to carry vsize past _REGION2_SIZE, where
// this rule still concludes 3-level. That is the case to construct if the
// conclusion is ever doubted.
//
// The vmalloc term needs SF_CMDLINE_VMALLOC and cannot be defaulted: the boot
// parser accepts any size and rounds it up, so an unread command line leaves
// the estimate unbounded above. The fact's absence is that state, and the rule
// declines on it rather than assuming the compile-time default.
//
// A third route to the same conclusion needs no estimate at all: the disjunct
// is `vsize > _REGION2_SIZE && kaslr_enabled()`, so a confirmed KASLR-off
// signal falsifies it outright whatever the memory layout.
//
// Modern layout only. Both disjuncts describe code that arrived with
// CONFIG_KERNEL_IMAGE_BASE itself; a kernel predating it lays memory out
// differently and reports the knob absent as a zero, which gates this rule off.
//
// s390 only; inert elsewhere, and inert without a readable config.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"

#include <string.h>

#if defined(__s390x__) || defined(__zarch__)
/* round_up(x, a) for a power-of-two a, the form get_vmem_size() uses. Local
 * because nothing else in the engine rounds up: every other consumer aligns
 * DOWN, which is the safe direction for a bound and the wrong one here. */
static unsigned long s390_round_up(unsigned long x, unsigned long a) {
  return (x + a - 1ul) & ~(a - 1ul);
}
#endif

int rule_s390_va_bits_from_config(const struct evidence_set *ev,
                                  const struct estimate *est,
                                  struct constraint *out, int out_max) {
#if defined(__s390x__) || defined(__zarch__)
  (void)est;
  if (out_max < 1)
    return 0;

  int have_base = 0, have_kasan = 0, have_pfn = 0, have_vmalloc = 0;
  int kaslr_off = 0;
  unsigned long image_base = 0, kasan = 0, max_pfn = 0, vmalloc_size = 0;
  /* sizeof(struct page) enters only through the vmemmap term, which is rounded
   * up to a 2 GiB granularity, so an over-estimate here is absorbed long before
   * it reaches the threshold. 256 is far above the mainline 64 and keeps the
   * bound an upper one when BTF did not supply the exact value. */
  unsigned long struct_page = 256ul;
  uint32_t base_src = 0, kasan_src = 0, pfn_src = 0, vmalloc_src = 0;
  uint32_t kaslr_off_src = 0;
  enum kasld_confidence base_conf = CONF_UNKNOWN, kasan_conf = CONF_UNKNOWN,
                        pfn_conf = CONF_UNKNOWN, vmalloc_conf = CONF_UNKNOWN,
                        kaslr_off_conf = CONF_UNKNOWN;

  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->value_kind != OBS_SCALAR)
      continue;
    switch (o->scalar_fact) {
    case SF_VIRT_KERNEL_IMAGE_BASE:
      have_base = 1;
      image_base = o->scalar_value;
      base_src = o->id;
      base_conf = o->conf;
      break;
    case SF_KASAN_ENABLED:
      have_kasan = 1;
      kasan = o->scalar_value;
      kasan_src = o->id;
      kasan_conf = o->conf;
      break;
    case SF_PHYS_MAX_PFN:
      have_pfn = 1;
      max_pfn = o->scalar_value;
      pfn_src = o->id;
      pfn_conf = o->conf;
      break;
    case SF_CMDLINE_VMALLOC:
      have_vmalloc = 1;
      vmalloc_size = o->scalar_value;
      vmalloc_src = o->id;
      vmalloc_conf = o->conf;
      break;
    case SF_STRUCT_PAGE_BYTES:
      if (o->scalar_value >= 1 && o->scalar_value <= (1ul << 20))
        struct_page = o->scalar_value;
      break;
    case SF_VIRT_KASLR_DISABLED:
      if (o->scalar_value != 0) {
        kaslr_off = 1;
        kaslr_off_src = o->id;
        kaslr_off_conf = o->conf;
      }
      break;
    default:
      break;
    }
  }

  /* A zero is the knob's absence, which is the pre-uncoupled layout: the
   * decision reproduced below is not the one that kernel makes. */
  if (!have_base || image_base == 0)
    return 0;

  uint32_t src = 0;
  enum kasld_confidence conf = CONF_UNKNOWN;

  /* Disjunct 2: the configured base puts the image's end above the 3-level
   * limit, so that limit cannot hold the image. Written as a subtraction so
   * the sum cannot overflow; S390_KERNEL_IMAGE_SIZE is far below the limit. */
  if (image_base > (unsigned long)S390_ASCE_LIMIT_3LEVEL -
                       (unsigned long)S390_KERNEL_IMAGE_SIZE) {
    src = base_src;
    conf = base_conf;
  } else if (kasan != 0) {
    /* Disjunct 1. The layout gate above is what makes this the right decision
     * to reproduce, so the config carries the conclusion jointly with the
     * KASAN flag and the weaker of the two bounds it. */
    src = kasan_src;
    conf = kasld_conf_min(kasan_conf, base_conf);
  } else {
    /* Neither parsed disjunct holds, so the level is 3 iff the third is false
     * too. Falsifying it needs either a confirmed KASLR-off signal -- the
     * disjunct is conjoined with kaslr_enabled() -- or the vmem estimate
     * bounded below _REGION2_SIZE. Both branches need the KASAN fact to have
     * been READ rather than merely absent: an unread config leaves the first
     * disjunct open and nothing can be concluded. */
    if (!have_kasan)
      return 0;

    if (kaslr_off) {
      conf =
          kasld_conf_min(kasld_conf_min(base_conf, kasan_conf), kaslr_off_conf);
      src = base_src;
    } else {
      unsigned long page_size, ident, mappable, vmemmap, vmalloc_up, vsize;

      /* Every input required: a missing one is an unbounded term, not a
       * default. SF_CMDLINE_VMALLOC's absence in particular means the command
       * line was never read, which leaves `vmalloc=` free to be any size. */
      if (!have_pfn || !have_vmalloc)
        return 0;
      page_size = kasld_page_size_observed(ev, NULL, NULL);
      if (page_size == 0)
        page_size = (unsigned long)PAGE_SIZE_MIN;
      if (max_pfn >= (~0ul / page_size) - 1ul)
        return 0; /* implausible frame count; refuse rather than wrap */

      ident = (max_pfn + 1ul) * page_size;
      mappable = ident > (unsigned long)S390_MAX_DCSS_ADDR
                     ? ident
                     : (unsigned long)S390_MAX_DCSS_ADDR;

      /* round_up(SZ_2G + max_mappable, rte) */
      vsize = s390_round_up(2ul * GB + mappable, S390_REGION3_SIZE);

      /* round_up(vmemmap_size, rte), plus one granule to cover the
       * SECTION_ALIGN_UP inside vmemmap_size: a 128 MiB section is 32768
       * frames, so the rounding it can add is megabytes against this 2 GiB. */
      vmemmap =
          s390_round_up((ident / page_size) * struct_page, S390_REGION3_SIZE) +
          S390_REGION3_SIZE;
      vsize += vmemmap;

      /* FIXMAP_SIZE is a few MiB (a page plus NR_CPUS lowcores); one granule
       * covers it without modelling NR_CPUS. The KMSAN term is added whether
       * or not the config said so -- it is 4 GiB against a 4 TiB threshold,
       * and paying it unconditionally removes a fact this rule would
       * otherwise have to require. */
      vsize += S390_REGION3_SIZE;
      vsize += S390_MODULES_LEN + S390_KASLR_LEN;
      vsize += S390_MODULES_LEN * 2ul;

      vmalloc_up = vmalloc_size > 0
                       ? s390_round_up(vmalloc_size, S390_SEGMENT_SIZE)
                       : (unsigned long)S390_VMALLOC_DEFAULT_SIZE;
      vsize += vmalloc_up;

      if (vsize > (unsigned long)S390_ASCE_LIMIT_3LEVEL)
        return 0; /* cannot rule the disjunct out; the level stays open */

      conf = kasld_conf_min(kasld_conf_min(base_conf, kasan_conf),
                            kasld_conf_min(pfn_conf, vmalloc_conf));
      src = base_src;
    }

    struct constraint *c3 = &out[0];
    memset(c3, 0, sizeof(*c3));
    c3->q = Q_VA_BITS;
    c3->op = C_EQUALS;
    c3->value = 42ul; /* the width VA_BITS_CANDIDATES names for _REGION2_SIZE */
    c3->conf = conf;
    c3->lineage_count = 0;
    /* Ruling the condition out rests on EVERY fact that went into it, not just
     * the one the confidence came from: the advisor's exclusion projection
     * drops a constraint by its lineage, so a fact left off here would leave
     * this conclusion standing in a vantage that no longer supports it. */
    {
      const uint32_t lin[] = {base_src, kasan_src, kaslr_off_src, pfn_src,
                              vmalloc_src};
      for (size_t li = 0; li < sizeof(lin) / sizeof(lin[0]); li++) {
        if (lin[li] == 0)
          continue;
        int dup = 0;
        for (int lj = 0; lj < c3->lineage_count; lj++)
          if (c3->derived_from[lj] == lin[li])
            dup = 1;
        if (!dup && c3->lineage_count < MAX_LINEAGE)
          c3->derived_from[c3->lineage_count++] = lin[li];
      }
    }
    snprintf(c3->origin, ORIGIN_LEN, "s390_va_bits_from_config");
    return 1;
  }

  struct constraint *c = &out[0];
  memset(c, 0, sizeof(*c));
  c->q = Q_VA_BITS;
  c->op = C_EQUALS;
  c->value = 53ul; /* the width VA_BITS_CANDIDATES names for _REGION1_SIZE */
  c->conf = conf;
  c->derived_from[0] = src;
  c->lineage_count = 1;
  if (src != base_src && base_src != 0)
    c->derived_from[c->lineage_count++] = base_src;
  snprintf(c->origin, ORIGIN_LEN, "s390_va_bits_from_config");
  return 1;
#else
  (void)ev;
  (void)est;
  (void)out;
  (void)out_max;
  return 0;
#endif
}
