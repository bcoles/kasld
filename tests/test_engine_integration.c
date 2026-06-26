// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Full-engine integration test: feed a realistic, mutually-consistent set of
// leaked observations + scalar facts through the ENTIRE production rule
// registry (engine_rules / engine_verdict_rules — the same lists the
// orchestrator runs) and assert the resolved estimates are SOUND:
//   - non-bottom (lo <= hi) for every interval quantity;
//   - the planted ground-truth value stays inside each resolved range
//     (the critical invariant — no rule may over-tighten past the truth);
//   - the engine actually narrowed from the honest top (the rules fired and
//     interacted through the fixpoint, not just sat inert).
//
// The per-rule unit tests exercise rules in isolation; this exercises their
// interaction + cross-quantity dependencies on leak-bearing input the offline
// replay corpus cannot provide. x86_64 host only (the registry is compiled for
// the build arch); the planted scenario is an x86_64 layout.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine.h"
#include "include/kasld/engine_rules.h"
#include "include/kasld/regions.h"
#include "test_harness.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void add_addr(struct engine *e, enum kasld_addr_type type,
                     enum kasld_region region, unsigned long lo,
                     unsigned long hi, const char *name) {
  struct observation o;
  memset(&o, 0, sizeof(o));
  o.value_kind = OBS_ADDRESS;
  o.type = type;
  o.region = region;
  o.lo = lo;
  o.sample = lo;
  o.set_mask = LO_SET | SAMPLE_SET;
  if (hi) {
    o.hi = hi;
    o.set_mask |= HI_SET;
  }
  o.pos = POS_BASE;
  o.conf = CONF_PARSED;
  if (name)
    snprintf(o.name, NAME_LEN, "%s", name);
  evidence_add(&e->ev, &o);
}

/* add_addr with an explicit confidence — for exercising confidence-ordered
 * conflict resolution (a parsed source must beat an inferred one regardless of
 * which is captured first). Used only by arch-gated tests, so unused on hosts
 * whose arch compiles none of them out. */
__attribute__((unused)) static void
add_addr_conf(struct engine *e, enum kasld_addr_type type,
              enum kasld_region region, unsigned long lo, unsigned long hi,
              enum kasld_confidence conf, const char *name) {
  struct observation o;
  memset(&o, 0, sizeof(o));
  o.value_kind = OBS_ADDRESS;
  o.type = type;
  o.region = region;
  o.lo = lo;
  o.sample = lo;
  o.set_mask = LO_SET | SAMPLE_SET;
  if (hi) {
    o.hi = hi;
    o.set_mask |= HI_SET;
  }
  o.pos = POS_BASE;
  o.conf = conf;
  if (name)
    snprintf(o.name, NAME_LEN, "%s", name);
  evidence_add(&e->ev, &o);
}

/* Top-edge twin of add_addr: emits an observation with pos=top and only the
 * upper extent set (HI_SET, no LO/SAMPLE). Used to model firmware-style
 * ceiling signals — linux,kernel-end and linux,memory-limit. Used only by
 * arch-gated tests (ppc64/riscv64), so unused on other hosts. */
__attribute__((unused)) static void add_addr_top(struct engine *e,
                                                 enum kasld_addr_type type,
                                                 enum kasld_region region,
                                                 unsigned long hi) {
  struct observation o;
  memset(&o, 0, sizeof(o));
  o.value_kind = OBS_ADDRESS;
  o.type = type;
  o.region = region;
  o.hi = hi;
  o.set_mask = HI_SET;
  o.pos = POS_TOP;
  o.conf = CONF_PARSED;
  evidence_add(&e->ev, &o);
}

static void add_scalar(struct engine *e, enum kasld_scalar_fact f,
                       unsigned long v) {
  struct observation o;
  memset(&o, 0, sizeof(o));
  o.value_kind = OBS_SCALAR;
  o.scalar_fact = f;
  o.scalar_value = v;
  o.conf = CONF_PARSED;
  evidence_add(&e->ev, &o);
}

static int contains(const struct estimate *e, unsigned long v) {
  return e->lo <= v && v <= e->hi;
}

/* A consistent x86_64 KASLR placement and the leaks a real run might gather. */
static void test_full_engine_x86_64_leaky(void) {
#if defined(__x86_64__)
  const unsigned long T = 0xffffffff8a000000ul;  /* true virt text base   */
  const unsigned long P = 0x10000000ul;          /* true phys base (256M) */
  const unsigned long PO = 0xffff888000000000ul; /* L4 virt_page_offset_base */
  const unsigned long gap = 0x1400000ul;         /* 20 MiB text..data     */

  struct engine e;
  engine_init(&e);

  /* Leaks the rules consume (all consistent with T/P/PO). */
  add_addr(&e, KASLD_TYPE_PHYS, REGION_KERNEL_TEXT, P, 0, "_stext");
  add_addr(&e, KASLD_TYPE_VIRT, REGION_KERNEL_TEXT, T, 0, "_stext");
  add_addr(&e, KASLD_TYPE_VIRT, REGION_KERNEL_DATA, T + gap, 0, "_edata");
  add_addr(&e, KASLD_TYPE_VIRT, REGION_DIRECTMAP, PO + 0x10000000ul, 0, NULL);
  add_addr(&e, KASLD_TYPE_PHYS, REGION_RAM, 0x0ul, 0x7ffffffful, NULL);
  add_addr(&e, KASLD_TYPE_PHYS, REGION_PCI_MMIO, 0xfe000000ul, 0xfefffffful,
           NULL);
  add_scalar(&e, SF_PHYS_MEMTOTAL, 0x80000000ul); /* 2 GiB */
  add_scalar(&e, SF_IMAGE_SIZE_MIN, gap);         /* image ~ text..data span */
  add_scalar(&e, SF_PHYS_ADDR_BITS, 46);
  add_scalar(&e, SF_PHYS_KERNEL_ALIGN, 0x200000ul);

  int nr = 0, nv = 0;
  const rule_fn *rules = engine_rules(&nr);
  const verdict_fn *vrules = engine_verdict_rules(&nv);
  engine_run_full(&e, rules, nr, vrules, nv);

  const struct quantity_def *qd = quantities;

  /* Soundness: every interval quantity is non-bottom and still admits truth. */
  const struct estimate *vt = &e.est[Q_VIRT_IMAGE_BASE];
  const struct estimate *pt = &e.est[Q_PHYS_IMAGE_BASE];
  const struct estimate *po = &e.est[Q_PAGE_OFFSET];
  assert(!estimate_is_bottom(vt, &qd[Q_VIRT_IMAGE_BASE]));
  assert(!estimate_is_bottom(pt, &qd[Q_PHYS_IMAGE_BASE]));
  assert(!estimate_is_bottom(po, &qd[Q_PAGE_OFFSET]));
  assert(contains(vt, T)); /* must not over-tighten past the true text base */
  assert(contains(pt, P)); /* ... nor the true phys base */
  assert(contains(po, PO));

  /* Liveness: the rules fired and narrowed each quantity from its honest top.
   */
  struct estimate top;
  qd[Q_VIRT_IMAGE_BASE].init_top(&top);
  assert(vt->hi < top.hi); /* image_size_text_data_gap ceiling */
  qd[Q_PHYS_IMAGE_BASE].init_top(&top);
  assert(pt->hi < top.hi); /* kernel_image_phys_bound / mmio / memtotal */
  qd[Q_PAGE_OFFSET].init_top(&top);
  assert(po->hi < top.hi); /* directmap_page_offset_bounds */
#endif
}

/* A hardened ppc64le system with KASLR disabled and no /proc/iomem leak:
 * the only phys observation is `P initrd pos=base lo=0x2c90000` (from
 * devicetree). The kernel sits at phys 0 (well below the initrd) —
 * the lowest-address dram-section observation does NOT mark the RAM
 * floor when it comes from a non-RAM region. dram_floor_bound must
 * scope its floor scan to REGION_RAM observations only; widening it to
 * is_phys_dram_region(...) would pin Q_PHYS_IMAGE_BASE.lo to 0x2c90000
 * and exclude the actual kernel-at-phys-0 placement. */
static void test_full_engine_ppc64_hardened_shape(void) {
#if defined(__powerpc64__) || defined(__ppc64__)
  struct engine e;
  engine_init(&e);
  add_scalar(&e, SF_VIRT_KASLR_DISABLED, 0x1);
  add_scalar(&e, SF_PHYS_KASLR_DISABLED, 0x1);
  add_scalar(&e, SF_VIRT_CONFIG_PAGE_OFFSET, 0xc000000000000000ul);
  add_scalar(&e, SF_EFI_PRESENT, 0x0);
  add_scalar(&e, SF_PHYS_MEMTOTAL, 0x7a04d000ul);
  add_scalar(&e, SF_PHYS_MAX_PFN, 0x80000ul);
  add_scalar(&e, SF_PAGE_SIZE, 0x1000ul);
  add_addr(&e, KASLD_TYPE_VIRT, REGION_PAGE_OFFSET, 0xc000000000000000ul, 0,
           NULL);
  add_addr(&e, KASLD_TYPE_PHYS, REGION_INITRD, 0x2c90000ul, 0x4a4f1d6ul, NULL);

  int nr = 0, nv = 0;
  const rule_fn *rules = engine_rules(&nr);
  const verdict_fn *vrules = engine_verdict_rules(&nv);
  engine_run_full(&e, rules, nr, vrules, nv);

  /* Default ppc64le layout: text at phys 0 (image base) / virt
   * 0xc000000000000000; virt_page_offset at 0xc000000000000000. */
  const unsigned long t_virt = 0xc000000000000000ul;
  const unsigned long t_phys = 0x0ul;
  const unsigned long t_po = 0xc000000000000000ul;

  const struct estimate *vt = &e.est[Q_VIRT_IMAGE_BASE];
  const struct estimate *pt = &e.est[Q_PHYS_IMAGE_BASE];
  const struct estimate *po = &e.est[Q_PAGE_OFFSET];

  assert(!estimate_is_bottom(vt, &quantities[Q_VIRT_IMAGE_BASE]));
  assert(!estimate_is_bottom(pt, &quantities[Q_PHYS_IMAGE_BASE]));
  assert(!estimate_is_bottom(po, &quantities[Q_PAGE_OFFSET]));

  assert(vt->lo <= t_virt && t_virt <= vt->hi);
  assert(pt->lo <= t_phys && t_phys <= pt->hi);
  assert(po->lo <= t_po && t_po <= po->hi);
#endif
}

/* An s390 system whose dmesg contains `boot: KASLR disabled: CPU has no
 * PRNG`. That message means the s390 boot stub skipped the random offset,
 * but the image is still relocated to a runtime-determined virt position
 * derived from physical memory layout — it does NOT imply text sits at
 * KERNEL_VIRT_TEXT_DEFAULT. dmesg_kaslr_disabled emits this as
 * SF_VIRT_KASLR_RANDOMIZATION_FAILED (distinct from SF_VIRT_KASLR_DISABLED,
 * which the virt_/phys_kaslr_disabled_pin rule would honour);
 * virt_/phys_kaslr_disabled_pin therefore does NOT fire, and the engine
 * resolves Q_VIRT_IMAGE_BASE to a wide window that admits the runtime-relocated
 * _stext. Were the no-PRNG line miscategorised as SF_VIRT_KASLR_DISABLED, the
 * engine would pin to KERNEL_VIRT_TEXT_DEFAULT (0x3FFE0100000) and exclude any
 * _stext displaced by the runtime relocation (e.g. 0x3FFFE6A0000, ~8 GiB above
 * the default).
 *
 * The test plants the scalars a low-priv s390 system would emit when
 * dmesg contains the no-PRNG line (notably without SF_VIRT_KASLR_DISABLED)
 * and asserts the resolved windows admit the displaced text base. */
static void test_full_engine_s390_no_prng_shape(void) {
#if defined(__s390__) || defined(__s390x__)
  struct engine e;
  engine_init(&e);
  add_scalar(&e, SF_EFI_PRESENT, 0x0);
  add_scalar(&e, SF_IMAGE_SIZE_MIN, 0x126046cul);
  add_scalar(&e, SF_PHYS_MEMTOTAL, 0x7bd9e000ul);
  add_scalar(&e, SF_PHYS_MAX_PFN, 0x80000ul);
  add_scalar(&e, SF_PAGE_SIZE, 0x1000ul);
  add_scalar(&e, SF_VIRT_ADDR_BITS, 0x35ul); /* 53 = s390 4-level paging */

  int nr = 0, nv = 0;
  const rule_fn *rules = engine_rules(&nr);
  const verdict_fn *vrules = engine_verdict_rules(&nv);
  engine_run_full(&e, rules, nr, vrules, nv);

  /* Sample displaced text base derived from runtime layout; the engine's
   * resolved window must admit it (and any other plausible displaced
   * value within the s390 KASLR window). */
  const unsigned long t_virt = 0x3fffe6a0000ul;
  const unsigned long t_phys = 0xaa0000ul;

  const struct estimate *vt = &e.est[Q_VIRT_IMAGE_BASE];
  const struct estimate *pt = &e.est[Q_PHYS_IMAGE_BASE];

  assert(!estimate_is_bottom(vt, &quantities[Q_VIRT_IMAGE_BASE]));
  assert(!estimate_is_bottom(pt, &quantities[Q_PHYS_IMAGE_BASE]));
  /* With SF_VIRT_KASLR_DISABLED erroneously emitted, vt would collapse to
   * [KERNEL_VIRT_TEXT_DEFAULT, KERNEL_VIRT_TEXT_DEFAULT] and t_virt would fall
   * outside. The exemption keeps the signal off and the window admits
   * the displaced text base. */
  assert(vt->lo <= t_virt && t_virt <= vt->hi);
  assert(pt->lo <= t_phys && t_phys <= pt->hi);
#endif
}

/* A no-KASLR arm32 system (CONFIG_RANDOMIZE_BASE is not available on
 * arm32; the kernel always loads at PAGE_OFFSET + IMAGE_BASE_OFFSET + head).
 * On any 32-bit arch, expressions like `4 * GB` in the arch header
 * overflow an `unsigned long` to 0 and collapse Q_PHYS_IMAGE_BASE's
 * honest-top to a bottom interval (lo > hi). The bottom then propagates
 * via text_base_coupling_synth onto Q_VIRT_IMAGE_BASE on coupled arches.
 *
 * The test plants the scalars a low-priv arm32 system emits when only
 * boot_config (PAGE_OFFSET, KASLR off) and meminfo are readable, and
 * asserts the resolved windows are non-bottom and admit the true text
 * placement. Pinned the moment any arch header introduces a 32-bit
 * overflow in its KERNEL_PHYS_MAX (or any rule that depends on it). */
static void test_full_engine_arm32_no_kaslr_shape(void) {
#if defined(__arm__) && !defined(__aarch64__)
  struct engine e;
  engine_init(&e);
  add_scalar(&e, SF_EFI_PRESENT, 0x0);
  add_scalar(&e, SF_PHYS_MEMTOTAL, 0xf4e4000ul); /* ~ 250 MiB */
  add_scalar(&e, SF_PHYS_MAX_PFN, 0x10000ul);
  add_scalar(&e, SF_PAGE_SIZE, 0x1000ul);
  add_scalar(&e, SF_VIRT_KASLR_DISABLED, 0x1);
  add_scalar(&e, SF_PHYS_KASLR_DISABLED, 0x1);
  add_addr(&e, KASLD_TYPE_VIRT, REGION_PAGE_OFFSET, 0xc0000000ul, 0, NULL);

  int nr = 0, nv = 0;
  const rule_fn *rules = engine_rules(&nr);
  const verdict_fn *vrules = engine_verdict_rules(&nv);
  engine_run_full(&e, rules, nr, vrules, nv);

  /* Default arm32 layout: _stext sits at PAGE_OFFSET + IMAGE_BASE_OFFSET + head
   * (a small head-asm offset), phys text at IMAGE_BASE_OFFSET above RAM_BASE
   * (= 0x8000 on the standard layout). The resolved windows must remain
   * non-bottom and admit these. */
  const unsigned long t_virt = 0xc0008220ul;
  const unsigned long t_phys = 0x8000ul;
  const unsigned long t_po = 0xc0000000ul;

  const struct estimate *vt = &e.est[Q_VIRT_IMAGE_BASE];
  const struct estimate *pt = &e.est[Q_PHYS_IMAGE_BASE];
  const struct estimate *po = &e.est[Q_PAGE_OFFSET];

  assert(!estimate_is_bottom(vt, &quantities[Q_VIRT_IMAGE_BASE]));
  assert(!estimate_is_bottom(pt, &quantities[Q_PHYS_IMAGE_BASE]));
  assert(!estimate_is_bottom(po, &quantities[Q_PAGE_OFFSET]));

  assert(vt->lo <= t_virt && t_virt <= vt->hi);
  assert(pt->lo <= t_phys && t_phys <= pt->hi);
  assert(po->lo <= t_po && t_po <= po->hi);
#endif
}

/* A typical i686 system: KASLR enabled, virt_page_offset and
 * CONFIG_PHYSICAL_START readable from /boot/config, BIOS e820 readable from
 * /sys/kernel/boot_params, zoneinfo + firmware/memmap readable. x86_32 is
 * coupled (TEXT_TRACKS_DIRECTMAP = 1) so the resolved Q_VIRT_IMAGE_BASE window
 * tracks the resolved Q_PHYS_IMAGE_BASE window via the compile-time PAGE_OFFSET
 * / PHYS_OFFSET / IMAGE_BASE_OFFSET projection. The test plants the scalars +
 * phys extents an unprivileged i686 user reads and asserts the resolved windows
 * remain non-bottom and admit a representative KASLR slid placement
 * (phys text + 96 MiB above CONFIG_PHYSICAL_START = 16 MiB → 112 MiB
 * absolute, virt = virt_page_offset + same). */
static void test_full_engine_i686_kaslr_shape(void) {
#if defined(__i386__) || defined(__i686__)
  struct engine e;
  engine_init(&e);
  add_scalar(&e, SF_EFI_PRESENT, 0x0);
  add_scalar(&e, SF_VIRT_CONFIG_PAGE_OFFSET, 0xc0000000ul);
  add_scalar(&e, SF_PHYSICAL_START, 0x1000000ul);    /* 16 MiB */
  add_scalar(&e, SF_PHYS_KERNEL_ALIGN, 0x1000000ul); /* 16 MiB slot */
  add_scalar(&e, SF_IMAGE_SIZE_MIN, 0x10f4000ul); /* ~17 MiB (exact source: */
  add_scalar(&e, SF_IMAGE_SIZE_MAX, 0x10f4000ul); /* emits both MIN and MAX) */
  add_scalar(&e, SF_PHYS_MEMTOTAL, 0x3e4da000ul);
  add_scalar(&e, SF_PHYS_LOWMEM, 0x350f8000ul);
  add_scalar(&e, SF_PHYS_MAX_PFN, 0x3ffe0ul);
  add_scalar(&e, SF_PAGE_SIZE, 0x1000ul);
  add_scalar(&e, SF_PHYS_ADDR_BITS, 0x24ul);
  add_addr(&e, KASLD_TYPE_VIRT, REGION_PAGE_OFFSET, 0xc0000000ul, 0, NULL);
  add_addr(&e, KASLD_TYPE_PHYS, REGION_RAM, 0x100000ul, 0x3ffdfffful, NULL);
  add_addr(&e, KASLD_TYPE_PHYS, REGION_INITRD, 0x3e9f8000ul, 0x3ffdf9e0ul,
           NULL);

  int nr = 0, nv = 0;
  const rule_fn *rules = engine_rules(&nr);
  const verdict_fn *vrules = engine_verdict_rules(&nv);
  engine_run_full(&e, rules, nr, vrules, nv);

  /* Representative KASLR-slid placement. */
  const unsigned long t_virt = 0xc6000000ul; /* virt_page_offset + 96 MiB */
  const unsigned long t_phys =
      0x06000000ul; /* CONFIG_PHYSICAL_START + 80 MiB slide */
  const unsigned long t_po = 0xc0000000ul;

  const struct estimate *vt = &e.est[Q_VIRT_IMAGE_BASE];
  const struct estimate *pt = &e.est[Q_PHYS_IMAGE_BASE];
  const struct estimate *po = &e.est[Q_PAGE_OFFSET];

  assert(!estimate_is_bottom(vt, &quantities[Q_VIRT_IMAGE_BASE]));
  assert(!estimate_is_bottom(pt, &quantities[Q_PHYS_IMAGE_BASE]));
  assert(!estimate_is_bottom(po, &quantities[Q_PAGE_OFFSET]));

  assert(vt->lo <= t_virt && t_virt <= vt->hi);
  assert(pt->lo <= t_phys && t_phys <= pt->hi);
  assert(po->lo <= t_po && t_po <= po->hi);
#endif
}

/* Same scenario but with a deliberately-bogus extra PHYS candidate far above
 * RAM: the engine must stay sound (truth still admitted, non-bottom). */
static void test_full_engine_robust_to_outlier(void) {
#if defined(__x86_64__)
  const unsigned long P = 0x10000000ul;
  struct engine e;
  engine_init(&e);
  add_addr(&e, KASLD_TYPE_PHYS, REGION_KERNEL_TEXT, P, 0, "_stext");
  add_addr(&e, KASLD_TYPE_PHYS, REGION_RAM, 0x0ul, 0x7ffffffful, NULL);
  /* Outlier far above DRAM — a bad leak. */
  add_addr(&e, KASLD_TYPE_PHYS, REGION_KERNEL_TEXT, 0x40000000000ul, 0, "bad");
  add_scalar(&e, SF_PHYS_MEMTOTAL, 0x80000000ul);

  int nr = 0, nv = 0;
  const rule_fn *rules = engine_rules(&nr);
  const verdict_fn *vrules = engine_verdict_rules(&nv);
  engine_run_full(&e, rules, nr, vrules, nv);

  const struct estimate *pt = &e.est[Q_PHYS_IMAGE_BASE];
  assert(!estimate_is_bottom(pt, &quantities[Q_PHYS_IMAGE_BASE]));
  assert(pt->lo <= P && P <= pt->hi); /* truth survives the outlier */
#endif
}

/* PowerPC firmware writes linux,kernel-end (phys address one byte past the
 * loaded kernel image). The sysfs_devicetree_kernel_end component emits it as
 * `P REGION_KERNEL_IMAGE pos=top hi=<kend>`; kernel_image_phys_bound then uses
 * obs_anchor() (which returns hi for a top-only observation) to tighten
 * Q_PHYS_IMAGE_BASE.hi.
 *
 * Plant a low kernel-end (24 MiB) on a ppc64 layout and assert the upper
 * bound lands at or below that — the engine's honest top for Q_PHYS_IMAGE_BASE
 * is far higher, so the rule firing on this signal is the only path that can
 * produce hi <= 24 MiB. */
static void test_full_engine_ppc_kernel_end_tightens(void) {
#if defined(__powerpc64__) || defined(__ppc64__)
  const unsigned long kend = 0x1800000ul; /* 24 MiB */
  struct engine e;
  engine_init(&e);
  add_scalar(&e, SF_VIRT_KASLR_DISABLED, 0x1);
  add_scalar(&e, SF_PHYS_KASLR_DISABLED, 0x1);
  add_scalar(&e, SF_VIRT_CONFIG_PAGE_OFFSET, 0xc000000000000000ul);
  add_addr(&e, KASLD_TYPE_VIRT, REGION_PAGE_OFFSET, 0xc000000000000000ul, 0,
           NULL);
  add_addr_top(&e, KASLD_TYPE_PHYS, REGION_KERNEL_IMAGE, kend);

  int nr = 0, nv = 0;
  const rule_fn *rules = engine_rules(&nr);
  const verdict_fn *vrules = engine_verdict_rules(&nv);
  engine_run_full(&e, rules, nr, vrules, nv);

  const struct estimate *pt = &e.est[Q_PHYS_IMAGE_BASE];
  assert(!estimate_is_bottom(pt, &quantities[Q_PHYS_IMAGE_BASE]));
  /* phys text base sits at or before the kernel image's last-byte witness. */
  assert(pt->hi <= kend);
  /* And the true placement (phys 0 for the ppc64 default layout) is admitted.
   */
  assert(pt->lo <= 0ul && 0ul <= pt->hi);
#endif
}

/* PowerPC firmware writes linux,memory-limit (the RAM ceiling honoured by the
 * kernel, set by mem= cmdline cap or firmware override). The
 * sysfs_devicetree_memory_limit component emits it as
 * `P REGION_RAM pos=top hi=limit-1`; dram_ceiling reads max(o->hi) across RAM
 * observations and projects it through SF_IMAGE_SIZE_MIN to tighten
 * Q_VIRT_IMAGE_BASE.hi on coupled arches (ppc64 is coupled).
 *
 * Plant a 128 MiB cap on a ppc64 layout and assert Q_VIRT_IMAGE_BASE.hi lands
 * below KERNEL_VIRT_TEXT_DEFAULT + the cap — i.e. dram_ceiling fired and
 * projected the cap. */
static void test_full_engine_ppc_memory_limit_caps_dram(void) {
#if defined(__powerpc64__) || defined(__ppc64__)
  const unsigned long limit = 0x08000000ul; /* 128 MiB */
  const unsigned long ksize = 0x00800000ul; /* 8 MiB image */
  struct engine e;
  engine_init(&e);
  add_scalar(&e, SF_VIRT_KASLR_DISABLED, 0x1);
  add_scalar(&e, SF_PHYS_KASLR_DISABLED, 0x1);
  add_scalar(&e, SF_VIRT_CONFIG_PAGE_OFFSET, 0xc000000000000000ul);
  add_scalar(&e, SF_IMAGE_SIZE_MIN, ksize);
  add_addr(&e, KASLD_TYPE_VIRT, REGION_PAGE_OFFSET, 0xc000000000000000ul, 0,
           NULL);
  /* The memory-limit emission as the component shapes it. */
  add_addr_top(&e, KASLD_TYPE_PHYS, REGION_RAM, limit - 1);

  int nr = 0, nv = 0;
  const rule_fn *rules = engine_rules(&nr);
  const verdict_fn *vrules = engine_verdict_rules(&nv);
  engine_run_full(&e, rules, nr, vrules, nv);

  const struct estimate *vt = &e.est[Q_VIRT_IMAGE_BASE];
  assert(!estimate_is_bottom(vt, &quantities[Q_VIRT_IMAGE_BASE]));
  /* dram_ceiling: phys_ceiling = (limit-1) - ksize; virt_ceiling = that +
   * PAGE_OFFSET + IMAGE_BASE_OFFSET. The resolved hi must be at or below that.
   */
  const unsigned long virt_ceiling = (limit - 1 - ksize) + 0xc000000000000000ul;
  assert(vt->hi <= virt_ceiling);
  /* And the true text base (phys 0 / virt 0xc00...000) is still admitted. */
  const unsigned long t_virt = 0xc000000000000000ul;
  assert(vt->lo <= t_virt && t_virt <= vt->hi);
#endif
}

/* The kernel-below-initrd convention (universal on every common boot path
 * except s390's top-down placement). With SF_IMAGE_SIZE_MIN and an initrd-start
 * phys observation, initrd_above_kernel emits
 *   phys_text_base + image_size <= initrd_start
 * as a C_UPPER_BOUND on Q_PHYS_IMAGE_BASE.
 *
 * Plant a high SF_IMAGE_SIZE_MIN and a tight initrd_start on an x86_64 layout
 * and assert Q_PHYS_IMAGE_BASE.hi <= initrd_start - image_size. (Gated to
 * x86_64 since this is where the integration harness compiles by default.) */
static void test_full_engine_initrd_above_kernel_upper_bound(void) {
#if defined(__x86_64__)
  const unsigned long istart = 0x40000000ul; /*  1 GiB */
  const unsigned long ksize = 0x01000000ul;  /* 16 MiB */
  struct engine e;
  engine_init(&e);
  add_scalar(&e, SF_IMAGE_SIZE_MIN, ksize);
  add_addr(&e, KASLD_TYPE_PHYS, REGION_INITRD, istart, 0, NULL);
  /* DRAM extent so the engine has a sensible RAM context but no kernel
   * leaks — initrd_above_kernel is the only rule that produces the bound. */
  add_addr(&e, KASLD_TYPE_PHYS, REGION_RAM, 0x0ul, 0x7ffffffful, NULL);

  int nr = 0, nv = 0;
  const rule_fn *rules = engine_rules(&nr);
  const verdict_fn *vrules = engine_verdict_rules(&nv);
  engine_run_full(&e, rules, nr, vrules, nv);

  const struct estimate *pt = &e.est[Q_PHYS_IMAGE_BASE];
  assert(!estimate_is_bottom(pt, &quantities[Q_PHYS_IMAGE_BASE]));
  /* phys text base + image must fit at or below initrd start. */
  assert(pt->hi <= istart - ksize);
#endif
}

/* riscv64 legacy (pre-v5.13) no-KASLR: text in the linear map at PAGE_OFFSET
 * (MAXPHYSMEM_128GB = 0xffffffe000000000). Replicates MilkV board behavior:
 * CONFIG_PAGE_OFFSET landmark, modern sv39 cpuinfo PAGE_OFFSET range (which the
 * resolver must reject in favour of the higher CONFIG landmark), module leak,
 * DRAM extents, disabled markers. Real _stext = 0xffffffe000229000. */
static void test_full_engine_riscv64_legacy_no_kaslr(void) {
#if (defined(__riscv) || defined(__riscv__)) && __riscv_xlen == 64
  struct engine e;
  engine_init(&e);
  add_scalar(&e, SF_EFI_PRESENT, 0x0);
  add_scalar(&e, SF_PHYS_MEMTOTAL, 0x13cd4000ul);
  add_scalar(&e, SF_PHYS_MAX_PFN, 0x9fe00ul);
  add_scalar(&e, SF_PAGE_SIZE, 0x1000ul);
  add_scalar(&e, SF_VIRT_ADDR_BITS, 39ul);
  add_scalar(&e, SF_VIRT_KASLR_DISABLED, 0x1);
  add_scalar(&e, SF_PHYS_KASLR_DISABLED, 0x1);
  /* PAGE_OFFSET evidence, in the order parallel execution produces on the
   * board: proc_cpuinfo (fast) lands its DERIVED modern-sv39 range FIRST
   * (CONF_INFERRED), then proc_config (slow gzip) lands the authoritative
   * CONFIG_PAGE_OFFSET (CONF_PARSED). The two contradict; confidence — not
   * capture order — must decide, so the legacy parsed value has to win despite
   * being added second. Reverting proc_cpuinfo's confidence to parsed would
   * make this resolve to the wrong (modern) value, failing the po->lo assertion
   * below. */
  add_addr_conf(&e, KASLD_TYPE_VIRT, REGION_PAGE_OFFSET, 0xffffffd600000000ul,
                0xffffffd800000000ul, CONF_INFERRED, NULL);
  add_addr(&e, KASLD_TYPE_VIRT, REGION_PAGE_OFFSET, 0xffffffe000000000ul, 0,
           NULL);
  /* module-region leaks (~2 GiB below text). */
  add_addr(&e, KASLD_TYPE_VIRT, REGION_MODULE_REGION, 0xffffffdf80922000ul, 0,
           NULL);
  add_addr(&e, KASLD_TYPE_VIRT, REGION_MODULE_REGION, 0xffffffdf80d99000ul, 0,
           NULL);
  /* DRAM. */
  add_addr(&e, KASLD_TYPE_PHYS, REGION_RAM, 0x80000000ul, 0, NULL);
  add_addr_top(&e, KASLD_TYPE_PHYS, REGION_RAM, 0x9fe00000ul);

  int nr = 0, nv = 0;
  const rule_fn *rules = engine_rules(&nr);
  const verdict_fn *vrules = engine_verdict_rules(&nv);
  engine_run_full(&e, rules, nr, vrules, nv);

  const struct estimate *vt = &e.est[Q_VIRT_IMAGE_BASE];
  const struct estimate *po = &e.est[Q_PAGE_OFFSET];
  unsigned long t_virt = 0xffffffe000229000ul; /* real _stext on the board */

  assert(!estimate_is_bottom(vt, &quantities[Q_VIRT_IMAGE_BASE]));
  /* PAGE_OFFSET resolves to the legacy value (the higher CONFIG landmark beats
   * the modern cpuinfo range). */
  assert(po->lo == 0xffffffe000000000ul);
  /* The window contains the real _stext, is in the legacy linear-map region
   * (NOT the 128 GiB-high modern KERNEL_LINK default), and module_text_bound
   * makes it tight. */
  assert(vt->lo <= t_virt && t_virt <= vt->hi);
  /* rule_riscv64_text_base's legacy branch raises lo to PAGE_OFFSET + the head
   * gap (sound: _text sits above _start = PAGE_OFFSET). */
  assert(vt->lo == 0xffffffe000000000ul + IMAGE_BASE_OFFSET);
  assert(vt->hi < 0xffffffe040000000ul); /* tight (< PAGE_OFFSET + 1 GiB) */
  assert(vt->lo != vt->hi ||             /* not falsely pinned... */
         vt->lo == t_virt);              /* ...unless exactly at truth */
  assert(vt->hi < (unsigned long)KERNEL_LINK_ADDR); /* not the modern default */
#endif
}

/* riscv64 legacy MAXPHYSMEM_2GB (CMODEL_MEDLOW): text in the linear map at
 * PAGE_OFFSET = 0xffffffff80000000 — which coincides with the modern
 * KERNEL_LINK_ADDR. No loadable modules (medlow), hence no module leak. The
 * resolved window must use the (high) legacy PAGE_OFFSET as its floor, not the
 * lowest-legacy WIDE floor — the case the `== legacy` match used to miss. */
static void test_full_engine_riscv64_legacy_2gb(void) {
#if (defined(__riscv) || defined(__riscv__)) && __riscv_xlen == 64
  struct engine e;
  engine_init(&e);
  add_scalar(&e, SF_EFI_PRESENT, 0x0);
  add_scalar(&e, SF_PAGE_SIZE, 0x1000ul);
  add_scalar(&e, SF_VIRT_ADDR_BITS, 39ul);
  add_scalar(&e, SF_VIRT_KASLR_DISABLED, 0x1);
  /* cpuinfo's DERIVED modern sv39 range (CONF_INFERRED) captured first, then
   * the authoritative CONFIG_PAGE_OFFSET (CONF_PARSED): the resolver must
   * reject the modern range in favour of the higher parsed CONFIG landmark by
   * confidence, not capture order. */
  add_addr_conf(&e, KASLD_TYPE_VIRT, REGION_PAGE_OFFSET, 0xffffffd600000000ul,
                0xffffffd800000000ul, CONF_INFERRED, NULL);
  add_addr(&e, KASLD_TYPE_VIRT, REGION_PAGE_OFFSET, 0xffffffff80000000ul, 0,
           NULL);
  add_addr(&e, KASLD_TYPE_PHYS, REGION_RAM, 0x80000000ul, 0, NULL);

  int nr = 0, nv = 0;
  const rule_fn *rules = engine_rules(&nr);
  const verdict_fn *vrules = engine_verdict_rules(&nv);
  engine_run_full(&e, rules, nr, vrules, nv);

  const struct estimate *vt = &e.est[Q_VIRT_IMAGE_BASE];
  unsigned long t_virt = 0xffffffff80202000ul; /* representative 2 GiB _stext */
  assert(!estimate_is_bottom(vt, &quantities[Q_VIRT_IMAGE_BASE]));
  /* Floor is the RESOLVED (high) PAGE_OFFSET + head — the `== 0xffffffe0...`
   * match would have left lo at the lowest-legacy WIDE floor (a 2 GiB-too-low,
   * useless window). */
  assert(vt->lo == 0xffffffff80000000ul + (unsigned long)IMAGE_BASE_OFFSET);
  assert(vt->lo <= t_virt && t_virt <= vt->hi);
#endif
}

/* arm64 sub-48 VA_BITS soundness (B Phase 1). A 4K-3level (VA_BITS=39, common
 * on Android) kernel: PAGE_OFFSET and KIMAGE_VADDR are HIGHER than the 48-bit
 * defaults. One test guards all three Phase-1 fixes:
 *   - arm64_coupling_validate must ADMIT the sub-48 directmap leak (its old
 *     ceiling _PAGE_END(48) rejected anything >= 0xffff800000000000);
 *   - arm64_va_bits_from_directmap must classify it as VA_BITS=39 and pin the
 *     exact PAGE_OFFSET (it used to collapse everything >= 0xffff000000000000
 *     to VA_BITS=48);
 *   - the widened Q_VIRT_IMAGE_BASE honest top must ADMIT the sub-48 text base
 *     (the old KASLR_VIRT_TEXT_MAX ceiling excluded it).
 * Reverting any one of the three fails an assertion below. */
static void test_full_engine_arm64_va39_sub48(void) {
#if defined(__aarch64__)
  struct engine e;
  engine_init(&e);
  add_scalar(&e, SF_EFI_PRESENT, 0x0);
  unsigned long po39 = arm64_page_offset_for(39ul); /* 0xffffff8000000000 */
  /* A 39-bit DIRECTMAP leak (within [PAGE_OFFSET(39), _PAGE_END(39))). */
  add_addr(&e, KASLD_TYPE_VIRT, REGION_DIRECTMAP, po39 + 0x1000000ul, 0, NULL);
  /* A real 39-bit kernel-text leak (_stext), KASLR on (no disabled signal).
   * The engine solves the image base _text = _stext - STEXT_OFFSET. */
  unsigned long t_stext = arm64_page_end_for(39ul) + 0x80000000ul + 0x202000ul;
  unsigned long t_text = t_stext - (unsigned long)STEXT_OFFSET;
  add_addr(&e, KASLD_TYPE_VIRT, REGION_KERNEL_TEXT, t_stext, 0, "_stext");

  int nr = 0, nv = 0;
  const rule_fn *rules = engine_rules(&nr);
  const verdict_fn *vrules = engine_verdict_rules(&nv);
  engine_run_full(&e, rules, nr, vrules, nv);

  const struct estimate *vt = &e.est[Q_VIRT_IMAGE_BASE];
  const struct estimate *po = &e.est[Q_PAGE_OFFSET];
  /* PAGE_OFFSET resolves to the exact 39-bit value (admitted + classified). */
  assert(po->lo == po39 && po->hi == po39);
  /* The image base resolves to the sub-48 _text — which sits ABOVE the old
   * 48-bit honest-top ceiling (KASLR_VIRT_TEXT_MAX), so only the widened
   * KASLR_VIRT_TEXT_MAX_WIDE admits it. */
  assert(t_text > (unsigned long)KASLR_VIRT_TEXT_MAX);
  assert(vt->lo == t_text && vt->hi == t_text);
#endif
}

/* B Phase 2: rule_arm64_text_base brackets the no-KASLR base across the
 * module-region spread for the resolved VA_BITS_MIN. A 39-bit (4K 3-level)
 * no-KASLR kernel's KIMAGE_VADDR(39) is one of {_PAGE_END(39)+128M, +256M,
 * +2G}; the size is unknown, so the window is the tight range [+128M, +2G], NOT
 * the 48-bit default the generic pin used to force. */
static void test_full_engine_arm64_va39_no_kaslr(void) {
#if defined(__aarch64__)
  struct engine e;
  engine_init(&e);
  add_scalar(&e, SF_EFI_PRESENT, 0x0);
  add_scalar(&e, SF_VIRT_KASLR_DISABLED, 0x1);
  /* PAGE_OFFSET as the probe / a directmap leak resolves it (39-bit). */
  add_addr_conf(&e, KASLD_TYPE_VIRT, REGION_PAGE_OFFSET,
                arm64_page_offset_for(39ul), 0, CONF_INFERRED, NULL);

  int nr = 0, nv = 0;
  const rule_fn *rules = engine_rules(&nr);
  const verdict_fn *vrules = engine_verdict_rules(&nv);
  engine_run_full(&e, rules, nr, vrules, nv);

  const struct estimate *vt = &e.est[Q_VIRT_IMAGE_BASE];
  unsigned long pe39 = arm64_page_end_for(39ul);
  assert(vt->lo == pe39 + 0x8000000ul);  /* +128M (smallest region) */
  assert(vt->hi == pe39 + 0x80000000ul); /* +2G   (largest region)  */
  /* Admits both a 128M-region (5.4..6.1) and a 2G-region no-KASLR text base. */
  assert(vt->lo <= pe39 + 0x8000000ul && pe39 + 0x80000000ul <= vt->hi);
#endif
}

/* 48-bit no-KASLR: the base is KIMAGE_VADDR(48), one of {_PAGE_END+128M, +256M,
 * +2G}. The window brackets the spread to [_PAGE_END+128M, _PAGE_END+2G] =
 * [0xffff800008000000, 0xffff800080000000]. The lower edge admits a 5.4..6.1
 * (128M-region) kernel's text — the bug this guards against pinned to the 2G
 * value (KERNEL_VIRT_TEXT_DEFAULT) and excluded the real low base. */
static void test_full_engine_arm64_va48_no_kaslr(void) {
#if defined(__aarch64__)
  struct engine e;
  engine_init(&e);
  add_scalar(&e, SF_EFI_PRESENT, 0x0);
  add_scalar(&e, SF_VIRT_KASLR_DISABLED, 0x1);
  add_addr_conf(&e, KASLD_TYPE_VIRT, REGION_PAGE_OFFSET,
                arm64_page_offset_for(48ul), 0, CONF_INFERRED, NULL);

  int nr = 0, nv = 0;
  const rule_fn *rules = engine_rules(&nr);
  const verdict_fn *vrules = engine_verdict_rules(&nv);
  engine_run_full(&e, rules, nr, vrules, nv);

  const struct estimate *vt = &e.est[Q_VIRT_IMAGE_BASE];
  assert(vt->lo == 0xffff800008000000ul); /* _PAGE_END(48) + 128M */
  assert(vt->hi == (unsigned long)KERNEL_VIRT_TEXT_DEFAULT); /* +2G */
  /* Both the 128M-region truth and the 2G default sit inside the window. */
  assert(vt->lo <= 0xffff800008000000ul && 0xffff800008000000ul <= vt->hi);
  assert(vt->lo <= (unsigned long)KERNEL_VIRT_TEXT_DEFAULT &&
         (unsigned long)KERNEL_VIRT_TEXT_DEFAULT <= vt->hi);
#endif
}

/* 48-bit KASLR-ON with no text leak: rule_arm64_text_base re-narrows the
 * (union, Phase-1-widened) honest top back to the 48-bit KASLR band once
 * PAGE_OFFSET resolves. The floor uses the smallest module region
 * (_PAGE_END(48)+128M) so a 5.4..6.1 kernel's lower text base is admitted; the
 * ceiling is still the 2G-region KASLR-window top (KASLR_VIRT_TEXT_MAX). */
static void test_full_engine_arm64_va48_kaslr_window(void) {
#if defined(__aarch64__)
  struct engine e;
  engine_init(&e);
  add_scalar(&e, SF_EFI_PRESENT, 0x0); /* KASLR on: no disabled signal */
  add_addr_conf(&e, KASLD_TYPE_VIRT, REGION_PAGE_OFFSET,
                arm64_page_offset_for(48ul), 0, CONF_INFERRED, NULL);

  int nr = 0, nv = 0;
  const rule_fn *rules = engine_rules(&nr);
  const verdict_fn *vrules = engine_verdict_rules(&nv);
  engine_run_full(&e, rules, nr, vrules, nv);

  const struct estimate *vt = &e.est[Q_VIRT_IMAGE_BASE];
  assert(vt->lo == arm64_page_end_for(48ul) + 0x8000000ul); /* +128M floor */
  assert(vt->hi == (unsigned long)KASLR_VIRT_TEXT_MAX);
  /* Proves the narrowing happened: the union ceiling is strictly higher. */
  assert(vt->hi < (unsigned long)KASLR_VIRT_TEXT_MAX_WIDE);
#endif
}

/* A sub-48 (39-bit) KASLR-on kernel resolves to its own text band — floor at
 * the smallest-region KIMAGE_VADDR(39) (_PAGE_END(39)+128M), ceiling at the
 * largest-region base plus the max KASLR offset — narrower than and disjoint
 * from the 48-bit window. compute_kaslr_info derives the entropy/slot count
 * from this resolved band, so reporting is VA_BITS-correct for free; this
 * guards that the band itself is right. */
static void test_full_engine_arm64_va39_kaslr_window(void) {
#if defined(__aarch64__)
  struct engine e;
  engine_init(&e);
  add_scalar(&e, SF_EFI_PRESENT, 0x0); /* KASLR on: no disabled signal */
  add_addr_conf(&e, KASLD_TYPE_VIRT, REGION_PAGE_OFFSET,
                arm64_page_offset_for(39ul), 0, CONF_INFERRED, NULL);

  int nr = 0, nv = 0;
  const rule_fn *rules = engine_rules(&nr);
  const verdict_fn *vrules = engine_verdict_rules(&nv);
  engine_run_full(&e, rules, nr, vrules, nv);

  unsigned long pe39 = arm64_page_end_for(39ul);
  unsigned long ceiling39 = pe39 + 0x80000000ul + (1ul << 36) + (1ul << 37);
  const struct estimate *vt = &e.est[Q_VIRT_IMAGE_BASE];
  assert(vt->lo == pe39 + 0x8000000ul); /* +128M floor */
  assert(vt->hi == ceiling39);          /* +2G base + max offset */
  /* Disjoint from the 48-bit window — its own narrower band. */
  assert(vt->lo > (unsigned long)KASLR_VIRT_TEXT_MAX);
#endif
}

/* Pre-v5.4 arm64 layout (e.g. v4.14): the kernel image sits LOW, below
 * _PAGE_END, at VA_START(48) + 128 MiB module region; _text a TEXT_OFFSET above
 * (real v4.14 value 0xffff000008080000). On the unprivileged/hardened profile
 * no leak resolves PAGE_OFFSET, so rule_arm64_text_base does not re-narrow and
 * Q_VIRT_IMAGE_BASE stays at its honest top — which must admit the real low
 * text base. Guards the KASLR_VIRT_TEXT_MIN_WIDE floor end-to-end through the
 * full registry; without the widened floor the window starts at KIMAGE_VADDR
 * (0xffff800080000000) and excludes the truth. */
static void test_full_engine_arm64_old_layout_sound(void) {
#if defined(__aarch64__)
  struct engine e;
  engine_init(&e);
  add_scalar(&e, SF_EFI_PRESENT, 0x0); /* file-only floor: no narrowing leak */

  int nr = 0, nv = 0;
  const rule_fn *rules = engine_rules(&nr);
  const verdict_fn *vrules = engine_verdict_rules(&nv);
  engine_run_full(&e, rules, nr, vrules, nv);

  const unsigned long t_text = 0xffff000008080000ul; /* v4.14 _text */
  const struct estimate *vt = &e.est[Q_VIRT_IMAGE_BASE];
  assert(!estimate_is_bottom(vt, &quantities[Q_VIRT_IMAGE_BASE]));
  assert(vt->lo <= t_text && t_text <= vt->hi);
#endif
}

/* Pre-v6.8 s390 runs identity-mapped: kernel text near address 0 (image base at
 * the bottom of RAM, _stext at IMAGE_BASE_OFFSET = 0x100000). With no text /
 * module leak (the hardened file-only floor) Q_VIRT_IMAGE_BASE stays at its
 * honest top, which must admit that low base. Guards the s390
 * KASLR_VIRT_TEXT_MIN_WIDE=0 floor; without it the window floors at the modern
 * ~4 TiB KASLR_VIRT_TEXT_MIN and excludes the identity-mapped text base. */
static void test_full_engine_s390_old_identity_map_sound(void) {
#if defined(__s390__) || defined(__s390x__)
  struct engine e;
  engine_init(&e);
  add_scalar(&e, SF_EFI_PRESENT, 0x0); /* file-only floor: no narrowing leak */

  int nr = 0, nv = 0;
  const rule_fn *rules = engine_rules(&nr);
  const verdict_fn *vrules = engine_verdict_rules(&nv);
  engine_run_full(&e, rules, nr, vrules, nv);

  const struct estimate *vt = &e.est[Q_VIRT_IMAGE_BASE];
  assert(!estimate_is_bottom(vt, &quantities[Q_VIRT_IMAGE_BASE]));
  /* _text near 0 (real v4.14 value 0x200) and _stext at IMAGE_BASE_OFFSET. */
  assert(vt->lo <= 0x200ul && 0x200ul <= vt->hi);
  assert(vt->lo <= (unsigned long)IMAGE_BASE_OFFSET &&
         (unsigned long)IMAGE_BASE_OFFSET <= vt->hi);
#endif
}

int main(void) {
  TEST_SUITE("test_engine_integration");

  BEGIN_CATEGORY("Full registry against planted leaks");
  RUN(test_full_engine_x86_64_leaky);
  RUN(test_full_engine_ppc64_hardened_shape);
  RUN(test_full_engine_s390_no_prng_shape);
  RUN(test_full_engine_arm32_no_kaslr_shape);
  RUN(test_full_engine_riscv64_legacy_no_kaslr);
  RUN(test_full_engine_riscv64_legacy_2gb);
  RUN(test_full_engine_arm64_va39_sub48);
  RUN(test_full_engine_arm64_va39_no_kaslr);
  RUN(test_full_engine_arm64_va48_no_kaslr);
  RUN(test_full_engine_arm64_va48_kaslr_window);
  RUN(test_full_engine_arm64_va39_kaslr_window);
  RUN(test_full_engine_arm64_old_layout_sound);
  RUN(test_full_engine_s390_old_identity_map_sound);
  RUN(test_full_engine_i686_kaslr_shape);
  RUN(test_full_engine_robust_to_outlier);
  RUN(test_full_engine_ppc_kernel_end_tightens);
  RUN(test_full_engine_ppc_memory_limit_caps_dram);
  RUN(test_full_engine_initrd_above_kernel_upper_bound);

  return TEST_DONE();
}
