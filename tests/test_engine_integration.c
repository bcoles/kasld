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
#include <stdlib.h>
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

/* Top-edge twin of add_addr: emits an observation with pos=top and only the
 * upper extent set (HI_SET, no LO/SAMPLE). Used to model firmware-style
 * ceiling signals — linux,kernel-end and linux,memory-limit. */
static void add_addr_top(struct engine *e, enum kasld_addr_type type,
                         enum kasld_region region, unsigned long hi) {
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
  add_scalar(&e, SF_IMAGE_SIZE, gap);             /* image ~ text..data span */
  add_scalar(&e, SF_PHYS_ADDR_BITS, 46);
  add_scalar(&e, SF_PHYS_KERNEL_ALIGN, 0x200000ul);

  int nr = 0, nv = 0;
  const rule_fn *rules = engine_rules(&nr);
  const verdict_fn *vrules = engine_verdict_rules(&nv);
  engine_run_full(&e, rules, nr, vrules, nv);

  const struct quantity_def *qd = quantities;

  /* Soundness: every interval quantity is non-bottom and still admits truth. */
  const struct estimate *vt = &e.est[Q_VIRT_TEXT_BASE];
  const struct estimate *pt = &e.est[Q_PHYS_TEXT_BASE];
  const struct estimate *po = &e.est[Q_PAGE_OFFSET];
  assert(!estimate_is_bottom(vt, &qd[Q_VIRT_TEXT_BASE]));
  assert(!estimate_is_bottom(pt, &qd[Q_PHYS_TEXT_BASE]));
  assert(!estimate_is_bottom(po, &qd[Q_PAGE_OFFSET]));
  assert(contains(vt, T)); /* must not over-tighten past the true text base */
  assert(contains(pt, P)); /* ... nor the true phys base */
  assert(contains(po, PO));

  /* Liveness: the rules fired and narrowed each quantity from its honest top.
   */
  struct estimate top;
  qd[Q_VIRT_TEXT_BASE].init_top(&top);
  assert(vt->hi < top.hi); /* image_size_text_data_gap ceiling */
  qd[Q_PHYS_TEXT_BASE].init_top(&top);
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
 * is_phys_dram_region(...) would pin Q_PHYS_TEXT_BASE.lo to 0x2c90000
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

  const struct estimate *vt = &e.est[Q_VIRT_TEXT_BASE];
  const struct estimate *pt = &e.est[Q_PHYS_TEXT_BASE];
  const struct estimate *po = &e.est[Q_PAGE_OFFSET];

  assert(!estimate_is_bottom(vt, &quantities[Q_VIRT_TEXT_BASE]));
  assert(!estimate_is_bottom(pt, &quantities[Q_PHYS_TEXT_BASE]));
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
 * resolves Q_VIRT_TEXT_BASE to a wide window that admits the runtime-relocated
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
  add_scalar(&e, SF_IMAGE_SIZE, 0x126046cul);
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

  const struct estimate *vt = &e.est[Q_VIRT_TEXT_BASE];
  const struct estimate *pt = &e.est[Q_PHYS_TEXT_BASE];

  assert(!estimate_is_bottom(vt, &quantities[Q_VIRT_TEXT_BASE]));
  assert(!estimate_is_bottom(pt, &quantities[Q_PHYS_TEXT_BASE]));
  /* With SF_VIRT_KASLR_DISABLED erroneously emitted, vt would collapse to
   * [KERNEL_VIRT_TEXT_DEFAULT, KERNEL_VIRT_TEXT_DEFAULT] and t_virt would fall
   * outside. The exemption keeps the signal off and the window admits
   * the displaced text base. */
  assert(vt->lo <= t_virt && t_virt <= vt->hi);
  assert(pt->lo <= t_phys && t_phys <= pt->hi);
#endif
}

/* A no-KASLR arm32 system (CONFIG_RANDOMIZE_BASE is not available on
 * arm32; the kernel always loads at PAGE_OFFSET + TEXT_OFFSET + head).
 * On any 32-bit arch, expressions like `4 * GB` in the arch header
 * overflow an `unsigned long` to 0 and collapse Q_PHYS_TEXT_BASE's
 * honest-top to a bottom interval (lo > hi). The bottom then propagates
 * via text_base_coupling_synth onto Q_VIRT_TEXT_BASE on coupled arches.
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

  /* Default arm32 layout: _stext sits at PAGE_OFFSET + TEXT_OFFSET + head
   * (a small head-asm offset), phys text at TEXT_OFFSET above RAM_BASE
   * (= 0x8000 on the standard layout). The resolved windows must remain
   * non-bottom and admit these. */
  const unsigned long t_virt = 0xc0008220ul;
  const unsigned long t_phys = 0x8000ul;
  const unsigned long t_po = 0xc0000000ul;

  const struct estimate *vt = &e.est[Q_VIRT_TEXT_BASE];
  const struct estimate *pt = &e.est[Q_PHYS_TEXT_BASE];
  const struct estimate *po = &e.est[Q_PAGE_OFFSET];

  assert(!estimate_is_bottom(vt, &quantities[Q_VIRT_TEXT_BASE]));
  assert(!estimate_is_bottom(pt, &quantities[Q_PHYS_TEXT_BASE]));
  assert(!estimate_is_bottom(po, &quantities[Q_PAGE_OFFSET]));

  assert(vt->lo <= t_virt && t_virt <= vt->hi);
  assert(pt->lo <= t_phys && t_phys <= pt->hi);
  assert(po->lo <= t_po && t_po <= po->hi);
#endif
}

/* A typical i686 system: KASLR enabled, virt_page_offset and
 * CONFIG_PHYSICAL_START readable from /boot/config, BIOS e820 readable from
 * /sys/kernel/boot_params, zoneinfo + firmware/memmap readable. x86_32 is
 * coupled (TEXT_TRACKS_DIRECTMAP = 1) so the resolved Q_VIRT_TEXT_BASE window
 * tracks the resolved Q_PHYS_TEXT_BASE window via the compile-time PAGE_OFFSET
 * / PHYS_OFFSET / TEXT_OFFSET projection. The test plants the scalars + phys
 * extents an unprivileged i686 user reads and asserts the resolved windows
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
  add_scalar(&e, SF_INIT_SIZE, 0x10f4000ul);         /* ~17 MiB */
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

  const struct estimate *vt = &e.est[Q_VIRT_TEXT_BASE];
  const struct estimate *pt = &e.est[Q_PHYS_TEXT_BASE];
  const struct estimate *po = &e.est[Q_PAGE_OFFSET];

  assert(!estimate_is_bottom(vt, &quantities[Q_VIRT_TEXT_BASE]));
  assert(!estimate_is_bottom(pt, &quantities[Q_PHYS_TEXT_BASE]));
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

  const struct estimate *pt = &e.est[Q_PHYS_TEXT_BASE];
  assert(!estimate_is_bottom(pt, &quantities[Q_PHYS_TEXT_BASE]));
  assert(pt->lo <= P && P <= pt->hi); /* truth survives the outlier */
#endif
}

/* PowerPC firmware writes linux,kernel-end (phys address one byte past the
 * loaded kernel image). The sysfs_devicetree_kernel_end component emits it as
 * `P REGION_KERNEL_IMAGE pos=top hi=<kend>`; kernel_image_phys_bound then uses
 * obs_anchor() (which returns hi for a top-only observation) to tighten
 * Q_PHYS_TEXT_BASE.hi.
 *
 * Plant a low kernel-end (24 MiB) on a ppc64 layout and assert the upper
 * bound lands at or below that — the engine's honest top for Q_PHYS_TEXT_BASE
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

  const struct estimate *pt = &e.est[Q_PHYS_TEXT_BASE];
  assert(!estimate_is_bottom(pt, &quantities[Q_PHYS_TEXT_BASE]));
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
 * observations and projects it through SF_IMAGE_SIZE to tighten
 * Q_VIRT_TEXT_BASE.hi on coupled arches (ppc64 is coupled).
 *
 * Plant a 128 MiB cap on a ppc64 layout and assert Q_VIRT_TEXT_BASE.hi lands
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
  add_scalar(&e, SF_IMAGE_SIZE, ksize);
  add_addr(&e, KASLD_TYPE_VIRT, REGION_PAGE_OFFSET, 0xc000000000000000ul, 0,
           NULL);
  /* The memory-limit emission as the component shapes it. */
  add_addr_top(&e, KASLD_TYPE_PHYS, REGION_RAM, limit - 1);

  int nr = 0, nv = 0;
  const rule_fn *rules = engine_rules(&nr);
  const verdict_fn *vrules = engine_verdict_rules(&nv);
  engine_run_full(&e, rules, nr, vrules, nv);

  const struct estimate *vt = &e.est[Q_VIRT_TEXT_BASE];
  assert(!estimate_is_bottom(vt, &quantities[Q_VIRT_TEXT_BASE]));
  /* dram_ceiling: phys_ceiling = (limit-1) - ksize; virt_ceiling = that +
   * PAGE_OFFSET + TEXT_OFFSET. The resolved hi must be at or below that. */
  const unsigned long virt_ceiling = (limit - 1 - ksize) + 0xc000000000000000ul;
  assert(vt->hi <= virt_ceiling);
  /* And the true text base (phys 0 / virt 0xc00...000) is still admitted. */
  const unsigned long t_virt = 0xc000000000000000ul;
  assert(vt->lo <= t_virt && t_virt <= vt->hi);
#endif
}

/* The kernel-below-initrd convention (universal on every common boot path
 * except s390's top-down placement). With SF_IMAGE_SIZE and an initrd-start
 * phys observation, initrd_above_kernel emits
 *   phys_text_base + image_size <= initrd_start
 * as a C_UPPER_BOUND on Q_PHYS_TEXT_BASE.
 *
 * Plant a high SF_IMAGE_SIZE and a tight initrd_start on an x86_64 layout
 * and assert Q_PHYS_TEXT_BASE.hi <= initrd_start - image_size. (Gated to
 * x86_64 since this is where the integration harness compiles by default.) */
static void test_full_engine_initrd_above_kernel_upper_bound(void) {
#if defined(__x86_64__)
  const unsigned long istart = 0x40000000ul; /*  1 GiB */
  const unsigned long ksize = 0x01000000ul;  /* 16 MiB */
  struct engine e;
  engine_init(&e);
  add_scalar(&e, SF_IMAGE_SIZE, ksize);
  add_addr(&e, KASLD_TYPE_PHYS, REGION_INITRD, istart, 0, NULL);
  /* DRAM extent so the engine has a sensible RAM context but no kernel
   * leaks — initrd_above_kernel is the only rule that produces the bound. */
  add_addr(&e, KASLD_TYPE_PHYS, REGION_RAM, 0x0ul, 0x7ffffffful, NULL);

  int nr = 0, nv = 0;
  const rule_fn *rules = engine_rules(&nr);
  const verdict_fn *vrules = engine_verdict_rules(&nv);
  engine_run_full(&e, rules, nr, vrules, nv);

  const struct estimate *pt = &e.est[Q_PHYS_TEXT_BASE];
  assert(!estimate_is_bottom(pt, &quantities[Q_PHYS_TEXT_BASE]));
  /* phys text base + image must fit at or below initrd start. */
  assert(pt->hi <= istart - ksize);
#endif
}

/* ── Counterfactual "hardening plan" prototype ──────────────────────────────
 * Inverts the corroboration map: for each component origin that supplies
 * evidence, re-resolve the FULL registry with that origin's observations
 * removed and measure the KASLR entropy (bits) restored on Q_PHYS_TEXT_BASE.
 * Sound because the engine is monotone — removing evidence can only widen — so
 * "bits restored" is exact, not estimated. Demonstrates which channel is
 * load-bearing (silence it, regain entropy) vs redundant (no change while a
 * tighter source is present). */
static void cf_add_addr(struct engine *e, enum kasld_addr_type type,
                        enum kasld_region region, unsigned long lo,
                        unsigned long hi, const char *name, const char *origin,
                        const char *skip) {
  if (skip && strcmp(origin, skip) == 0)
    return;
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
  snprintf(o.origin, ORIGIN_LEN, "%s", origin);
  evidence_add(&e->ev, &o);
}

static void cf_add_scalar(struct engine *e, enum kasld_scalar_fact f,
                          unsigned long v, const char *origin,
                          const char *skip) {
  if (skip && strcmp(origin, skip) == 0)
    return;
  struct observation o;
  memset(&o, 0, sizeof(o));
  o.value_kind = OBS_SCALAR;
  o.scalar_fact = f;
  o.scalar_value = v;
  o.conf = CONF_PARSED;
  snprintf(o.origin, ORIGIN_LEN, "%s", origin);
  evidence_add(&e->ev, &o);
}

/* Build a consistent x86_64 phys-leak scenario, omitting one origin's evidence
 * (skip == NULL keeps everything), and run the full registry. */
static void cf_build(struct engine *e, const char *skip) {
  engine_init(e);
  const unsigned long P = 0x10000000ul; /* true phys base, 256 MiB */
  cf_add_addr(e, KASLD_TYPE_PHYS, REGION_KERNEL_TEXT, P, 0, "_stext",
              "proc_iomem_kernel", skip); /* the tight kernel locator */
  cf_add_addr(e, KASLD_TYPE_PHYS, REGION_RAM, 0x0ul, 0x7ffffffful, NULL,
              "firmware_memmap", skip);
  cf_add_scalar(e, SF_PHYS_MEMTOTAL, 0x80000000ul, "meminfo_facts", skip);
  cf_add_scalar(e, SF_PHYS_ADDR_BITS, 46, "cpuinfo_facts", skip);
  /* Always-present supporting facts (never silenced in the loop below). */
  cf_add_scalar(e, SF_IMAGE_SIZE, 0x1400000ul, "kernel_image_facts", NULL);
  cf_add_scalar(e, SF_PHYS_KERNEL_ALIGN, 0x200000ul, "boot_params_facts", NULL);
  int nr = 0, nv = 0;
  const rule_fn *rules = engine_rules(&nr);
  const verdict_fn *vrules = engine_verdict_rules(&nv);
  engine_run_full(e, rules, nr, vrules, nv);
}

static int cf_phys_bits(const struct engine *e) {
  unsigned long align = e->est[Q_PHYS_KASLR_ALIGN].lo;
  unsigned long slots =
      quantity_slots(Q_PHYS_TEXT_BASE, &e->est[Q_PHYS_TEXT_BASE],
                     e->constraints, e->n_constraints, align);
  int b = 0;
  while (slots > 1) {
    slots >>= 1;
    b++;
  }
  return b;
}

static void test_full_engine_x86_64_counterfactual_hardening(void) {
#if defined(__x86_64__)
  struct engine e;
  cf_build(&e, NULL);
  int b0 = cf_phys_bits(&e);

  /* Reference: same registry, zero evidence — the honest arch-default window.
   */
  struct engine top;
  engine_init(&top);
  int nr = 0, nv = 0;
  const rule_fn *rules = engine_rules(&nr);
  const verdict_fn *vrules = engine_verdict_rules(&nv);
  engine_run_full(&top, rules, nr, vrules, nv);
  int btop = cf_phys_bits(&top);
  assert(b0 < btop); /* the leaks actually narrowed phys entropy */

  const char *origins[] = {"proc_iomem_kernel", "firmware_memmap",
                           "meminfo_facts", "cpuinfo_facts"};
  int restored[4];
  for (int i = 0; i < 4; i++) {
    struct engine c;
    cf_build(&c, origins[i]);
    restored[i] = cf_phys_bits(&c) - b0;
    assert(restored[i] >= 0); /* monotone: removing evidence only widens */
    if (!getenv("TEST_QUIET"))
      fprintf(stderr, "    [cf] silence %-18s phys_text +%d bits\n", origins[i],
              restored[i]);
  }
  /* The kernel-locating channel is load-bearing; the loose ceilings are
   * redundant while it is present. */
  assert(restored[0] > 0);            /* proc_iomem_kernel restores entropy */
  assert(restored[0] >= restored[2]); /* >= memtotal ceiling (redundant ~0) */
  assert(restored[0] >= restored[3]); /* >= addr-bits ceiling (redundant ~0) */
#endif
}

int main(void) {
  TEST_SUITE("test_engine_integration");

  BEGIN_CATEGORY("Full registry against planted leaks");
  RUN(test_full_engine_x86_64_leaky);
  RUN(test_full_engine_ppc64_hardened_shape);
  RUN(test_full_engine_s390_no_prng_shape);
  RUN(test_full_engine_arm32_no_kaslr_shape);
  RUN(test_full_engine_i686_kaslr_shape);
  RUN(test_full_engine_robust_to_outlier);
  RUN(test_full_engine_ppc_kernel_end_tightens);
  RUN(test_full_engine_ppc_memory_limit_caps_dram);
  RUN(test_full_engine_initrd_above_kernel_upper_bound);
  RUN(test_full_engine_x86_64_counterfactual_hardening);

  return TEST_DONE();
}
