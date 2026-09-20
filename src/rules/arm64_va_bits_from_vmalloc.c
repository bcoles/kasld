// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Rule: resolve Q_VA_BITS on arm64 from /proc/meminfo's VmallocTotal.
//
// VMALLOC_TOTAL is VMALLOC_END - VMALLOC_START, and on arm64 both edges are
// functions of the virtual address width. The kernel prints it unconditionally
// (fs/proc/meminfo.c), so it is world-readable wherever the file is, and it
// reports the layout the kernel is RUNNING rather than the one it was built
// for. That last property is what makes it worth inverting: two captures of the
// same distribution kernel, both CONFIG_ARM64_VA_BITS=52, report different
// totals because one booted on hardware with the large-VA extension and the
// other did not. The config cannot tell them apart; this can.
//
// It is also the only route that works on a CAPTURE. The width otherwise comes
// from an mmap probe, which is a live probe and is suppressed under a staged
// sysroot -- correctly, since it would measure the analysing host -- so a
// replayed capture leaves Q_VA_BITS a six-member set with nothing to narrow it.
//
// INVERSION. VmallocTotal is one equation in several unknowns: the width, the
// page size, sizeof(struct page), and the constants of whichever layout era the
// kernel belongs to. The rule enumerates the combinations it models, computes
// the total each implies, and keeps the widths whose total equals the
// observation exactly. A single surviving width is a pin; anything else emits
// nothing.
//
// SILENCE IS THE SAFE FAILURE, and it is what an unmodelled era produces. The
// arm64 vmalloc layout has been rearranged repeatedly -- the kernel half and
// the linear map exchanged places, the module region grew and moved, a BPF
// window appeared below it and later went away again, and the vmemmap stopped
// hanging under PAGE_OFFSET and was anchored at a fixed -1 GiB instead. Seven
// of those arrangements are modelled below. A kernel from any of the others
// matches no combination, so the rule says nothing and the width stays where
// the rest of the engine left it.
//
// The modelled set is what boots could be obtained for and checked against, not
// what the history contains. Each shape here reproduces the figure a real
// kernel of that arrangement printed, at a width confirmed from a different
// artefact of the same boot.
//
// An era added here cannot make an existing answer WRONG: a width is emitted
// only where the observation is reproduced, and a new shape does not stop an
// old one reproducing it. It can, however, make the rule answer LESS often. A
// new shape can reproduce the same figure at a different width, and two
// surviving widths is not an answer -- the count below rejects it. That is the
// right outcome, since the observation genuinely does not separate them, but it
// means an era is not free: adding one can take an answer away, and each has to
// be measured against the corpus rather than assumed to be an improvement.
//
// The match is exact at the resolution the figure is published in. The kernel
// prints the span >> 10, so the comparison is made in kB rather than bytes --
// a byte-exact test cannot succeed on a span that is not 1024-aligned, and
// x86_64's is not. Nothing is lost by it: the alternatives are separated by
// terabytes rather than by rounding, and at 4 KiB pages the 48-bit layout
// totals 0x7dff3f800000 against the 52-bit one's 0x41ff3f800000.
//
// CAPPED AT CONF_HEURISTIC ALL THE SAME, so the pin shapes the LIKELY window
// and never the guaranteed one. Exactness is not the question. /proc/meminfo is
// container-fakeable -- lxcfs rewrites it wholesale, and a hostile mount can
// state anything -- and no container-fakeable input may move the guaranteed
// window. An exact match on a forged figure is still a forged figure, and here
// it would be worse than a wrong count: the width it pins is what PAGE_OFFSET
// and the text band are derived from, so a chosen value moves those too.
//
// There is no second source to check it against. The trusted counterpart for
// RAM is zoneinfo, which the memtotal rules prefer for exactly this reason;
// vmalloc has no such file, and /proc/vmallocinfo is root-only. Until one
// exists this stays below the sound floor, alongside virt_ceiling_from_memtotal
// and the rest of the meminfo family.
//
// ARCHITECTURE COVERAGE for this family of rules, recorded here because the
// siblings point at it.
//
// Four architectures declare VA_BITS_CANDIDATES, and so have a width for a rule
// of this shape to pin: arm64, riscv64 and x86_64 have one each; s390
// deliberately has none. Its VMALLOC_START and VMALLOC_END are runtime
// variables, sized from installed memory during boot rather than fixed by the
// layout -- VMALLOC_DEFAULT_SIZE is 512 GiB less the module region -- so the
// figure it reports says nothing about the paging level and inverts to no
// width. Its level is derived by reproducing the boot code's own choice
// instead, in s390_va_bits_from_config.
//
// On every other architecture the question does not arise: there is no width
// quantity to pin, whatever the span does. The spans carry no layout signal
// either. Their headers put ppc32's and x86_32's span at high_memory, so it
// tracks installed memory rather than the layout, and arm32's starts there too
// but holds at the configured size once RAM passes the lowmem limit. The
// remainder -- mips32, mips64, ppc64, riscv32 and loongarch64 -- report one
// span across every capture, or two between kernel eras; that is an
// observation of the corpus rather than a reading of their headers, and
// several of them have only one or two captures, which is too few to call a
// span constant from. It does not need to be settled: none of them declares a
// width, so there is nothing for a rule of this shape to pin either way.
//
// arm64 only; inert elsewhere.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"
#include "include/kasld/quantity.h"

#include <string.h>

#if defined(__aarch64__)

/* One function per layout SHAPE, because the eras do not differ only in their
 * constants: where the vmemmap sits, what it is sized from, and what the
 * vmalloc span is measured against all changed between them. A table of
 * constants modelled the newest shape and could not express the others.
 *
 * Each is named for what it computes rather than for the release that
 * introduced it. A version number is not something to key on, and nothing here
 * selects a shape: the caller tries them all and keeps the widths that any of
 * them reproduces. */
/* Two widths, not one. `va_run` is the width the kernel is RUNNING -- the
 * quantity being solved for -- and `va_cfg` is the width it was BUILT for.
 * They differ on a kernel configured wide that found no hardware support and
 * fell back, and the newest layout's vmalloc end depends on both: the linear
 * map is placed for the configured width, and the span left over is what the
 * running width did not use. Shapes from eras that cannot tell them apart
 * ignore `va_cfg`. */
typedef unsigned long (*arm64_vmalloc_fn)(unsigned long va_run,
                                          unsigned long va_cfg,
                                          unsigned long page_shift,
                                          unsigned long struct_page);

/* The newest shape. VMEMMAP_END is a fixed -1 GiB and the vmemmap hangs below
 * it, sized from the linear map; vmalloc starts above a 2 GiB module region at
 * _PAGE_END(VA_BITS_MIN).
 *
 * VA_BITS_MIN is not min(VA_BITS, 48). On a kernel built wider than 48 bits it
 * is 48 -- except at a 16 KiB granule, where it is 47, because that granule
 * reaches 48 bits only by adding a level it does not otherwise need. Treating
 * it as 48 everywhere puts the module region, and with it the whole vmalloc
 * span, an entire canonical bit away from where a 16 KiB kernel has it.
 *
 * Where the configured and running widths agree, vmalloc ends SZ_8M below the
 * vmemmap. Where they do not, the vmemmap was sized for the configured width
 * and the running one leaves a prefix of it unused; the kernel hands that
 * prefix back to vmalloc, so the end moves up by exactly the page structures
 * the unused linear map would have needed. */
static unsigned long arm64_vmalloc_vmemmap_anchored(unsigned long va_run,
                                                    unsigned long va_cfg,
                                                    unsigned long page_shift,
                                                    unsigned long struct_page) {
  const unsigned long va_min =
      va_cfg > 48ul ? (page_shift == 14ul ? 47ul : 48ul) : va_cfg;
  if (va_min < 1)
    return 0;
  /* A kernel does not fall back to an arbitrary width. It runs at the width it
   * was built for, or -- when that needs hardware support it did not find --
   * at VA_BITS_MIN, which is what that name means: the narrowest the layout is
   * prepared to run. Admitting any narrower width would make this shape answer
   * for kernels that cannot exist, and because the span does not depend on the
   * running width when the two agree, every one of them would reproduce the
   * same figure and the rule would fall silent on a capture it can read. */
  if (va_run != va_cfg && va_run != va_min)
    return 0;
  const unsigned long page_end = 0ul - (1ul << (va_min - 1));
  const unsigned long page_offset = 0ul - (1ul << va_cfg);
  const unsigned long vmemmap_size =
      ((page_end - page_offset) >> page_shift) * struct_page;
  const unsigned long vmemmap_start = (0ul - (1ul << 30)) - vmemmap_size;
  const unsigned long vmalloc_start = page_end + (1ul << 31);

  unsigned long vmalloc_end;
  if (va_cfg == va_min) {
    vmalloc_end = vmemmap_start - (1ul << 23); /* SZ_8M */
  } else {
    const unsigned long unused =
        ((0ul - (1ul << va_run)) - page_offset) >> page_shift;
    vmalloc_end = vmemmap_start + unused * struct_page - (1ul << 23);
  }
  return vmalloc_end > vmalloc_start ? vmalloc_end - vmalloc_start : 0;
}

/* The post-flip shapes that precede the fixed vmemmap anchor. The kernel half
 * and the linear map have already exchanged places -- PAGE_OFFSET is
 * -(1 << VA_BITS) and the image sits above _PAGE_END(VA_BITS_MIN) -- but the
 * vmemmap is not yet pinned to a fixed address near the top. Two arrangements
 * of that, and both size the vmemmap by STRUCT_PAGE_MAX_SHIFT rather than by
 * sizeof(struct page): the shift ROUNDS UP, so a 56-byte struct page is sized
 * as 64. The newest shape above uses the exact size instead, which is why it
 * cannot be reached by adding a constant to these.
 *
 * What varies between kernels of one arrangement is the region reserved below
 * vmalloc, so that is the parameter: a module window alone, a BPF window below
 * it, or the single large module region that replaced both. The region is not
 * inferable from the span, so each candidate is tried.  */
static unsigned long arm64_vmalloc_vmemmap_pow2(unsigned long va_bits,
                                                unsigned long page_shift,
                                                unsigned long struct_page,
                                                unsigned long reserved_below) {
  unsigned long spms = 0;
  while ((1ul << spms) < struct_page)
    spms++;
  if (page_shift <= spms)
    return 0;
  /* VMEMMAP_START is a power-of-two boundary below the top, not a computed
   * size subtracted from a fixed end. */
  const unsigned long vmemmap_shift = page_shift - spms;
  if (va_bits <= vmemmap_shift || va_bits - vmemmap_shift >= 64)
    return 0;
  const unsigned long va_min = va_bits < 48ul ? va_bits : 48ul;
  const unsigned long page_end = 0ul - (1ul << (va_min - 1));
  const unsigned long vmemmap_start = 0ul - (1ul << (va_bits - vmemmap_shift));

  const unsigned long vmalloc_start = page_end + reserved_below;
  const unsigned long vmalloc_end = vmemmap_start - (1ul << 28); /* SZ_256M */
  return vmalloc_end > vmalloc_start ? vmalloc_end - vmalloc_start : 0;
}

/* The earliest post-flip shape. Same upper half as above, but vmalloc ends a
 * PUD, a vmemmap and 64 KiB below the TOP of the address space rather than a
 * fixed distance below the vmemmap -- the end is measured absolutely, so the
 * vmemmap's own placement does not enter it.
 *
 * Only ONE region is tried here, where the shape above tries three. This
 * arrangement was replaced before the BPF window was removed, so every kernel
 * that ever used it had that window and reserved the larger region; a smaller
 * one would model nothing.
 *
 * Below 52 bits this reduces to exactly the pre-flip shape -- both come to
 * 2^(VA_BITS-1) less the PUD, the vmemmap and 64 KiB -- so it earns its place
 * only on a 52-bit kernel of that era, where the two diverge.
 *
 * THAT DEGENERACY IS ALSO A LIMIT ON WHAT THIS RULE MAY BE USED FOR. A span
 * reproduced by both of them says nothing about which side of the layout flip
 * the kernel is on, and the two agree at every width up to 48 at all three
 * granules -- so on any kernel narrower than 52 bits the figure cannot date
 * the layout. It is tempting to read the matching shape as proof of the era
 * and use it to drop the pre-flip image position from the window, which would
 * narrow the image base considerably on a machine with no leak. It is not
 * sound: at the widths where it would be applied the shape is not determined,
 * and the span is a container-fakeable figure besides, so an exclusion drawn
 * from it could put the guaranteed window past a real pre-flip image.
 *
 * The era is settled by a resolved PAGE_OFFSET instead, which arm64_text_base
 * already uses to license its tight floor -- a trustworthy observation of a
 * kernel address, not an inversion of a number userspace can rewrite. Nothing
 * here should grow a second answer to that question. */
static unsigned long arm64_vmalloc_end_absolute(unsigned long va_bits,
                                                unsigned long page_shift,
                                                unsigned long struct_page,
                                                unsigned long reserved_below) {
  unsigned long spms = 0;
  while ((1ul << spms) < struct_page)
    spms++;
  if (page_shift <= spms || va_bits < page_shift + 2 || page_shift < 4)
    return 0;
  const unsigned long va_min = va_bits < 48ul ? va_bits : 48ul;
  const unsigned long page_end = 0ul - (1ul << (va_min - 1));
  const unsigned long page_offset = 0ul - (1ul << va_bits);
  const unsigned long vmemmap_size =
      (page_end - page_offset) >> (page_shift - spms);

  const unsigned long per_level = page_shift - 3ul;
  unsigned long levels = 1;
  while (page_shift + per_level * levels < va_bits)
    levels++;
  const unsigned long pud_shift = levels >= 4
                                      ? page_shift + per_level * 2ul
                                      : page_shift + per_level * (levels - 1ul);

  const unsigned long vmalloc_start = page_end + reserved_below;
  const unsigned long vmalloc_end =
      0ul - (1ul << pud_shift) - vmemmap_size - (1ul << 16);
  return vmalloc_end > vmalloc_start ? vmalloc_end - vmalloc_start : 0;
}

/* Module window only. */
static unsigned long arm64_vmalloc_pow2_modules(unsigned long va_run,
                                                unsigned long va_cfg,
                                                unsigned long page_shift,
                                                unsigned long struct_page) {
  (void)va_cfg;
  return arm64_vmalloc_vmemmap_pow2(va_run, page_shift, struct_page, 1ul << 27);
}
/* BPF window below the module window. */
static unsigned long arm64_vmalloc_pow2_bpf(unsigned long va_run,
                                            unsigned long va_cfg,
                                            unsigned long page_shift,
                                            unsigned long struct_page) {
  (void)va_cfg;
  return arm64_vmalloc_vmemmap_pow2(va_run, page_shift, struct_page, 1ul << 28);
}
/* The single 2 GiB module region that replaced both. */
static unsigned long arm64_vmalloc_pow2_large(unsigned long va_run,
                                              unsigned long va_cfg,
                                              unsigned long page_shift,
                                              unsigned long struct_page) {
  (void)va_cfg;
  return arm64_vmalloc_vmemmap_pow2(va_run, page_shift, struct_page, 1ul << 31);
}
static unsigned long arm64_vmalloc_absolute_bpf(unsigned long va_run,
                                                unsigned long va_cfg,
                                                unsigned long page_shift,
                                                unsigned long struct_page) {
  (void)va_cfg;
  return arm64_vmalloc_end_absolute(va_run, page_shift, struct_page, 1ul << 28);
}

/* The pre-flip shape, before the kernel half and the linear map exchanged
 * places. PAGE_OFFSET is -(1 << (VA_BITS - 1)) rather than -(1 << VA_BITS);
 * the vmemmap is a power-of-two block below it; and vmalloc ends a PUD, a
 * vmemmap and 64 KiB under PAGE_OFFSET, starting above the reserved region
 * that sits at VA_START.
 *
 * That region is the one thing the two pre-flip arrangements disagree on, so
 * its size is the parameter. Either a module window alone, or a BPF window of
 * the same size below it -- once JIT allocations were moved out of the module
 * area they needed their own, and VMALLOC_START rose by 128 MiB without
 * anything else in the layout moving. Both are tried; see the wrappers.
 *
 * KASAN moves VMALLOC_START, since the lowest window begins above the shadow.
 * It is taken as absent: a shadow shifts the span by its own size, so a kernel
 * built with one reproduces nothing here and the rule stays silent on it
 * rather than answering from a layout it does not have. */
static unsigned long arm64_vmalloc_preflip(unsigned long va_bits,
                                           unsigned long page_shift,
                                           unsigned long struct_page,
                                           unsigned long reserved_below) {
  /* STRUCT_PAGE_MAX_SHIFT is order_base_2(sizeof(struct page)), which ROUNDS
   * UP: a 56-byte struct page gives 6, the same shift a 64-byte one gives.
   * Rounding rather than requiring a power of two is the kernel's own
   * arithmetic, and requiring one made this shape inert on every machine whose
   * struct page is not a power of two. */
  unsigned long spms = 0;
  while ((1ul << spms) < struct_page)
    spms++;
  if (va_bits < page_shift + 2 || page_shift < 4)
    return 0;

  const unsigned long va_start = 0ul - (1ul << va_bits);
  const unsigned long page_offset = 0ul - (1ul << (va_bits - 1));
  const unsigned long vmemmap_size = 1ul << (va_bits - page_shift - 1 + spms);
  /* PUD_SIZE for the levels this page size gives at this width: each level
   * below the top covers PAGE_SHIFT - 3 bits, and a folded PUD is the pgd. */
  const unsigned long per_level = page_shift - 3ul;
  unsigned long levels = 1;
  while (page_shift + per_level * levels < va_bits)
    levels++;
  const unsigned long pud_shift = levels >= 4
                                      ? page_shift + per_level * 2ul
                                      : page_shift + per_level * (levels - 1ul);
  const unsigned long pud_size = 1ul << pud_shift;

  const unsigned long vmalloc_start = va_start + reserved_below;
  const unsigned long vmalloc_end =
      page_offset - pud_size - vmemmap_size - (1ul << 16);
  return vmalloc_end > vmalloc_start ? vmalloc_end - vmalloc_start : 0;
}

/* A module window of 128 MiB at VA_START, and nothing below it. */
static unsigned long arm64_vmalloc_preflip_modules(unsigned long va_run,
                                                   unsigned long va_cfg,
                                                   unsigned long page_shift,
                                                   unsigned long struct_page) {
  (void)va_cfg;
  return arm64_vmalloc_preflip(va_run, page_shift, struct_page, 1ul << 27);
}

/* A BPF window of 128 MiB below the module window, so 256 MiB in total. */
static unsigned long arm64_vmalloc_preflip_bpf(unsigned long va_run,
                                               unsigned long va_cfg,
                                               unsigned long page_shift,
                                               unsigned long struct_page) {
  (void)va_cfg;
  return arm64_vmalloc_preflip(va_run, page_shift, struct_page, 1ul << 28);
}

static const arm64_vmalloc_fn arm64_vmalloc_shapes[] = {
    arm64_vmalloc_vmemmap_anchored, arm64_vmalloc_pow2_modules,
    arm64_vmalloc_pow2_bpf,         arm64_vmalloc_pow2_large,
    arm64_vmalloc_absolute_bpf,     arm64_vmalloc_preflip_bpf,
    arm64_vmalloc_preflip_modules,
};

#endif /* __aarch64__ */

int rule_arm64_va_bits_from_vmalloc(const struct evidence_set *ev,
                                    const struct estimate *est,
                                    struct constraint *out, int out_max) {
  (void)est;
#if defined(__aarch64__)
  if (out_max < 1)
    return 0;

  enum kasld_confidence conf = CONF_UNKNOWN;
  uint32_t src = 0;
  const unsigned long observed =
      kasld_scalar_fact_value(ev, SF_VMALLOC_TOTAL, &conf, &src);
  if (!observed)
    return 0;
  /* Page size through its own accessor, which rejects a value the architecture
   * does not admit rather than passing it on to be enumerated against. */
  const unsigned long page_size = kasld_page_size_observed(ev, NULL, NULL);
  const unsigned long struct_page =
      kasld_scalar_fact_value(ev, SF_STRUCT_PAGE_BYTES, NULL, NULL);

  /* Unobserved inputs are enumerated rather than assumed. A guess that happened
   * to be wrong would not produce a wrong answer here -- the total would simply
   * not match -- but it would lose the answer on a machine that does not use
   * the common value. */
  static const unsigned long page_sizes[] = {4096ul, 16384ul, 65536ul};
  static const unsigned long struct_pages[] = {56ul, 64ul, 72ul, 80ul};
  static const unsigned long widths[] = VA_BITS_CANDIDATES;

  unsigned long found = 0;
  int n_found = 0;
  for (size_t w = 0; w < sizeof(widths) / sizeof(widths[0]); w++) {
    int matched = 0;
    for (size_t e = 0;
         e < sizeof(arm64_vmalloc_shapes) / sizeof(arm64_vmalloc_shapes[0]) &&
         !matched;
         e++)
      for (size_t p = 0;
           p < sizeof(page_sizes) / sizeof(page_sizes[0]) && !matched; p++) {
        if (page_size && page_sizes[p] != page_size)
          continue;
        for (size_t s = 0;
             s < sizeof(struct_pages) / sizeof(struct_pages[0]) && !matched;
             s++) {
          if (struct_page && struct_pages[s] != struct_page)
            continue;
          unsigned long shift = 0;
          while ((1ul << shift) < page_sizes[p])
            shift++;
          /* The width the kernel was BUILT for is enumerated alongside the
           * one it is RUNNING, because a kernel configured wider than its
           * hardware supports falls back, and the newest layout's span depends
           * on both. Only a configured width at least as wide as the running
           * one is possible; shapes from eras that cannot tell the two apart
           * ignore it and simply return the same span for each candidate. */
          for (size_t g = 0; g < sizeof(widths) / sizeof(widths[0]) && !matched;
               g++) {
            if (widths[g] < widths[w])
              continue;
            const unsigned long modelled = arm64_vmalloc_shapes[e](
                widths[w], widths[g], shift, struct_pages[s]);
            /* Compared at kB, the resolution the kernel published:
             * VmallocTotal is printed as (VMALLOC_END - VMALLOC_START) >> 10,
             * so up to 1023 bytes are floored away before it is read. */
            if (modelled && (modelled >> 10) == (observed >> 10))
              matched = 1;
          }
        }
      }
    if (matched) {
      found = widths[w];
      n_found++;
    }
  }

  /* One width, or nothing. Two widths agreeing on a total would mean the
   * observation does not separate them, and narrowing the finite set to that
   * pair is a job for a constraint form this rule does not need yet. */
  if (n_found != 1)
    return 0;

  struct constraint *c = &out[0];
  memset(c, 0, sizeof(*c));
  c->q = Q_VA_BITS;
  c->op = C_EQUALS;
  c->value = found;
  c->conf = kasld_conf_min(conf, CONF_HEURISTIC);
  if (src) {
    c->derived_from[0] = src;
    c->lineage_count = 1;
  }
  snprintf(c->origin, ORIGIN_LEN, "arm64_va_bits_from_vmalloc");
  return 1;
#else
  (void)ev;
  (void)out;
  (void)out_max;
  return 0;
#endif
}
