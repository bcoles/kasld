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
// arm64 vmalloc layout has been through four shapes -- the pre-v5.4 image, the
// v5.4 window, the SZ_256M gap of v5.15 through v6.6, and the SZ_8M gap with a
// vmemmap anchored at -1 GiB from v6.12 -- and only the last is modelled here.
// A kernel from any other matches no combination, so the rule says nothing and
// the width stays where the rest of the engine left it. Adding an era can only
// make the rule answer more often; it cannot make an existing answer wrong.
//
// Sound because the match is exact. A width is emitted only when the modelled
// layout reproduces the observed total to the byte, and the alternatives are
// separated by terabytes rather than by rounding -- at 4 KiB pages the 48-bit
// layout totals 0x7dff3f800000 and the 52-bit one 0x41ff3f800000.
//
// arm64 only; inert elsewhere.
// ---
// <bcoles@gmail.com>

#include "include/kasld/engine_rules.h"
#include "include/kasld/quantity.h"

#include <string.h>

#if defined(__aarch64__)

/* The layout constants this rule models, one struct per era so that adding
 * another is a table entry rather than a branch. Only the shape from v6.12 is
 * here; the fields are named for what they mean rather than for the release
 * that introduced them, since a version number is not something to key on. */
struct arm64_vmalloc_era {
  unsigned long modules_vsize; /* MODULES_VSIZE: vmalloc starts above it    */
  unsigned long vmemmap_end;   /* VMEMMAP_END, as a negative offset from 0  */
  unsigned long vmalloc_gap;   /* VMALLOC_END = VMEMMAP_START - this        */
};

static const struct arm64_vmalloc_era arm64_vmalloc_eras[] = {
    /* MODULES_VADDR = _PAGE_END(VA_BITS_MIN), MODULES_VSIZE = SZ_2G,
     * VMEMMAP_END = -SZ_1G, VMALLOC_END = VMEMMAP_START - SZ_8M. */
    {1ul << 31, 1ul << 30, 1ul << 23},
};

/* VMALLOC_TOTAL for one (era, width, page size, struct page size), or 0 where
 * the combination cannot be evaluated. All arithmetic is on the unsigned
 * wrap-around the kernel's own macros rely on: _PAGE_END and PAGE_OFFSET are
 * negative offsets from the top of the address space. */
static unsigned long arm64_vmalloc_total(const struct arm64_vmalloc_era *era,
                                         unsigned long va_bits,
                                         unsigned long page_size,
                                         unsigned long struct_page) {
  if (va_bits < 2 || va_bits > 63 || page_size == 0 || struct_page == 0)
    return 0;
  unsigned long page_shift = 0;
  while ((1ul << page_shift) < page_size)
    page_shift++;
  if ((1ul << page_shift) != page_size)
    return 0;

  const unsigned long va_min = va_bits < 48ul ? va_bits : 48ul;
  const unsigned long page_end = 0ul - (1ul << (va_min - 1));
  const unsigned long page_offset = 0ul - (1ul << va_bits);

  const unsigned long vmemmap_range = page_end - page_offset;
  const unsigned long vmemmap_size = (vmemmap_range >> page_shift) * struct_page;
  const unsigned long vmemmap_start = (0ul - era->vmemmap_end) - vmemmap_size;

  const unsigned long vmalloc_start = page_end + era->modules_vsize;
  const unsigned long vmalloc_end = vmemmap_start - era->vmalloc_gap;
  if (vmalloc_end <= vmalloc_start)
    return 0;
  return vmalloc_end - vmalloc_start;
}

#endif /* __aarch64__ */

int rule_arm64_va_bits_from_vmalloc(const struct evidence_set *ev,
                                    const struct estimate *est,
                                    struct constraint *out, int out_max) {
  (void)est;
#if defined(__aarch64__)
  if (out_max < 1)
    return 0;

  unsigned long observed = 0, page_size = 0, struct_page = 0;
  enum kasld_confidence conf = CONF_UNKNOWN;
  uint32_t src = 0;
  for (int i = 0; i < ev->n_obs; i++) {
    const struct observation *o = &ev->obs[i];
    if (!o->valid || o->value_kind != OBS_SCALAR || !o->scalar_value)
      continue;
    if (o->scalar_fact == SF_VMALLOC_TOTAL) {
      observed = o->scalar_value;
      conf = o->conf;
      src = o->id;
    } else if (o->scalar_fact == SF_PAGE_SIZE) {
      page_size = o->scalar_value;
    } else if (o->scalar_fact == SF_STRUCT_PAGE_BYTES) {
      struct_page = o->scalar_value;
    }
  }
  if (!observed)
    return 0;

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
         e < sizeof(arm64_vmalloc_eras) / sizeof(arm64_vmalloc_eras[0]) &&
         !matched;
         e++)
      for (size_t p = 0; p < sizeof(page_sizes) / sizeof(page_sizes[0]) &&
                         !matched;
           p++) {
        if (page_size && page_sizes[p] != page_size)
          continue;
        for (size_t s = 0;
             s < sizeof(struct_pages) / sizeof(struct_pages[0]) && !matched;
             s++) {
          if (struct_page && struct_pages[s] != struct_page)
            continue;
          if (arm64_vmalloc_total(&arm64_vmalloc_eras[e], widths[w],
                                  page_sizes[p], struct_pages[s]) == observed)
            matched = 1;
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
  c->conf = kasld_conf_min(conf, CONF_INFERRED);
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
