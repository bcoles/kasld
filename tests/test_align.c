// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Unit tests for the text-base floor helper (api.h):
//   kasld_floor_aligned_suboffset() / kasld_floor_text_base()
//
// The helper turns a leaked *interior* virtual text pointer (text_base <= addr)
// into a sound aligned estimate of the base. The base is KASLR_VIRT_ALIGN-
// aligned only up to a fixed sub-offset (KERNEL_VIRT_TEXT_DEFAULT mod align):
// 0 on x86_64/arm64/ppc, 0x2000 on riscv64, IMAGE_BASE_OFFSET on arm32, 1 MiB
// on s390. A plain `addr & -align` drops below the real base on the sub-offset
// arches — the bug these tests pin shut. We drive the pure parameterised core
// with each arch's (align, default_base) on one host so the sub-offset cases
// are covered without cross-compiling.
//
// Contract checked for every case: the result V is
//   (a) a sound upper bound on the base:  V <= addr
//   (b) carries the right sub-offset:     V mod align == default_base mod align
//   (c) the tightest such value:          V + align > addr
// ---
// <bcoles@gmail.com>

#include "include/kasld/api.h"
#include "test_harness.h"

#include <assert.h>
#include <stdio.h>

/* Assert the full contract, plus the exact expected value. */
static void check(unsigned long addr, unsigned long align,
                  unsigned long default_base, unsigned long expected) {
  unsigned long v = kasld_floor_aligned_suboffset(addr, align, default_base);
  assert(v == expected); /* exact */
  assert(v <= addr);     /* (a) sound upper bound */
  assert((v & (align - 1)) ==
         (default_base & (align - 1))); /* (b) sub-offset */
  assert(v + align > addr);             /* (c) tightest */
}

/* sub-offset 0 (x86_64/arm64/ppc): identical to a plain `addr & -align`. */
static void test_suboffset_zero_is_plain_floor(void) {
  check(0xffffffff81abc000ul, 0x200000ul, 0xffffffff81000000ul,
        0xffffffff81a00000ul);
  check(0xffffffff81000000ul, 0x200000ul, 0xffffffff81000000ul,
        0xffffffff81000000ul); /* addr already on the boundary */
}

/* Real riscv64 case: base at PMD + 0x2000, leak at base + 0x52ec8. A plain
 * floor would give 0xffffffff80000000 — below _text, unsound. */
static void test_riscv64_suboffset(void) {
  check(0xffffffff80054ec8ul, 0x200000ul, 0xffffffff80002000ul,
        0xffffffff80002000ul);
}

/* Real armv7 (2G/2G VMSPLIT) case: base = PAGE_OFFSET + IMAGE_BASE_OFFSET (sub
 * 0x8000), leak 0x8010ce7c. Plain floor -> 0x80000000 (below _text). */
static void test_arm32_suboffset(void) {
  check(0x8010ce7cul, 0x200000ul, 0xc0008000ul, 0x80008000ul);
}

/* s390-style large sub-offset (1 MiB). */
static void test_s390_suboffset(void) {
  check(0x00345678ul, 0x200000ul, 0x00100000ul, 0x00300000ul);
}

/* The wrap-down branch: addr sits above a boundary but *below* boundary+sub,
 * so floor+sub overshoots addr and one whole align must be subtracted. */
static void test_wraps_down_when_floor_plus_sub_overshoots(void) {
  check(0x00250000ul, 0x200000ul, 0x00100000ul, 0x00100000ul);
}

/* addr exactly on a valid base => returns addr unchanged. */
static void test_addr_equals_base(void) {
  check(0xffffffff80002000ul, 0x200000ul, 0xffffffff80002000ul,
        0xffffffff80002000ul);
}

/* The public wrapper binds this build's arch macros; assert the contract holds
 * for whatever (KASLR_VIRT_ALIGN, KERNEL_VIRT_TEXT_DEFAULT) was compiled in,
 * and that it delegates to the core. */
static void test_public_helper_host_arch(void) {
  unsigned long align = (unsigned long)KASLR_VIRT_ALIGN;
  unsigned long def = (unsigned long)KERNEL_VIRT_TEXT_DEFAULT;
  unsigned long addr =
      def + 0x123456ul; /* an interior pointer above the base */
  unsigned long v = kasld_floor_text_base(addr);
  assert(v <= addr);
  assert((v & (align - 1)) == (def & (align - 1)));
  assert(v + align > addr);
  assert(v == kasld_floor_aligned_suboffset(addr, align, def));
}

int main(void) {
  TEST_SUITE("Text-base floor (kasld_floor_text_base)");
  BEGIN_CATEGORY("sub-offset-preserving floor");
  RUN(test_suboffset_zero_is_plain_floor);
  RUN(test_riscv64_suboffset);
  RUN(test_arm32_suboffset);
  RUN(test_s390_suboffset);
  RUN(test_wraps_down_when_floor_plus_sub_overshoots);
  RUN(test_addr_equals_base);
  RUN(test_public_helper_host_arch);
  return TEST_DONE();
}
