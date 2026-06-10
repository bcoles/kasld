// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Parser unit tests for btf_struct_page_size's BTF reader. The component is
// #included with its main renamed so the static btf_struct_size() parser is in
// scope; we drive it with hand-built BTF blobs (the real
// /sys/kernel/btf/vmlinux is multi-MB and absent on the build host). Covers: a
// struct found after trailing-bearing predecessors, name discrimination, a
// non-native magic, and a truncated blob (no over-read).
// ---
// <bcoles@gmail.com>

int btf_struct_page_main(int argc, char **argv);
#define main btf_struct_page_main
#include "../src/components/btf_struct_page_size.c"
#undef main

#include "test_harness.h"

#include <assert.h>
#include <string.h>

static void put16(unsigned char *p, uint16_t v) { memcpy(p, &v, 2); }
static void put32(unsigned char *p, uint32_t v) { memcpy(p, &v, 4); }
static uint32_t info(uint32_t kind, uint32_t vlen) {
  return (kind << 24) | (vlen & 0xffff);
}

/* Build a BTF blob with three types — INT "int" (4 trailing bytes), STRUCT
 * "other" size 16 (one 12-byte member), STRUCT "page" size 64 — so the parser
 * must skip both a non-struct trailing record and a non-matching struct before
 * matching by name. Returns the total length. */
static size_t build_btf(unsigned char *b, uint16_t magic) {
  memset(b, 0, 256);
  /* header (24 bytes): sections are relative to hdr_len */
  put16(b + 0, magic);
  b[2] = 1;          /* version */
  b[3] = 0;          /* flags */
  put32(b + 4, 24);  /* hdr_len  */
  put32(b + 8, 0);   /* type_off */
  put32(b + 12, 52); /* type_len */
  put32(b + 16, 52); /* str_off  */
  put32(b + 20, 16); /* str_len  */
  unsigned char *t = b + 24;
  /* INT "int": name_off=1, kind 1, size 4, + 4 trailing */
  put32(t + 0, 1);
  put32(t + 4, info(1, 0));
  put32(t + 8, 4);
  put32(t + 12, 0); /* int-encoding trailing */
  /* STRUCT "other": name_off=5, kind 4 vlen 1, size 16, + 12-byte member */
  put32(t + 16, 5);
  put32(t + 20, info(4, 1));
  put32(t + 24, 16);
  memset(t + 28, 0, 12); /* one btf_member */
  /* STRUCT "page": name_off=11, kind 4 vlen 0, size 64 */
  put32(t + 40, 11);
  put32(t + 44, info(4, 0));
  put32(t + 48, 64);
  /* string section at b+24+52 = b+76 */
  memcpy(b + 76, "\0int\0other\0page", 16);
  return 24 + 52 + 16;
}

static void test_btf_finds_struct_page_size(void) {
  unsigned char b[256];
  size_t len = build_btf(b, BTF_MAGIC);
  assert(btf_struct_size(b, len, "page") == 64);
}

static void test_btf_name_discriminates(void) {
  unsigned char b[256];
  size_t len = build_btf(b, BTF_MAGIC);
  assert(btf_struct_size(b, len, "other") == 16);
  assert(btf_struct_size(b, len, "nonexistent") == 0);
}

static void test_btf_non_native_magic_rejected(void) {
  unsigned char b[256];
  size_t len = build_btf(b, 0x9FeB); /* byte-swapped magic */
  assert(btf_struct_size(b, len, "page") == 0);
}

static void test_btf_truncated_no_overread(void) {
  unsigned char b[256];
  build_btf(b, BTF_MAGIC);
  /* A length shorter than the header, and one that cuts the type section, must
   * both return 0 without reading past the buffer. */
  assert(btf_struct_size(b, 10, "page") == 0);
  assert(btf_struct_size(b, 40, "page") == 0);
}

int main(void) {
  TEST_SUITE("test_btf");
  BEGIN_CATEGORY("BTF struct-size parser");
  RUN(test_btf_finds_struct_page_size);
  RUN(test_btf_name_discriminates);
  RUN(test_btf_non_native_magic_rejected);
  RUN(test_btf_truncated_no_overread);
  return TEST_DONE();
}
