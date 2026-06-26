// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Unit tests for the kernel image-size readers in kasld/kernel_image.h.
//
// Each reader parses a real on-disk format; the tests craft minimal fixtures
// for each (raw Image header, ELF32-BE / ELF64-LE vmlinux, System.map, whole-
// file gzip, EFI-zboot gzip) under a temporary KASLD_SYSROOT and assert the
// parsed size. Fixture bytes are written field-by-field, so the suite is
// independent of the host's word size and endianness and is valid under
// tests/test-cross. KASLD_SYSROOT is resolved once (cached), so it is set
// before the first reader call and every fixture lives under one tree.
// ---
// <bcoles@gmail.com>

#define _DEFAULT_SOURCE         /* mkdtemp */
#define _POSIX_C_SOURCE 200809L /* setenv */

#include "../src/include/kasld/kernel_image.h"

#include "test_harness.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static char g_root[3072];

/* Write n bytes to <sysroot>/boot/<name>. */
static void wr(const char *name, const void *buf, size_t n) {
  char p[4096];
  snprintf(p, sizeof(p), "%s/boot/%s", g_root, name);
  FILE *f = fopen(p, "wb");
  assert(f);
  assert(fwrite(buf, 1, n, f) == n);
  fclose(f);
}

/* Write head bytes then extend the file to `total` bytes (sparse). */
static void wr_sized(const char *name, const uint8_t *head, size_t headn,
                     long total) {
  char p[4096];
  snprintf(p, sizeof(p), "%s/boot/%s", g_root, name);
  FILE *f = fopen(p, "wb");
  assert(f);
  if (headn)
    assert(fwrite(head, 1, headn, f) == headn);
  if (total > (long)headn) {
    assert(fseek(f, total - 1, SEEK_SET) == 0);
    assert(fputc(0, f) != EOF);
  }
  fclose(f);
}

static void put_le(uint8_t *b, uint64_t v, int n) {
  for (int i = 0; i < n; i++)
    b[i] = (uint8_t)(v >> (8 * i));
}
static void put_be(uint8_t *b, uint64_t v, int n) {
  for (int i = 0; i < n; i++)
    b[n - 1 - i] = (uint8_t)(v >> (8 * i));
}

/* arm64 raw Image header: image_size (u64 LE) at offset 16, "ARM\x64" magic at
 * offset 56. */
static void test_image_header(void) {
  uint8_t b[60] = {0};
  b[0] = 0x4d;
  b[1] = 0x5a; /* "MZ" */
  put_le(b + 16, 24u * 1024 * 1024, 8);
  b[56] = 0x41;
  b[57] = 0x52;
  b[58] = 0x4d;
  b[59] = 0x64; /* "ARM\x64" => 0x644d5241 */
  wr("Image-hdr", b, sizeof(b));
  assert(kasld_image_size_from_header("hdr") == 24u * 1024 * 1024);
}

/* x86 bzImage setup header: "HdrS" at 0x202, protocol >= 2.10, init_size at
 * 0x260. */
static void test_bzimage(void) {
  uint8_t b[0x264] = {0};
  b[0] = 0x4d;
  b[1] = 0x5a; /* "MZ" (EFI-stub bzImage) */
  b[0x202] = 'H';
  b[0x203] = 'd';
  b[0x204] = 'r';
  b[0x205] = 'S';
  put_le(b + 0x206, 0x020f, 2);            /* version 2.15 (>= 2.10) */
  put_le(b + 0x260, 60u * 1024 * 1024, 4); /* init_size */
  wr("vmlinuz-bz", b, sizeof(b));
  assert(kasld_image_size_from_bzimage("bz") == 60u * 1024 * 1024);
}

/* A bzImage predating protocol 2.10 has no init_size field; reject it. */
static void test_bzimage_old_protocol(void) {
  uint8_t b[0x264] = {0};
  b[0x202] = 'H';
  b[0x203] = 'd';
  b[0x204] = 'r';
  b[0x205] = 'S';
  put_le(b + 0x206, 0x0209, 2);            /* 2.09 < 2.10 */
  put_le(b + 0x260, 60u * 1024 * 1024, 4); /* present but not valid pre-2.10 */
  wr("vmlinuz-bzold", b, sizeof(b));
  assert(kasld_image_size_from_bzimage("bzold") == 0);
}

/* ELF64 little-endian, one PT_LOAD: span = max(vaddr+memsz) - min(vaddr). */
static void test_elf64_le(void) {
  uint8_t b[128] = {0};
  b[0] = 0x7f;
  b[1] = 'E';
  b[2] = 'L';
  b[3] = 'F';
  b[4] = 2;                                      /* ELFCLASS64 */
  b[5] = 1;                                      /* ELFDATA2LSB */
  put_le(b + 32, 64, 8);                         /* e_phoff */
  put_le(b + 54, 56, 2);                         /* e_phentsize */
  put_le(b + 56, 1, 2);                          /* e_phnum */
  put_le(b + 64 + 0, 1, 4);                      /* p_type = PT_LOAD */
  put_le(b + 64 + 16, 0xffff800010000000ULL, 8); /* p_vaddr */
  put_le(b + 64 + 40, 32u * 1024 * 1024, 8);     /* p_memsz */
  wr("vmlinuz-e64", b, sizeof(b));
  assert(kasld_image_size_from_elf("e64") == 32u * 1024 * 1024);
}

/* ELF32 big-endian (the mips/ppc32 shape), one PT_LOAD. */
static void test_elf32_be(void) {
  uint8_t b[128] = {0};
  b[0] = 0x7f;
  b[1] = 'E';
  b[2] = 'L';
  b[3] = 'F';
  b[4] = 1;                                  /* ELFCLASS32 */
  b[5] = 2;                                  /* ELFDATA2MSB */
  put_be(b + 28, 52, 4);                     /* e_phoff */
  put_be(b + 42, 32, 2);                     /* e_phentsize */
  put_be(b + 44, 1, 2);                      /* e_phnum */
  put_be(b + 52 + 0, 1, 4);                  /* p_type = PT_LOAD */
  put_be(b + 52 + 8, 0x80100000, 4);         /* p_vaddr */
  put_be(b + 52 + 20, 16u * 1024 * 1024, 4); /* p_memsz */
  wr("vmlinuz-e32", b, sizeof(b));
  assert(kasld_image_size_from_elf("e32") == 16u * 1024 * 1024);
}

/* System.map: _end - _text from the symbol addresses (64-bit addrs exercise
 * the 32-bit-safe accumulator). */
static void test_sysmap(void) {
  const char *m = "ffffffff81000000 T _text\n"
                  "ffffffff81000500 t some_fn\n"
                  "ffffffff83000000 B _end\n";
  wr("System.map-sm", m, strlen(m));
  assert(kasld_image_size_from_sysmap("sm") == 0x02000000UL);
}

/* _stext is used when _text is absent. */
static void test_sysmap_stext_fallback(void) {
  const char *m = "ffffffff81000000 T _stext\n"
                  "ffffffff82800000 B _end\n";
  wr("System.map-st", m, strlen(m));
  assert(kasld_image_size_from_sysmap("st") == 0x01800000UL);
}

/* Whole-file gzip vmlinuz: ISIZE is the last 4 bytes (LE). */
static void test_gzip_wholefile(void) {
  uint8_t b[64] = {0};
  b[0] = 0x1f;
  b[1] = 0x8b;
  b[2] = 0x08;
  put_le(b + 60, 24u * 1024 * 1024, 4); /* ISIZE at end of a 64-byte file */
  wr("vmlinuz-gz", b, sizeof(b));
  assert(kasld_image_size_from_gzip("gz") == 24u * 1024 * 1024);
}

/* EFI zboot ("MZ"+"zimg", gzip payload): ISIZE at
 * payload_offset+payload_size-4. poff=64, psz=256 => file 320 bytes, ISIZE at
 * 316. */
static void test_gzip_zboot(void) {
  uint8_t b[320] = {0};
  b[0] = 0x4d;
  b[1] = 0x5a; /* "MZ" */
  b[4] = 'z';
  b[5] = 'i';
  b[6] = 'm';
  b[7] = 'g';
  put_le(b + 8, 64, 4);   /* payload_offset */
  put_le(b + 12, 256, 4); /* payload_size */
  b[24] = 'g';
  b[25] = 'z';
  b[26] = 'i';
  b[27] = 'p';
  put_le(b + 316, 8u * 1024 * 1024, 4); /* inner gzip ISIZE */
  wr("vmlinuz-zb", b, sizeof(b));
  assert(kasld_image_size_from_gzip("zb") == 8u * 1024 * 1024);
}

/* A compressed (non-ELF) vmlinuz's on-disk size is a sound lower bound. */
static void test_vmlinuz_compressed_lb(void) {
  uint8_t head[4] = {0x42, 0x42, 0x42, 0x42}; /* not ELF/Image/bzImage/gzip */
  wr_sized("vmlinuz-cz", head, 4, 2 * 1024 * 1024);
  assert(kasld_image_size_from_vmlinuz("cz") == 2u * 1024 * 1024);
}

/* An ELF vmlinux's on-disk size is NOT a footprint lower bound (it carries
 * unloaded symbol/section data); the file-size reader must reject it. */
static void test_vmlinuz_elf_rejected_as_lb(void) {
  uint8_t head[4] = {0x7f, 'E', 'L', 'F'};
  wr_sized("vmlinuz-elfblob", head, 4, 2 * 1024 * 1024);
  assert(kasld_image_size_from_vmlinuz("elfblob") == 0);
}

/* Non-kernel bytes match nothing; a value below KIMG_MIN_BYTES is discarded. */
static void test_rejections(void) {
  uint8_t junk[128];
  memset(junk, 0xab, sizeof(junk));
  wr("vmlinuz-junk", junk, sizeof(junk));
  assert(kasld_image_size_from_gzip("junk") == 0);
  assert(kasld_image_size_from_elf("junk") == 0);
  assert(kasld_image_size_from_header("junk") == 0);
  assert(kasld_image_size_from_bzimage("junk") == 0);
  wr("System.map-junk", junk, sizeof(junk));
  assert(kasld_image_size_from_sysmap("junk") == 0);

  uint8_t tiny[64] = {0};
  tiny[0] = 0x1f;
  tiny[1] = 0x8b;
  tiny[2] = 0x08;
  put_le(tiny + 60, 1024, 4); /* 1 KiB < KIMG_MIN_BYTES */
  wr("vmlinuz-tiny", tiny, sizeof(tiny));
  assert(kasld_image_size_from_gzip("tiny") == 0);
}

int main(void) {
  char tmpl[] = "/tmp/kasld_kimg_XXXXXX";
  char *d = mkdtemp(tmpl);
  assert(d != NULL);
  snprintf(g_root, sizeof(g_root), "%s", d);
  char bootp[4096];
  snprintf(bootp, sizeof(bootp), "%s/boot", g_root);
  assert(mkdir(bootp, 0700) == 0);
  setenv("KASLD_SYSROOT", g_root,
         1); /* before the first reader call (cached) */

  TEST_SUITE("test_kernel_image");
  BEGIN_CATEGORY("exact readers");
  RUN(test_image_header);
  RUN(test_bzimage);
  RUN(test_bzimage_old_protocol);
  RUN(test_elf64_le);
  RUN(test_elf32_be);
  RUN(test_sysmap);
  RUN(test_sysmap_stext_fallback);
  BEGIN_CATEGORY("decompressed lower bound");
  RUN(test_gzip_wholefile);
  RUN(test_gzip_zboot);
  RUN(test_vmlinuz_compressed_lb);
  RUN(test_vmlinuz_elf_rejected_as_lb);
  BEGIN_CATEGORY("rejections");
  RUN(test_rejections);
  return TEST_DONE();
}
