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

/* The component is driven too, for the classification it returns when no reader
 * answered: which of "denied" and "absent" applies is the only thing a run with
 * no size can still say about the host. */
int kernel_image_facts_main(void);
#define main kernel_image_facts_main
#include "../src/components/kernel_image_facts.c"
#undef main

#include "test_harness.h"
#include "test_sysroot.h"

#include <assert.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Write n bytes to <sysroot>/boot/<name>. */
static void wr(const char *name, const void *buf, size_t n) {
  char abs[TH_SYSROOT_MAX];
  snprintf(abs, sizeof(abs), "/boot/%s", name);
  th_sysroot_write_n(abs, buf, n);
}

/* The component keys its /boot paths on the release, and under a sysroot the
 * release comes from the capture's own /proc/version rather than from the host
 * reading it. Staging that line fixes the release for these tests, so the
 * fixture names do not depend on whatever kernel this suite is compiled or run
 * on. */
#define STAGED_RELEASE "6.8.0-kasldtest"
static void stage_capture_identity(void) {
  th_sysroot_write("/proc/version",
                   "Linux version " STAGED_RELEASE
                   " (b@h) (gcc) #1 SMP Thu Jan 1 00:00:00 UTC 2026\n");
}

static void rm_boot(const char *name) {
  char abs[TH_SYSROOT_MAX];
  snprintf(abs, sizeof(abs), "/boot/%s", name);
  th_sysroot_rm(abs);
}

/* Write head bytes then extend the file to `total` bytes (sparse). */
static void wr_sized(const char *name, const uint8_t *head, size_t headn,
                     long total) {
  char abs[TH_SYSROOT_MAX], p[TH_SYSROOT_MAX];
  snprintf(abs, sizeof(abs), "/boot/%s", name);
  th_sysroot_stage_path(abs, p, sizeof(p));
  FILE *f = fopen(p, "wb");
  TH_CHECK(f);
  if (headn)
    TH_CHECK(fwrite(head, 1, headn, f) == headn);
  if (total > (long)headn) {
    TH_CHECK(fseek(f, total - 1, SEEK_SET) == 0);
    TH_CHECK(fputc(0, f) != EOF);
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
  TH_CHECK(kasld_image_size_from_header("hdr", NULL) == 24u * 1024 * 1024);
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
  enum kasld_image_bound bnd = KIMG_BOUND_NONE;
  TH_CHECK(kasld_image_size_from_bzimage("bz", &bnd) == 60u * 1024 * 1024);
  /* init_size is the greater of the footprint and the decompressor's working
   * space, so it bounds the image from above and never from below. */
  TH_CHECK(bnd == KIMG_BOUND_UPPER);
}

/* The other two setup-header fields the same read yields.
 *
 * kernel_alignment (0x230) and relocatable_kernel (0x234) sit at the offsets
 * boot_params uses, because boot_params IS this header -- so the image answers
 * where the sysfs copy is unreadable. Staged with values no default carries, so
 * a pass cannot come from a zeroed buffer or from the sysfs path being taken
 * instead. Both edges of the tri-state are asserted: a 0 byte has to read as
 * "not relocatable" rather than as "could not tell". */
static void test_bzimage_align_and_relocatable(void) {
  uint8_t b[0x264] = {0};
  unsigned long size = 0, align = 0;
  int reloc = -1;
  b[0x202] = 'H';
  b[0x203] = 'd';
  b[0x204] = 'r';
  b[0x205] = 'S';
  put_le(b + 0x206, 0x020f, 2);
  put_le(b + 0x230, 0x400000, 4); /* 4 MiB: neither arch default */
  b[0x234] = 1;
  put_le(b + 0x260, 60u * 1024 * 1024, 4);
  wr("vmlinuz-hdrfields", b, sizeof(b));
  TH_CHECK(kasld_read_bzimage_hdr("hdrfields", &size, &align, &reloc) == 1);
  TH_CHECK(size == 60u * 1024 * 1024);
  TH_CHECK(align == 0x400000);
  TH_CHECK(reloc == 1);

  b[0x234] = 0;
  wr("vmlinuz-hdrnoreloc", b, sizeof(b));
  reloc = -1;
  TH_CHECK(kasld_read_bzimage_hdr("hdrnoreloc", NULL, NULL, &reloc) == 1);
  TH_CHECK(reloc == 0);

  /* Absent image: nothing is claimed, and the caller's tri-state is untouched
   * so an unreadable header cannot read as a non-relocatable kernel. */
  reloc = -1;
  align = 0;
  TH_CHECK(kasld_read_bzimage_hdr("hdrmissing", NULL, &align, &reloc) == 0);
  TH_CHECK(reloc == -1 && align == 0);
}

/* Each field answers for its own protocol version, and for no other.
 *
 * A header too old for init_size (2.10) still states the alignment (2.05), and
 * one too old for either states neither. The second half is the one that bites:
 * below 2.05 the byte at 0x234 is real-mode setup code, and reporting whatever
 * sits there as relocatable_kernel == 0 would tell the caller this kernel
 * cannot be relocated -- which it turns into a KASLR-off pin inside the
 * guaranteed window. Unknown must stay -1 there, never 0. */
static void test_bzimage_fields_gate_on_their_own_version(void) {
  uint8_t b[0x264] = {0};
  unsigned long size = 1, align = 1;
  int reloc = 1;
  b[0x202] = 'H';
  b[0x203] = 'd';
  b[0x204] = 'r';
  b[0x205] = 'S';
  put_le(b + 0x230, 0x200000, 4);
  b[0x234] = 0; /* a zero byte where the field would be */
  put_le(b + 0x260, 60u * 1024 * 1024, 4);

  /* 2.09: alignment and relocatable are carried, init_size is not. */
  put_le(b + 0x206, 0x0209, 2);
  wr("vmlinuz-hdr209", b, sizeof(b));
  TH_CHECK(kasld_read_bzimage_hdr("hdr209", &size, &align, &reloc) == 1);
  TH_CHECK(size == 0);
  TH_CHECK(align == 0x200000);
  TH_CHECK(reloc == 0);

  /* 2.04: none of the three exists yet. The zero at 0x234 is setup code, and
   * must read as "cannot tell" rather than "not relocatable". */
  size = 1;
  align = 1;
  reloc = 1;
  put_le(b + 0x206, 0x0204, 2);
  wr("vmlinuz-hdr204", b, sizeof(b));
  TH_CHECK(kasld_read_bzimage_hdr("hdr204", &size, &align, &reloc) == 1);
  TH_CHECK(size == 0);
  TH_CHECK(align == 0);
  TH_CHECK(reloc == -1);
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
  TH_CHECK(kasld_image_size_from_bzimage("bzold", NULL) == 0);
}

/* ELF64 little-endian, one PT_LOAD: span = max(vaddr+memsz) - min(vaddr). */
/* ELF64 little-endian with a symbol table: _end - _text from the symbols, NOT
 * the PT_LOAD span. The segment here deliberately stops short of _end, as a
 * real ppc kernel's does (p_memsz ends at the last section, while _end is
 * aligned above it), so a reader using segment geometry returns a smaller
 * figure and fails this.
 *
 * _text and _end are placed as TAIL-MERGED names -- stored as the suffix of a
 * longer symbol's name, which is how a linker emits them -- so a reader that
 * scans for NUL-delimited strings cannot find either and falls back to the
 * _stext/_etext pair, which understates. */
static void elf64_sym(uint8_t *b, size_t off, uint32_t name, uint64_t value) {
  put_le(b + off + 0, name, 4);  /* st_name */
  b[off + 4] = 0x10;             /* STB_GLOBAL | STT_NOTYPE */
  put_le(b + off + 6, 1, 2);     /* st_shndx */
  put_le(b + off + 8, value, 8); /* st_value */
}

static void test_elf64_le(void) {
  /* strtab: "\0" "zz_text\0" "_stext\0" "zzz_end\0"  -- _text at offset 3
   * inside "zz_text", _end at offset 20 inside "zzz_end". */
  static const char st[] = "\0zz_text\0_stext\0zzz_end\0";
  enum { STROFF = 640, SYMOFF = 384, SHOFF = 128 };
  uint8_t b[1024] = {0};
  b[0] = 0x7f;
  b[1] = 'E';
  b[2] = 'L';
  b[3] = 'F';
  b[4] = 2;                 /* ELFCLASS64 */
  b[5] = 1;                 /* ELFDATA2LSB */
  put_le(b + 32, 64, 8);    /* e_phoff */
  put_le(b + 40, SHOFF, 8); /* e_shoff */
  put_le(b + 54, 56, 2);    /* e_phentsize */
  put_le(b + 56, 1, 2);     /* e_phnum */
  put_le(b + 58, 64, 2);    /* e_shentsize */
  put_le(b + 60, 3, 2);     /* e_shnum */

  put_le(b + 64 + 0, 1, 4);                      /* p_type = PT_LOAD */
  put_le(b + 64 + 16, 0xffff800010000000ULL, 8); /* p_vaddr */
  put_le(b + 64 + 40, 31u * 1024 * 1024, 8);     /* p_memsz: short of _end */

  /* [1] SHT_SYMTAB, sh_link -> [2]; [2] SHT_STRTAB */
  put_le(b + SHOFF + 64 + 4, 2, 4);            /* sh_type = SHT_SYMTAB */
  put_le(b + SHOFF + 64 + 24, SYMOFF, 8);      /* sh_offset */
  put_le(b + SHOFF + 64 + 32, 24 * 4, 8);      /* sh_size: 4 entries */
  put_le(b + SHOFF + 64 + 40, 2, 4);           /* sh_link */
  put_le(b + SHOFF + 128 + 4, 3, 4);           /* sh_type = SHT_STRTAB */
  put_le(b + SHOFF + 128 + 24, STROFF, 8);     /* sh_offset */
  put_le(b + SHOFF + 128 + 32, sizeof(st), 8); /* sh_size */

  elf64_sym(b, SYMOFF + 24, 3, 0xffff800010000000ULL);  /* _text */
  elf64_sym(b, SYMOFF + 48, 9, 0xffff800010010000ULL);  /* _stext */
  elf64_sym(b, SYMOFF + 72, 19, 0xffff800012000000ULL); /* _end */
  memcpy(b + STROFF, st, sizeof(st));

  wr("vmlinuz-e64", b, sizeof(b));
  enum kasld_image_bound bnd = KIMG_BOUND_NONE;
  TH_CHECK(kasld_image_size_from_elf("e64", &bnd) == 32u * 1024 * 1024);
  TH_CHECK(bnd == KIMG_BOUND_EXACT);
}

/* ELF32 big-endian (the mips/ppc32 shape). Same shape, opposite byte order. */
static void elf32_sym(uint8_t *b, size_t off, uint32_t name, uint32_t value) {
  put_be(b + off + 0, name, 4);  /* st_name */
  put_be(b + off + 4, value, 4); /* st_value */
  b[off + 12] = 0x10;            /* STB_GLOBAL | STT_NOTYPE */
  put_be(b + off + 14, 1, 2);    /* st_shndx */
}

static void test_elf32_be(void) {
  static const char st[] = "\0zz_text\0_stext\0zzz_end\0";
  enum { STROFF = 640, SYMOFF = 384, SHOFF = 128 };
  uint8_t b[1024] = {0};
  b[0] = 0x7f;
  b[1] = 'E';
  b[2] = 'L';
  b[3] = 'F';
  b[4] = 1;                 /* ELFCLASS32 */
  b[5] = 2;                 /* ELFDATA2MSB */
  put_be(b + 28, 52, 4);    /* e_phoff */
  put_be(b + 32, SHOFF, 4); /* e_shoff */
  put_be(b + 42, 32, 2);    /* e_phentsize */
  put_be(b + 44, 1, 2);     /* e_phnum */
  put_be(b + 46, 40, 2);    /* e_shentsize */
  put_be(b + 48, 3, 2);     /* e_shnum */

  put_be(b + 52 + 0, 1, 4);                  /* p_type = PT_LOAD */
  put_be(b + 52 + 8, 0x80100000, 4);         /* p_vaddr */
  put_be(b + 52 + 20, 15u * 1024 * 1024, 4); /* p_memsz: short of _end */

  put_be(b + SHOFF + 40 + 4, 2, 4);           /* SHT_SYMTAB */
  put_be(b + SHOFF + 40 + 16, SYMOFF, 4);     /* sh_offset */
  put_be(b + SHOFF + 40 + 20, 16 * 4, 4);     /* sh_size: 4 entries */
  put_be(b + SHOFF + 40 + 24, 2, 4);          /* sh_link */
  put_be(b + SHOFF + 80 + 4, 3, 4);           /* SHT_STRTAB */
  put_be(b + SHOFF + 80 + 16, STROFF, 4);     /* sh_offset */
  put_be(b + SHOFF + 80 + 20, sizeof(st), 4); /* sh_size */

  elf32_sym(b, SYMOFF + 16, 3, 0x80100000);  /* _text */
  elf32_sym(b, SYMOFF + 32, 9, 0x80100400);  /* _stext */
  elf32_sym(b, SYMOFF + 48, 19, 0x81100000); /* _end */
  memcpy(b + STROFF, st, sizeof(st));

  wr("vmlinuz-e32", b, sizeof(b));
  enum kasld_image_bound bnd = KIMG_BOUND_NONE;
  TH_CHECK(kasld_image_size_from_elf("e32", &bnd) == 16u * 1024 * 1024);
  TH_CHECK(bnd == KIMG_BOUND_EXACT);
}

/* A partial pair bounds the footprint from below alone: _stext sits above
 * _text, so the span understates and must not be offered as an upper bound. */
static void test_elf_partial_pair_is_not_exact(void) {
  static const char st[] = "\0_stext\0_etext\0";
  enum { STROFF = 640, SYMOFF = 384, SHOFF = 128 };
  uint8_t b[1024] = {0};
  b[0] = 0x7f;
  b[1] = 'E';
  b[2] = 'L';
  b[3] = 'F';
  b[4] = 2;
  b[5] = 1;
  put_le(b + 40, SHOFF, 8);
  put_le(b + 58, 64, 2);
  put_le(b + 60, 3, 2);
  put_le(b + SHOFF + 64 + 4, 2, 4);
  put_le(b + SHOFF + 64 + 24, SYMOFF, 8);
  put_le(b + SHOFF + 64 + 32, 24 * 3, 8);
  put_le(b + SHOFF + 64 + 40, 2, 4);
  put_le(b + SHOFF + 128 + 4, 3, 4);
  put_le(b + SHOFF + 128 + 24, STROFF, 8);
  put_le(b + SHOFF + 128 + 32, sizeof(st), 8);
  elf64_sym(b, SYMOFF + 24, 1, 0xffff800010000000ULL); /* _stext */
  elf64_sym(b, SYMOFF + 48, 8, 0xffff800011000000ULL); /* _etext */
  memcpy(b + STROFF, st, sizeof(st));

  wr("vmlinuz-ep", b, sizeof(b));
  enum kasld_image_bound bnd = KIMG_BOUND_EXACT;
  TH_CHECK(kasld_image_size_from_elf("ep", &bnd) == 16u * 1024 * 1024);
  TH_CHECK(bnd == KIMG_BOUND_LOWER);
}

/* A stripped ELF carries no symbol table, so it yields no size at all rather
 * than one derived from segment geometry, which bounds the footprint in
 * neither direction. */
static void test_elf_stripped_declines(void) {
  uint8_t b[256] = {0};
  b[0] = 0x7f;
  b[1] = 'E';
  b[2] = 'L';
  b[3] = 'F';
  b[4] = 2;
  b[5] = 1;
  put_le(b + 32, 64, 8);                         /* e_phoff */
  put_le(b + 54, 56, 2);                         /* e_phentsize */
  put_le(b + 56, 1, 2);                          /* e_phnum */
  put_le(b + 64 + 0, 1, 4);                      /* PT_LOAD */
  put_le(b + 64 + 16, 0xffff800010000000ULL, 8); /* p_vaddr */
  put_le(b + 64 + 40, 32u * 1024 * 1024, 8);     /* p_memsz */
  wr("vmlinuz-es", b, sizeof(b));
  enum kasld_image_bound bnd = KIMG_BOUND_EXACT;
  TH_CHECK(kasld_image_size_from_elf("es", &bnd) == 0);
  TH_CHECK(bnd == KIMG_BOUND_NONE);
}

/* System.map: _end - _text from the symbol addresses (64-bit addrs exercise
 * the 32-bit-safe accumulator). */
static void test_sysmap(void) {
  const char *m = "ffffffff81000000 T _text\n"
                  "ffffffff81000500 t some_fn\n"
                  "ffffffff83000000 B _end\n";
  wr("System.map-sm", m, strlen(m));
  enum kasld_image_bound bnd = KIMG_BOUND_NONE;
  TH_CHECK(kasld_image_size_from_sysmap("sm", &bnd) == 0x02000000UL);
  TH_CHECK(bnd == KIMG_BOUND_EXACT);
}

/* _stext is used when _text is absent, and the span is then a lower bound
 * alone: _stext sits above _text by a head gap, so offering it as an upper
 * bound would put the image-base floor above the true base. */
static void test_sysmap_stext_fallback(void) {
  const char *m = "ffffffff81000000 T _stext\n"
                  "ffffffff82800000 B _end\n";
  wr("System.map-st", m, strlen(m));
  enum kasld_image_bound bnd = KIMG_BOUND_EXACT;
  TH_CHECK(kasld_image_size_from_sysmap("st", &bnd) == 0x01800000UL);
  TH_CHECK(bnd == KIMG_BOUND_LOWER);
}

/* Whole-file gzip vmlinuz: ISIZE is the last 4 bytes (LE). */
static void test_gzip_wholefile(void) {
  uint8_t b[64] = {0};
  b[0] = 0x1f;
  b[1] = 0x8b;
  b[2] = 0x08;
  put_le(b + 60, 24u * 1024 * 1024, 4); /* ISIZE at end of a 64-byte file */
  wr("vmlinuz-gz", b, sizeof(b));
  TH_CHECK(kasld_image_size_from_gzip("gz", NULL) == 24u * 1024 * 1024);
}

/* An EFI zboot container is not read by the gzip reader at all: its length word
 * sits at an offset the header supplies, with nothing there to corroborate it,
 * so the word is used only where the payload's declared size can confirm it.
 * The container falls through to the file-size lower bound instead. */
static void test_gzip_declines_zboot(void) {
  uint8_t b[320] = {0};
  b[0] = 0x4d;
  b[1] = 0x5a; /* "MZ\0\0" */
  memcpy(b + 4, "zimg", 4);
  put_le(b + 8, 64, 4);   /* payload_offset */
  put_le(b + 12, 256, 4); /* payload_size */
  memcpy(b + 24, "gzip", 4);
  b[64] = 0x1f;
  b[65] = 0x8b;                         /* payload gzip magic */
  put_le(b + 316, 8u * 1024 * 1024, 4); /* a well-formed length word */
  wr("vmlinuz-zb", b, sizeof(b));
  TH_CHECK(kasld_image_size_from_gzip("zb", NULL) == 0);
}

/* The container header parser bounds every offset it hands back against the
 * file, so a caller can read at them without re-deriving the checks. */
static void zb_hdr(uint8_t *b, unsigned long poff, unsigned long psz,
                   const char *comp) {
  memset(b, 0, 56);
  b[0] = 0x4d;
  b[1] = 0x5a;
  memcpy(b + 4, "zimg", 4);
  put_le(b + 8, poff, 4);
  put_le(b + 12, psz, 4);
  memcpy(b + 24, comp, strlen(comp));
}

static void test_zboot_header_bounds(void) {
  uint8_t b[56];
  struct kasld_zboot z;

  /* gzip: ZBOOT_SIZE_LEN is 0, so the length word is the last four bytes of
   * the payload the header names. */
  zb_hdr(b, 64, 256, "gzip");
  TH_CHECK(kasld_zboot_header(b, sizeof(b), 320, &z) == 1);
  TH_CHECK(z.payload_off == 64 && z.payload_size == 256);
  TH_CHECK(z.size_trailer == 316 && z.gzip == 1);

  /* zstd: the length is appended past payload_size, so the word sits four
   * bytes further on and the container must be that much longer. */
  zb_hdr(b, 64, 256, "zstd");
  TH_CHECK(kasld_zboot_header(b, sizeof(b), 324, &z) == 1);
  TH_CHECK(z.size_trailer == 320 && z.gzip == 0);
  TH_CHECK(kasld_zboot_header(b, sizeof(b), 320, &z) == 0);

  /* An unrecognised compressor names no length-word position, so guessing one
   * would read an unrelated word: refused outright. */
  zb_hdr(b, 64, 256, "lzma");
  TH_CHECK(kasld_zboot_header(b, sizeof(b), 320, &z) == 0);

  /* Fields inconsistent with the file. */
  zb_hdr(b, 64, 0xffffffffUL, "gzip");
  TH_CHECK(kasld_zboot_header(b, sizeof(b), 320, &z) == 0);
  zb_hdr(b, 0xffffffffUL, 256, "gzip");
  TH_CHECK(kasld_zboot_header(b, sizeof(b), 320, &z) == 0);
  zb_hdr(b, 8, 256, "gzip"); /* payload inside the header */
  TH_CHECK(kasld_zboot_header(b, sizeof(b), 320, &z) == 0);
  zb_hdr(b, 64, 8, "gzip"); /* payload too short to hold a stream */
  TH_CHECK(kasld_zboot_header(b, sizeof(b), 320, &z) == 0);

  /* Not a container at all. */
  zb_hdr(b, 64, 256, "gzip");
  b[4] = 'X';
  TH_CHECK(kasld_zboot_header(b, sizeof(b), 320, &z) == 0);
  zb_hdr(b, 64, 256, "gzip");
  TH_CHECK(kasld_zboot_header(b, 32, 320, &z) == 0); /* header truncated */
}

/* arm32 zImage: signature 0x016f2818 at 0x24, table offset at 0x38; the table
 * carries the count, magic 0x5a534c4b, the offset of the inflated-size word,
 * and _kernel_bss_size. The extent is the inflated size plus the BSS size. */
static void test_zimage_table(void) {
  uint8_t b[512] = {0};
  put_le(b + 0x24, 0x016f2818u, 4); /* zImage signature */
  put_le(b + 0x38, 0x80, 4);        /* table at 0x80 */
  put_le(b + 0x80, 6, 4);           /* entry count */
  put_le(b + 0x84, 0x5a534c4bu, 4); /* table magic */
  put_le(b + 0x88, 0x100, 4);       /* inflated-size word at 0x100 */
  put_le(b + 0x8c, 0x40000, 4);     /* _kernel_bss_size */
  put_le(b + 0x100, 20u * 1024 * 1024, 4);
  wr("vmlinuz-zi", b, sizeof(b));
  enum kasld_image_bound bnd = KIMG_BOUND_NONE;
  TH_CHECK(kasld_image_size_from_zimage("zi", &bnd) ==
           20u * 1024 * 1024 + 0x40000u);
  /* _kernel_bss_size spans __bss_start to __bss_stop, so the sum reaches
   * __bss_stop and not _end, which arch/arm aligns above it under
   * CONFIG_ARM_MPU. A lower bound, therefore, not the footprint. */
  TH_CHECK(bnd == KIMG_BOUND_LOWER);
}

/* The inflated-size word is appended little-endian whatever the target's byte
 * order, while the table's own words follow the image's. A big-endian table is
 * read through its magic; the size word stays LE. */
static void test_zimage_table_be(void) {
  uint8_t b[512] = {0};
  put_be(b + 0x24, 0x016f2818u, 4);
  put_be(b + 0x38, 0x80, 4);
  put_be(b + 0x80, 6, 4);
  put_be(b + 0x84, 0x5a534c4bu, 4);
  put_be(b + 0x88, 0x100, 4);
  put_be(b + 0x8c, 0x40000, 4);
  put_le(b + 0x100, 20u * 1024 * 1024, 4); /* LE even here */
  wr("vmlinuz-zibe", b, sizeof(b));
  TH_CHECK(kasld_image_size_from_zimage("zibe", NULL) ==
           20u * 1024 * 1024 + 0x40000u);
}

/* A table offset or inflated-size offset outside the file, a wrong table magic,
 * and a count too small to cover the entries read are all refused. */
static void test_zimage_table_rejections(void) {
  uint8_t b[512] = {0};
  put_le(b + 0x24, 0x016f2818u, 4);
  put_le(b + 0x80, 6, 4);
  put_le(b + 0x84, 0x5a534c4bu, 4);
  put_le(b + 0x88, 0x100, 4);
  put_le(b + 0x8c, 0x40000, 4);
  put_le(b + 0x100, 20u * 1024 * 1024, 4);

  put_le(b + 0x38, 0xffffffffu, 4); /* table past the end */
  wr("vmlinuz-zia", b, sizeof(b));
  TH_CHECK(kasld_image_size_from_zimage("zia", NULL) == 0);

  put_le(b + 0x38, 0x80, 4);
  put_le(b + 0x84, 0xdeadbeefu, 4); /* wrong table magic */
  wr("vmlinuz-zib", b, sizeof(b));
  TH_CHECK(kasld_image_size_from_zimage("zib", NULL) == 0);

  put_le(b + 0x84, 0x5a534c4bu, 4);
  put_le(b + 0x80, 2, 4); /* count below the entries read */
  wr("vmlinuz-zic", b, sizeof(b));
  TH_CHECK(kasld_image_size_from_zimage("zic", NULL) == 0);

  put_le(b + 0x80, 6, 4);
  put_le(b + 0x88, 0xffffffffu, 4); /* size word past the end */
  wr("vmlinuz-zid", b, sizeof(b));
  TH_CHECK(kasld_image_size_from_zimage("zid", NULL) == 0);

  put_le(b + 0x88, 0x100, 4);
  put_le(b + 0x8c, 0x7fffffffu,
         4); /* BSS larger than the image it belongs to */
  wr("vmlinuz-zie", b, sizeof(b));
  TH_CHECK(kasld_image_size_from_zimage("zie", NULL) == 0);
}

/* A compressed (non-ELF) vmlinuz's on-disk size is a sound lower bound. */
static void test_vmlinuz_compressed_lb(void) {
  uint8_t head[4] = {0x42, 0x42, 0x42, 0x42}; /* not ELF/Image/bzImage/gzip */
  wr_sized("vmlinuz-cz", head, 4, 2 * 1024 * 1024);
  TH_CHECK(kasld_image_size_from_vmlinuz("cz", NULL) == 2u * 1024 * 1024);
}

/* An ELF vmlinux's on-disk size is NOT a footprint lower bound (it carries
 * unloaded symbol/section data); the file-size reader must reject it. */
static void test_vmlinuz_elf_rejected_as_lb(void) {
  uint8_t head[4] = {0x7f, 'E', 'L', 'F'};
  wr_sized("vmlinuz-elfblob", head, 4, 2 * 1024 * 1024);
  TH_CHECK(kasld_image_size_from_vmlinuz("elfblob", NULL) == 0);
}

/* The stat reader answers only where the CONTENT cannot be read: a file the
 * readers above can open belongs to them. Both halves are asserted, because a
 * reader that answered unconditionally would pass the denied half alone.
 *
 * The denied half is skipped under a uid that bypasses the mode bits, where the
 * open succeeds and the reader correctly declines -- the condition cannot be
 * staged there at all, and asserting the readable half is all that remains. */
static void test_stat_denied_content(void) {
  uint8_t head[4] = {0x42, 0x42, 0x42, 0x42}; /* a blob, not an ELF */
  char p[TH_SYSROOT_MAX];

  wr_sized("vmlinuz-denied", head, 4, 2 * 1024 * 1024);
  th_sysroot_stage_path("/boot/vmlinuz-denied", p, sizeof(p));
  TH_CHECK(kasld_image_size_from_stat("denied", NULL) == 0);

  if (geteuid() == 0) {
    printf("    (denied half skipped: this uid bypasses the mode bits)\n");
    return;
  }
  TH_CHECK(chmod(p, 0) == 0);
#if BOOT_IMAGE_SIZE_FLOORS_FOOTPRINT
  TH_CHECK(kasld_image_size_from_stat("denied", NULL) == 2u * 1024 * 1024);
#else
  /* The /boot artefact is an ELF on this architecture, so its size bounds
   * nothing and the reader is compiled out. */
  TH_CHECK(kasld_image_size_from_stat("denied", NULL) == 0);
#endif
  TH_CHECK(chmod(p, 0600) == 0);
}

/* The .BTF section's length. Unlike every other reader this one takes no
 * release: the path is fixed, and only the file's size is consulted. */
static void test_btf_section_length(void) {
  char p[TH_SYSROOT_MAX];
  FILE *f;

  th_sysroot_stage_path("/sys/kernel/btf/vmlinux", p, sizeof(p));
  f = fopen(p, "wb");
  TH_CHECK(f);
  TH_CHECK(fseek(f, 3 * 1024 * 1024 - 1, SEEK_SET) == 0);
  TH_CHECK(fputc(0, f) != EOF);
  fclose(f);
  TH_CHECK(kasld_image_size_from_btf(NULL) == 3u * 1024 * 1024);

  /* Below the plausibility floor, and absent: nothing either way. */
  th_sysroot_write_n("/sys/kernel/btf/vmlinux", "x", 1);
  TH_CHECK(kasld_image_size_from_btf(NULL) == 0);
  th_sysroot_rm("/sys/kernel/btf/vmlinux");
  TH_CHECK(kasld_image_size_from_btf(NULL) == 0);
}

/* Non-kernel bytes match nothing; a value below KIMG_MIN_BYTES is discarded. */
static void test_rejections(void) {
  uint8_t junk[128];
  memset(junk, 0xab, sizeof(junk));
  wr("vmlinuz-junk", junk, sizeof(junk));
  TH_CHECK(kasld_image_size_from_gzip("junk", NULL) == 0);
  TH_CHECK(kasld_image_size_from_elf("junk", NULL) == 0);
  TH_CHECK(kasld_image_size_from_header("junk", NULL) == 0);
  TH_CHECK(kasld_image_size_from_bzimage("junk", NULL) == 0);
  wr("System.map-junk", junk, sizeof(junk));
  TH_CHECK(kasld_image_size_from_sysmap("junk", NULL) == 0);

  uint8_t tiny[64] = {0};
  tiny[0] = 0x1f;
  tiny[1] = 0x8b;
  tiny[2] = 0x08;
  put_le(tiny + 60, 1024, 4); /* 1 KiB < KIMG_MIN_BYTES */
  wr("vmlinuz-tiny", tiny, sizeof(tiny));
  TH_CHECK(kasld_image_size_from_gzip("tiny", NULL) == 0);
}

/* The component's own output, captured. The readers are asserted directly
 * above, but WHICH FACT each answer becomes is the component's decision, and it
 * is the half that matters most: an upper bound is emitted only for a span
 * proven exact, because the evidence layer takes the minimum over upper bounds,
 * so one resting on a partial symbol pair would displace the exact facts rather
 * than widening the window. A reader wired to emit both from a lower bound
 * passes every assertion above. */
static char cap[8192];

static void run_capture(void) {
  fflush(stdout);
  char tmpl[] = "/tmp/kasld_kimg_capXXXXXX";
  int fd = mkstemp(tmpl);
  TH_CHECK(fd >= 0);
  int saved = dup(1);
  dup2(fd, 1);
  fflush(stderr);
  int saved_err = dup(2);
  int devnull = open("/dev/null", O_WRONLY);
  if (devnull >= 0)
    dup2(devnull, 2);

  kernel_image_facts_main();

  fflush(stdout);
  fflush(stderr);
  dup2(saved, 1);
  close(saved);
  dup2(saved_err, 2);
  close(saved_err);
  if (devnull >= 0)
    close(devnull);

  lseek(fd, 0, SEEK_SET);
  ssize_t got = read(fd, cap, sizeof(cap) - 1);
  cap[got > 0 ? (size_t)got : 0] = '\0';
  close(fd);
  unlink(tmpl);
}

/* Remove every artefact the component looks at, so one case cannot be answered
 * by a file another left behind. */
static void clear_boot(void) {
  rm_boot("vmlinuz-" STAGED_RELEASE);
  rm_boot("Image-" STAGED_RELEASE);
  rm_boot("System.map-" STAGED_RELEASE);
}

/* An exact footprint feeds both ends. */
static void test_component_exact_emits_both(void) {
  uint8_t b[64] = {0};
  stage_capture_identity();
  clear_boot();
  b[0] = 0x4d;
  b[1] = 0x5a; /* "MZ" */
  put_le(b + 16, 24u * 1024 * 1024, 8);
  b[56] = 0x41;
  b[57] = 0x52;
  b[58] = 0x4d;
  b[59] = 0x64; /* "ARM\x64" */
  wr("Image-" STAGED_RELEASE, b, sizeof(b));
  run_capture();
  TH_CHECK(strstr(cap, "image_size_min conf=parsed value=0x1800000") != NULL);
  TH_CHECK(strstr(cap, "image_size_max conf=parsed value=0x1800000") != NULL);
  clear_boot();
}

/* An x86 bzImage: init_size bounds the footprint from above alone, so it feeds
 * the upper bound, and the lower bound comes from the compressed file's own
 * length instead. Emitting init_size as both is the failure this covers -- the
 * evidence layer takes the max over lower bounds, so an over-stated one
 * displaces the exact facts and lowers the ceiling past what truth permits. */
static void test_component_upper_bound_source_emits_both_ends_apart(void) {
  uint8_t b[0x264] = {0};
  stage_capture_identity();
  clear_boot();
  b[0] = 0x4d;
  b[1] = 0x5a;
  b[0x202] = 'H';
  b[0x203] = 'd';
  b[0x204] = 'r';
  b[0x205] = 'S';
  put_le(b + 0x206, 0x020f, 2);
  put_le(b + 0x260, 60u * 1024 * 1024, 4); /* init_size */
  wr("vmlinuz-" STAGED_RELEASE, b, sizeof(b));
  run_capture();
  /* The upper bound is init_size. */
  TH_CHECK(strstr(cap, "image_size_max conf=parsed value=0x3c00000") != NULL);
  /* A lower bound is still stated, and it is NOT init_size: the file is 0x264
   * bytes, far below the plausibility floor, so no lower-bound reader answers
   * and the only thing that must not appear is init_size on that side. */
  TH_CHECK(strstr(cap, "image_size_min conf=parsed value=0x3c00000") == NULL);
  clear_boot();
}

/* A System.map with no _text: the span rests on _stext, which sits above it, so
 * the figure is a lower bound and the upper bound must not be emitted. */
static void test_component_sysmap_partial_pair_emits_min_only(void) {
  const char *m = "ffffffff81000000 T _stext\n"
                  "ffffffff82800000 B _end\n";
  stage_capture_identity();
  clear_boot();
  wr("System.map-" STAGED_RELEASE, m, strlen(m));
  run_capture();
  TH_CHECK(strstr(cap, "image_size_min conf=parsed value=0x1800000") != NULL);
  TH_CHECK(strstr(cap, "image_size_max") == NULL);
  clear_boot();
}

/* The same through the ELF reader, whose symbol table carries only the inner
 * pair. */
static void test_component_elf_partial_pair_emits_min_only(void) {
  static const char st[] = "\0_stext\0_etext\0";
  enum { STROFF = 640, SYMOFF = 384, SHOFF = 128 };
  uint8_t b[1024] = {0};
  stage_capture_identity();
  clear_boot();
  b[0] = 0x7f;
  b[1] = 'E';
  b[2] = 'L';
  b[3] = 'F';
  b[4] = 2;
  b[5] = 1;
  put_le(b + 40, SHOFF, 8);
  put_le(b + 58, 64, 2);
  put_le(b + 60, 3, 2);
  put_le(b + SHOFF + 64 + 4, 2, 4);
  put_le(b + SHOFF + 64 + 24, SYMOFF, 8);
  put_le(b + SHOFF + 64 + 32, 24 * 3, 8);
  put_le(b + SHOFF + 64 + 40, 2, 4);
  put_le(b + SHOFF + 128 + 4, 3, 4);
  put_le(b + SHOFF + 128 + 24, STROFF, 8);
  put_le(b + SHOFF + 128 + 32, sizeof(st), 8);
  elf64_sym(b, SYMOFF + 24, 1, 0xffff800010000000ULL);
  elf64_sym(b, SYMOFF + 48, 8, 0xffff800011000000ULL);
  memcpy(b + STROFF, st, sizeof(st));
  wr("vmlinuz-" STAGED_RELEASE, b, sizeof(b));
  run_capture();
  TH_CHECK(strstr(cap, "image_size_min conf=parsed value=0x1000000") != NULL);
  TH_CHECK(strstr(cap, "image_size_max") == NULL);
  clear_boot();
}

/* A source that is a lower bound by its nature, rather than by a partial pair:
 * a whole-file gzip's ISIZE excludes BSS. */
static void test_component_lower_bound_emits_min_only(void) {
  uint8_t b[64] = {0};
  stage_capture_identity();
  clear_boot();
  b[0] = 0x1f;
  b[1] = 0x8b;
  b[2] = 0x08;
  put_le(b + 60, 24u * 1024 * 1024, 4); /* ISIZE */
  wr("vmlinuz-" STAGED_RELEASE, b, sizeof(b));
  run_capture();
  TH_CHECK(strstr(cap, "image_size_min conf=parsed value=0x1800000") != NULL);
  TH_CHECK(strstr(cap, "image_size_max") == NULL);
  clear_boot();
}

/* No artefact at all: absent, which is how the host is laid out, not a gate. */
static void test_component_absent_artefact_is_unavailable(void) {
  stage_capture_identity();
  rm_boot("vmlinuz-" STAGED_RELEASE);
  rm_boot("Image-" STAGED_RELEASE);
  rm_boot("System.map-" STAGED_RELEASE);
  TH_CHECK(kernel_image_facts_main() == KASLD_EXIT_UNAVAILABLE);
}

/* Readable, but too small for any reader to make a size of: neither denied nor
 * absent, so neither class is claimed. */
static void test_component_readable_but_unparsed_is_neither(void) {
  stage_capture_identity();
  wr("vmlinuz-" STAGED_RELEASE, "not a kernel", 12);
  TH_CHECK(kernel_image_facts_main() == 0);
  rm_boot("vmlinuz-" STAGED_RELEASE);
}

/* Present and unreadable is this host's hardening, and must not be reported as
 * a missing artefact. Root bypasses the mode bits, so the assertion is made
 * only where the denial can actually occur. */
static void test_component_denied_artefact_is_noperm(void) {
  char p[TH_SYSROOT_MAX];
  stage_capture_identity();
  wr("vmlinuz-" STAGED_RELEASE, "not a kernel", 12);
  th_sysroot_stage_path("/boot/vmlinuz-" STAGED_RELEASE, p, sizeof(p));
  TH_CHECK(chmod(p, 0) == 0);
  if (geteuid() == 0) {
    printf("      (skipped: root reads regardless of mode)\n");
  } else {
    TH_CHECK(kernel_image_facts_main() == KASLD_EXIT_NOPERM);
  }
  TH_CHECK(chmod(p, 0644) == 0);
  rm_boot("vmlinuz-" STAGED_RELEASE);
}

int main(void) {
  th_sysroot_init("kernel_image");

  TEST_SUITE("test_kernel_image");
  BEGIN_CATEGORY("exact readers");
  RUN(test_image_header);
  RUN(test_bzimage);
  RUN(test_bzimage_old_protocol);
  RUN(test_bzimage_align_and_relocatable);
  RUN(test_bzimage_fields_gate_on_their_own_version);
  RUN(test_elf64_le);
  RUN(test_elf32_be);
  RUN(test_elf_partial_pair_is_not_exact);
  RUN(test_elf_stripped_declines);
  RUN(test_sysmap);
  RUN(test_sysmap_stext_fallback);
  RUN(test_zimage_table);
  RUN(test_zimage_table_be);
  BEGIN_CATEGORY("decompressed lower bound");
  RUN(test_gzip_wholefile);
  RUN(test_gzip_declines_zboot);
  RUN(test_vmlinuz_compressed_lb);
  RUN(test_vmlinuz_elf_rejected_as_lb);
  RUN(test_stat_denied_content);
  RUN(test_btf_section_length);
  BEGIN_CATEGORY("component emission");
  RUN(test_component_exact_emits_both);
  RUN(test_component_upper_bound_source_emits_both_ends_apart);
  RUN(test_component_sysmap_partial_pair_emits_min_only);
  RUN(test_component_elf_partial_pair_emits_min_only);
  RUN(test_component_lower_bound_emits_min_only);
  BEGIN_CATEGORY("component classification");
  RUN(test_component_absent_artefact_is_unavailable);
  RUN(test_component_readable_but_unparsed_is_neither);
  RUN(test_component_denied_artefact_is_noperm);
  BEGIN_CATEGORY("rejections");
  RUN(test_rejections);
  RUN(test_zimage_table_rejections);
  RUN(test_zboot_header_bounds);
  return TEST_DONE();
}
