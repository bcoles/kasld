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
  TH_CHECK(kasld_image_size_from_header("hdr") == 24u * 1024 * 1024);
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
  TH_CHECK(kasld_image_size_from_bzimage("bz") == 60u * 1024 * 1024);
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
  TH_CHECK(kasld_image_size_from_bzimage("bzold") == 0);
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
  TH_CHECK(kasld_image_size_from_elf("e64") == 32u * 1024 * 1024);
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
  TH_CHECK(kasld_image_size_from_elf("e32") == 16u * 1024 * 1024);
}

/* System.map: _end - _text from the symbol addresses (64-bit addrs exercise
 * the 32-bit-safe accumulator). */
static void test_sysmap(void) {
  const char *m = "ffffffff81000000 T _text\n"
                  "ffffffff81000500 t some_fn\n"
                  "ffffffff83000000 B _end\n";
  wr("System.map-sm", m, strlen(m));
  TH_CHECK(kasld_image_size_from_sysmap("sm") == 0x02000000UL);
}

/* _stext is used when _text is absent. */
static void test_sysmap_stext_fallback(void) {
  const char *m = "ffffffff81000000 T _stext\n"
                  "ffffffff82800000 B _end\n";
  wr("System.map-st", m, strlen(m));
  TH_CHECK(kasld_image_size_from_sysmap("st") == 0x01800000UL);
}

/* Whole-file gzip vmlinuz: ISIZE is the last 4 bytes (LE). */
static void test_gzip_wholefile(void) {
  uint8_t b[64] = {0};
  b[0] = 0x1f;
  b[1] = 0x8b;
  b[2] = 0x08;
  put_le(b + 60, 24u * 1024 * 1024, 4); /* ISIZE at end of a 64-byte file */
  wr("vmlinuz-gz", b, sizeof(b));
  TH_CHECK(kasld_image_size_from_gzip("gz") == 24u * 1024 * 1024);
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
  TH_CHECK(kasld_image_size_from_gzip("zb") == 8u * 1024 * 1024);
}

/* A compressed (non-ELF) vmlinuz's on-disk size is a sound lower bound. */
static void test_vmlinuz_compressed_lb(void) {
  uint8_t head[4] = {0x42, 0x42, 0x42, 0x42}; /* not ELF/Image/bzImage/gzip */
  wr_sized("vmlinuz-cz", head, 4, 2 * 1024 * 1024);
  TH_CHECK(kasld_image_size_from_vmlinuz("cz") == 2u * 1024 * 1024);
}

/* An ELF vmlinux's on-disk size is NOT a footprint lower bound (it carries
 * unloaded symbol/section data); the file-size reader must reject it. */
static void test_vmlinuz_elf_rejected_as_lb(void) {
  uint8_t head[4] = {0x7f, 'E', 'L', 'F'};
  wr_sized("vmlinuz-elfblob", head, 4, 2 * 1024 * 1024);
  TH_CHECK(kasld_image_size_from_vmlinuz("elfblob") == 0);
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
  TH_CHECK(kasld_image_size_from_stat("denied") == 0);

  if (geteuid() == 0) {
    printf("    (denied half skipped: this uid bypasses the mode bits)\n");
    return;
  }
  TH_CHECK(chmod(p, 0) == 0);
#if BOOT_IMAGE_SIZE_FLOORS_FOOTPRINT
  TH_CHECK(kasld_image_size_from_stat("denied") == 2u * 1024 * 1024);
#else
  /* The /boot artefact is an ELF on this architecture, so its size bounds
   * nothing and the reader is compiled out. */
  TH_CHECK(kasld_image_size_from_stat("denied") == 0);
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
  TH_CHECK(kasld_image_size_from_btf() == 3u * 1024 * 1024);

  /* Below the plausibility floor, and absent: nothing either way. */
  th_sysroot_write_n("/sys/kernel/btf/vmlinux", "x", 1);
  TH_CHECK(kasld_image_size_from_btf() == 0);
  th_sysroot_rm("/sys/kernel/btf/vmlinux");
  TH_CHECK(kasld_image_size_from_btf() == 0);
}

/* Non-kernel bytes match nothing; a value below KIMG_MIN_BYTES is discarded. */
static void test_rejections(void) {
  uint8_t junk[128];
  memset(junk, 0xab, sizeof(junk));
  wr("vmlinuz-junk", junk, sizeof(junk));
  TH_CHECK(kasld_image_size_from_gzip("junk") == 0);
  TH_CHECK(kasld_image_size_from_elf("junk") == 0);
  TH_CHECK(kasld_image_size_from_header("junk") == 0);
  TH_CHECK(kasld_image_size_from_bzimage("junk") == 0);
  wr("System.map-junk", junk, sizeof(junk));
  TH_CHECK(kasld_image_size_from_sysmap("junk") == 0);

  uint8_t tiny[64] = {0};
  tiny[0] = 0x1f;
  tiny[1] = 0x8b;
  tiny[2] = 0x08;
  put_le(tiny + 60, 1024, 4); /* 1 KiB < KIMG_MIN_BYTES */
  wr("vmlinuz-tiny", tiny, sizeof(tiny));
  TH_CHECK(kasld_image_size_from_gzip("tiny") == 0);
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
  RUN(test_sysmap);
  RUN(test_sysmap_stext_fallback);
  BEGIN_CATEGORY("decompressed lower bound");
  RUN(test_gzip_wholefile);
  RUN(test_gzip_zboot);
  RUN(test_vmlinuz_compressed_lb);
  RUN(test_vmlinuz_elf_rejected_as_lb);
  RUN(test_stat_denied_content);
  RUN(test_btf_section_length);
  BEGIN_CATEGORY("component classification");
  RUN(test_component_absent_artefact_is_unavailable);
  RUN(test_component_readable_but_unparsed_is_neither);
  RUN(test_component_denied_artefact_is_noperm);
  BEGIN_CATEGORY("rejections");
  RUN(test_rejections);
  return TEST_DONE();
}
