// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Tests for extract_elf_section(): the reader that walks a component binary's
// ELF section headers to pull out the .kasld_meta it declared.
//
// Every field it steers by comes out of the file -- e_shoff, e_shnum,
// e_shstrndx, then each section's sh_name, sh_offset and sh_size -- and is used
// to seek and to index. The string-table index and each section's name offset
// are the two that index rather than merely seek: e_shstrndx picks an entry in
// the section table, and sh_name an offset into the string table, so a value
// past the end of either reads memory that is not there. Both are bounds-checked
// and neither check had a test.
//
// The companion parse_meta() is fuzzed; this reader is not -- the harness for it
// says so, taking the section payload as its input and starting after the walk.
// So the walk is what this covers, and it covers it by malformed input: a
// well-formed binary exercises none of the refusals.
//
// Fixtures are built here rather than captured, because what is being tested is
// the response to headers no compiler emits. mutate() writes one field of an
// otherwise valid image, so each case differs from the passing one in exactly
// the way its name says.
// ---
// <bcoles@gmail.com>
#define _GNU_SOURCE

#include "../src/meta.c"

#include "test_harness.h"

#include <elf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SEC_NAME ".kasld_meta"
#define PAYLOAD "method:parsed\nphase:inference\n"

/* A minimal ELF64 carrying three sections: the null entry, SEC_NAME with
 * PAYLOAD, and .shstrtab naming them. Laid out header / section table / string
 * table / payload so every offset is known and can be corrupted by name. */
/* Four header SLOTS, but e_shnum says three. The spare is a decoy: it repeats
 * the string table's descriptor, so a reader that ignored the e_shstrndx bound
 * and resolved names through slot 3 would succeed and return the payload. That
 * is what makes the bound testable -- refusing and failing-anyway both return
 * NULL, so only a mutant that SUCCEEDS can be told apart. */
#define NSEC 4
#define NSLOT 5
#define SHOFF sizeof(Elf64_Ehdr)
#define STROFF (SHOFF + NSLOT * sizeof(Elf64_Shdr))
static const char STRTAB[] = "\0" SEC_NAME "\0.shstrtab\0.other";
#define STRSZ sizeof(STRTAB)
#define PAYOFF (STROFF + STRSZ)
#define IMGSZ (PAYOFF + sizeof(PAYLOAD) - 1)

static unsigned char img[IMGSZ];

static Elf64_Ehdr *eh(void) { return (Elf64_Ehdr *)img; }
static Elf64_Shdr *sh(int i) { return &((Elf64_Shdr *)(img + SHOFF))[i]; }

static void build(void) {
  memset(img, 0, sizeof img);
  Elf64_Ehdr *e = eh();
  e->e_ident[EI_MAG0] = ELFMAG0;
  e->e_ident[EI_MAG1] = ELFMAG1;
  e->e_ident[EI_MAG2] = ELFMAG2;
  e->e_ident[EI_MAG3] = ELFMAG3;
  e->e_ident[EI_CLASS] = ELFCLASS64;
  e->e_shoff = SHOFF;
  e->e_shentsize = sizeof(Elf64_Shdr);
  e->e_shnum = NSEC;
  e->e_shstrndx = 3;
  /* 1: an ordinary other section, met BEFORE the wanted one. Its name is where
   * a sh_name is corrupted below: a bad name on a section the loop reaches
   * after the match would never be read, the match having broken out first. */
  sh(1)->sh_name = 1 + sizeof(SEC_NAME) + sizeof(".shstrtab");
  sh(1)->sh_offset = STROFF;
  sh(1)->sh_size = 1;
  /* 2: the section under test. Its name is at offset 1, past the leading NUL. */
  sh(2)->sh_name = 1;
  sh(2)->sh_offset = PAYOFF;
  sh(2)->sh_size = sizeof(PAYLOAD) - 1;
  /* 3: the string table. */
  sh(3)->sh_name = 1 + sizeof(SEC_NAME);
  sh(3)->sh_offset = STROFF;
  sh(3)->sh_size = STRSZ;
  /* 4: out of range per e_shnum, and a working string-table descriptor. */
  *sh(4) = *sh(3);
  memcpy(img + STROFF, STRTAB, STRSZ);
  memcpy(img + PAYOFF, PAYLOAD, sizeof(PAYLOAD) - 1);
}

/* Write the current image (optionally truncated) and read the section back.
 * Returns the extracted payload, or NULL. Caller frees. */
static char *extract(size_t len) {
  char tmpl[] = "/tmp/kasld_meta_elf_XXXXXX";
  int fd = mkstemp(tmpl);
  TH_CHECK(fd >= 0);
  TH_CHECK(write(fd, img, len) == (ssize_t)len);
  close(fd);
  char *r = extract_elf_section(tmpl, SEC_NAME);
  unlink(tmpl);
  return r;
}

static char *extract_full(void) { return extract(sizeof img); }

/* The passing case. Without it the refusals below prove only that the reader
 * can fail, not that it can tell the difference. */
static void test_reads_a_well_formed_section(void) {
  build();
  char *r = extract_full();
  TH_CHECK(r != NULL);
  TH_CHECK(strcmp(r, PAYLOAD) == 0);
  free(r);
}

/* A name the binary does not carry is absence, not an error. */
static void test_absent_section_is_not_an_error(void) {
  build();
  char tmpl[] = "/tmp/kasld_meta_elf_XXXXXX";
  int fd = mkstemp(tmpl);
  TH_CHECK(fd >= 0);
  TH_CHECK(write(fd, img, sizeof img) == (ssize_t)sizeof img);
  close(fd);
  char *r = extract_elf_section(tmpl, ".no_such_section");
  unlink(tmpl);
  TH_CHECK(r == NULL);
}

static void test_missing_file(void) {
  TH_CHECK(extract_elf_section("/nonexistent/kasld/component", SEC_NAME) == NULL);
}

/* Shorter than e_ident, and shorter than the header the class implies. */
static void test_truncated_before_a_header_exists(void) {
  build();
  char *r = extract(8);
  TH_CHECK(r == NULL);
  r = extract(sizeof(Elf64_Ehdr) - 1);
  TH_CHECK(r == NULL);
}

static void test_not_an_elf(void) {
  build();
  eh()->e_ident[EI_MAG2] = 'X';
  TH_CHECK(extract_full() == NULL);
}

/* The string-table index selects an entry in the section table. Past the end
 * it would read a header that is not there, so it is refused. */
static void test_string_table_index_past_the_section_table(void) {
  /* Slot 3 would work if it were reached; e_shnum says it is not there. */
  build();
  eh()->e_shstrndx = NSEC;
  TH_CHECK(extract_full() == NULL);
  build();
  eh()->e_shstrndx = 0xffff;
  TH_CHECK(extract_full() == NULL);
  /* And the decoy is a decoy only because of the bound: name it within range
   * and the same bytes read correctly, so the refusal above is the check
   * firing rather than the image being unreadable. */
  build();
  eh()->e_shnum = NSLOT;
  eh()->e_shstrndx = 4;
  char *r = extract_full();
  TH_CHECK(r != NULL);
  TH_CHECK(strcmp(r, PAYLOAD) == 0);
  free(r);
}

/* No section table at all, and a table of no entries. */
static void test_absent_section_table(void) {
  build();
  eh()->e_shoff = 0;
  TH_CHECK(extract_full() == NULL);
  build();
  eh()->e_shnum = 0;
  TH_CHECK(extract_full() == NULL);
}

/* A name offset past the string table would read beyond it. The section
 * carrying one is skipped, which is not the same as failing: the wanted section
 * is still found afterwards. Slot 1 is met BEFORE the match, so with the bound
 * removed the out-of-bounds read happens here -- silently on a plain build,
 * and as a fault under AddressSanitizer, which is where that bound's necessity
 * shows. By outcome alone a missing bound is indistinguishable, because the
 * byte just past the table is the NUL the reader appends. */
static void test_name_offset_past_the_string_table(void) {
  build();
  sh(1)->sh_name = 0x10000; /* far past the table, and met first */
  char *r = extract_full();
  TH_CHECK(r != NULL);
  TH_CHECK(strcmp(r, PAYLOAD) == 0);
  free(r);

  /* On the wanted section itself, an unreadable name means it cannot be
   * matched, and nothing else carries the name. */
  build();
  sh(2)->sh_name = 0x10000;
  TH_CHECK(extract_full() == NULL);
}

/* Both sanity limits: a string table or a section larger than the reader will
 * hold is refused rather than allocated.
 *
 * The section limit is a correctness bound and removing it is caught here. The
 * 1 MiB string-table limit is not: it caps an allocation, and with it gone the
 * read simply comes up short and fails anyway, so no outcome distinguishes the
 * two. It is asserted below for the behaviour it states, not as proof the
 * check is load-bearing -- showing that would need a file that really carries
 * a megabyte of string table. */
static void test_sizes_beyond_the_sanity_limits(void) {
  build();
  sh(3)->sh_size = 1024 * 1024 + 1;
  TH_CHECK(extract_full() == NULL);

  build();
  sh(2)->sh_size = 8193;
  TH_CHECK(extract_full() == NULL);

  build();
  sh(2)->sh_size = 0; /* present but empty says nothing */
  TH_CHECK(extract_full() == NULL);
}

/* Offsets that run past the end of the file: the seek succeeds and the read
 * comes up short, which must not be read as a section. */
static void test_offsets_past_the_end_of_file(void) {
  build();
  sh(3)->sh_offset = IMGSZ + 4096;
  TH_CHECK(extract_full() == NULL);

  build();
  sh(2)->sh_offset = IMGSZ + 4096;
  TH_CHECK(extract_full() == NULL);

  build();
  eh()->e_shoff = IMGSZ + 4096;
  TH_CHECK(extract_full() == NULL);
}

/* A 32-bit image is read by the other arm of every branch above. */
static void test_a_32bit_image_is_rejected_when_malformed(void) {
  build();
  eh()->e_ident[EI_CLASS] = ELFCLASS32;
  /* The 64-bit layout is not a valid 32-bit one, so this must refuse rather
   * than read the wrong fields as plausible. */
  TH_CHECK(extract_full() == NULL);
}

int main(void) {
  TEST_SUITE("meta_elf");

  BEGIN_CATEGORY("A well-formed binary");
  RUN(test_reads_a_well_formed_section);
  RUN(test_absent_section_is_not_an_error);

  BEGIN_CATEGORY("Nothing to read");
  RUN(test_missing_file);
  RUN(test_truncated_before_a_header_exists);
  RUN(test_not_an_elf);

  BEGIN_CATEGORY("Indices that would read out of bounds");
  RUN(test_string_table_index_past_the_section_table);
  RUN(test_name_offset_past_the_string_table);

  BEGIN_CATEGORY("Sizes and offsets the file cannot back");
  RUN(test_absent_section_table);
  RUN(test_sizes_beyond_the_sanity_limits);
  RUN(test_offsets_past_the_end_of_file);
  RUN(test_a_32bit_image_is_rejected_when_malformed);

  return TEST_DONE();
}
