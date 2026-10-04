// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Tests for sysfs_kernel_notes_phys32_reloc: the PVH physical-relocation ELF
// note, parsed over a staged binary /sys/kernel/notes.
//
// Two things are under test, and the second is the reason this component exists
// separately from the other note reader.
//
// The header fields are attacker-untrusted in the same way: namesz and descsz
// are read from the file and then used to align, size and index, so a value
// near UINT32_MAX could wrap the 4-byte alignment to a small total and index
// outside the buffer. They are rejected before any arithmetic reaches them.
//
// The descriptor is three BUILD constants, and what may be concluded from each
// differs. The image window is an exact two-way split -- 1 GiB under
// CONFIG_RANDOMIZE_BASE, 512 MiB without -- so it answers whether the option
// was configured, and nothing else. It does not say the randomizer RAN: that is
// the boot stub's record in boot_params, which a PVH entry never writes. So the
// positive case must state the option and never SF_KASLR_RANDOMIZED, and a
// window matching neither size must state nothing about the option at all
// rather than guess from its magnitude.
//
// A value the kernel omitted is not an answer either. The documented defaults
// for the trailing fields stand in for a loader, which can also read the
// program headers this process cannot, so a short descriptor publishes only the
// fields that are present.
//
// x86_64 only; the component refuses to compile elsewhere.
// ---
// <bcoles@gmail.com>
#define _GNU_SOURCE
#if defined(__x86_64__) || defined(__amd64__)

int sysfs_kernel_notes_phys32_reloc_main(void);
#define main sysfs_kernel_notes_phys32_reloc_main
#include "../src/components/sysfs_kernel_notes_phys32_reloc.c"
#undef main

#include "test_component.h"
#include "test_harness.h"
#include "test_sysroot.h"

#include <stdint.h>
#include <string.h>

static unsigned char nbuf[1024];
static size_t nlen;

static void notes_reset(void) { nlen = 0; }

static void put32(uint32_t v) {
  memcpy(nbuf + nlen, &v, 4);
  nlen += 4;
}

static void note_add(const char *name, uint32_t type, const void *desc,
                     uint32_t descsz) {
  uint32_t namesz = (uint32_t)strlen(name) + 1;
  put32(namesz);
  put32(descsz);
  put32(type);
  memcpy(nbuf + nlen, name, namesz);
  nlen += namesz;
  while (nlen % 4)
    nbuf[nlen++] = 0;
  if (descsz) {
    memcpy(nbuf + nlen, desc, descsz);
    nlen += descsz;
    while (nlen % 4)
      nbuf[nlen++] = 0;
  }
}

/* A raw header with no payload, for the untrusted-field cases. */
static void note_add_raw_header(uint32_t namesz, uint32_t descsz,
                                uint32_t type) {
  put32(namesz);
  put32(descsz);
  put32(type);
}

static void stage_notes(void) {
  th_sysroot_write_n("/sys/kernel/notes", nbuf, nlen);
}

/* The note as the kernel emits it: alignment, floor, image window. */
static void add_reloc_note(uint32_t align, uint32_t min_addr, uint32_t last,
                           unsigned fields) {
  uint32_t d[3] = {align, min_addr, last};
  note_add("Xen", XEN_ELFNOTE_PHYS32_RELOC, d, fields * 4);
}

static void run(int *rc) {
  TH_RUN_COMPONENT(*rc, sysfs_kernel_notes_phys32_reloc_main());
}

static int states_option(void) {
  return strstr(th_cap, "kaslr_compiled_in") != NULL;
}
static int states_kaslr_off(void) {
  return strstr(th_cap, "virt_kaslr_disabled") != NULL ||
         strstr(th_cap, "phys_kaslr_disabled") != NULL;
}

/* A 1 GiB image window is KERNEL_IMAGE_SIZE under CONFIG_RANDOMIZE_BASE, so the
 * option was configured. The constants come out alongside it, and nothing
 * claims the randomizer ran -- the note cannot know that. */
static void test_randomize_base_window_states_the_option(void) {
  th_sysroot_clear();
  notes_reset();
  add_reloc_note(0x200000, 0x1000000, 0x3fffffff, 3);
  stage_notes();
  int rc;
  run(&rc);

  TH_CHECK(strstr(th_cap, "phys_kernel_align conf=parsed value=0x200000") !=
           NULL);
  TH_CHECK(strstr(th_cap, "physical_start conf=parsed value=0x1000000") !=
           NULL);
  TH_CHECK(strstr(th_cap, "kaslr_compiled_in conf=parsed value=0x1") != NULL);
  TH_CHECK(strstr(th_cap, "kaslr_randomized") == NULL);
  TH_CHECK(!states_kaslr_off());
}

/* 512 MiB is the window without the option, and the randomizer is compiled only
 * under it, so no code existed to move the base on either axis. */
static void test_plain_window_states_kaslr_off(void) {
  th_sysroot_clear();
  notes_reset();
  add_reloc_note(0x200000, 0x1000000, 0x1fffffff, 3);
  stage_notes();
  int rc;
  run(&rc);

  TH_CHECK(strstr(th_cap, "virt_kaslr_disabled conf=parsed value=0x1") != NULL);
  TH_CHECK(strstr(th_cap, "phys_kaslr_disabled conf=parsed value=0x1") != NULL);
  TH_CHECK(!states_option());
  TH_CHECK(strstr(th_cap, "kaslr_randomized") == NULL);
}

/* A window matching neither size is not described by the two-way split. The
 * constants are still constants, but the option stays unstated: a third
 * KERNEL_IMAGE_SIZE would otherwise be read as whichever answer it sat nearer.
 */
static void test_unrecognised_window_states_nothing_about_the_option(void) {
  th_sysroot_clear();
  notes_reset();
  add_reloc_note(0x200000, 0x1000000, 0x0fffffff, 3);
  stage_notes();
  int rc;
  run(&rc);

  TH_CHECK(strstr(th_cap, "phys_kernel_align conf=parsed value=0x200000") !=
           NULL);
  TH_CHECK(strstr(th_cap, "physical_start conf=parsed value=0x1000000") !=
           NULL);
  TH_CHECK(!states_option());
  TH_CHECK(!states_kaslr_off());
}

/* Two values present: the window is absent, so the option is unstated. */
static void test_two_field_descriptor_states_no_option(void) {
  th_sysroot_clear();
  notes_reset();
  add_reloc_note(0x200000, 0x1000000, 0, 2);
  stage_notes();
  int rc;
  run(&rc);

  TH_CHECK(strstr(th_cap, "phys_kernel_align conf=parsed value=0x200000") !=
           NULL);
  TH_CHECK(strstr(th_cap, "physical_start conf=parsed value=0x1000000") !=
           NULL);
  TH_CHECK(!states_option());
  TH_CHECK(!states_kaslr_off());
}

/* One value present: the alignment alone. The floor is not defaulted to 0 --
 * that would be a lower bound of nothing dressed as a parsed fact. */
static void test_one_field_descriptor_states_only_the_alignment(void) {
  th_sysroot_clear();
  notes_reset();
  add_reloc_note(0x200000, 0, 0, 1);
  stage_notes();
  int rc;
  run(&rc);

  TH_CHECK(strstr(th_cap, "phys_kernel_align conf=parsed value=0x200000") !=
           NULL);
  TH_CHECK(strstr(th_cap, "physical_start") == NULL);
  TH_CHECK(!states_option());
}

/* namesz and descsz are file-supplied. Values near UINT32_MAX would wrap the
 * 4-byte alignment; they are refused before the arithmetic. */
static void test_oversized_header_fields_are_refused(void) {
  th_sysroot_clear();
  notes_reset();
  note_add_raw_header(0xfffffffcu, 0xfffffffcu, XEN_ELFNOTE_PHYS32_RELOC);
  stage_notes();
  int rc;
  run(&rc);

  TH_CHECK(!states_option());
  TH_CHECK(!states_kaslr_off());
  TH_CHECK(strstr(th_cap, "phys_kernel_align") == NULL);
}

/* A kernel before v6.12 carries the PVH entry note and not this one. */
static void test_entry_note_alone_emits_nothing(void) {
  th_sysroot_clear();
  notes_reset();
  uint64_t entry = 0x2948b40;
  note_add("Xen", 18, &entry, sizeof entry);
  stage_notes();
  int rc;
  run(&rc);

  TH_CHECK(strstr(th_cap, "phys_kernel_align") == NULL);
  TH_CHECK(strstr(th_cap, "physical_start") == NULL);
  TH_CHECK(!states_option());
  TH_CHECK(!states_kaslr_off());
}

/* A foreign note of the same type number is not this note. */
static void test_same_type_under_another_name_is_ignored(void) {
  th_sysroot_clear();
  notes_reset();
  uint32_t d[3] = {0x200000, 0x1000000, 0x1fffffff};
  note_add("GNU", XEN_ELFNOTE_PHYS32_RELOC, d, sizeof d);
  stage_notes();
  int rc;
  run(&rc);

  TH_CHECK(!states_option());
  TH_CHECK(!states_kaslr_off());
  TH_CHECK(strstr(th_cap, "phys_kernel_align") == NULL);
}

static void test_absent_notes_emit_nothing(void) {
  th_sysroot_clear();
  int rc;
  run(&rc);

  TH_CHECK(rc == KASLD_EXIT_UNAVAILABLE);
  TH_CHECK(strstr(th_cap, "phys_kernel_align") == NULL);
  TH_CHECK(!states_option());
}

int main(void) {
  th_sysroot_init("sysfs_kernel_notes_phys32_reloc");
  TEST_SUITE("sysfs_kernel_notes_phys32_reloc");

  BEGIN_CATEGORY("The image window answers the option");
  RUN(test_randomize_base_window_states_the_option);
  RUN(test_plain_window_states_kaslr_off);
  RUN(test_unrecognised_window_states_nothing_about_the_option);

  BEGIN_CATEGORY("A short descriptor publishes only what is there");
  RUN(test_two_field_descriptor_states_no_option);
  RUN(test_one_field_descriptor_states_only_the_alignment);

  BEGIN_CATEGORY("Untrusted header fields");
  RUN(test_oversized_header_fields_are_refused);

  BEGIN_CATEGORY("Absence and near misses");
  RUN(test_entry_note_alone_emits_nothing);
  RUN(test_same_type_under_another_name_is_ignored);
  RUN(test_absent_notes_emit_nothing);

  return TEST_DONE();
}

#else /* non-x86_64 host: the component is x86_64-only (it #errors)            \
       */
#include "test_harness.h"
int main(void) {
  TEST_SUITE("sysfs_kernel_notes_phys32_reloc");
  return TEST_DONE();
}
#endif
