// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Tests for sysfs_kernel_notes_xen: ELF note parsing over a staged binary
// /sys/kernel/notes. This is the last component reading a binary format that
// had no test, and a binary reader is where the one real parsing bug in this
// tree came from — a header field trusted because the structure it sat in
// looked like the right structure.
//
// Two things are being guarded, and they pull in opposite directions.
//
// The header fields are attacker-untrusted. namesz and descsz are read from the
// file and then used to align, size and index, so a value near UINT32_MAX would
// wrap the 4-byte alignment to a small total, slip past a size check written
// after the wrap, and index far outside the buffer. They are rejected before
// any arithmetic touches them, and the tests below feed exactly those values.
//
// The values are also untrusted in a quieter way: on a v6.9 or later kernel the
// notes are no longer relocated, so they hold link-time addresses that look
// entirely plausible and are simply wrong. Three states exist, and only the
// first may be published — see the cross-check the component performs. Every
// path that cannot positively establish the notes are live discards them, so
// most of what follows asserts silence rather than a value.
//
// x86 only; the component refuses to compile elsewhere.
// ---
// <bcoles@gmail.com>
#define _GNU_SOURCE

int sysfs_kernel_notes_xen_main(void);
#define main sysfs_kernel_notes_xen_main
#include "../src/components/sysfs_kernel_notes_xen.c"
#undef main

#include "test_component.h"
#include "test_harness.h"
#include "test_sysroot.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static unsigned char nbuf[1024];
static size_t nlen;

static void notes_reset(void) { nlen = 0; }

/* Append one ELF note: namesz, descsz, type, then name and desc each padded
 * out to a 4-byte boundary, which is the layout the reader walks. */
static void note_add(const char *name, uint32_t type, const void *desc,
                     uint32_t descsz) {
  uint32_t namesz = (uint32_t)strlen(name) + 1;
  uint32_t hdr[3] = {namesz, descsz, type};
  memcpy(nbuf + nlen, hdr, sizeof hdr);
  nlen += sizeof hdr;
  memcpy(nbuf + nlen, name, namesz);
  nlen += (namesz + 3) & ~3u;
  if (descsz) {
    memcpy(nbuf + nlen, desc, descsz);
    nlen += (descsz + 3) & ~3u;
  }
}

/* Append a header with sizes the reader must refuse before using them, plus a
 * body for the reader to succeed at reading.
 *
 * The body matters. Without it the note-body read comes up short and the loop
 * stops before the sizes are ever used, so the fixture would exercise the
 * short-read path and say nothing about the guard: with the guard removed the
 * test still passed. The declared sizes are nonsense, but enough bytes have to
 * follow for the reader to get as far as trusting them. */
static void note_add_raw_header(uint32_t namesz, uint32_t descsz,
                                uint32_t type) {
  uint32_t hdr[3] = {namesz, descsz, type};
  memcpy(nbuf + nlen, hdr, sizeof hdr);
  nlen += sizeof hdr;
  memset(nbuf + nlen, 0x41, 32);
  nlen += 32;
}

static void stage_notes(void) {
  th_sysroot_write_n("/sys/kernel/notes", nbuf, nlen);
}

/* A live (pre-v6.9) note set: the PHYS32 canary sits far enough above the
 * physical minimum to show a KASLR slide was applied. */
static unsigned long live_phys32(void) {
  return (unsigned long)KERNEL_PHYS_MIN + 4ul * (unsigned long)KASLR_PHYS_ALIGN;
}

static void run(int *rc) {
  TH_RUN_COMPONENT(*rc, sysfs_kernel_notes_xen_main());
}

/* Relocated notes are the one publishable state. */
static void test_live_notes_are_published(void) {
  th_sysroot_clear();
  unsigned long entry = (unsigned long)KERNEL_VIRT_TEXT_MIN + 0x100000ul;
  unsigned long hyper = (unsigned long)KERNEL_VIRT_TEXT_MIN + 0x316000ul;
  unsigned long p32 = live_phys32();
  notes_reset();
  note_add("Xen", XEN_ELFNOTE_ENTRY, &entry, sizeof entry);
  note_add("Xen", XEN_ELFNOTE_HYPERCALL_PAGE, &hyper, sizeof hyper);
  note_add("Xen", XEN_ELFNOTE_PHYS32_ENTRY, &p32, sizeof p32);
  stage_notes();
  /* No xen_elfnote_* symbols: the place-relative encoding is not in use. */
  th_sysroot_write("/proc/kallsyms", "ffffffff81000000 T _text\n");
  int rc;
  run(&rc);
  assert(strstr(th_cap, "startup_xen") != NULL);
  assert(strstr(th_cap, "hypercall_page") != NULL);
  assert(th_cap_field_is("sample", entry));
  assert(th_cap_field_is("sample", hyper));
}

/* The PHYS32 canary below one alignment step means no slide was applied: the
 * values are link-time addresses, and all three are discarded together. */
static void test_the_unrelocated_canary_discards_everything(void) {
  th_sysroot_clear();
  unsigned long entry = (unsigned long)KERNEL_VIRT_TEXT_MIN + 0x100000ul;
  unsigned long p32 = (unsigned long)KERNEL_PHYS_MIN;
  notes_reset();
  note_add("Xen", XEN_ELFNOTE_ENTRY, &entry, sizeof entry);
  note_add("Xen", XEN_ELFNOTE_PHYS32_ENTRY, &p32, sizeof p32);
  stage_notes();
  th_sysroot_write("/proc/kallsyms", "ffffffff81000000 T _text\n");
  int rc;
  run(&rc);
  assert(strstr(th_cap, "startup_xen") == NULL);
  assert(strstr(th_cap, "pvh_start_xen") == NULL);
}

/* Place-relative encoding: the values look plausible and are not live. The
 * xen_elfnote_* symbols are what says so. */
static void test_place_relative_symbols_discard_everything(void) {
  th_sysroot_clear();
  unsigned long entry = (unsigned long)KERNEL_VIRT_TEXT_MIN + 0x100000ul;
  unsigned long p32 = live_phys32();
  notes_reset();
  note_add("Xen", XEN_ELFNOTE_ENTRY, &entry, sizeof entry);
  note_add("Xen", XEN_ELFNOTE_PHYS32_ENTRY, &p32, sizeof p32);
  stage_notes();
  th_sysroot_write("/proc/kallsyms", "ffffffff81000000 T _text\n"
                                     "ffffffff81234000 T xen_elfnote_entry\n");
  int rc;
  run(&rc);
  assert(strstr(th_cap, "startup_xen") == NULL);
}

/* Without the canary there is nothing to verify against, and unverified is
 * discarded rather than assumed live. */
static void test_no_canary_discards_conservatively(void) {
  th_sysroot_clear();
  unsigned long hyper = (unsigned long)KERNEL_VIRT_TEXT_MIN + 0x316000ul;
  notes_reset();
  note_add("Xen", XEN_ELFNOTE_HYPERCALL_PAGE, &hyper, sizeof hyper);
  stage_notes();
  th_sysroot_write("/proc/kallsyms", "ffffffff81000000 T _text\n");
  int rc;
  run(&rc);
  assert(strstr(th_cap, "hypercall_page") == NULL);
}

/* Sizes that would wrap the 4-byte alignment are refused before they are
 * aligned, sized against the buffer, or used to index it. */
static void test_oversized_header_fields_are_refused(void) {
  th_sysroot_clear();
  notes_reset();
  note_add_raw_header(0xfffffffdu, 8u, XEN_ELFNOTE_ENTRY);
  stage_notes();
  int rc;
  run(&rc);
  assert(th_cap_count("sample=") == 0);

  th_sysroot_clear();
  notes_reset();
  note_add_raw_header(4u, 0xfffffffdu, XEN_ELFNOTE_ENTRY);
  stage_notes();
  run(&rc);
  assert(th_cap_count("sample=") == 0);
}

/* A non-Xen note carrying a text pointer is still a leak, labelled by its
 * origin, and it does not go through the Xen cross-check. */
static void test_a_foreign_note_is_scanned_generically(void) {
  th_sysroot_clear();
  unsigned long val = (unsigned long)KERNEL_VIRT_TEXT_MIN + 0x200000ul;
  notes_reset();
  note_add("Linux", 7, &val, sizeof val);
  stage_notes();
  int rc;
  run(&rc);
  assert(th_cap_field_is("sample", val));
  assert(strstr(th_cap, "Linux") != NULL);
}

/* No file at all: nothing claimed, no crash. */
static void test_absent_notes_emit_nothing(void) {
  th_sysroot_clear();
  int rc;
  run(&rc);
  assert(th_cap_count("sample=") == 0);
}

int main(void) {
  th_sysroot_init("sysfs_kernel_notes_xen");
  TEST_SUITE("sysfs_kernel_notes_xen");

  BEGIN_CATEGORY("Live notes");
  RUN(test_live_notes_are_published);
  RUN(test_a_foreign_note_is_scanned_generically);

  BEGIN_CATEGORY("Stale notes are discarded");
  RUN(test_the_unrelocated_canary_discards_everything);
  RUN(test_place_relative_symbols_discard_everything);
  RUN(test_no_canary_discards_conservatively);

  BEGIN_CATEGORY("Untrusted header fields");
  RUN(test_oversized_header_fields_are_refused);

  BEGIN_CATEGORY("Absence");
  RUN(test_absent_notes_emit_nothing);

  return TEST_DONE();
}
