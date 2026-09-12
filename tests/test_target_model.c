// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Unit tests for the build/target model check (target_model.h).
//
// The property that matters is asymmetric: a missed mismatch prints a window
// that cannot contain the base, but a FALSE mismatch refuses a run the tool
// could have completed. So every "cannot tell" path must read as no mismatch,
// and the tests spend most of their effort there.
//
// The file signals are driven over a staged KASLD_SYSROOT, which is also the
// mode they exist for: offline, the mmap probe measures the analysing host and
// must not be consulted at all.
// ---
// <bcoles@gmail.com>
#define _GNU_SOURCE

#include "include/kasld/target_model.h"
#include "test_harness.h"
#include "test_sysroot.h"

#include <assert.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

static void stage_kallsyms(const char *text) {
  char path[320];
  th_sysroot_stage_path("/proc/kallsyms", path, sizeof(path));
  if (text == NULL) {
    unlink(path);
    return;
  }
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  TH_CHECK(fd >= 0);
  size_t n = strlen(text);
  TH_CHECK(write(fd, text, n) == (ssize_t)n);
  close(fd);
}

/* The column width is the kernel's pointer width, and it is preserved when
 * kptr_restrict masks the values — the digits become zeros, not fewer. */
static void test_kallsyms_column_width(void) {
  stage_kallsyms("ffffffff81a00000 T _text\n");
  TH_CHECK(kasld__kallsyms_hex_digits() == 16);
  stage_kallsyms("0000000000000000 A irq_stack_union\n");
  TH_CHECK(kasld__kallsyms_hex_digits() == 16); /* masked, still 64-bit wide */
  stage_kallsyms("c1000000 T _text\n");
  TH_CHECK(kasld__kallsyms_hex_digits() == 8);
}

/* Anything that is not an address column reads as no signal, so a malformed or
 * unexpected file cannot manufacture a mismatch. */
static void test_kallsyms_non_column_is_no_signal(void) {
  stage_kallsyms("this is not a symbol table\n");
  TH_CHECK(kasld__kallsyms_hex_digits() == 0);
  /* Hex digits not followed by the type separator are a token, not a column. */
  stage_kallsyms("deadbeef\n");
  TH_CHECK(kasld__kallsyms_hex_digits() == 0);
  stage_kallsyms(NULL); /* absent entirely */
  TH_CHECK(kasld__kallsyms_hex_digits() == 0);
}

/* Offline, a wider column is the whole answer — and the mmap probe must not
 * have contributed, since it would describe the analysing host. */
static void test_replay_uses_only_the_file_signal(void) {
  stage_kallsyms("ffffffff81a00000 T _text\n");
  struct kasld_model_check w = kasld_check_target_model(KASLD_FACTS_CAPTURE);
  if (sizeof(kasld_addr_t) < 8) {
    TH_CHECK(w.verdict == KASLD_MODEL_MISMATCH);
    TH_CHECK(w.signal == KASLD_MODEL_SIGNAL_KALLSYMS);
    TH_CHECK(w.kallsyms_hex_digits == 16);
    TH_CHECK(w.task_size == 0); /* never measured while replaying */
  } else {
    /* A 64-bit build cannot be narrower than its target. */
    TH_CHECK(w.verdict == KASLD_MODEL_OK);
  }
}

/* A column matching this build is not a mismatch, on either width. */
static void test_matching_width_is_not_a_mismatch(void) {
  char line[64];
  snprintf(line, sizeof(line), "%0*lx T _text\n",
           (int)(sizeof(kasld_addr_t) * 2), (unsigned long)0x1000);
  stage_kallsyms(line);
  struct kasld_model_check w = kasld_check_target_model(KASLD_FACTS_CAPTURE);
  TH_CHECK(w.verdict == KASLD_MODEL_OK);
}

/* No readable source and no probe: the honest answer is that nothing was
 * established, which must not refuse the run. This is the Android shape — a
 * policy hides the file — and the case a careless implementation gets wrong. */
static void test_no_signal_is_not_a_mismatch(void) {
  stage_kallsyms(NULL);
  struct kasld_model_check w = kasld_check_target_model(KASLD_FACTS_CAPTURE);
  TH_CHECK(w.verdict == KASLD_MODEL_OK);
  TH_CHECK(w.signal == KASLD_MODEL_SIGNAL_NONE);
}

/* Live, a 64-bit build has nothing to find: a narrower kernel could not have
 * loaded it and a wider one does not exist. The file is not even opened. */
static void test_64bit_build_is_inert_live(void) {
  if (sizeof(kasld_addr_t) < 8)
    return;
  stage_kallsyms("c1000000 T _text\n"); /* a 32-bit column */
  struct kasld_model_check w = kasld_check_target_model(KASLD_FACTS_LIVE);
  TH_CHECK(w.verdict == KASLD_MODEL_OK);
  TH_CHECK(w.kallsyms_hex_digits == 0); /* not consulted */
}

/* Offline that reasoning does not hold — nothing loaded anything — so a
 * NARROWER capture is a mismatch too. This is the case the live-only argument
 * hid: a 64-bit build reading a 32-bit capture resolved a 64-bit window for a
 * kernel that has none. */
static void test_narrower_capture_is_a_mismatch(void) {
  if (sizeof(kasld_addr_t) < 8)
    return;
  stage_kallsyms("c1000000 T _text\n");
  struct kasld_model_check w = kasld_check_target_model(KASLD_FACTS_CAPTURE);
  TH_CHECK(w.verdict == KASLD_MODEL_MISMATCH);
  TH_CHECK(w.signal == KASLD_MODEL_SIGNAL_KALLSYMS);
  TH_CHECK(w.kallsyms_hex_digits == 8);
  TH_CHECK(w.task_size == 0); /* never measured while replaying */
}

/* Where the architecture fixes the boundary, the expectation is exact, and the
 * compat boundary that sits BELOW it must be caught. mips is the only arch that
 * declares this today; elsewhere the macro is absent and the path compiles out,
 * which the assertions below account for rather than assume. */
static void test_exact_boundary_arch(void) {
#ifdef TASK_SIZE_EXACT
  /* Both conditions must hold for an exact test to be sound, and each rules out
   * an architecture that would otherwise look eligible:
   *   a fixed split — with a choice of splits the test would refuse every
   *     kernel not built with the highest one;
   *   no gap — where the linear map starts above TASK_SIZE the measurement is
   *     legitimately below PAGE_OFFSET, so equality is the wrong expectation.
   * riscv32 is the near miss: its split is fixed, but the fixmap/PCI-IO/vmemmap
   * stack sits between the two, so it must not declare this. */
  TH_CHECK((unsigned long)PAGE_OFFSET_MIN == (unsigned long)PAGE_OFFSET_MAX);
  TH_CHECK((unsigned long)TASK_SIZE_EXACT == (unsigned long)PAGE_OFFSET_MAX);
#endif
  /* No assertion for the arches that omit it: omission is the safe default and
   * has several sound reasons, so its absence proves nothing either way. */
}

/* The refusal document must not be mistakable for a report. Its shape is
 * asserted here rather than only in the orchestrator, because the property
 * that matters is what it does NOT contain. */
static void test_refusal_document_shape(void) {
  /* json: an error object and nothing else. The orchestrator builds this from
   * the same fields, so pin the contract those fields must satisfy. */
  struct kasld_model_check w;
  memset(&w, 0, sizeof(w));
  w.verdict = KASLD_MODEL_MISMATCH;
  w.signal = KASLD_MODEL_SIGNAL_TASK_SIZE;
  w.task_size = 0xffffe000UL;
  TH_CHECK(kasld_model_signal_name(w.signal) != NULL);
  TH_CHECK(strstr(kasld_model_signal_name(w.signal), "boundary") != NULL);
  w.signal = KASLD_MODEL_SIGNAL_KALLSYMS;
  TH_CHECK(strstr(kasld_model_signal_name(w.signal), "kallsyms") != NULL);
  TH_CHECK(kasld_model_signal_is_width(w.signal));
  w.signal = KASLD_MODEL_SIGNAL_PROVENANCE;
  TH_CHECK(strstr(kasld_model_signal_name(w.signal), "capture") != NULL);
  /* The architecture refusal is reported apart from the width one: they call
   * for different corrective action. */
  TH_CHECK(!kasld_model_signal_is_width(w.signal));
  /* An unset signal still names something printable rather than NULL. */
  w.signal = KASLD_MODEL_SIGNAL_NONE;
  TH_CHECK(strcmp(kasld_model_signal_name(w.signal), "none") == 0);
}

/* The provenance signal reads the capture record prepare-bundle leaves at the
 * root of a prepared tree. "none" removes it. */
static void stage_capture(const char *text) {
  char path[320];
  th_sysroot_stage_path(KASLD_CAPTURE_FILE, path, sizeof(path));
  if (text == NULL) {
    unlink(path);
    return;
  }
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  TH_CHECK(fd >= 0);
  size_t n = strlen(text);
  TH_CHECK(write(fd, text, n) == (ssize_t)n);
  close(fd);
}

/* An architecture name no build in the tree answers to, so the "some other
 * machine" case is exercised whichever architecture this test is compiled for.
 */
static const char *foreign_arch(void) {
  return strcmp(KASLD_ARCH_NAME, "s390") == 0 ? "arm64" : "s390";
}

/* A capture recording a different machine is a mismatch, and the verdict names
 * it so the operator learns which build to run. */
static void test_foreign_capture_is_a_mismatch(void) {
  char rec[160];
  stage_kallsyms(NULL);
  snprintf(rec, sizeof(rec),
           "kernel_release:   6.1.0-test\narch_canonical:   %s\n",
           foreign_arch());
  stage_capture(rec);
  struct kasld_model_check w = kasld_check_target_model(KASLD_FACTS_CAPTURE);
  TH_CHECK(w.verdict == KASLD_MODEL_MISMATCH);
  TH_CHECK(w.signal == KASLD_MODEL_SIGNAL_PROVENANCE);
  TH_CHECK(strcmp(w.declared_arch, foreign_arch()) == 0);
  stage_capture(NULL);
}

/* A capture recording this build's own machine is analysed. */
static void test_own_capture_is_not_a_mismatch(void) {
  char rec[160];
  stage_kallsyms(NULL);
  snprintf(rec, sizeof(rec), "arch_canonical:   %s\n", KASLD_ARCH_NAME);
  stage_capture(rec);
  TH_CHECK(kasld_check_target_model(KASLD_FACTS_CAPTURE).verdict ==
           KASLD_MODEL_OK);
  stage_capture(NULL);
}

/* mips records its byte order in the same field, because uname cannot express
 * it there. Both orders share one arch header and resolve identical windows, so
 * the suffix must not read as a different machine. */
static void test_mips_byte_order_suffix_is_not_a_mismatch(void) {
  if (strcmp(KASLD_ARCH_NAME, "mips64") != 0 &&
      strcmp(KASLD_ARCH_NAME, "mips32") != 0)
    return;
  char rec[160];
  stage_kallsyms(NULL);
  snprintf(rec, sizeof(rec), "arch_canonical:   %sel\n", KASLD_ARCH_NAME);
  stage_capture(rec);
  TH_CHECK(kasld_check_target_model(KASLD_FACTS_CAPTURE).verdict ==
           KASLD_MODEL_OK);
  snprintf(rec, sizeof(rec), "arch_canonical:   %seb\n", KASLD_ARCH_NAME);
  stage_capture(rec);
  TH_CHECK(kasld_check_target_model(KASLD_FACTS_CAPTURE).verdict ==
           KASLD_MODEL_OK);
  stage_capture(NULL);
}

/* A tree with no capture record -- a hand-made sysroot, or one predating the
 * field -- states nothing, and stating nothing must not refuse the run. */
static void test_no_capture_record_is_not_a_mismatch(void) {
  stage_kallsyms(NULL);
  stage_capture(NULL);
  struct kasld_model_check w = kasld_check_target_model(KASLD_FACTS_CAPTURE);
  TH_CHECK(w.verdict == KASLD_MODEL_OK);
  TH_CHECK(w.declared_arch[0] == '\0');
  /* A record that carries other fields but not this one is the same case. */
  stage_capture("collect_version:  3\nanonymized:       1\n");
  TH_CHECK(kasld_check_target_model(KASLD_FACTS_CAPTURE).verdict ==
           KASLD_MODEL_OK);
  stage_capture(NULL);
}

/* "unknown" is what a capture records when collect did not recognise the
 * machine. It is an absent answer wearing a name, and comparing it as a name
 * would refuse an unlabelled capture even to the build that models it. */
static void test_unrecognised_machine_is_not_a_mismatch(void) {
  stage_kallsyms(NULL);
  stage_capture("arch_canonical:   unknown\n");
  struct kasld_model_check w = kasld_check_target_model(KASLD_FACTS_CAPTURE);
  TH_CHECK(w.verdict == KASLD_MODEL_OK);
  TH_CHECK(w.declared_arch[0] == '\0');
  stage_capture(NULL);
}

/* Live, the record is not read: there is no capture, and a tree that happens to
 * hold the file describes nothing about the running kernel. */
static void test_capture_record_not_consulted_live(void) {
  char rec[160];
  stage_kallsyms(NULL);
  snprintf(rec, sizeof(rec), "arch_canonical:   %s\n", foreign_arch());
  stage_capture(rec);
  TH_CHECK(kasld_check_target_model(KASLD_FACTS_LIVE).verdict ==
           KASLD_MODEL_OK);
  stage_capture(NULL);
}

int main(void) {
  TEST_SUITE("Build/target model check (target_model.h)");
  th_sysroot_init("target_model");

  BEGIN_CATEGORY("kallsyms column width");
  RUN(test_kallsyms_column_width);
  RUN(test_kallsyms_non_column_is_no_signal);
  BEGIN_CATEGORY("verdict");
  RUN(test_replay_uses_only_the_file_signal);
  RUN(test_matching_width_is_not_a_mismatch);
  RUN(test_no_signal_is_not_a_mismatch);
  RUN(test_64bit_build_is_inert_live);
  RUN(test_narrower_capture_is_a_mismatch);
  RUN(test_exact_boundary_arch);
  BEGIN_CATEGORY("recorded architecture");
  RUN(test_foreign_capture_is_a_mismatch);
  RUN(test_own_capture_is_not_a_mismatch);
  RUN(test_mips_byte_order_suffix_is_not_a_mismatch);
  RUN(test_no_capture_record_is_not_a_mismatch);
  RUN(test_unrecognised_machine_is_not_a_mismatch);
  RUN(test_capture_record_not_consulted_live);
  BEGIN_CATEGORY("refusal document");
  RUN(test_refusal_document_shape);

  return TEST_DONE();
}
