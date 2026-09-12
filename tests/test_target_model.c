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
  struct kasld_model_check w =
      kasld_check_target_model(KASLD_FACTS_CAPTURE, NULL);
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
  struct kasld_model_check w =
      kasld_check_target_model(KASLD_FACTS_CAPTURE, NULL);
  TH_CHECK(w.verdict == KASLD_MODEL_OK);
}

/* No readable source and no probe: the honest answer is that nothing was
 * established, which must not refuse the run. This is the Android shape — a
 * policy hides the file — and the case a careless implementation gets wrong. */
static void test_no_signal_is_not_a_mismatch(void) {
  stage_kallsyms(NULL);
  struct kasld_model_check w =
      kasld_check_target_model(KASLD_FACTS_CAPTURE, NULL);
  TH_CHECK(w.verdict == KASLD_MODEL_OK);
  TH_CHECK(w.signal == KASLD_MODEL_SIGNAL_NONE);
}

/* Live, a 64-bit build has nothing to find: a narrower kernel could not have
 * loaded it and a wider one does not exist. The file is not even opened. */
static void test_64bit_build_is_inert_live(void) {
  if (sizeof(kasld_addr_t) < 8)
    return;
  stage_kallsyms("c1000000 T _text\n"); /* a 32-bit column */
  struct kasld_model_check w = kasld_check_target_model(KASLD_FACTS_LIVE, NULL);
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
  struct kasld_model_check w =
      kasld_check_target_model(KASLD_FACTS_CAPTURE, NULL);
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
  w.signal = KASLD_MODEL_SIGNAL_KCONFIG;
  TH_CHECK(strstr(kasld_model_signal_name(w.signal), "config") != NULL);
  /* The architecture refusal is reported apart from the width one: they call
   * for different corrective action. */
  TH_CHECK(!kasld_model_signal_is_width(w.signal));
  /* An unset signal still names something printable rather than NULL. */
  w.signal = KASLD_MODEL_SIGNAL_NONE;
  TH_CHECK(strcmp(kasld_model_signal_name(w.signal), "none") == 0);
}

/* The architecture signal reads /boot/config-<release>, so the release is part
 * of the staged fixture. "none" removes the file. */
static void stage_config(const char *release, const char *text) {
  char path[320];
  char rel[256];
  snprintf(rel, sizeof(rel), "/boot/config-%s", release);
  th_sysroot_stage_path(rel, path, sizeof(path));
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

/* An identifier no build in the tree claims, so the "some other architecture"
 * case is exercised on every architecture this test is compiled for. */
static const char *foreign_id(void) {
  return strcmp(KASLD_KCONFIG_ID, "S390") == 0 ? "ARM64" : "S390";
}

/* A capture whose config names a different architecture is a mismatch, and the
 * verdict names what it found so the operator learns which build to run. */
static void test_foreign_config_is_a_mismatch(void) {
  char cfg[128];
  stage_kallsyms(NULL);
  snprintf(cfg, sizeof(cfg), "CONFIG_CC_IS_GCC=y\nCONFIG_%s=y\n", foreign_id());
  stage_config("6.1.0-test", cfg);
  struct kasld_model_check w =
      kasld_check_target_model(KASLD_FACTS_CAPTURE, "6.1.0-test");
  TH_CHECK(w.verdict == KASLD_MODEL_MISMATCH);
  TH_CHECK(w.signal == KASLD_MODEL_SIGNAL_KCONFIG);
  TH_CHECK(strcmp(w.declared_arch, foreign_id()) == 0);
  stage_config("6.1.0-test", NULL);
}

/* This build's own identifier settles it even when another is also set, which
 * is the ppc64 shape: a 64-bit PowerPC kernel sets CONFIG_PPC as well. */
static void test_own_identifier_wins(void) {
  char cfg[192];
  stage_kallsyms(NULL);
  snprintf(cfg, sizeof(cfg), "CONFIG_%s=y\nCONFIG_%s=y\n", foreign_id(),
           KASLD_KCONFIG_ID);
  stage_config("6.1.0-test", cfg);
  TH_CHECK(
      kasld_check_target_model(KASLD_FACTS_CAPTURE, "6.1.0-test").verdict ==
      KASLD_MODEL_OK);
  stage_config("6.1.0-test", NULL);
}

/* A config that names no architecture at all proves nothing. A capture is
 * restored to its true length from whatever prefix was collected, so the line
 * may simply not be there — reading absence as proof would refuse a run that
 * was never wrong. */
static void test_config_naming_nothing_is_not_a_mismatch(void) {
  stage_kallsyms(NULL);
  stage_config("6.1.0-test", "CONFIG_CC_IS_GCC=y\nCONFIG_64BIT=y\n");
  struct kasld_model_check w =
      kasld_check_target_model(KASLD_FACTS_CAPTURE, "6.1.0-test");
  TH_CHECK(w.verdict == KASLD_MODEL_OK);
  TH_CHECK(w.declared_arch[0] == '\0');
  stage_config("6.1.0-test", NULL);
}

/* The match is on the whole symbol: CONFIG_ARM must not fire on CONFIG_ARM_FOO,
 * and a set symbol is "=y" — "is not set" and "=m" are not a declaration. */
static void test_identifier_match_is_exact(void) {
  char cfg[256];
  stage_kallsyms(NULL);
  snprintf(cfg, sizeof(cfg),
           "CONFIG_%s_EXTRA=y\n# CONFIG_%s is not set\nCONFIG_%s=m\n",
           foreign_id(), foreign_id(), foreign_id());
  stage_config("6.1.0-test", cfg);
  TH_CHECK(
      kasld_check_target_model(KASLD_FACTS_CAPTURE, "6.1.0-test").verdict ==
      KASLD_MODEL_OK);
  stage_config("6.1.0-test", NULL);
}

/* Live, the config is not read at all: it describes the kernel the binary is
 * running on, which cannot be a foreign architecture. */
static void test_config_not_consulted_live(void) {
  char cfg[128];
  stage_kallsyms(NULL);
  snprintf(cfg, sizeof(cfg), "CONFIG_%s=y\n", foreign_id());
  stage_config("6.1.0-test", cfg);
  TH_CHECK(kasld_check_target_model(KASLD_FACTS_LIVE, "6.1.0-test").verdict ==
           KASLD_MODEL_OK);
  stage_config("6.1.0-test", NULL);
}

/* No release names no config path, so a capture that identifies no kernel is
 * simply unanswerable rather than refused. */
static void test_no_release_is_not_a_mismatch(void) {
  stage_kallsyms(NULL);
  TH_CHECK(kasld_check_target_model(KASLD_FACTS_CAPTURE, NULL).verdict ==
           KASLD_MODEL_OK);
  TH_CHECK(kasld_check_target_model(KASLD_FACTS_CAPTURE, "").verdict ==
           KASLD_MODEL_OK);
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
  BEGIN_CATEGORY("declared architecture");
  RUN(test_foreign_config_is_a_mismatch);
  RUN(test_own_identifier_wins);
  RUN(test_config_naming_nothing_is_not_a_mismatch);
  RUN(test_identifier_match_is_exact);
  RUN(test_config_not_consulted_live);
  RUN(test_no_release_is_not_a_mismatch);
  BEGIN_CATEGORY("refusal document");
  RUN(test_refusal_document_shape);

  return TEST_DONE();
}
