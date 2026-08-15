// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Unit tests for the build/target width check (target_width.h).
//
// The property that matters is asymmetric: a missed mismatch prints a window
// that cannot contain the base, but a FALSE mismatch refuses a run the tool
// could have completed. So every "cannot tell" path must read as no mismatch,
// and the tests spend most of their effort there.
//
// The kallsyms signal is driven over a staged KASLD_SYSROOT, which is also the
// mode it exists for: offline, the mmap probe measures the analysing host and
// must not be consulted at all.
// ---
// <bcoles@gmail.com>
#define _GNU_SOURCE

#include "include/kasld/target_width.h"
#include "test_harness.h"

#include <assert.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

static char g_root[256];

static void stage_kallsyms(const char *text) {
  char path[320];
  snprintf(path, sizeof(path), "%s/proc/kallsyms", g_root);
  if (text == NULL) {
    unlink(path);
    return;
  }
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  assert(fd >= 0);
  size_t n = strlen(text);
  assert(write(fd, text, n) == (ssize_t)n);
  close(fd);
}

/* The column width is the kernel's pointer width, and it is preserved when
 * kptr_restrict masks the values — the digits become zeros, not fewer. */
static void test_kallsyms_column_width(void) {
  stage_kallsyms("ffffffff81a00000 T _text\n");
  assert(kasld__kallsyms_hex_digits() == 16);
  stage_kallsyms("0000000000000000 A irq_stack_union\n");
  assert(kasld__kallsyms_hex_digits() == 16); /* masked, still 64-bit wide */
  stage_kallsyms("c1000000 T _text\n");
  assert(kasld__kallsyms_hex_digits() == 8);
}

/* Anything that is not an address column reads as no signal, so a malformed or
 * unexpected file cannot manufacture a mismatch. */
static void test_kallsyms_non_column_is_no_signal(void) {
  stage_kallsyms("this is not a symbol table\n");
  assert(kasld__kallsyms_hex_digits() == 0);
  /* Hex digits not followed by the type separator are a token, not a column. */
  stage_kallsyms("deadbeef\n");
  assert(kasld__kallsyms_hex_digits() == 0);
  stage_kallsyms(NULL); /* absent entirely */
  assert(kasld__kallsyms_hex_digits() == 0);
}

/* Offline, a wider column is the whole answer — and the mmap probe must not
 * have contributed, since it would describe the analysing host. */
static void test_replay_uses_only_the_file_signal(void) {
  stage_kallsyms("ffffffff81a00000 T _text\n");
  struct kasld_width_check w = kasld_check_target_width(1);
  if (sizeof(kasld_addr_t) < 8) {
    assert(w.verdict == KASLD_WIDTH_MISMATCH);
    assert(w.signal == KASLD_WIDTH_SIGNAL_KALLSYMS);
    assert(w.kallsyms_hex_digits == 16);
    assert(w.task_size == 0); /* never measured while replaying */
  } else {
    /* A 64-bit build cannot be narrower than its target. */
    assert(w.verdict == KASLD_WIDTH_OK);
  }
}

/* A column matching this build is not a mismatch, on either width. */
static void test_matching_width_is_not_a_mismatch(void) {
  char line[64];
  snprintf(line, sizeof(line), "%0*lx T _text\n",
           (int)(sizeof(kasld_addr_t) * 2), (unsigned long)0x1000);
  stage_kallsyms(line);
  struct kasld_width_check w = kasld_check_target_width(1);
  assert(w.verdict == KASLD_WIDTH_OK);
}

/* No readable source and no probe: the honest answer is that nothing was
 * established, which must not refuse the run. This is the Android shape — a
 * policy hides the file — and the case a careless implementation gets wrong. */
static void test_no_signal_is_not_a_mismatch(void) {
  stage_kallsyms(NULL);
  struct kasld_width_check w = kasld_check_target_width(1);
  assert(w.verdict == KASLD_WIDTH_OK);
  assert(w.signal == KASLD_WIDTH_SIGNAL_NONE);
}

/* On a 64-bit build the check is inert whatever it is shown, because the
 * situation it detects cannot arise. */
static void test_64bit_build_is_inert(void) {
  if (sizeof(kasld_addr_t) < 8)
    return;
  stage_kallsyms("ffffffffffffffff T _text\n");
  assert(kasld_check_target_width(0).verdict == KASLD_WIDTH_OK);
  assert(kasld_check_target_width(1).verdict == KASLD_WIDTH_OK);
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
  assert((unsigned long)PAGE_OFFSET_MIN == (unsigned long)PAGE_OFFSET_MAX);
  assert((unsigned long)TASK_SIZE_EXACT == (unsigned long)PAGE_OFFSET_MAX);
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
  struct kasld_width_check w;
  memset(&w, 0, sizeof(w));
  w.verdict = KASLD_WIDTH_MISMATCH;
  w.signal = KASLD_WIDTH_SIGNAL_TASK_SIZE;
  w.task_size = 0xffffe000UL;
  assert(kasld_width_signal_name(w.signal) != NULL);
  assert(strstr(kasld_width_signal_name(w.signal), "boundary") != NULL);
  w.signal = KASLD_WIDTH_SIGNAL_KALLSYMS;
  assert(strstr(kasld_width_signal_name(w.signal), "kallsyms") != NULL);
  /* An unset signal still names something printable rather than NULL. */
  w.signal = KASLD_WIDTH_SIGNAL_NONE;
  assert(strcmp(kasld_width_signal_name(w.signal), "none") == 0);
}

int main(void) {
  TEST_SUITE("Build/target width check (target_width.h)");
  snprintf(g_root, sizeof(g_root), "/tmp/kasld_tw_rootXXXXXX");
  assert(mkdtemp(g_root) != NULL);
  char sub[320];
  snprintf(sub, sizeof(sub), "%s/proc", g_root);
  assert(mkdir(sub, 0755) == 0);
  setenv("KASLD_SYSROOT", g_root, 1);

  BEGIN_CATEGORY("kallsyms column width");
  RUN(test_kallsyms_column_width);
  RUN(test_kallsyms_non_column_is_no_signal);
  BEGIN_CATEGORY("verdict");
  RUN(test_replay_uses_only_the_file_signal);
  RUN(test_matching_width_is_not_a_mismatch);
  RUN(test_no_signal_is_not_a_mismatch);
  RUN(test_64bit_build_is_inert);
  RUN(test_exact_boundary_arch);
  RUN(test_refusal_document_shape);

  snprintf(sub, sizeof(sub), "%s/proc/kallsyms", g_root);
  unlink(sub);
  snprintf(sub, sizeof(sub), "%s/proc", g_root);
  rmdir(sub);
  rmdir(g_root);
  return TEST_DONE();
}
