// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Unit tests for kasld_classify_outcome() (outcome.h) — the reaped-component
// wait(2) status -> component_outcome mapping. Pure logic: no subprocess,
// seccomp filter, or namespace. The wait status is built with the Linux
// encoding the W* macros decode (exit code in bits 8..15; a fatal signal in
// bits 0..6), so the SIGSYS-denial and exit-code paths are exercised directly.
// ---
// <bcoles@gmail.com>

#include "include/kasld/outcome.h"
#include "test_harness.h"

#include <assert.h>
#include <signal.h>

/* wait-status encodings the kernel/libc produce and the W* macros decode. */
static int st_exited(int code) { return (code & 0xff) << 8; }
static int st_signaled(int sig) { return sig & 0x7f; }

/* A tagged result means the component succeeded, regardless of how it exited —
 * even a denial exit or a SIGSYS death after it already emitted output. */
static void test_tagged_output_is_success(void) {
  assert(kasld_classify_outcome(st_exited(KASLD_EXIT_NOPERM), 0, 1) ==
         OUTCOME_SUCCESS);
  assert(kasld_classify_outcome(st_signaled(SIGSYS), 0, 1) == OUTCOME_SUCCESS);
  assert(kasld_classify_outcome(st_exited(0), 0, 1) == OUTCOME_SUCCESS);
}

/* A timed-out component is TIMEOUT even though the kill left a signal status.
 */
static void test_timeout_beats_status(void) {
  assert(kasld_classify_outcome(st_signaled(SIGKILL), 1, 0) == OUTCOME_TIMEOUT);
  assert(kasld_classify_outcome(st_signaled(SIGSYS), 1, 0) == OUTCOME_TIMEOUT);
  assert(kasld_classify_outcome(st_exited(KASLD_EXIT_NOPERM), 1, 0) ==
         OUTCOME_TIMEOUT);
}

/* seccomp SCMP_ACT_KILL -> SIGSYS -> access denied, not a bare no-result. */
static void test_sigsys_is_access_denied(void) {
  assert(kasld_classify_outcome(st_signaled(SIGSYS), 0, 0) ==
         OUTCOME_ACCESS_DENIED);
}

/* The component's self-reported exit codes. */
static void test_exit_codes(void) {
  assert(kasld_classify_outcome(st_exited(KASLD_EXIT_NOPERM), 0, 0) ==
         OUTCOME_ACCESS_DENIED);
  assert(kasld_classify_outcome(st_exited(KASLD_EXIT_UNAVAILABLE), 0, 0) ==
         OUTCOME_UNAVAILABLE);
  assert(kasld_classify_outcome(st_exited(0), 0, 0) == OUTCOME_NO_RESULT);
  assert(kasld_classify_outcome(st_exited(1), 0, 0) == OUTCOME_NO_RESULT);
}

/* A non-SIGSYS fatal signal (a crash) is not an access denial. */
static void test_other_signal_is_no_result(void) {
  assert(kasld_classify_outcome(st_signaled(SIGSEGV), 0, 0) ==
         OUTCOME_NO_RESULT);
  assert(kasld_classify_outcome(st_signaled(SIGABRT), 0, 0) ==
         OUTCOME_NO_RESULT);
}

int main(void) {
  TEST_SUITE("component outcome classification");
  BEGIN_CATEGORY("kasld_classify_outcome");
  RUN(test_tagged_output_is_success);
  RUN(test_timeout_beats_status);
  RUN(test_sigsys_is_access_denied);
  RUN(test_exit_codes);
  RUN(test_other_signal_is_no_result);
  return TEST_DONE();
}
