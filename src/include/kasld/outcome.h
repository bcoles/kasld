// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Component outcome classification.
//
// Maps a reaped component subprocess's wait(2) status to a component_outcome.
// Factored out of the orchestrator as a pure function so it can be unit-tested
// without a live subprocess, seccomp filter, or namespace.
// ---
// <bcoles@gmail.com>

#ifndef KASLD_OUTCOME_H
#define KASLD_OUTCOME_H

#include "internal.h" /* enum component_outcome; KASLD_EXIT_* via api.h */

#include <signal.h>   /* SIGSYS */
#include <sys/wait.h> /* WIFEXITED / WEXITSTATUS / WIFSIGNALED / WTERMSIG */

/* Classify a reaped component from its wait() status and two run flags.
 * Precedence, high to low:
 *   had_tagged  the component emitted a tagged result → SUCCESS, however it
 *               then exited.
 *   timed_out   the orchestrator killed it mid-run → report the timeout, not
 *               whatever signal the kill produced.
 *   SIGSYS      a seccomp SCMP_ACT_KILL denial (the strict-container analogue
 *               of the EPERM that SCMP_ACT_ERRNO returns) → access denied, not
 *               a bare signal death.
 *   exit 77/69  the component's self-reported KASLD_EXIT_NOPERM (access denied)
 *               / KASLD_EXIT_UNAVAILABLE (feature absent).
 *   otherwise   no result. */
static inline enum component_outcome
kasld_classify_outcome(int status, int timed_out, int had_tagged) {
  if (had_tagged)
    return OUTCOME_SUCCESS;
  if (timed_out)
    return OUTCOME_TIMEOUT;
  if (WIFSIGNALED(status) && WTERMSIG(status) == SIGSYS)
    return OUTCOME_ACCESS_DENIED;
  int rc = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
  if (rc == KASLD_EXIT_NOPERM)
    return OUTCOME_ACCESS_DENIED;
  if (rc == KASLD_EXIT_UNAVAILABLE)
    return OUTCOME_UNAVAILABLE;
  return OUTCOME_NO_RESULT;
}

#endif /* KASLD_OUTCOME_H */
