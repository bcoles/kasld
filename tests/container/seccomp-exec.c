// This file is part of KASLD - https://github.com/bcoles/kasld
//
// seccomp-exec — install a minimal seccomp-BPF filter, then exec a program.
//
// A container runtime routinely confines a process with a seccomp filter that
// intercepts syscalls the guest is not allowed to make. The filter's action
// decides what the caller sees: SCMP_ACT_ERRNO returns a failure code (the
// syscall appears to fail, e.g. EPERM — docker's default), while SCMP_ACT_KILL
// terminates the caller with SIGSYS. kasld must stay sound and keep working
// under both. This wrapper reproduces either action for the container test
// harness without a container runtime, seccomp library, or privilege
// (PR_SET_NO_NEW_PRIVS lets an unprivileged process install a filter).
//
// The filter is narrow: it blocks perf_event_open() (kasld's most
// commonly-filtered syscall) and allows everything else. The filter is
// inherited across execve() and fork(), so it applies to the exec'd kasld and
// every component subprocess it forks — exactly a container's syscall gate.
//
// Usage:  seccomp-exec <errno|kill> <program> [args...]
//   errno  perf_event_open() fails with EPERM      (docker-default shape)
//   kill   perf_event_open() kills the caller (SIGSYS)  (strict shape)
//
// x86_64 only (the BPF audits AUDIT_ARCH_X86_64); a no-op passthrough on other
// arches so the harness degrades to a plain exec rather than mis-filtering.
// ---
// <bcoles@gmail.com>

#define _GNU_SOURCE
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/prctl.h>
#include <sys/syscall.h>

#if defined(__x86_64__) && __has_include(<linux/seccomp.h>) &&                  \
    __has_include(<linux/filter.h>) && __has_include(<linux/audit.h>)
#define SECCOMP_EXEC_ACTIVE 1
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

/* SECCOMP_RET_KILL_PROCESS (kill the whole process, not just the thread) is
 * newer than the base ABI; fall back to SECCOMP_RET_KILL_THREAD, which on a
 * single-threaded component is equivalent. Both deliver SIGSYS, so waitpid
 * reports WIFSIGNALED with WTERMSIG == SIGSYS either way. */
#ifndef SECCOMP_RET_KILL_PROCESS
#define SECCOMP_RET_KILL_PROCESS SECCOMP_RET_KILL_THREAD
#endif

static int install_filter(unsigned int block_action) {
  struct sock_filter code[] = {
      /* Guard on the syscall ABI: a non-x86_64 ABI (e.g. a 32-bit compat
       * syscall) is allowed unconditionally rather than mis-numbered. */
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      /* Load the syscall number; block perf_event_open, allow the rest. */
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_perf_event_open, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, block_action),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
  };
  struct sock_fprog prog = {
      .len = (unsigned short)(sizeof(code) / sizeof(code[0])),
      .filter = code,
  };
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
    perror("prctl(PR_SET_NO_NEW_PRIVS)");
    return -1;
  }
  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0) != 0) {
    perror("prctl(PR_SET_SECCOMP)");
    return -1;
  }
  return 0;
}
#endif

int main(int argc, char **argv) {
  if (argc < 3) {
    fprintf(stderr, "usage: %s <errno|kill> <program> [args...]\n", argv[0]);
    return 2;
  }
  const char *mode = argv[1];

#ifdef SECCOMP_EXEC_ACTIVE
  unsigned int action;
  if (strcmp(mode, "errno") == 0)
    action = SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA);
  else if (strcmp(mode, "kill") == 0)
    action = SECCOMP_RET_KILL_PROCESS;
  else {
    fprintf(stderr, "%s: mode must be 'errno' or 'kill'\n", argv[0]);
    return 2;
  }
  if (install_filter(action) != 0)
    return 3;
#else
  fprintf(stderr,
          "%s: seccomp filtering unavailable on this arch — plain exec\n",
          argv[0]);
  (void)mode;
#endif

  execv(argv[2], &argv[2]);
  perror("execv");
  return 127;
}
