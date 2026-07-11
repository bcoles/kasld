// This file is part of KASLD - https://github.com/bcoles/kasld
//
// fork-fail.so — an LD_PRELOAD shim that makes a fraction of fork() calls fail
// with EAGAIN, to test that kasld stays coherent under fork starvation.
//
// A container with a pids cgroup limit (kubernetes `pids.max`, docker
// `--pids-limit`) makes fork()/clone() return EAGAIN once the task count is
// hit. The orchestrator forks one subprocess per component; a failed fork must
// skip that component and continue — not hang, crash, or emit invalid JSON.
// Reproducing that with a real pids cgroup needs delegation and a task count
// that is fragile across machines; interposing fork() is deterministic and
// needs no privilege or cgroup.
//
// Fails every Nth fork() (N = $FORK_FAIL_EVERY, default 2); the first N-1 of
// each group succeed so startup progresses. The shim is inherited across
// execve(), so it also perturbs the components' own fork() use — a superset of
// the orchestrator's path, exercising graceful degradation end to end.
//
// Usage:  FORK_FAIL_EVERY=3 LD_PRELOAD=.../fork-fail.so kasld ...
// ---
// <bcoles@gmail.com>

#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

static int fail_every = 2;
static unsigned long fork_count;

__attribute__((constructor)) static void fork_fail_init(void) {
  const char *e = getenv("FORK_FAIL_EVERY");
  if (e && *e) {
    int v = atoi(e);
    if (v > 0)
      fail_every = v;
  }
}

pid_t fork(void) {
  static pid_t (*real_fork)(void);
  if (!real_fork)
    real_fork = (pid_t (*)(void))dlsym(RTLD_NEXT, "fork");

  fork_count++;
  if (fail_every > 0 && (fork_count % (unsigned long)fail_every) == 0) {
    errno = EAGAIN;
    return -1;
  }
  return real_fork();
}
