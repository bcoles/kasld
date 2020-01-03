// This file is part of KASLD - https://github.com/bcoles/kasld
// Check kernel command line /proc/cmdline for nokaslr flag
// ---
// <bcoles@gmail.com>

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>

struct utsname get_kernel_version() {
  struct utsname u;
  if (uname(&u) != 0) {
    printf("[-] uname(): %m\n");
    exit(1);
  }
  return u;
}

unsigned long get_kernel_addr_cmdline() {
  FILE *f;
  const char *path = "/proc/cmdline";
  const char* flag = "nokaslr";
  char cmdline[1024];
  unsigned long addr = 0;
  struct utsname u = get_kernel_version();

  printf("[.] trying %s ...\n", path);

  f = fopen(path, "rb");
  if (f == NULL) {
    printf("[-] open/read(%s): %m\n", path);
    return 0;
  }

  if (fgets(cmdline, sizeof(cmdline), f) == NULL)
    printf("[-] fgets(%s): %m\n", path);

  fclose(f);

  if (memmem(&cmdline[0], sizeof(cmdline), flag, strlen(flag)) == NULL)
    return 0;

  printf("[.] Kernel booted with nokaslr flag.\n");

  if (strstr(u.machine, "64") != NULL) {
    addr = 0xffffffff81000000;
  } else if (strstr(u.machine, "86") != NULL) {
    addr = 0xc1000000ul;
    // addr = 0xc0400000ul; /* old kernels (pre-kaslr?) */
  } else {
    printf("[.] kernel base for arch '%s' is unknown\n", u.machine);
  }

  return addr;
}

int main (int argc, char **argv) {
  unsigned long addr = get_kernel_addr_cmdline();
  if (!addr) return 1;

  printf("kernel base (likely): %lx\n", addr);

  return 0;
}

