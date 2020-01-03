// This file is part of KASLD - https://github.com/bcoles/kasld
// Print default kernel base virtual address
// ---
// <bcoles@gmail.com>

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

unsigned long get_kernel_addr_default() {
  unsigned long addr = 0;
  struct utsname u = get_kernel_version();

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
  unsigned long addr = get_kernel_addr_default();
  if (!addr) return 1;

  printf("kernel base (arch default): %lx\n", addr);

  return 0;
}

