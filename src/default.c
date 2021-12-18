// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Print architecture default kernel base virtual address
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

  if (strstr(u.machine, "x86_64")) {
    addr = 0xffffffff81000000ul;
  } else if (strstr(u.machine, "i486") != NULL) {
    addr = 0xc1000000ul;
  } else if (strstr(u.machine, "i586") != NULL) {
    addr = 0xc1000000ul;
  } else if (strstr(u.machine, "i686") != NULL) {
    addr = 0xc1000000ul;
  /* TODO */
  } else if (strstr(u.machine, "armv6l") != NULL) {
    addr = 0xc0100000ul;
  } else if (strstr(u.machine, "armv7l") != NULL) {
    addr = 0xc0100000ul;
  } else {
    printf("[.] kernel base for arch '%s' is unknown\n", u.machine);
  }

  return addr;
}

int main(int argc, char **argv) {
  unsigned long addr = get_kernel_addr_default();
  if (!addr)
    return 1;

  printf("kernel base (arch default): %lx\n", addr);

  return 0;
}
