// This file is part of KASLD - https://github.com/bcoles/kasld
// Check kernel config for CONFIG_RELOCATABLE and CONFIG_RANDOMIZE_BASE
// - https://lwn.net/Articles/444556/
// - https://cateee.net/lkddb/web-lkddb/RANDOMIZE_BASE.html
// - https://cateee.net/lkddb/web-lkddb/RELOCATABLE.html
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

unsigned long get_kernel_addr_cmdline() {
  unsigned long addr = 0;

  printf("[.] checking /boot/config ...\n");

  if (system("test -r /boot/config-$(uname -r)") != 0)
    return 0;
  if (system("grep -q CONFIG_RELOCATABLE=y /boot/config-$(uname -r) && grep -q CONFIG_RANDOMIZE_BASE=y /boot/config-$(uname -r)") == 0)
    return 0;

  printf("[.] Kernel appears to have been compiled without CONFIG_RELOCATABLE and CONFIG_RANDOMIZE_BASE\n");

  struct utsname u = get_kernel_version();

  if (strstr(u.machine, "64") != NULL) {
    addr = 0xffffffff81000000;
  } else if (strstr(u.machine, "86") != NULL) {
    addr = 0xc1000000ul;
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

