// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Kernel message ring buffer syslog/dmesg helper functions.
// ---
// <bcoles@gmail.com>

#define _GNU_SOURCE
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/klog.h>
#include <sys/mman.h>
#include <unistd.h>

#define SYSLOG_ACTION_READ_ALL 3
#define SYSLOG_ACTION_SIZE_BUFFER 10

/* mmap entire kernel message ring buffer into +buffer+.
 * Copied from exploit code by xairy:
 * https://github.com/xairy/kernel-exploits/blob/master/CVE-2017-1000112/poc.c
 */
int mmap_syslog(char **buffer, int *size) {
  *size = klogctl(SYSLOG_ACTION_SIZE_BUFFER, 0, 0);
  if (*size == -1) {
    perror("[-] klogctl(SYSLOG_ACTION_SIZE_BUFFER)");
    return 1;
  }

  *size = (*size / getpagesize() + 1) * getpagesize();
  *buffer = (char *)mmap(NULL, *size, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

  *size = klogctl(SYSLOG_ACTION_READ_ALL, &((*buffer)[0]), *size);
  if (*size == -1) {
    perror("[-] klogctl(SYSLOG_ACTION_READ_ALL)");
    return 1;
  }

  return 0;
}
