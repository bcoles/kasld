// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Kernel message ring buffer syslog/dmesg helper functions.
// ---
// <bcoles@gmail.com>

#ifndef KASLD_SYSLOG_H
#define KASLD_SYSLOG_H

#define _GNU_SOURCE
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/klog.h>
#include <sys/mman.h>
#include <unistd.h>

#define SYSLOG_ACTION_READ_ALL 3
#define SYSLOG_ACTION_SIZE_BUFFER 10

/* Read /var/log/dmesg into an mmap'd buffer.
 * Fallback when klogctl() is denied (dmesg_restrict=1).
 */
static int read_dmesg_log_file(char **buffer, int *size) {
  FILE *f;
  long len;
  int alloc;
  const char *path = "/var/log/dmesg";

  f = fopen(path, "rb");
  if (f == NULL) {
    perror("[-] fopen(/var/log/dmesg)");
    return 1;
  }

  if (fseek(f, 0, SEEK_END) != 0 || (len = ftell(f)) <= 0) {
    fclose(f);
    return 1;
  }

  rewind(f);

  alloc = ((int)len / getpagesize() + 1) * getpagesize();
  *buffer = (char *)mmap(NULL, alloc, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (*buffer == MAP_FAILED) {
    fclose(f);
    return 1;
  }

  *size = (int)fread(*buffer, 1, len, f);
  fclose(f);

  if (*size <= 0) {
    munmap(*buffer, alloc);
    return 1;
  }

  return 0;
}

/* mmap entire kernel message ring buffer into +buffer+.
 * Falls back to /var/log/dmesg when klogctl() is denied.
 *
 * Copied from exploit code by xairy:
 * https://github.com/xairy/kernel-exploits/blob/master/CVE-2017-1000112/poc.c
 *
 * Defined static: each component is compiled as a standalone binary,
 * so header-embedded implementations are the intended pattern.
 */
static int mmap_syslog(char **buffer, int *size) {
  int alloc;

  *size = klogctl(SYSLOG_ACTION_SIZE_BUFFER, 0, 0);
  if (*size == -1) {
    perror("[-] klogctl(SYSLOG_ACTION_SIZE_BUFFER)");
    return read_dmesg_log_file(buffer, size);
  }

  alloc = (*size / getpagesize() + 1) * getpagesize();
  *buffer = (char *)mmap(NULL, alloc, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (*buffer == MAP_FAILED) {
    return read_dmesg_log_file(buffer, size);
  }

  *size = klogctl(SYSLOG_ACTION_READ_ALL, *buffer, alloc);
  if (*size == -1) {
    perror("[-] klogctl(SYSLOG_ACTION_READ_ALL)");
    munmap(*buffer, alloc);
    return read_dmesg_log_file(buffer, size);
  }

  return 0;
}

#endif /* KASLD_SYSLOG_H */
