// This file is part of KASLD - https://github.com/bcoles/kasld
//
// Kernel message ring buffer syslog/dmesg helper functions.
// ---
// <bcoles@gmail.com>

#ifndef KASLD_SYSLOG_H
#define KASLD_SYSLOG_H

#define _GNU_SOURCE
#include "include/kasld/sysroot.h"

#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/klog.h>
#include <sys/mman.h>
#include <unistd.h>

#define SYSLOG_ACTION_READ_ALL 3
#define SYSLOG_ACTION_SIZE_BUFFER 10

/* Size the mapping for a `len`-byte kernel log: `len` page-rounded STRICTLY
 * upward, so every byte of a len-sized read lands inside the mapping and
 * buffer[len] is still a writable byte the caller may terminate on. Callers
 * walking the buffer by line depend on that byte existing.
 *
 * Returns 0 when `len` is out of range, which both sources treat as "no log to
 * read". The bound is that the rounded size must still fit a positive int:
 * that is the width this interface reports a size in, and `int` is also what
 * klogctl() takes and returns. A log larger than that is refused rather than
 * partly read — a prefix of a kernel log would silently drop whatever leaks sat
 * in the rest of it.
 *
 * Both sources round through here so that neither can size a mapping from one
 * value and then fill it from another. */
static size_t kasld_syslog_alloc(long len) {
  long page = getpagesize();

  if (len <= 0 || page <= 0 || len > (long)INT_MAX - page)
    return 0;
  return (size_t)((len / page + 1) * page);
}

/* Read /var/log/dmesg into an mmap'd buffer.
 * Fallback when klogctl() is denied (dmesg_restrict=1).
 */
static int read_dmesg_log_file(char **buffer, int *size) {
  FILE *f;
  long len;
  size_t alloc;
  const char *path = "/var/log/dmesg";

  f = kasld_fopen(path, "rb");
  if (f == NULL) {
    perror("[-] fopen(/var/log/dmesg)");
    return 1;
  }

  if (fseek(f, 0, SEEK_END) != 0 || (len = ftell(f)) <= 0) {
    fclose(f);
    return 1;
  }

  rewind(f);

  /* The mapping and the read are sized from the same `len`. Under
   * KASLD_SYSROOT this file comes from a captured tree rather than from the
   * running kernel, so its length is whatever that tree says it is. */
  alloc = kasld_syslog_alloc(len);
  if (alloc == 0) {
    fprintf(stderr, "[-] %s: implausible length (%ld bytes)\n", path, len);
    fclose(f);
    return 1;
  }
  *buffer = (char *)mmap(NULL, alloc, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (*buffer == MAP_FAILED) {
    fclose(f);
    return 1;
  }

  *size = (int)fread(*buffer, 1, (size_t)len, f);
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
 * On success *size is the number of bytes read and the mapping is strictly
 * larger, so buffer[*size] is a writable byte inside it: a caller may walk the
 * buffer by line and terminate the last one in place. Both sources establish
 * that through kasld_syslog_alloc().
 *
 * Copied from exploit code by xairy:
 * https://github.com/xairy/kernel-exploits/blob/master/CVE-2017-1000112/poc.c
 *
 * Defined static: each component is compiled as a standalone binary,
 * so header-embedded implementations are the intended pattern.
 */
static int mmap_syslog(char **buffer, int *size) {
  size_t alloc;
  int ring;

  /* Offline analysis: under KASLD_SYSROOT, klogctl() would read the live HOST
   * kernel log, not the analysed tree, so read the captured /var/log/dmesg
   * instead. With no sysroot set (the normal case) this falls through to the
   * klogctl-first path below (the live ring buffer is authoritative; the file
   * is only the fallback when klogctl is denied). */
  if (kasld_fact_source() == KASLD_FACTS_CAPTURE)
    return read_dmesg_log_file(buffer, size);

  /* The reported ring size is held apart from *size until the read succeeds,
   * so a fallback to the log file never inherits a size from the ring. */
  ring = klogctl(SYSLOG_ACTION_SIZE_BUFFER, 0, 0);
  if (ring < 0) {
    perror("[-] klogctl(SYSLOG_ACTION_SIZE_BUFFER)");
    return read_dmesg_log_file(buffer, size);
  }

  /* A ring can be raised to 2 GiB by the log_buf_len boot parameter, which is
   * past what the rounded size can report as a positive int. */
  alloc = kasld_syslog_alloc(ring);
  if (alloc == 0)
    return read_dmesg_log_file(buffer, size);

  *buffer = (char *)mmap(NULL, alloc, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (*buffer == MAP_FAILED) {
    return read_dmesg_log_file(buffer, size);
  }

  *size = klogctl(SYSLOG_ACTION_READ_ALL, *buffer, (int)alloc);
  if (*size < 0) {
    perror("[-] klogctl(SYSLOG_ACTION_READ_ALL)");
    munmap(*buffer, alloc);
    return read_dmesg_log_file(buffer, size);
  }

  /* alloc is strictly above the size the kernel reported, so a full read still
   * leaves buffer[*size] inside the mapping. Clamped rather than assumed: the
   * terminable-byte invariant must not rest on the two klogctl calls agreeing
   * about how much the ring holds. */
  if ((size_t)*size >= alloc)
    *size = (int)alloc - 1;

  return 0;
}

#endif /* KASLD_SYSLOG_H */
