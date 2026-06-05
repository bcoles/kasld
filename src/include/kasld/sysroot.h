// This file is part of KASLD - https://github.com/bcoles/kasld
//
// KASLD_SYSROOT: optional path-redirection layer for offline replay.
//
// When the environment variable KASLD_SYSROOT names a non-empty directory,
// every kernel-fact path kasld reads (/proc, /sys, /boot, /var/log, ...) is
// transparently rewritten to "<KASLD_SYSROOT><path>", so the analysis runs
// against a captured filesystem tree instead of the live kernel. Inference
// is a pure function of these inputs, so a faithful capture replays to the
// same bounds offline — and to a foreign-arch capture under qemu-user with
// the matching cross-built kasld binary. See extra/collect for the capture
// tool that produces these trees.
//
// When KASLD_SYSROOT is unset (the normal case), these wrappers are exact
// pass-throughs: kasld_resolve() returns the original pointer and no copy is
// made. Only absolute paths are rewritten; a relative path is left alone.
//
// Not everything routes through here. Runtime-discovered objects that must
// observe the actual running system regardless of any sysroot deliberately
// keep the raw libc calls: /proc/self/exe (the real running binary), an
// ioctl target mountpoint, set-uid leak helpers. Those are runtime
// primitives, not facts, and cannot be replayed from a capture anyway.
// ---
// <bcoles@gmail.com>

#ifndef KASLD_SYSROOT_H
#define KASLD_SYSROOT_H

#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <unistd.h>

#ifndef KASLD_PATH_MAX
#define KASLD_PATH_MAX 4096
#endif

/* The KASLD_SYSROOT prefix, resolved once. NULL means unset (pass-through).
 * Read from the environment on first use; the result is cached because it is
 * fixed for the lifetime of the process (and inherited across the
 * orchestrator's component fork/exec). */
__attribute__((unused)) static const char *kasld_sysroot(void) {
  static const char *root;
  static int cached;
  if (!cached) {
    const char *v = getenv("KASLD_SYSROOT");
    root = (v && *v) ? v : NULL;
    cached = 1;
  }
  return root;
}

/* Resolve an absolute fact path against the sysroot. With no sysroot set (or
 * a non-absolute path), returns `abs` unchanged. Otherwise writes
 * "<root><abs>" into buf and returns it; if that would not fit, falls back to
 * `abs` (a miss against the live tree is safer than a truncated path). */
__attribute__((unused)) static const char *
kasld_resolve(const char *abs, char *buf, size_t bufsz) {
  const char *root = kasld_sysroot();
  size_t rl, al;
  if (root == NULL || abs == NULL || abs[0] != '/')
    return abs;
  rl = strlen(root);
  al = strlen(abs);
  if (rl + al + 1 > bufsz)
    return abs;
  memcpy(buf, root, rl);
  memcpy(buf + rl, abs, al + 1);
  return buf;
}

__attribute__((unused)) static FILE *kasld_fopen(const char *path,
                                                 const char *mode) {
  char buf[KASLD_PATH_MAX];
  return fopen(kasld_resolve(path, buf, sizeof(buf)), mode);
}

/* Read-only open() only — kasld never creates files, so no mode arg (and
 * thus no variadic wrapper) is needed. */
__attribute__((unused)) static int kasld_open(const char *path, int flags) {
  char buf[KASLD_PATH_MAX];
  return open(kasld_resolve(path, buf, sizeof(buf)), flags);
}

__attribute__((unused)) static int kasld_stat(const char *path,
                                              struct stat *st) {
  char buf[KASLD_PATH_MAX];
  return stat(kasld_resolve(path, buf, sizeof(buf)), st);
}

__attribute__((unused)) static int kasld_access(const char *path, int mode) {
  char buf[KASLD_PATH_MAX];
  return access(kasld_resolve(path, buf, sizeof(buf)), mode);
}

/* opendir() through the sysroot. Entry names are returned as-is (relative to
 * the dir), so callers rebuild child paths with the original (un-rewritten)
 * directory prefix and re-resolve via the other wrappers. */
__attribute__((unused)) static DIR *kasld_opendir(const char *path) {
  char buf[KASLD_PATH_MAX];
  return opendir(kasld_resolve(path, buf, sizeof(buf)));
}

/* uname(2) with a replay override of the kernel release. Components build
 * release-named /boot paths (vmlinuz-<rel>, config-<rel>, System.map-<rel>)
 * from uname().release, so a capture must present its captured release, not
 * the host's. KASLD_SYSROOT redirects the path; this supplies the release in
 * it. The override is needed because it propagates to component subprocesses
 * via the environment, whereas qemu-user's QEMU_UNAME is not honored after the
 * self-re-exec qemu performs for a foreign-arch child. Unset (normal runs) =>
 * exact uname() pass-through. Only .release is overridden; .machine is the
 * emulated arch (already correct under qemu) and compile-time on native. */
__attribute__((unused)) static int kasld_uname(struct utsname *u) {
  int rc = uname(u);
  if (rc == 0) {
    const char *rel = getenv("KASLD_UNAME_RELEASE");
    if (rel && *rel) {
      size_t n = sizeof(u->release) - 1;
      strncpy(u->release, rel, n);
      u->release[n] = '\0';
    }
  }
  return rc;
}

#endif /* KASLD_SYSROOT_H */
