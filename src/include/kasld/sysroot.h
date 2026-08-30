// This file is part of KASLD - https://github.com/bcoles/kasld
//
// KASLD_SYSROOT: optional path-redirection layer for offline analysis.
//
// When the environment variable KASLD_SYSROOT names a non-empty directory,
// every kernel-fact path kasld reads (/proc, /sys, /boot, /var/log, ...) is
// transparently rewritten to "<KASLD_SYSROOT><path>", so the analysis runs
// against a copy of those files taken from another system instead of the live
// kernel. Inference is a pure function of these inputs, so the same files yield
// the same bounds offline — including a foreign-arch copy under qemu-user with
// the matching cross-built kasld binary. See extra/collect for the tool that
// gathers such a tree.
//
// When KASLD_SYSROOT is unset (the normal case), these wrappers are exact
// pass-throughs: kasld_resolve() returns the original pointer and no copy is
// made. Only absolute paths are rewritten; a relative path is left alone.
//
// Not everything routes through here. Runtime-discovered objects that must
// observe the actual running system regardless of any sysroot deliberately
// keep the raw libc calls: /proc/self/exe (the real running binary), an
// ioctl target mountpoint, set-uid leak helpers. Those are runtime
// primitives, not facts, and have no meaning when read from a copied tree.
// ---
// <bcoles@gmail.com>

#ifndef KASLD_SYSROOT_H
#define KASLD_SYSROOT_H

#include <dirent.h>
#include <errno.h>
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

#ifdef KASLD_HERMETIC_PROBE
/* Test builds only: records fact paths resolved with no sysroot set — that is,
 * read from the machine running the test rather than from a tree the test
 * supplied. tests/test_harness.h fails the binary on any record.
 *
 * Every path reaching kasld_resolve is a kernel fact, so this needs no notion
 * of which paths matter. It lives here rather than in a source scan because the
 * read is usually several frames below the test: a renderer test that names no
 * path still reaches container detection, the LSM probe and the group database.
 * It also catches staging done too LATE, since the prefix is cached on first
 * use and a read before the setenv resolves live.
 *
 * Never defined for a shipped build. */
#define KASLD_HERMETIC_MAX 12
__attribute__((
    unused)) static const char *kasld_hermetic_paths[KASLD_HERMETIC_MAX];
__attribute__((unused)) static int kasld_hermetic_n;
__attribute__((unused)) static int kasld_hermetic_dropped;

__attribute__((unused)) static void kasld_hermetic_record(const char *abs) {
  int i;
  for (i = 0; i < kasld_hermetic_n; i++)
    if (strcmp(kasld_hermetic_paths[i], abs) == 0)
      return;
  if (kasld_hermetic_n == KASLD_HERMETIC_MAX) {
    kasld_hermetic_dropped++;
    return;
  }
  /* Callers pass string literals or buffers that outlive the run; copying
   * would need an allocator this header has no reason to want. */
  kasld_hermetic_paths[kasld_hermetic_n++] = abs;
}
#endif

/* Resolve an absolute fact path against the sysroot. With no sysroot set (or
 * a non-absolute path), returns `abs` unchanged. Otherwise writes
 * "<root><abs>" into buf and returns it.
 *
 * Returns NULL if the prefixed path does not fit. buf is KASLD_PATH_MAX at
 * every call site, so a path that does not fit is already longer than one the
 * kernel will open: there is no reading it either way. Callers must check, and
 * fail the read with ENAMETOOLONG. Returning `abs` instead would read the
 * analysing machine's own file while a sysroot named another tree. */
__attribute__((unused)) static const char *
kasld_resolve(const char *abs, char *buf, size_t bufsz) {
  const char *root = kasld_sysroot();
  size_t rl, al;
#ifdef KASLD_HERMETIC_PROBE
  if (root == NULL && abs != NULL && abs[0] == '/')
    kasld_hermetic_record(abs);
#endif
  if (root == NULL || abs == NULL || abs[0] != '/')
    return abs;
  rl = strlen(root);
  al = strlen(abs);
  if (rl + al + 1 > bufsz)
    return NULL;
  memcpy(buf, root, rl);
  memcpy(buf + rl, abs, al + 1);
  return buf;
}

__attribute__((unused)) static FILE *kasld_fopen(const char *path,
                                                 const char *mode) {
  char buf[KASLD_PATH_MAX];
  const char *p = kasld_resolve(path, buf, sizeof(buf));
  if (!p) {
    errno = ENAMETOOLONG;
    return NULL;
  }
  return fopen(p, mode);
}

/* Read-only open() only — kasld never creates files, so no mode arg (and
 * thus no variadic wrapper) is needed. */
__attribute__((unused)) static int kasld_open(const char *path, int flags) {
  char buf[KASLD_PATH_MAX];
  const char *p = kasld_resolve(path, buf, sizeof(buf));
  if (!p) {
    errno = ENAMETOOLONG;
    return -1;
  }
  return open(p, flags);
}

__attribute__((unused)) static int kasld_stat(const char *path,
                                              struct stat *st) {
  char buf[KASLD_PATH_MAX];
  const char *p = kasld_resolve(path, buf, sizeof(buf));
  if (!p) {
    errno = ENAMETOOLONG;
    return -1;
  }
  return stat(p, st);
}

__attribute__((unused)) static int kasld_access(const char *path, int mode) {
  char buf[KASLD_PATH_MAX];
  const char *p = kasld_resolve(path, buf, sizeof(buf));
  if (!p) {
    errno = ENAMETOOLONG;
    return -1;
  }
  return access(p, mode);
}

/* opendir() through the sysroot. Entry names are returned as-is (relative to
 * the dir), so callers rebuild child paths with the original (un-rewritten)
 * directory prefix and re-resolve via the other wrappers. */
__attribute__((unused)) static DIR *kasld_opendir(const char *path) {
  char buf[KASLD_PATH_MAX];
  const char *p = kasld_resolve(path, buf, sizeof(buf));
  if (!p) {
    errno = ENAMETOOLONG;
    return NULL;
  }
  return opendir(p);
}

/* Read the first line of a fact file into buf: NUL-terminated, trailing
 * newline stripped. A generic convenience over kasld_fopen (so it honors
 * KASLD_SYSROOT); callers parse the resulting string themselves. Returns 0 on
 * success, -1 if the file cannot be opened or the first line cannot be read. */
__attribute__((unused)) static int kasld_read_file_line(const char *path,
                                                        char *buf, size_t len) {
  FILE *f = kasld_fopen(path, "r");
  if (!f)
    return -1;
  if (fgets(buf, (int)len, f) == NULL) {
    fclose(f);
    return -1;
  }
  fclose(f);
  buf[strcspn(buf, "\n")] = '\0';
  return 0;
}

/* Fill release and version from a captured /proc/version. The kernel writes
 * "<sysname> version <release> (<by>@<host>) (<compiler>) <version>", where
 * <version> is utsname.version and begins with '#' followed by the build
 * number. Both fields are left untouched unless the whole line parses. */
__attribute__((unused)) static int
kasld_uname_from_proc_version(struct utsname *u) {
  char line[512];
  char *rel, *end, *ver;
  size_t n;

  if (kasld_read_file_line("/proc/version", line, sizeof(line)) != 0)
    return -1;
  /* First match only: a compiler string can carry its own " version ". */
  rel = strstr(line, " version ");
  if (!rel)
    return -1;
  rel += sizeof(" version ") - 1;
  end = strchr(rel, ' ');
  if (!end || end == rel)
    return -1;
  /* The compiler string is parenthesized and carries no '#', but anchor on the
   * build number anyway so only a utsname.version can start the tail. */
  for (ver = end; (ver = strchr(ver, '#')) != NULL; ver++)
    if (ver[1] >= '0' && ver[1] <= '9')
      break;
  if (!ver)
    return -1;

  /* utsname.version is 64 chars plus NUL, the same width the kernel truncates
   * to, so a long version clips here exactly as it does live and the two
   * compose the same fingerprint. */
  *end = '\0';
  n = sizeof(u->release) - 1;
  strncpy(u->release, rel, n);
  u->release[n] = '\0';
  n = sizeof(u->version) - 1;
  strncpy(u->version, ver, n);
  u->version[n] = '\0';
  return 0;
}

/* uname(2) with the kernel identity taken from the tree under analysis.
 *
 * Components build release-named /boot paths (vmlinuz-<rel>, config-<rel>,
 * System.map-<rel>) from uname().release, and the offset-table components key
 * on "<release> <version>", so both fields have to describe the captured
 * kernel rather than the machine running the analysis. Under KASLD_SYSROOT
 * they come from the captured /proc/version, which carries both.
 *
 * KASLD_UNAME_RELEASE overrides the release afterwards; it is what a run
 * without a captured /proc/version has, and it propagates to subprocesses via
 * the environment, whereas qemu-user's QEMU_UNAME is not honored after the
 * self-re-exec qemu performs for a foreign-arch child. With neither set
 * (normal runs) => exact uname() pass-through. .machine is never overridden:
 * it is the emulated arch under qemu, and compile-time on native. */
__attribute__((unused)) static int kasld_uname(struct utsname *u) {
  int rc = uname(u);
  if (rc == 0) {
    const char *rel;
    if (kasld_sysroot())
      kasld_uname_from_proc_version(u);
    rel = getenv("KASLD_UNAME_RELEASE");
    if (rel && *rel) {
      size_t n = sizeof(u->release) - 1;
      strncpy(u->release, rel, n);
      u->release[n] = '\0';
    }
  }
  return rc;
}

/* Compose "<release> <version>" into buf and trim trailing spaces. Offset-table
 * components match this full-uname build fingerprint against per-build entries;
 * a long Ubuntu HWE version is clipped at utsname.version's 64-char field and
 * can end on a space, so trimming keeps the live string equal to the (also
 * trimmed) stored fingerprint. The caller passes the utsname (from kasld_uname)
 * so each component keeps its own uname fetch and failure policy. */
__attribute__((unused)) static void
kasld_uname_fingerprint(char *buf, size_t n, const struct utsname *u) {
  size_t i;
  snprintf(buf, n, "%s %s", u->release, u->version);
  for (i = strlen(buf); i > 0 && buf[i - 1] == ' '; i--)
    buf[i - 1] = '\0';
}

#endif /* KASLD_SYSROOT_H */
