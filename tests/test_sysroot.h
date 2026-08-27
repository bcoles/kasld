// This file is part of KASLD - https://github.com/bcoles/kasld
//
// test_sysroot.h — a staged filesystem for tests that read a fact source.
//
// A test that consults a real path asserts against whatever the machine
// running it happens to hold, or -- harder to notice -- against what it happens
// to LACK, which nothing in the test's text reveals. The fix is to supply the
// tree rather than borrow it: stage a directory, put the files under it, and
// point KASLD_SYSROOT at it, which the kasld_* wrappers resolve every absolute
// path through.
//
// The prefix is cached on first use (kasld_sysroot()), so the root must be
// established before the first read. The CONTENTS are not cached, which is what
// makes per-test staging work: one root for the process, a tree each test
// shapes for itself.
//
// That per-test shaping is the point. A tree staged once in main() is a
// dependency every later test inherits silently -- a test can come to rely on a
// file it never mentions, and reads as if it stood alone. Here a test stages
// what it needs and clears first, so the dependency is written where the
// assertion is.
//
// Absence is a legitimate staging, and often the interesting one: an empty tree
// is how a test says "this source is not present".
// ---
// <bcoles@gmail.com>

#ifndef KASLD_TEST_SYSROOT_H
#define KASLD_TEST_SYSROOT_H

/* Every includer uses a subset of the helpers below, so the rest are unused in
 * any given translation unit. Suppressed here rather than by tagging each
 * definition: the definitions are matched verbatim by tests/check-test-staging,
 * which reads their bodies to confirm the root is registered for removal, and
 * an attribute between `static` and the return type breaks that match. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"

#include <assert.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define TH_SYSROOT_MAX 384

static char th_sysroot_root[128];

/* Every path this header touches is built here, and every caller goes through
 * it. A staged path must be absolute: a relative one would land outside the
 * root, and the recursive clear below would then be pointed somewhere it has no
 * business being. */
static void th_sysroot_path(const char *abs, char *out, size_t outsz) {
  assert(th_sysroot_root[0] != '\0' && "th_sysroot_init() first");
  assert(abs && abs[0] == '/' && "staged paths are absolute");
  assert(strstr(abs, "/..") == NULL && "no traversal in a staged path");
  int n = snprintf(out, outsz, "%s%s", th_sysroot_root, abs);
  assert(n > 0 && (size_t)n < outsz && "staged path too long");
}

static void th_sysroot_fini(void);

/* Create the staged root and point KASLD_SYSROOT at it.
 *
 * Call once, before anything reads a fact. Under the hermeticity probe that
 * ordering is checked rather than trusted: the probe records absolute paths
 * resolved with no root set, so a non-empty record here means a read already
 * escaped to the host and the rest of this file's isolation is a fiction.
 *
 * `label` names the binary and goes in the directory name, so a tree that
 * outlives its run says which test left it.
 *
 * Removal is registered here rather than left to the caller. A test that ends
 * by returning from main() cleans up whether or not it remembers to, which is
 * what keeps a suite run from depositing a tree per binary every time it
 * passes. A test that dies on a failed assertion does NOT: abort() runs no
 * atexit handler, so the tree it was working in survives for a reader. Cleanup
 * on success, evidence on failure. */
static void th_sysroot_init(const char *label) {
  assert(th_sysroot_root[0] == '\0' && "th_sysroot_init() called twice");
  assert(label && *label && "name the binary; the directory carries it");
  assert(strchr(label, '/') == NULL && "label is a name, not a path");
#ifdef KASLD_HERMETIC_PROBE
  assert(kasld_hermetic_n == 0 &&
         "th_sysroot_init() must run before the first fact read");
#endif
  int n = snprintf(th_sysroot_root, sizeof(th_sysroot_root),
                   "/tmp/kasld_%s_XXXXXX", label);
  assert(n > 0 && (size_t)n < sizeof(th_sysroot_root) && "label too long");
  assert(mkdtemp(th_sysroot_root) != NULL);
  assert(setenv("KASLD_SYSROOT", th_sysroot_root, 1) == 0);
  assert(atexit(th_sysroot_fini) == 0);
}

/* mkdir -p over the directory part of a staged path, in place. */
static void th_sysroot_mkparents(char *full) {
  char *slash = strrchr(full, '/');
  if (!slash || slash == full)
    return;
  *slash = '\0';
  for (char *p = full + strlen(th_sysroot_root) + 1; *p; p++) {
    if (*p != '/')
      continue;
    *p = '\0';
    (void)mkdir(full, 0755); /* EEXIST is the common case */
    *p = '/';
  }
  (void)mkdir(full, 0755);
  *slash = '/';
}

/* Stage `abs` with `len` bytes of `buf`. Length-taking because a fact source is
 * not always text: a zero page, an ELF core header and a kernel image header
 * are staged as byte buffers, and a NUL is ordinary content in them, not a
 * terminator. */
static void th_sysroot_write_n(const char *abs, const void *buf, size_t len) {
  char full[TH_SYSROOT_MAX];
  th_sysroot_path(abs, full, sizeof(full));
  th_sysroot_mkparents(full);
  FILE *f = fopen(full, "wb");
  assert(f != NULL);
  if (len)
    assert(fwrite(buf, 1, len, f) == len);
  assert(fclose(f) == 0);
}

/* Stage `abs` with `contents`. A NULL `contents` writes an empty file, which is
 * what a marker like /.dockerenv actually is. */
static void th_sysroot_write(const char *abs, const char *contents) {
  th_sysroot_write_n(abs, contents, contents ? strlen(contents) : 0);
}

/* Resolve `abs` to its real location under the root and make its parent
 * directories, for a test that must use the file APIs directly: an incremental
 * writer, a sparse file whose SIZE is the fixture, a mode or a symlink. Staging
 * still goes through here, so such a test is inside the managed tree and is
 * removed with it. */
static void th_sysroot_stage_path(const char *abs, char *out, size_t outsz) {
  th_sysroot_path(abs, out, outsz);
  th_sysroot_mkparents(out);
}

static void th_sysroot_rm(const char *abs) {
  char full[TH_SYSROOT_MAX];
  th_sysroot_path(abs, full, sizeof(full));
  (void)unlink(full);
}

/* Depth-first removal of everything under `dir`, which is always inside the
 * staged root -- the callers below start at the root and recurse only into
 * entries they read from it. Symlinks are unlinked, never followed: nothing
 * here stages one, and following would let a staged tree reach outside itself.
 */
static void th_sysroot_rm_r(const char *dir) {
  DIR *d = opendir(dir);
  if (!d)
    return;
  struct dirent *e;
  while ((e = readdir(d)) != NULL) {
    if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
      continue;
    char child[TH_SYSROOT_MAX];
    if ((size_t)snprintf(child, sizeof(child), "%s/%s", dir, e->d_name) >=
        sizeof(child))
      continue;
    struct stat st;
    if (lstat(child, &st) != 0)
      continue;
    if (S_ISDIR(st.st_mode))
      th_sysroot_rm_r(child);
    else
      (void)unlink(child);
  }
  closedir(d);
  (void)rmdir(dir);
}

/* Empty the tree, keeping the root itself (and so the cached prefix). Call at
 * the top of a test that stages: it starts from a stated tree rather than
 * whatever ran before it. */
static void th_sysroot_clear(void) {
  assert(th_sysroot_root[0] != '\0' && "th_sysroot_init() first");
  DIR *d = opendir(th_sysroot_root);
  if (!d)
    return;
  struct dirent *e;
  while ((e = readdir(d)) != NULL) {
    if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
      continue;
    char child[TH_SYSROOT_MAX];
    if ((size_t)snprintf(child, sizeof(child), "%s/%s", th_sysroot_root,
                         e->d_name) >= sizeof(child))
      continue;
    struct stat st;
    if (lstat(child, &st) != 0)
      continue;
    if (S_ISDIR(st.st_mode))
      th_sysroot_rm_r(child);
    else
      (void)unlink(child);
  }
  closedir(d);
}

/* Remove the tree and the root. Registered by th_sysroot_init(), so calling it
 * explicitly is optional; the early return makes the second call a no-op. */
static void th_sysroot_fini(void) {
  if (th_sysroot_root[0] == '\0')
    return;
  th_sysroot_clear();
  (void)rmdir(th_sysroot_root);
  th_sysroot_root[0] = '\0';
}

#pragma GCC diagnostic pop

#endif /* KASLD_TEST_SYSROOT_H */
